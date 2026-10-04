package ebpf

import (
	"fmt"
	"k-guard/internal/trust"
	"k-guard/internal/types"
	"log/slog"
	"net"
	"os"
	"reflect"
	"runtime"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -go-package ebpf -target amd64 -cc clang -cflags "-Wno-int-conversion -DKGUARD_HAVE_VMLINUX -I../../bpf/include" -type dns_answer_event -type pmu_event -type lpe_event -type iouring_event -type file_id -type event_hdr -type exec_event -type connect_event -type open_event -type ptrace_event -type kmod_event -type ns_change_event BPF ../../bpf/kguard.c -- -I../../bpf/include -I../../bpf -D__TARGET_ARCH_x86
type Manager struct {
	Objects BPFObjects
	Reader  *ringbuf.Reader

	links []link.Link

	LSMEnabled bool

	perfEventFds []int

	activeSensors []string

	ptraceAllow *trust.Set
}

type LpmKey256 struct {
	PrefixLenBits uint32
	Data          [256]byte
}

type FileID = types.FileID

func NewManager() (*Manager, error) {
	// Removing the memory limit, standard practice
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("memlock rlimit: %w", err)
	}

	m := &Manager{}
	if err := LoadBPFObjects(&m.Objects, nil); err != nil {
		return nil, fmt.Errorf("loading BPF objects: %w", err)
	}

	type tpSpec struct {
		category, event, name string
		prog                  *ebpf.Program
	}
	tracepoints := []tpSpec{
		{"syscalls", "sys_enter_execve", "tp_execve", m.Objects.TpExecve},
		{"syscalls", "sys_enter_dup2", "tp_dup2", m.Objects.TpDup2},
		{"syscalls", "sys_enter_dup3", "tp_dup3", m.Objects.TpDup3},
		{"sched", "sched_process_exec", "tp_schedexec", m.Objects.TpSchedexec},
		{"sched", "sched_process_fork", "tp_schedfork", m.Objects.TpSchedfork},
		{"syscalls", "sys_enter_connect", "tp_connect", m.Objects.TpConnect},
		{"syscalls", "sys_enter_sendto", "tp_sendto", m.Objects.TpSendto},
		{"syscalls", "sys_enter_openat", "tp_openat", m.Objects.TpOpenat},
		{"syscalls", "sys_enter_openat2", "tp_openat2", m.Objects.TpOpenat2},
		{"syscalls", "sys_enter_ptrace", "tp_ptrace", m.Objects.TpPtrace},
		{"syscalls", "sys_enter_setuid", "tp_setuid", m.Objects.TpSetuid},
		{"syscalls", "sys_enter_unshare", "tp_unshare", m.Objects.TpUnshare},
		{"syscalls", "sys_enter_setns", "tp_setns", m.Objects.TpSetns},
		{"syscalls", "sys_enter_init_module", "tp_init_module", m.Objects.TpInitModule},
		{"syscalls", "sys_enter_memfd_create", "tp_memfd_create", m.Objects.TpMemfdCreate},
		{"io_uring", "io_uring_submit_req", "tp_iouring_req", m.Objects.TpIoUringSubmitReq},
	}

	for _, tp := range tracepoints {
		if tp.prog == nil {
			slog.Warn("program not present in compiled object, skipping sensor", "component", "ebpf", "program", tp.name)
			continue
		}

		l, aerr := link.Tracepoint(tp.category, tp.event, tp.prog, nil)
		if aerr != nil {
			slog.Warn("failed to attach tracepoint sensor (kernel/permissions may not support it)",
				"component", "ebpf",
				"category", tp.category,
				"event", tp.event,
				"error", aerr,
			)
			continue
		}
		m.links = append(m.links, l)
		m.activeSensors = append(m.activeSensors, tp.name)
	}

	if len(m.activeSensors) == 0 {
		m.Close()
		return nil, fmt.Errorf("no sensors could be attached at all, check kernel version, capabilities, and that the object was built for this arch")
	}

	if m.Objects.LsmBprmCheck != nil {
		l, aerr := link.AttachLSM(link.LSMOptions{Program: m.Objects.LsmBprmCheck})
		if aerr != nil {
			slog.Warn("LSM enforcement hook failed to attach; falling back to detect-only mode",
				"component", "ebpf",
				"error", aerr,
			)
		} else {
			m.links = append(m.links, l)
			m.LSMEnabled = true
			slog.Info("LSM enforcement hook attached, pre-exec blocking is ACTIVE", "component", "ebpf")
			// We start by setting Enforcment to false so that it doesn't start working before we need it to
			// it's also to avoid it possbily terminating any program unexpectidely, just a security measure
			if serr := m.SetEnforcement(false); serr != nil {
				slog.Warn("could not initialize enforcement kill-switch", "component", "ebpf", "error", serr)
			}
		}
	} else {
		slog.Warn("LSM enforcement program not present in compiled object; running in DETECT-ONLY mode", "component", "ebpf")

	}

	if m.Objects.KguardTaskAlloc != nil {
		l, aerr := link.AttachLSM(link.LSMOptions{Program: m.Objects.KguardTaskAlloc})
		if aerr != nil {
			slog.Warn("LSM task_alloc hook failed to attach", "component", "ebpf", "error", aerr)
		} else {
			m.links = append(m.links, l)
			slog.Info("LSM task_alloc hook attached, lineage tracking is ACTIVE", "component", "ebpf")
		}
	} else {
		slog.Warn("KguardTaskAlloc object is nil in compiled BPF objects", "component", "ebpf")
	}

	if m.Objects.LsmFileOpen != nil {
		l, aerr := link.AttachLSM(link.LSMOptions{Program: m.Objects.LsmFileOpen})
		if aerr != nil {
			slog.Warn("LSM file open/write enforcement hook failed to attach", "component", "ebpf", "error", aerr)
		} else {
			m.links = append(m.links, l)
			slog.Info("LSM file-write enforcement hook attached, write blocking is ACTIVE", "component", "ebpf")
		}
	} else {
		slog.Warn("LsmFileOpen object is nil in compiled BPF objects", "component", "ebpf")
	}

	if m.Objects.LsmPtraceAccessCheck != nil {
		l, aerr := link.AttachLSM(link.LSMOptions{Program: m.Objects.LsmPtraceAccessCheck})
		if aerr != nil {
			slog.Warn("LSM Ptrace Access check enforcement hook failed to attach", "component", "ebpf", "error", aerr)
		} else {
			m.links = append(m.links, l)
			slog.Info("LSM Ptrace Access enforcement hook attached, ptrace blocking is ACTIVE", "component", "ebpf")
		}
	} else {
		slog.Warn("LsmPtraceAccessCheck object is nil in compiled BPF objects", "component", "ebpf")
	}

	if m.Objects.KguardKernelReadFile != nil {
		l, aerr := link.AttachLSM(link.LSMOptions{Program: m.Objects.KguardKernelReadFile})
		if aerr != nil {
			slog.Warn("LSM kernel_read_file enforcement hook failed to attach", "component", "ebpf", "error", aerr)
		} else {
			m.links = append(m.links, l)
			slog.Info("LSM kernel_read_file enforcement hook attached, module read blocking is ACTIVE", "component", "ebpf")
		}
	} else {
		slog.Warn("KguardKernelReadFile object is nil in compiled BPF objects", "component", "ebpf")
	}

	if m.Objects.KguardKernelLoadData != nil {
		l, aerr := link.AttachLSM(link.LSMOptions{Program: m.Objects.KguardKernelLoadData})
		if aerr != nil {
			slog.Warn("LSM kernel_load_data enforcement hook failed to attach", "component", "ebpf", "error", aerr)
		} else {
			m.links = append(m.links, l)
			slog.Info("LSM kernel_load_data enforcement hook attached, module load blocking is ACTIVE", "component", "ebpf")
		}
	} else {
		slog.Warn("KguardKernelLoadData object is nil in compiled BPF objects", "component", "ebpf")
	}

	if m.Objects.LsmTaskKill != nil {
		l, aerr := link.AttachLSM(link.LSMOptions{Program: m.Objects.LsmTaskKill})
		if aerr != nil {
			slog.Warn("LSM task_kill hook failed to attach", "component", "ebpf", "error", aerr)
		} else {
			m.links = append(m.links, l)
			slog.Info("LSM task_kill self-defense hook attached", "component", "ebpf")
		}
	}

	if m.Objects.LsmBpfCmd != nil {
		l, aerr := link.AttachLSM(link.LSMOptions{Program: m.Objects.LsmBpfCmd})
		if aerr != nil {
			slog.Warn("LSM bpf_cmd hook failed to attach", "component", "ebpf", "error", aerr)
		} else {
			m.links = append(m.links, l)
			slog.Info("LSM bpf_cmd self-defense hook attached", "component", "ebpf")
		}
	}

	m.attachTCDNS()

	if m.Objects.OnBranchMispredict != nil && !hasHardwarePMU() {
		slog.Info("PMU branch-mispredict sensor skipped: no hardware PMU device present (detect-only mode)", "component", "ebpf")
	} else if m.Objects.OnBranchMispredict != nil {
		attr := &unix.PerfEventAttr{
			Type:   unix.PERF_TYPE_HARDWARE,
			Config: unix.PERF_COUNT_HW_BRANCH_MISSES,
			Sample: 10000,
			Bits:   unix.PerfBitDisabled | unix.PerfBitExcludeHv,
		}

		numCPU, cerr := ebpf.PossibleCPU()
		if cerr != nil {
			slog.Warn("could not determine possible CPU count, falling back to runtime.NumCPU()", "component", "ebpf", "error", cerr)
			numCPU = runtime.NumCPU()
		}

		attached := 0
		for cpu := 0; cpu < numCPU; cpu++ {
			fd, err := unix.PerfEventOpen(attr, -1, cpu, -1, 0)
			if err != nil {
				slog.Warn("failed to open perf event on CPU", "component", "ebpf", "cpu", cpu, "error", err)
				continue
			}

			if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_SET_BPF, m.Objects.OnBranchMispredict.FD()); err != nil {
				slog.Warn("failed to bind PMU sensor program on CPU", "component", "ebpf", "cpu", cpu, "error", err)
				_ = unix.Close(fd)
				continue
			}
			if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_ENABLE, 0); err != nil {
				slog.Warn("failed to enable PMU sensor on CPU", "component", "ebpf", "cpu", cpu, "error", err)
				_ = unix.Close(fd)
				continue
			}

			m.perfEventFds = append(m.perfEventFds, fd)
			attached++
		}

		if attached > 0 {
			m.activeSensors = append(m.activeSensors, "pmu_branch_mispredict")
			slog.Info("PMU branch-mispredict sensor attached", "component", "ebpf", "attached_cpus", attached, "possible_cpus", numCPU)
		} else {
			slog.Warn("PMU branch-mispredict sensor failed to attach on any CPU, sensor disabled", "component", "ebpf")
		}
	}

	// Attach LSM Task Fix Setuid Hook
	if m.Objects.KguardTaskFixSetuid != nil {
		l, aerr := link.AttachLSM(link.LSMOptions{Program: m.Objects.KguardTaskFixSetuid})
		if aerr != nil {
			slog.Warn("LSM task_fix_setuid hook failed to attach", "component", "ebpf", "error", aerr)
		} else {
			m.links = append(m.links, l)
			slog.Info("LSM task_fix_setuid hook attached, local privilege escalation blocking is ACTIVE", "component", "ebpf")
		}
	} else {
		slog.Warn("KguardTaskFixSetuid object is nil in compiled BPF objects", "component", "ebpf")
	}

	if err := m.Objects.SelfPid.Set(uint32(os.Getpid())); err != nil {
		return nil, fmt.Errorf("setting self_pid: %w", err)
	}

	if err := m.RegisterProtectedIDs(); err != nil {
		slog.Warn("failed to populate protected IDs map", "component", "ebpf", "error", err)
	}

	if !m.LSMEnabled {
		slog.Info("without LSM hook, running in detect-only mode (post-exec reactions only)", "component", "ebpf")
	}

	if m.Objects.Rb == nil {
		m.Close()
		return nil, fmt.Errorf("ring buffer map not found in compiled object")
	}
	rd, err := ringbuf.NewReader(m.Objects.Rb)
	if err != nil {
		m.Close()
		return nil, fmt.Errorf("opening ringbuf reader: %w", err)
	}
	m.Reader = rd

	slog.Info("eBPF manager initialized successfully", "component", "ebpf", "active_sensors", m.activeSensors, "lsm_enabled", m.LSMEnabled)

	return m, nil
}

func (m *Manager) ActiveSensors() []string {
	out := make([]string, len(m.activeSensors))
	copy(out, m.activeSensors)
	return out
}

func hasHardwarePMU() bool {
	entries, err := os.ReadDir("/sys/bus/event_source/devices")
	if err != nil {
		// can't tell either way so we just skip it
		return true
	}
	for _, e := range entries {
		name := e.Name()

		if name == "cpu" || strings.HasPrefix(name, "cpu_") {
			return true
		}
	}
	return false
}

func (m *Manager) SetEnforcement(enabled bool) error {
	var v uint8
	if enabled {
		v = 1
	}
	return m.Objects.EnforcementEnabled.Set(v)
}

func (m *Manager) SetPtraceEnforcement(enabled bool) error {
	var v uint8
	if enabled {
		v = 1
	}
	return m.Objects.PtraceEnforcementEnabled.Set(v)
}

func (m *Manager) SetKmodEnforcement(enabled bool) error {
	var v uint8
	if enabled {
		v = 1
	}
	return m.Objects.KmodEnforcementEnabled.Set(v)
}

// This is the Sync Helper function, it syncs the paths with
// whichever Map it's linked to
// If you're asking, why don't we delete everything then insert
// to same perf, deleting everything leavs a little amount of time
// where a binary that could be blocked isn't in the list, so we
// avoid that
func syncPaths(em *ebpf.Map, items []string, is64Byte bool) error {
	if em == nil {
		return nil
	}

	if is64Byte {
		return syncTypedMap(em, items, func(s string) [64]byte {
			var k [64]byte
			copy(k[:], s)
			return k
		})
	}

	return syncTypedMap(em, items, func(s string) [256]byte {
		var k [256]byte
		copy(k[:], s)
		return k
	})
}

func syncKeyedMap[K comparable](em *ebpf.Map, want map[K]bool) error {
	existing := make(map[K]bool)
	var key K
	var val uint8

	it := em.Iterate()
	for it.Next(&key, &val) {
		existing[key] = true
	}
	if err := it.Err(); err != nil {
		return fmt.Errorf("iterating map: %w", err)
	}

	for k := range existing {
		if !want[k] {
			_ = em.Delete(k)
		}
	}
	for k := range want {
		if !existing[k] {
			if err := em.Update(k, uint8(1), ebpf.UpdateAny); err != nil {
				return fmt.Errorf("updating map: %w", err)
			}
		}
	}
	return nil
}

func syncTypedMap[K comparable](em *ebpf.Map, items []string, fromString func(string) K) error {
	want := make(map[K]bool, len(items))
	for _, item := range items {
		if item == "" {
			continue
		}
		want[fromString(item)] = true
	}
	return syncKeyedMap(em, want)
}

func syncValueMap[K comparable](em *ebpf.Map, want map[K]uint8) error {
	if em == nil {
		return nil
	}
	existing := make(map[K]uint8)
	var key K
	var val uint8

	it := em.Iterate()
	for it.Next(&key, &val) {
		existing[key] = val
	}
	if err := it.Err(); err != nil {
		return fmt.Errorf("iterating map: %w", err)
	}

	for k := range existing {
		if _, needed := want[k]; !needed {
			_ = em.Delete(k)
		}
	}
	for k, wantVal := range want {
		if currentVal, exists := existing[k]; !exists || currentVal != wantVal {
			if err := em.Update(k, wantVal, ebpf.UpdateAny); err != nil {
				return fmt.Errorf("updating map: %w", err)
			}
		}
	}
	return nil
}

func (m *Manager) SyncBlockedPaths(paths map[string]uint8) error {
	em := m.Objects.BlockedPaths
	if em == nil {
		return nil
	}
	want := make(map[[256]byte]uint8, len(paths))
	for p, mode := range paths {
		if p == "" {
			continue
		}
		var k [256]byte
		copy(k[:], p)
		want[k] = mode
	}
	return syncValueMap(em, want)
}

func (m *Manager) SyncSuspiciousPaths(paths []string) error {
	return syncPaths(m.Objects.SuspiciousPaths, paths, false)
}

func (m *Manager) SyncSensitiveWritePaths(paths []string) error {
	return syncPaths(m.Objects.SensitiveWritePaths, paths, false)
}

func (m *Manager) SyncBlockedWritePaths(paths []string) error {
	return syncPaths(m.Objects.BlockedWritePaths, paths, false)
}

func (m *Manager) SyncAllowedPtraceAttached(paths []string) error {
	em := m.Objects.AllowedPtraceAttaches
	if em == nil {
		return nil
	}
	if m.ptraceAllow == nil {
		m.ptraceAllow = trust.NewSet()
	}
	wantIDs := m.ptraceAllow.Sync(paths, "allowed_ptrace_attaches")

	want := make(map[trust.FileID]bool, len(wantIDs))
	for _, id := range wantIDs {
		want[id] = true
	}
	return syncKeyedMap(em, want)
}

func makeLpmKey256(prefix string) LpmKey256 {
	var k LpmKey256
	k.PrefixLenBits = uint32(len(prefix) * 8)
	copy(k.Data[:], prefix)
	return k
}

func (m *Manager) SyncPrefixBlocks(prefixes map[string]uint8) error {
	em := m.Objects.BlockedPrefix
	if em == nil {
		return nil
	}
	want := make(map[LpmKey256]uint8, len(prefixes))
	for prefix, mode := range prefixes {
		if prefix == "" {
			continue
		}
		want[makeLpmKey256(prefix)] = mode
	}
	return syncValueMap(em, want)
}

func (m *Manager) AddContainerCgroup(cgroupID uint64) error {
	if m.Objects.ContainerCgroups == nil {
		return nil
	}
	var val uint8 = 1
	return m.Objects.ContainerCgroups.Update(&cgroupID, &val, ebpf.UpdateAny)
}

func pathToKey(p string) [256]byte {
	var k [256]byte
	copy(k[:], p)
	return k
}

func (m *Manager) RegisterProtectedIDs() error {
	if m.Objects.ProtectedIds == nil {
		return nil
	}

	var val uint8 = 1

	// Helper to extract FD info and store ID
	protectObj := func(obj any) {
		valRef := reflect.ValueOf(obj)
		if valRef.Kind() != reflect.Struct {
			return
		}

		for i := 0; i < valRef.NumField(); i++ {
			field := valRef.Field(i)
			if field.IsNil() {
				continue
			}

			// Check for ebpf Map
			if bpfMap, ok := field.Interface().(*ebpf.Map); ok {
				if info, err := bpfMap.Info(); err == nil {
					if id, ok := info.ID(); ok && id != 0 {
						_ = m.Objects.ProtectedIds.Update(&id, &val, ebpf.UpdateAny)
					}
				}
			}

			// Check for ebpf Program
			if bpfProg, ok := field.Interface().(*ebpf.Program); ok {
				if info, err := bpfProg.Info(); err == nil {
					if id, ok := info.ID(); ok && id != 0 {
						_ = m.Objects.ProtectedIds.Update(&id, &val, ebpf.UpdateAny)
					}
				}
			}
		}
	}

	// Iterate generated struct fields
	protectObj(m.Objects.BPFMaps)
	protectObj(m.Objects.BPFPrograms)

	// Register attached links
	for _, l := range m.links {
		if l == nil {
			continue
		}
		if info, err := l.Info(); err == nil {
			if id := uint32(info.ID); id != 0 {
				_ = m.Objects.ProtectedIds.Update(&id, &val, ebpf.UpdateAny)
			}
		}
	}

	slog.Info("eBPF object self-defense map dynamically populated", "component", "ebpf")
	return nil
}

func (m *Manager) Close() {
	if m.Reader != nil {
		_ = m.Reader.Close()
	}
	for _, l := range m.links {
		if l != nil {
			_ = l.Close()
		}
	}
	if m.ptraceAllow != nil {
		m.ptraceAllow.Close()
	}
	_ = m.Objects.Close()
}

func (m *Manager) attachTCDNS() {
	if m.Objects.TcEgressDns == nil || m.Objects.TcIngressDns == nil {
		return
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		slog.Warn("failed to list network interfaces for TC attach", "component", "ebpf", "error", err)
		return
	}

	attachedCount := 0
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue // Skip down interfaces
		}

		nlLink, err := netlink.LinkByIndex(iface.Index)
		if err != nil {
			continue
		}

		// Ensure 'clsact' qdisc exists on the interface
		qdisc := &netlink.GenericQdisc{
			QdiscAttrs: netlink.QdiscAttrs{
				LinkIndex: nlLink.Attrs().Index,
				Handle:    netlink.MakeHandle(0xffff, 0), // clsact handle (ffff:0)
				Parent:    netlink.HANDLE_CLSACT,
			},
			QdiscType: "clsact",
		}

		_ = netlink.QdiscReplace(qdisc)

		egressFilter := &netlink.BpfFilter{
			FilterAttrs: netlink.FilterAttrs{
				LinkIndex: nlLink.Attrs().Index,
				Parent:    netlink.HANDLE_MIN_EGRESS,
				Handle:    netlink.MakeHandle(0, 1),
				Protocol:  unix.ETH_P_ALL,
				Priority:  1,
			},
			Fd:           m.Objects.TcEgressDns.FD(),
			Name:         "tc_egress_dns",
			DirectAction: true,
		}
		if err := netlink.FilterReplace(egressFilter); err == nil {
			attachedCount++
		} else {
			slog.Warn("failed to attach TC egress filter", "component", "ebpf", "interface", iface.Name, "error", err)
		}

		ingressFilter := &netlink.BpfFilter{
			FilterAttrs: netlink.FilterAttrs{
				LinkIndex: nlLink.Attrs().Index,
				Parent:    netlink.HANDLE_MIN_INGRESS,
				Handle:    netlink.MakeHandle(0, 2),
				Protocol:  unix.ETH_P_ALL,
				Priority:  1,
			},
			Fd:           m.Objects.TcIngressDns.FD(),
			Name:         "tc_ingress_dns",
			DirectAction: true,
		}
		if err := netlink.FilterReplace(ingressFilter); err == nil {
			attachedCount++
		} else {
			slog.Warn("failed to attach TC ingress filter", "component", "ebpf", "interface", iface.Name, "error", err)
		}
	}

	if attachedCount > 0 {
		m.activeSensors = append(m.activeSensors, "tc_dns_classifier")
		slog.Info("TC DNS classifier attached", "component", "ebpf", "active_filters", attachedCount)
	}
}
