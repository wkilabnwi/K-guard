package ebpf

import (
	"fmt"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -go-package ebpf -target amd64 -cc clang -cflags "-DKGUARD_HAVE_VMLINUX -I../../bpf/include" -type event_hdr -type exec_event -type connect_event -type open_event -type ptrace_event -type kmod_event BPF ../../bpf/kguard.c -- -I../../bpf/include -I../../bpf -D__TARGET_ARCH_x86
type Manager struct {
	Objects BPFObjects
	Reader  *ringbuf.Reader

	links []link.Link

	LSMEnabled bool

	activeSensors []string
}

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
		{"sched", "sched_process_exec", "tp_schedexec", m.Objects.TpSchedexec},
		{"sched", "sched_process_fork", "tp_schedfork", m.Objects.TpSchedfork},
		{"syscalls", "sys_enter_connect", "tp_connect", m.Objects.TpConnect},
		{"syscalls", "sys_enter_openat", "tp_openat", m.Objects.TpOpenat},
		{"syscalls", "sys_enter_openat2", "tp_openat2", m.Objects.TpOpenat2},
		{"syscalls", "sys_enter_ptrace", "tp_ptrace", m.Objects.TpPtrace},
		{"syscalls", "sys_enter_setuid", "tp_setuid", m.Objects.TpSetuid},
		{"syscalls", "sys_enter_init_module", "tp_init_module", m.Objects.TpInitModule},
		{"syscalls", "sys_enter_memfd_create", "tp_memfd_create", m.Objects.TpMemfdCreate},
	}

	for _, tp := range tracepoints {
		if tp.prog == nil {
			log.Printf("[ebpf] program %q not present in compiled object, skipping sensor", tp.name)
			continue
		}

		// Attaching each of the TPs to it's eBPF program
		l, aerr := link.Tracepoint(tp.category, tp.event, tp.prog, nil)
		if aerr != nil {
			log.Printf("[ebpf] WARNING: failed to attach %s/%s (kernel/permissions may not support it): %v",
				tp.category, tp.event, aerr)
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
			log.Printf("[ebpf] WARNING: LSM enforcement hook is present in the object but failed to attach: %v", aerr)
			log.Printf("[ebpf] Common causes: kernel missing CONFIG_BPF_LSM, 'bpf' not in /sys/kernel/security/lsm ")
			log.Printf("check: cat /sys/kernel/security/lsm), or insufficient capabilities. Falling back to detect-only mode.")
		} else {
			m.links = append(m.links, l)
			m.LSMEnabled = true
			log.Println("[ebpf] LSM enforcement hook attached, pre-exec blocking is ACTIVE.")
			// We start by setting Enforcment to false so that it doesn't start working before we need it to
			// it's also to avoid it possbily terminating any program unexpectidely, just a security measure
			if serr := m.SetEnforcement(false); serr != nil {
				log.Printf("[ebpf] WARNING: could not initialize enforcement kill-switch: %v", serr)
			}
		}
	} else {
		log.Println("[ebpf] LSM enforcement program not present in the compiled object (built without vmlinux.h) - " +
			"running in DETECT-ONLY mode. See bpf/include/README.md to enable real pre-exec blocking.")

	}

	if m.Objects.LsmFileOpen != nil {
		l, aerr := link.AttachLSM(link.LSMOptions{Program: m.Objects.LsmFileOpen})
		if aerr != nil {
			log.Printf("[ebpf] WARNING: LSM file open/write enforcement hook failed to attach: %v", aerr)
		} else {
			m.links = append(m.links, l)
			log.Println("[ebpf] LSM file-write enforcement hook attached, write blocking is ACTIVE.")
		}
	} else {
		log.Println("[ebpf] WARNING: LsmFileOpen object is nil in compiled BPF objects!")
	}

	if m.Objects.LsmPtraceAccessCheck != nil {
		l, aerr := link.AttachLSM(link.LSMOptions{Program: m.Objects.LsmPtraceAccessCheck})
		if aerr != nil {
			log.Printf("[ebpf] WARNING: LSM Ptrace Access check enforcement hook failed to attach: %v", aerr)
		} else {
			m.links = append(m.links, l)
			log.Println("[ebpf] LSM Ptrace Access enforcement hook attached, write blocking is ACTIVE.")
		}
	} else {
		log.Println("[ebpf] WARNING: LsmFileOpen object is nil in compiled BPF objects!")
	}

	if m.Objects.KguardKernelReadFile != nil {
		l, aerr := link.AttachLSM(link.LSMOptions{Program: m.Objects.KguardKernelReadFile})
		if aerr != nil {
			log.Printf("[ebpf] WARNING: LSM kernel_read_file enforcement hook failed to attach: %v", aerr)
		} else {
			m.links = append(m.links, l)
			log.Println("[ebpf] LSM kernel_read_file enforcement hook attached, module read blocking is ACTIVE.")
		}
	} else {
		log.Println("[ebpf] WARNING: KguardKernelReadFile object is nil in compiled BPF objects!")
	}

	if m.Objects.KguardKernelLoadData != nil {
		l, aerr := link.AttachLSM(link.LSMOptions{Program: m.Objects.KguardKernelLoadData}) // Note: link.AttachLSM uses link.LSMOptions
		if aerr != nil {
			log.Printf("[ebpf] WARNING: LSM kernel_load_data enforcement hook failed to attach: %v", aerr)
		} else {
			m.links = append(m.links, l)
			log.Println("[ebpf] LSM kernel_load_data enforcement hook attached, module load blocking is ACTIVE.")
		}
	} else {
		log.Println("[ebpf] WARNING: KguardKernelLoadData object is nil in compiled BPF objects!")
	}

	if !m.LSMEnabled {
		log.Println("[ebpf] NOTE: without the LSM hook, K-Guard can only react after a binary has already started executing, not prevent the exec outright.")
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

	log.Printf("[ebpf] active sensors: %v (LSM enforcement: %v)", m.activeSensors, m.LSMEnabled)

	return m, nil
}

func (m *Manager) ActiveSensors() []string {
	out := make([]string, len(m.activeSensors))
	copy(out, m.activeSensors)
	return out
}

func (m *Manager) SetEnforcement(enabled bool) error {
	if m.Objects.EnforcementEnabled == nil {
		return nil
	}
	//uint8 because C code only acccepts a byte, should've thought about it earlier
	var v uint8
	if enabled {
		v = 1
	}
	return m.Objects.EnforcementEnabled.Update(uint32(0), v, ebpf.UpdateAny)
}

func (m *Manager) SetPtraceEnforcement(enabled bool) error {
	if m.Objects.PtraceEnforcementEnabled == nil {
		return nil
	}
	//uint8 because C code only acccepts a byte, should've thought about it earlier
	var v uint8
	if enabled {
		v = 1
	}
	return m.Objects.PtraceEnforcementEnabled.Update(uint32(0), v, ebpf.UpdateAny)
}

func (m *Manager) SetKmodEnforcement(enabled bool) error {
	if m.Objects.KmodEnforcementEnabled == nil {
		return nil
	}
	var v uint8
	if enabled {
		v = 1
	}
	return m.Objects.KmodEnforcementEnabled.Update(uint32(0), v, ebpf.UpdateAny)
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

// syncTypedMap centralizes all common iteration, diffing, and syncing logic
func syncTypedMap[K comparable](em *ebpf.Map, items []string, fromString func(string) K) error {
	existingSet := make(map[K]bool)
	var key K
	var val uint8

	it := em.Iterate()
	for it.Next(&key, &val) {
		existingSet[key] = true
	}
	if err := it.Err(); err != nil {
		return fmt.Errorf("iterating map: %w", err)
	}

	want := make(map[K]bool, len(items))
	for _, item := range items {
		if item == "" {
			continue
		}
		want[fromString(item)] = true
	}

	// Remove keys that are no longer wanted
	for k := range existingSet {
		if !want[k] {
			_ = em.Delete(k)
		}
	}

	// Add missing keys
	for k := range want {
		if !existingSet[k] {
			if err := em.Update(k, uint8(1), ebpf.UpdateAny); err != nil {
				return fmt.Errorf("updating map: %w", err)
			}
		}
	}

	return nil
}

func (m *Manager) SyncBlockedPaths(paths []string) error {
	return syncPaths(m.Objects.BlockedPaths, paths, false)
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
	return syncPaths(m.Objects.AllowedPtraceAttaches, paths, true)
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

func (m *Manager) Close() {
	if m.Reader != nil {
		m.Reader.Close()
	}
	for _, l := range m.links {
		if l != nil {
			l.Close()
		}
	}
	_ = m.Objects.Close()
}
