package ebpf

import (
	"fmt"
	"log"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -go-package ebpf -target amd64 -cc clang -cflags "-DKGUARD_HAVE_VMLINUX -I../../bpf/include" -type event_hdr -type exec_event -type connect_event -type open_event BPF ../../bpf/kguard.c -- -I../../bpf/include -I../../bpf -D__TARGET_ARCH_x86
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

// This is the Sync Helper function, it syncs the paths with
// whichever Map it's linked to
// If you're asking, why don't we delete everything then insert
// to same perf, deleting everything leavs a little amount of time
// where a binary that could be blocked isn't in the list, so we
// avoid that
func syncFixedPaths(em *ebpf.Map, paths []string) error {
	if em == nil {
		return nil
	}

	existingSet := make(map[[256]byte]bool)
	var key [256]byte
	var val uint8
	it := em.Iterate()
	for it.Next(&key, &val) {
		existingSet[key] = true
	}
	if err := it.Err(); err != nil {
		return fmt.Errorf("iterating map: %w", err)
	}

	want := make(map[[256]byte]bool, len(paths)*2)
	for _, p := range paths {
		if p == "" {
			continue
		}

		hasSlash := strings.HasSuffix(p, "/")
		cleanP := filepath.Clean(p)
		if hasSlash && !strings.HasSuffix(cleanP, "/") {
			cleanP += "/"
		}

		want[pathToKey(cleanP)] = true

		// Resolve symlinks for both binaries AND folders (/var/run/ - > /run/)
		if realP, err := filepath.EvalSymlinks(p); err == nil {
			if hasSlash && !strings.HasSuffix(realP, "/") {
				realP += "/"
			}
			if realP != cleanP {
				want[pathToKey(realP)] = true
			}
		}
	}

	for k := range existingSet {
		if !want[k] {
			_ = em.Delete(k)
		}
	}
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
	return syncFixedPaths(m.Objects.BlockedPaths, paths)
}

func (m *Manager) SyncSuspiciousPaths(paths []string) error {
	return syncFixedPaths(m.Objects.SuspiciousPaths, paths)
}

func (m *Manager) SyncSensitiveWritePaths(paths []string) error {
	return syncFixedPaths(m.Objects.SensitiveWritePaths, paths)
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
