# Prevention & Self-Protection

[← Back to README](../README.md)

## Operating modes

- **Detection only**: the default, and the only mode on kernels/builds without `CONFIG_BPF_LSM`. K-Guard reacts to an exec after the fact: it alerts and, for `KILL`/`BLOCK` rules, sends `SIGKILL` to the offending PID via `pidfd`.
- **Prevention**: active when LSM hooks attach and `enforcement_enabled: true`. See below.

### Prevention features

- **Exec prevention**: `bprm_check_security` drops blocked binaries (`-EPERM`) before they run. Supports exact path matching (`BPF_MAP_TYPE_HASH`) and path-prefix matching (`BPF_MAP_TYPE_LPM_TRIE`, for `process.path.startsWith` rules).
- **File write prevention**: `lsm/file_open` drops write-intent opens (`O_WRONLY`/`O_RDWR`) on `blocked_write_paths` (`-EPERM`).
- **Ptrace prevention**: with `ptrace_enforcement_enabled: true`, `lsm/ptrace_access_check` blocks unauthorized injection unless the caller matches `allowed_ptrace_attaches`.
- **Kernel module load prevention**: intercepts module loads and blocks them when they originate from tracked container cgroups (the `container_cgroups` BPF map).
- **Privilege escalation prevention**: `lsm/task_fix_setuid` blocks a process from gaining UID 0 (`-EPERM`) unless it exec'd a setuid-root binary first.
- **Capability escalation prevention**: `lsm/capable` monitors critical privilege checks (`CAP_SYS_ADMIN`, `CAP_SYS_MODULE`) exercised inside tracked container cgroups, ignoring setup-phase checks in the host mount namespace.
- **Reverse-shell prevention**: `sys_enter_dup2`/`dup3` watch fd cloning. If an active network socket is duplicated onto stdio (`0`, `1`, `2`), the state is tracked in BPF task storage across `fork()`. When `lsm/bprm_check_security` fires, shell execution is blocked (`-EPERM`).
- **W^X memory protection**: `lsm/mmap_file` and `lsm/file_mprotect` inspect memory allocations and flag/block pages requesting simultaneous write and execute permissions (`PROT_WRITE | PROT_EXEC`).

## Enforcement kill-switch

An `enforcement_enabled` switch lets you disable LSM blocking instantly at runtime without detaching or reloading programs. Detection keeps running either way.

The kill-switches and self-protection state (`enforcement_enabled`, `ptrace_enforcement_enabled`, `kmod_enforcement_enabled`, `self_pid`) are plain BPF global variables (`.bss`), not map entries. Userspace reads and writes them through cilium/ebpf's `*ebpf.Variable` API (e.g. `m.Objects.EnforcementEnabled.Set(...)`), which requires `github.com/cilium/ebpf` **v0.17+**.

## Agent self-protection

- `lsm/task_kill` intercepts termination signals aimed at K-Guard's PID and rejects them (`-EPERM`) unless sent by K-Guard itself or PID 1.
- `lsm/bpf` restricts critical eBPF commands (`BPF_LINK_DETACH`, `BPF_MAP_GET_FD_BY_ID`, `BPF_PROG_GET_FD_BY_ID`, etc.) so hostile processes can't detach or inspect K-Guard's in-kernel filters.

On startup K-Guard uses Go reflection (`reflect`) to inspect the `bpf2go`-generated structs, so newly added maps, programs and active link IDs are protected automatically without manual Go changes.

## Safety guarantees

- **Process safe-list**: K-Guard never `SIGKILL`s PID 1, its own PID, any PID in `protected_pids`, or any process whose live `/proc/<pid>/exe` identity matches `protected_comms`.
- **No PID-recycling accidents**: kills go through `pidfd_open` + `pidfd_send_signal` rather than a raw `kill()`, so a recycled PID can't be hit by mistake.
- **Fail-open on exit**: when K-Guard exits, the kernel closes its `bpf_link` file descriptors and immediately detaches all LSM hooks, restoring normal behavior without locking or bricking the host.

## Memory safety

`max_memory_mb` sets a threshold checked every 10 seconds. If runtime memory exceeds it, K-Guard triggers an immediate `runtime.GC()` to stabilize its footprint on high-throughput nodes.

## Supervisor mode (crash-loop protection)

```bash
sudo ./k-guard -config /etc/k-guard/config.yaml -supervisor
```

- Spawns and monitors a child worker; after a panic it restarts the agent following a brief backoff.
- **Rate-limited fail-open**: if the agent crashes more than 5 times in 5 minutes, the supervisor stops restarting and exits cleanly.
