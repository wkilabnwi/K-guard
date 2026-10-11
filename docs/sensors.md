# Sensors

[← Back to README](../README.md)

K-Guard attaches a mix of tracepoint sensors and, when the kernel allows it, BPF LSM hooks.

| Event | Hook | Notes |
|---|---|---|
| `EXEC` | `tracepoint/sched/sched_process_exec` (+ `lsm/task_alloc` for lineage tracking) | Observed *after* the exec has already started |
| `EXEC_BLOCKED` | `lsm/bprm_check_security` | Pre-exec: the kernel is stopped from ever running the binary |
| `CONNECT` | `sys_enter_connect` | Outbound connections: IPv4, IPv6 and Unix domain sockets |
| `SENDTO` | `sys_enter_sendto` / `sys_enter_sendmsg` / `sys_enter_sendmmsg` | Unconnected and complex socket egress (UDP, DNS exfiltration, scatter/gather socket writes) |
| `OPEN_SENSITIVE` | `sys_enter_openat` / `sys_enter_openat2` | Reads of paths like `/etc/passwd`, `/etc/shadow`, `/root/.ssh` |
| `SENSITIVE_WRITE` | `sys_enter_openat` / `sys_enter_openat2` | Opens with write intent (`O_WRONLY`/`O_RDWR`) on a configured protected path |
| `BLOCKED_WRITE` | `lsm/file_open` | Pre-emptively drops writes (`-EPERM`) on `blocked_write_paths` |
| `PTRACE` | `sys_enter_ptrace` | Attach/injection attempts |
| `PTRACE_BLOCKED` | `lsm/ptrace_access_check` | Pre-emptively drops unauthorized ptrace attach/injection (`-EPERM`) |
| `SETUID` | `sys_enter_setuid` | Privilege changes |
| `NS_CHANGE` | `sys_enter_unshare` / `sys_enter_setns` | Namespace mutation attempts |
| `LPE_BLOCKED` | `lsm/task_fix_setuid` | Blocks a UID transition to root unless gained via a setuid-root binary, tracked in kernel-side lineage |
| `MODULE_LOAD` | `sys_enter_init_module` | Kernel module loading |
| `KMOD_BLOCKED` | `lsm/kernel_read_file`, `lsm/kernel_load_data` | Blocks unauthorized module loads inside containers using the `container_cgroups` BPF map |
| `MEMFD_CREATE` | `sys_enter_memfd_create` | Fileless-exec precursor |
| `FILELESS_EXEC` | `lsm/bprm_check_security` | Detected in-kernel via zero link count (`i_nlink == 0`) on `tmpfs` (`memfd`) |
| `IO_URING` | `tracepoint/io_uring/io_uring_submit_req` | Monitors async file ops (`IORING_OP_OPENAT`, `OPENAT2`, `CONNECT`) |
| `TASK_KILL_BLOCKED` | `lsm/task_kill` | Self-protection: blocks external termination signals sent to K-Guard |
| `BPF_CMD_BLOCKED` | `lsm/bpf` | Self-protection: blocks unauthorized inspection/detaching of K-Guard eBPF maps and programs |
| `BRANCH_MISPREDICT` | `perf_event` (`PERF_TYPE_HARDWARE`, `PERF_COUNT_HW_BRANCH_MISSES`) | Hardware PMU counter, not a syscall/LSM hook. One `perf_event` per possible CPU, sampled every 10k mispredicted branches |
| `REVERSE_SHELL` | `sys_enter_dup2`, `sys_enter_dup3` + `lsm/bprm_check_security` | Pre-exec: detects socket redirection and drops execution (`-EPERM`) |

DNS traffic is captured separately via TC classifiers. See [Enrichment](enrichment.md#dns-interception--ip-to-domain-correlation).

## Kernel lineage and state tracking

eBPF tracks context across child forks via `BPF_MAP_TYPE_TASK_STORAGE` attached directly to `struct task_struct`, using `bpf_get_current_task_btf()` for BTF pointer resolution. Kernel-side memory is cleaned up automatically on process exit. Both features require **Linux 5.11+**, which is why that is K-Guard's minimum kernel.

A userspace LRU cache maps `pid` → `ppid` to reconstruct and log the process execution tree when an alert fires.

## Event filtering

Outbound connects are filtered before reaching the rule engine when:

- the emitting process matches `ignored_connect_comms` (see [Identity-based trust](identity-trust.md)), or
- the destination is loopback (`127.0.0.0/8`, `::1`).

Both are almost always background or tunnel noise.

`sensitive_write_paths` raise a `SENSITIVE_WRITE` alert (detect only). `blocked_write_paths` are synced into an in-kernel map where `lsm/file_open` actively drops the call with `-EPERM`.

Unconnected socket egress (`sendto`, `sendmsg`, `sendmmsg`) is inspected for explicit destination addresses (`AF_INET`, `AF_INET6`, `AF_UNIX`). `sendmsg` and `sendmmsg` tracepoints extract target address structures from `user_msghdr` vectors to capture complex socket payloads and batched egress vectors.

## io_uring monitoring

`io_uring` lets applications bypass the usual synchronous syscall entry points (`openat`, `connect`) by submitting async Submission Queue Entries. K-Guard hooks `io_uring_submit_req` to inspect opcodes and extract file paths or socket targets submitted through the ring.

> **Kernel note:** the tracepoint name and availability vary by kernel version (it was renamed from `io_uring_submit_sqe` in a later release). Verify that `/sys/kernel/tracing/events/io_uring/` exposes the tracepoint on your target kernel.

## Hardware PMU sensor (branch mispredictions)

Unlike every other sensor, this one doesn't hook a syscall or LSM callback. It opens a `PERF_TYPE_HARDWARE` counter (`perf_event_open`) on every possible CPU (`ebpf.PossibleCPU()`, not `runtime.NumCPU()`, so a cpuset/static-CPU-manager pod still gets full node coverage rather than just the CPUs it happens to be scheduled on) and binds the `on_branch_mispredict` program to each one via `PERF_EVENT_IOC_SET_BPF` + `PERF_EVENT_IOC_ENABLE`.

This depends on hardware the other sensors don't: a real PMU device exposed by the kernel. Many virtualized environments don't pass one through, including **hypervisor-backed dev VMs on macOS** (colima, on `vz` or `qemu`/HVF) and **some cloud instance types** (AWS Nitro is known to withhold PMU access from guests). On those hosts `perf_event_open` fails with `ENOENT` for every CPU.

K-Guard checks up front (`hasHardwarePMU()`, looking for a `cpu`/`cpu_core`/`cpu_atom` entry under `/sys/bus/event_source/devices`) instead of failing per CPU, and skips the sensor with a single log line if none is found. Check any host in advance:

```bash
ls /sys/bus/event_source/devices/
```

If `cpu` (or `cpu_core`/`cpu_atom` on hybrid Intel) isn't listed, the sensor won't attach, and `pmu_branch_mispredict` won't appear in the active-sensor list or `/healthz`. Every other sensor is unaffected.

The sysfs-detection logic has unit test coverage (`internal/ebpf/loader_pmu_test.go`) that doesn't need PMU hardware. The attach path does, and should be verified on real hardware (ideally bare metal, or a cloud VPS that shows a `cpu` entry) before you rely on it.
