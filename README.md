# K-Guard

K-Guard is a lightweight Linux host intrusion detection and pre-execution *prevention* agent built on eBPF. It monitors security-relevant syscalls and kernel events, evaluates them against a hot-reloadable CEL-based rule engine (supporting both **YAML** and **JSON** formats), and fans matching alerts out to multiple sinks (stdout, syslog, webhook, local JSON-Lines storage, and a read-only web dashboard).
For any question, feel free to contact louai.sahli1@gmail.com.

## DEMO

See `Demo` Folder

## What it watches

K-Guard attaches a mix of tracepoint sensors and, when the kernel allows
it, a BPF LSM hook:

| Event | Hook | Notes |
|---|---|---|
| `EXEC` | `tracepoint/sched/sched_process_exec` (+ `lsm/task_alloc` for lineage tracking) | Observed *after* the exec has already started |
| `EXEC_BLOCKED` | `lsm/bprm_check_security` | Pre-exec : the kernel is stopped from ever running the binary |
| `CONNECT` | `sys_enter_connect` | Outbound connections : IPv4, IPv6, and Unix domain sockets |
| `OPEN_SENSITIVE` | `sys_enter_openat` / `sys_enter_openat2` | Reads of paths like `/etc/passwd`, `/etc/shadow`, `/root/.ssh` |
| `SENSITIVE_WRITE` | `sys_enter_openat` / `sys_enter_openat2` | Opens with write intent (`O_WRONLY`/`O_RDWR`) on a configured protected path |
| `BLOCKED_WRITE` | `lsm/file_open` | LSM file hook pre-emptively drops writes (`-EPERM`) on `blocked_write_paths` |
| `PTRACE` | `sys_enter_ptrace` | Attach/injection attempts |
| `PTRACE_BLOCKED`|`lsm/ptrace_access_check` | Pre-emptively drops unauthorized ptrace attach/injection attempts (-EPERM) |
| `SETUID` | `sys_enter_setuid` | Privilege changes |
| `LPE_BLOCKED` | `lsm/task_fix_setuid` | Pre-emptively blocks a UID transition to root unless the process legitimately gained it via a setuid-root binary, tracked in kernel-side lineage |
| `MODULE_LOAD` | `sys_enter_init_module` | Kernel module loading |
`KMOD_BLOCKED` | `lsm/kernel_read_file, lsm/kernel_load_data` | Pre-emptively blocks unauthorized module loads inside containers using the `container_cgroups` BPF map |
| `MEMFD_CREATE` | `sys_enter_memfd_create` | Fileless-exec precursor |
| `FILELESS_EXEC` | `lsm/bprm_check_security` | Detected structurally in-kernel via zero-link count (`i_nlink == 0`) on `tmpfs` (`memfd`) |
| `IO_URING` | `tracepoint/io_uring/io_uring_submit_req` | Monitored asynchronous file ops (`IORING_OP_OPENAT`, `OPENAT2`, `CONNECT`) |
| `TASK_KILL_BLOCKED` | `lsm/task_kill` | Self-protection: pre-emptively blocks external processes from sending termination signals to K-Guard |
| `BPF_CMD_BLOCKED` | `lsm/bpf` | Self-protection: blocks unauthorized processes from inspecting or detaching K-Guard eBPF maps/programs |
| `BRANCH_MISPREDICT` | `perf_event` (`PERF_TYPE_HARDWARE`, `PERF_COUNT_HW_BRANCH_MISSES`) | Hardware PMU counter, not a syscall/LSM hook. One `perf_event` per possible CPU, sampled every 10k mispredicted branches.|

### Hardware PMU sensor (branch mispredictions)
 
Unlike every other sensor in the table above, this one doesn't hook a
syscall or LSM callback, it opens a `PERF_TYPE_HARDWARE` counter
(`perf_event_open`) on every possible CPU (`ebpf.PossibleCPU()`, not
`runtime.NumCPU()`, so a cpuset/static-CPU-manager pod still gets full
node coverage rather than just the CPUs it happens to be scheduled on)
and binds the `on_branch_mispredict` program to each one via
`PERF_EVENT_IOC_SET_BPF` + `PERF_EVENT_IOC_ENABLE`.
 
That means it depends on hardware the other sensors don't: a real PMU
device exposed by the kernel. Many virtualized environments don't pass
one through to the guest, this includes **hypervisor-backed dev VMs on
macOS** (colima, whether backed by `vz` or `qemu`/HVF) and **some cloud
instance types** (AWS Nitro in particular is known to withhold PMU
access from guests for isolation reasons). On those hosts,
`perf_event_open` fails with `ENOENT` for every CPU, regardless of
config.
 
K-Guard checks for this up front (`hasHardwarePMU()`, looking for a
`cpu`/`cpu_core`/`cpu_atom` entry under
`/sys/bus/event_source/devices`) rather than attempting and failing per
CPU, and skips the sensor with a single clear log line if none is
found. You can check any host in advance the same way:
 
```bash
ls /sys/bus/event_source/devices/
```
 
If `cpu` (or `cpu_core`/`cpu_atom` on hybrid Intel) isn't listed, this
sensor will not attach on that host, and `pmu_branch_mispredict` won't
appear in the active-sensor list or `/healthz`. Every other sensor is
unaffected either way. The sysfs-detection logic itself has unit test
coverage (`internal/ebpf/loader_pmu_test.go`) that doesn't require real
PMU hardware to run; the attach path itself does, and should be
verified on real (ideally bare-metal, or a cloud VPS that confirms a
`cpu` entry) hardware before being relied on for detection coverage in
a given deployment.

### Two operating modes

- **DETECTION ONLY** : the default, and the only mode available on
  kernels/builds without `CONFIG_BPF_LSM` support. K-Guard reacts to an
  exec after the fact: it alerts and, for `KILL`/`BLOCK` rules, sends
  `SIGKILL` to the offending PID via `pidfd`.
- **PREVENTION**: When LSM hooks attach and `enforcement_enabled: true`:
  - **Exec Prevention**: `bprm_check_security` drops blocked binaries (`-EPERM`).
  - **File Write Prevention**: `lsm/file_open` drops write-intent opens (`O_WRONLY`/`O_RDWR`) on `blocked_write_paths` (`-EPERM`).
  - **Ptrace Prevention**: When `ptrace_enforcement_enabled`: true and LSM hooks are active, `lsm/ptrace_access_check` blocks unauthorized injection attempts unless the caller matches the `allowed_ptrace_attaches` whitelist.
  - **Kernel Module Load Prevention**: Intercepts `init_module` calls and blocks them at the kernel boundary when originating from tracked container cgroups registered in the `container_cgroups` BPF map.
  - **Privilege Escalation Prevention**: `lsm/task_fix_setuid` blocks a process from gaining UID 0 (`-EPERM`) unless it exec'd a setuid-root binary first.
  - **Agent Self-Protection**:
    - `lsm/task_kill` intercepts termination signals targeted at K-Guard's PID and rejects them (`-EPERM`) unless sent by K-Guard itself or PID 1.
    - `lsm/bpf` restricts critical eBPF system calls (`BPF_LINK_DETACH`, `BPF_MAP_GET_FD_BY_ID`, `BPF_PROG_GET_FD_BY_ID`, etc.) to prevent hostile processes from detaching or inspecting K-Guard's in-kernel security filters.

An enforcement kill-switch (`enforcement_enabled` BPF array map) lets you
disable LSM blocking instantly at runtime without detaching or reloading
any programs. Detection keeps running either way.

Kill-switches and self-protection state (`enforcement_enabled`,
`ptrace_enforcement_enabled`, `kmod_enforcement_enabled`, `self_pid`) are
plain BPF global variables (`.bss`), not map entries. Userspace reads/writes
them via cilium/ebpf's `*ebpf.Variable` API (`m.Objects.EnforcementEnabled.Set(...)`)
rather than a raw map lookup, requires `github.com/cilium/ebpf` v0.17+.

## Rule engine & Configuration Formats

K-Guard supports both **YAML** and **JSON** configuration files (auto-detected via file extension or structural fallback). Configs are reloaded via `SIGHUP` or a 5-second poll loop.

Configuration files are unmarshaled directly into standard Go structs, and CEL ASTs are pre-compiled and initialized once (`sync.Once`) upfront to keep the engine format-agnostic and ultra-fast during runtime evaluation.

### Rule Structure

Rules are evaluated using Common Expression Language (CEL), providing flexibility when inspecting event fields (`process.path`, `process.basename`, `process.sha256`, `event.is_suspicious_path`, etc.):

* **`name`**: Friendly name for the rule.
* **`severity`**: `low` \| `medium` \| `high` \| `critical`.
* **`action`**: 
  * `ALERT`: Generate alert only.
  * `KILL`: Terminate process post-exec via `pidfd_send_signal`.
  * `BLOCK`: Sync exact path to in-kernel LSM map for pre-exec block (falls back to `KILL` if path isn't explicit).
* **`expression`**: CEL expression evaluated against the event context.

### Example Configurations

```yaml
rules:
  - name: "block-netcat"
    severity: "critical"
    action: "BLOCK"
    expression: "process.basename == 'nc'"

  - name: "tmp-exec"
    severity: "high"
    action: "KILL"
    expression: "process.path.startsWith('/tmp/') && event.is_suspicious_path"

  - name: "known-malware-hash"
    severity: "critical"
    action: "KILL"
    expression: "process.sha256 == '<hex digest>'"

enforcement_enabled: true
dedup_window_seconds: 10

allowlist:
  - "/usr/bin/ssh"

protected_comms:
  - "/usr/sbin/sshd"
  - "/usr/bin/systemd"

suspicious_path:
  - "/testkill/"
  - "/tmp/"

sensitive_write_paths:
  - "/etc/"
  - "/root/.ssh/"

blocked_write_paths:
  - "/etc/passwd"

ignored_connect_comms:
  - "/usr/bin/dockerd"

ptrace_enforcement_enabled: true
max_memory_mb: 256
allowed_ptrace_attaches:
  - "/usr/bin/gdb"
  - "/usr/bin/dlv"

kmod_enforcement_enabled: true

proc_path: "/proc"
cgroup_path: "/sys/fs/cgroup"
kubelet_url: "https://127.0.0.1:10250"
kubelet_insecure: false
kubelet_cert_file: "/var/lib/rancher/k8s/server/tls/client-admin.crt"
kubelet_key_file: "/var/lib/rancher/k8s/server/tls/client-admin.key"

sinks:
  stdout: true
  syslog: true
  webhook_url: "https://example.com/hooks/kguard"
  slack_webhook_url: "https://hooks.slack.com/services/..."
  store_path: "/var/lib/kguard/alerts"
  metrics_listen_addr: ":9090"
  dashboard_listen_addr: ":8080"
```

**JSON Support**: K-Guard auto-detects JSON files (`.json`) or JSON payloads as well. All field keys map 1:1 with the YAML structure above:

```json

{
  "enforcement_enabled": true,
  "rules": [
    { "name": "Block netcat", "severity": "critical", "action": "BLOCK", "expression": "process.path == '/usr/bin/nc'" }
  ]
}
```

Duplicate alerts for the same `(rule, pid)` (or `(connect, pid, dest_ip)`,
or `(event_type, pid)` for the generic sensors) within
`dedup_window_seconds` are suppressed after the first.

Kernel Lineage & State Tracking: eBPF tracks context across child forks via `BPF_MAP_TYPE_TASK_STORAGE` attached directly to `struct task_struct`, utilizing `bpf_get_current_task_btf()` for instant BTF pointer resolution and automatic kernel-side memory cleanup on process exit.

An LRU cache in userspace maps `pid` -> `ppid` entries to reconstruct and log the visual process execution tree on alert.

Outbound connects from processes whose resolved bin matches `ignored_connect_comms`
(e.g. `["/usr/sbin/sshd"]`) are filtered before reaching the engine at all, as are
any loopback destinations (`127.0.0.0/8`, `::1`), both are near-always
background/tunnel noise rather than signal worth alerting on.

`sensitive_write_paths` raise a `SENSITIVE_WRITE` alert (audit/detect only). By contrast, `blocked_write_paths` are synced into an in-kernel BPF map where the `lsm/file_open` hook actively drops the system call with `-EPERM` if any process tries to open them with write intent.

When evaluating `sha256` rules:
- **Zero-Buffer Streaming**: Executables are streamed directly off disk via `io.Copy`, preventing memory spikes or allocations when inspecting large binaries.
- **Cross-PID In-Memory Cache**: Hashes are resolved to their canonical disk path and cached in a thread-safe in-memory cache. If multiple processes (across hundreds of PIDs) execute the same binary, only the first process triggers disk I/O, subsequent checks hit RAM instantly.

## Config validation

K-Guard refuses to start (or reload) if the config fails validation.
Common gotchas:

- **CEL Expression Syntax Validation**: K-Guard pre-compiles and 
  validates `CEL` syntax on startup/reload and will reject invalid 
  expressions (e.g., syntax errors, unparseable operators, or invalid field accesses).
- **YAML/JSON Flexibility**: Parser logic auto-detects `YAML` or `JSON` format 
  regardless of the file extension fallback.
- **empty strings in path/comm lists.** `suspicious_path`,
  `sensitive_write_paths`, `blocked_write_paths`, `allowlist`,
  `protected_comms`, `ignored_connect_comms`, and
  `allowed_ptrace_attaches` reject `""` entries, an empty pattern
  would otherwise match every path via comparison, making it a wildcard.
- **`protected_comms`, `ignored_connect_comms`**, and
  `allowed_ptrace_attaches` are absolute paths, not process names.
  Each configured path is opened once and resolved to a `(device, inode)`
  identity via a held file descriptor, matching against the real
  underlying binary rather than the `comm` mutable field, which could
  be rewritten via `prctl(PR_SET_NAME)` or simply by being exec'd
  under a different name. Validation rejects any entry that isn't an
  absolute path.
- **Symlinks and self-relocating binaries need their stable path**, not a
  transient one. `os.Open` follows symlinks, so pointing these fields
  at a maintained symlink (e.g. k3s's
  `/var/lib/rancher/k3s/data/current/bin/k3s`) is fine and recommended
  when the underlying binary moves between versions/restarts, pin the
  symlink, not a path containing a build hash or other value that
  changes on upgrade. If the pinned target changes on disk without a
  config reload, K-Guard keeps enforcing against the *old* identity
  until the next `SIGHUP`/poll reload re-resolves it, noisier, not
  silently permissive.

## Config file permissions

For the config.json files, K-Guard refuses to read it if :

- It is **not** group, or world-writable (`chmod 600` or stricter).
- It is owned by the UID K-Guard is running as (skipped when running
  as root).

A world-writable rules file would let any local user disable
enforcement or add their own binary to the allowlist.

## Reload diffing

On every hot reload, K-Guard logs what actually changed in the config (rules added/removed/modified,
allowlist/path/comm list changes, enforcement toggles, etc.) instead of just
"config reloaded". Auth tokens are never logged, only that they changed.

## Identity-based trust (protected_comms, ignored_connect_comms, allowed_ptrace_attaches)

These three lists used to match against the kernel's `comm` field,
short, human-readable, and trivially spoofable, since any process can
rewrite its own `comm` at will and the kernel itself sets `comm` from
whatever name a binary was exec'd under. K-Guard now resolves each
configured entry to the real file it points at:

- Each path is opened once (kept pinned via a held file descriptor,
  not repeatedly re-`stat`'d) and identified by its `(device, inode)`
  pair : the same identity the kernel's own VFS layer uses.
- `allowed_ptrace_attaches` is enforced entirely in-kernel: the
  `ptrace_access_check` LSM hook resolves the *calling* process's own
  `mm->exe_file` and looks it up directly in a kernel map keyed by
  `(dev, ino)`.
- `ignored_connect_comms` is resolved the same way in-kernel, every
  event's header carries the emitting process's resolved exe identity
  and checked in userspace.
- `protected_comms` is checked at the moment of a kill attempt by
  re-resolving the *live* pid's current `/proc/<pid>/exe`, rather than
  trusting whatever `comm` the triggering event carried, so a rename or
  a config change between event and kill can't be exploited either way.

Device numbers are normalized (major/minor decode + kernel-layout
re-encode) before comparison, since the raw `dev_t` encoding used by
`stat(2)` in userspace differs from the raw value the kernel exposes
via `inode->i_sb->s_dev`. All three lists are hot-reloaded the same way
as everything else, via `SIGHUP`/the 5-second poll.

### Asynchronous Execution & Bypasses

- **`IO_URING` Monitoring**: `io_uring` allows applications to bypass standard synchronous syscall entry points (like `openat` or `connect`) by submitting async Submission Queue Entries (SQE). K-Guard hooks `io_uring_submit_req` to inspect opcodes and extract file paths or socket targets submitted directly through ring buffers.

## Kubernetes context enrichment
 
When running on a Kubernetes node, K-Guard resolves each alert's cgroup
back to the owning Pod/container and attaches that context before
dispatch. Resolution works even if the process has already exited by
the time enrichment runs:
 
1. The originating cgroup path is read from `/proc/<pid>/cgroup`. If the
   PID is already dead, K-Guard falls back to walking `cgroup_path`
   looking for a directory whose inode matches the eBPF-reported cgroup
   ID.
2. The cgroup path is parsed (systemd scope naming, cgroupfs raw hex IDs,
   and pod-UID directory naming are all recognized) to extract a
   container ID, container runtime, and/or Pod UID.
3. That's cross-referenced against a local cache of the Kubelet's `/pods`
   API to resolve the Pod name and namespace.
Enriched alerts carry `container_id`, `pod_name`, `namespace`,
`pod_uid`, and `runtime` fields whenever resolution succeeds; alerts
from non-Kubernetes processes (or ones K-Guard can't resolve) are
dispatched with those fields empty rather than being held back.
 
Configure it via these optional top-level config keys:
 
| Key | Default | Notes |
|---|---|---|
| `proc_path` | `/proc` | override for containerized/chrooted K-Guard deployments |
| `cgroup_path` | `/sys/fs/cgroup` | |
| `kubelet_url` | `http://127.0.0.1:10255` | the Kubelet's read-only or authenticated API |
| `kubelet_insecure` | `false` | skip TLS certificate verification; not recommended outside of testing |
| `kubelet_cert_file` / `kubelet_key_file` | unset | client cert/key pair for mTLS against an HTTPS Kubelet endpoint. Must both be set together, or both left unset. On k8s these are typically `/var/lib/rancher/k8s/server/tls/client-admin.crt` / `.key`; other distributions will have a different client-cert location or may use a bearer token instead |
 
Resolved pod/container metadata is cached (LRU, keyed by cgroup ID and
PID) so repeat lookups for the same process don't hit the Kubelet API on
every event. The Kubelet's pod list itself is refreshed on a 30-second
background sync, plus once synchronously (3s timeout) at startup so the
cache is warm before the first eBPF events arrive.
 
> **Note:** the K8s keys (`proc_path`, `cgroup_path`,
> `kubelet_insecure`) are read once at startup.
> so unlike `kubelet_cert_file`, `kubelet_key_file`, `kubelet_url`.
> which are hot-reloadable, the first three aren't.

## Alert sinks

- **stdout** : human-readable, multi-line per alert. Promotes lineage-flagged events, and renders visual (`Process Lineage Trace`) showing root ancestors and parent chains.
- **syslog** : JSON body, severity mapped to a syslog level
- **webhook** : POSTs `{ "text": <summary>, "alert": <Alert> }` as JSON
- **slack** : POSTs clean, formatted Markdown alert messages directly to Slack or Discord webhooks (`sinks.slack_webhook_url`)
- **store** : append-only, date-rotated JSON-Lines files; backs the
  dashboard and its `/api/alerts` JSON endpoint
- **metrics** : Prometheus text exposition at `/metrics`
  (`kguard_events_total`, `kguard_rule_hits_total`, `kguard_kills_total`,
  `kguard_kill_errors_total`, `kguard_blocks_total`,
  `kguard_ringbuf_drops_total`, `kguard_sink_errors_total`,
  `kguard_hash_check_errors_total`)

Each sink runs on its own bounded queue and delivery goroutine, so a
slow or stuck sink only drops alerts for itself, it never blocks the
ring buffer reader or other sinks.

## Dashboard & Metrics

Both the dashboard (`sinks.dashboard_listen_addr`) and metrics
(`sinks.metrics_listen_addr`) HTTP servers support optional bearer-token
auth. If no token is configured, the server still starts but logs a
warning and serves without authentification, fine for `127.0.0.1`-only binding
plus SSH port-forwarding, but might be a problem if the address is reachable from
elsewhere.

Set a token via config:

```json
"sinks": {
  "dashboard_auth_token": "<random token>",
  "metrics_auth_token": "<random token>"
}
```

or, preferably, via environment variables (kept out of the
permission-checked but still plaintext config file), which take
precedence over the config value if both are set:

```bash
export KGUARD_DASHBOARD_TOKEN="$(openssl rand -hex 32)"
export KGUARD_METRICS_TOKEN="$(openssl rand -hex 32)"
```

When testing manually using `sudo`, remember `sudo` resets the
environment by default so use `sudo -E` to keep your exported
tokens, or source them from a file `sudo` can read as root.

A `/healthz` endpoint (unauthenticated, no bearer token needed) is served
alongside `/metrics` for liveness probes, reports uptime, active sensors,
LSM status, build revision, and seconds since the last event was read from
the ring buffer.

## Safety guarantees

K-Guard guarantees both self-preservation and protection against accidental collateral damage:
- **In-Kernel Self-Defense**: Active LSM hooks (`lsm/task_kill` and `lsm/bpf`) prevent non-PID 1 external processes from sending termination signals or detaching/modifying K-Guard's eBPF map descriptors and links.
- **Process Safe-List**: K-Guard will never `SIGKILL` PID 1, its own PID, any PID listed in `protected_pids`, or any process whose live `/proc/<pid>/exe` identity matches `protected_comms`.

Kills go through `pidfd_open` + `pidfd_send_signal` rather than a raw
`kill()` by PID, so a PID that has already exited and been recycled by
the kernel for an unrelated process can't be killed by mistake.

## Memory Safety 

To prevent memory bloat or memory leaks under heavy syscall load on high-throughput nodes:
- **Max RSS Memory Valve (`max_memory_mb`)**: Monitors K-Guard's runtime memory allocation every 10 seconds. If memory allocation exceeds the configured threshold (`max_memory_mb`), K-Guard automatically triggers an immediate Garbage Collection (`runtime.GC()`) to reclaim memory and stabilize RSS footprint.

## Testing & Troubleshooting

**Testing LSM Hooks Note** : When testing security hooks like `PTRACE`, keep kernel credential checks (`__ptrace_may_access`) in mind. Non-root users targeting root processes (like PID 1) will be rejected by the kernel with `-EPERM` before reaching the eBPF LSM layer. To test eBPF-level dropping and event emission correctly, run tests with appropriate capabilities/root or target processes owned by the same user.

**Testing the PMU sensor Note** : The `BRANCH_MISPREDICT` sensor can't be exercised end-to-end on most local dev VMs (see above) : `ls /sys/bus/event_source/devices/` for a `cpu*` entry before assuming it's working, and check the startup log for `PMU branch-mispredict sensor` either way. A no-PMU host is expected in plenty of environments, not a bug on its own so the rest of K-Guard runs unaffected.

## Running

```
sudo ./k-guard -config /config/rules.json

Validate a config without touching the kernel:
sudo ./k-guard -config /config/rules.json -check

Print build/version info:
./k-guard -version
```

Send `SIGHUP` to force an immediate config reload; `SIGINT`/`SIGTERM`
for graceful shutdown (all sinks are drained before exit).

See `BUILD.md` for how to build the eBPF objects and the Go binary.

## Testing

K-Guard uses a split testing strategy: pure Go unit tests run anywhere in non-privileged mode, while eBPF kernel integration tests run conditionally when executed as root on Linux.

### Run Unit Tests (Non-Privileged / Cross-Platform)

Tests parser logic, path normalization, map byte alignment, string representation, and BPF spec loading:

```bash
go test -v ./...
```

### Run Kernel Integration Tests (Linux + Root Required)

To execute full eBPF map interactions and program loader attachment tests, run as root:

```bash
sudo go test -v ./internal/ebpf/...
```

- Integration tests automatically skip on non-Linux platforms or non-root runners.

## License

MIT
