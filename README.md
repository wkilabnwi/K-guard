# K-Guard

K-Guard is a lightweight Linux host intrusion detection (and, where the
kernel supports it, pre-execution *prevention*) agent built on eBPF. It
watches a set of security-relevant syscalls and kernel events, evaluates
them against a hot-reloadable JSON rule set, and fans matching alerts out
to one or more sinks (stdout, syslog, a webhook, a local JSON-Lines
store, and a small read-only web dashboard).
For any question, feel free to contact louai.sahli1@gmail.com.

## DEMO

See `Demo` Folder

## What it watches

K-Guard attaches a mix of tracepoint sensors and, when the kernel allows
it, a BPF LSM hook:

| Event | Hook | Notes |
|---|---|---|
| `EXEC` | `tracepoint/sched/sched_process_exec` (+ `sys_enter_execve` for argv0) | Observed *after* the exec has already started |
| `EXEC_BLOCKED` | `lsm/bprm_check_security` | Pre-exec : the kernel is stopped from ever running the binary |
| `CONNECT` | `sys_enter_connect` | Outbound connections : IPv4, IPv6, and Unix domain sockets |
| `OPEN_SENSITIVE` | `sys_enter_openat` / `sys_enter_openat2` | Reads of paths like `/etc/passwd`, `/etc/shadow`, `/root/.ssh` |
| `PTRACE` | `sys_enter_ptrace` | Attach/injection attempts |
| `SETUID` | `sys_enter_setuid` | Privilege changes |
| `MODULE_LOAD` | `sys_enter_init_module` | Kernel module loading |
| `MEMFD_CREATE` | `sys_enter_memfd_create` | Fileless-exec precursor |

### Two operating modes

- **DETECTION ONLY** : the default, and the only mode available on
  kernels/builds without `CONFIG_BPF_LSM` support. K-Guard reacts to an
  exec after the fact: it alerts and, for `KILL`/`BLOCK` rules, sends
  `SIGKILL` to the offending PID via `pidfd`.
- **PREVENTION** : when the LSM hook attaches successfully *and*
  `enforcement_enabled: true` is set in config, `BLOCK`-action rules
  matched by exact path are synced into an in-kernel hash map and the
  `bprm_check_security` hook returns `-EPERM` before the kernel ever
  commits to the exec. No process ever runs, so there's nothing to kill.

An enforcement kill-switch (`enforcement_enabled` BPF array map) lets you
disable LSM blocking instantly at runtime without detaching or reloading
any programs. Detection keeps running either way.

## Rule engine

Rules live in a JSON config file (default `configs/rules.json`) and are
hot-reloaded either on a 5-second poll or immediately on `SIGHUP`. Each
rule has:

- `match`: `exact_path`, `basename`, `prefix`, `substring`, or `sha256`
- `pattern`: what to compare against
- `severity`: `low` / `medium` / `high` / `critical`
- `action`: `ALERT` (log only), `KILL` (SIGKILL the PID), or `BLOCK`
  (synced to the in-kernel LSM block-list when `match` is `exact_path`;
  otherwise falls back to `KILL` post-exec)
- `suspicious_path_only` (optional): only evaluate the rule if the exec
  path matches one of the configured `suspicious_paths`

An `allowlist` of exact paths/basenames is checked first and skips rule
evaluation entirely. `protected_pids` / `protected_comms`, plus PID 1 and
K-Guard's own PID, can never be killed regardless of what matches.

Example config:

```json
{
  "enforcement_enabled": true,
  "dedup_window_seconds": 10,
  "allowlist": ["/usr/bin/ssh"],
  "protected_comms": ["sshd", "systemd"],
  "suspicious_path": ["/testkill/", "/tmp/"],
  "ignored_connect_comms": ["docker"],
  "rules": [
    { "name": "block-netcat", "match": "basename", "pattern": "nc", "severity": "critical", "action": "BLOCK" },
    { "name": "tmp-exec", "match": "prefix", "pattern": "/tmp/", "severity": "high", "action": "KILL", "suspicious_path_only": true },
    { "name": "known-malware-hash", "match": "sha256", "pattern": "<hex digest>", "severity": "critical", "action": "KILL" }
  ],
  "sinks": {
    "stdout": true,
    "syslog": true,
    "webhook_url": "https://example.com/hooks/kguard",
    "store_path": "/var/lib/kguard/alerts",
    "metrics_listen_addr": ":9090",
    "dashboard_listen_addr": ":8080"
  }
}
```

Duplicate alerts for the same `(rule, pid)` (or `(connect, pid, dest_ip)`,
or `(event_type, pid)` for the generic sensors) within
`dedup_window_seconds` are suppressed after the first.

A small correlator remembers, per-PID, the most recent exec and whether
it came from a configured suspicious path (see `suspicious_paths` above). If a
`CONNECT` event follows shortly after, its severity is escalated from
`low` to `high` and the alert notes the correlated exec, a decent
signal for "downloaded to /tmp and immediately phoned home."

Outbound connects from processes listed in `ignored_connect_comms`
(e.g. `["sshd"]`) are filtered before reaching the engine at all, as are
any loopback destinations (`127.0.0.0/8`, `::1`), both are near-always
background/tunnel noise rather than signal worth alerting on.

## Alert sinks

- **stdout** : human-readable, multi-line per alert
- **syslog** : JSON body, severity mapped to a syslog level
- **webhook** : POSTs `{ "text": <summary>, "alert": <Alert> }` as JSON
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

## Dashboard

If `sinks.dashboard_listen_addr` is set (and `sinks.store_path` is also
set, since the dashboard reads its history from the store), a minimal
stdlib-only web UI is served showing current enforcement mode, active
sensors, and the most recent alerts, auto-refreshing every 5 seconds.

## Safety guarantees

K-Guard will never `SIGKILL`:
- PID 1
- its own PID
- any PID/comm listed in `protected_pids` / `protected_comms`

Kills go through `pidfd_open` + `pidfd_send_signal` rather than a raw
`kill()` by PID, so a PID that has already exited and been recycled by
the kernel for an unrelated process can't be killed by mistake.

## Running

```
./k-guard -config /config/rules.json
```

Send `SIGHUP` to force an immediate config reload; `SIGINT`/`SIGTERM`
for graceful shutdown (all sinks are drained before exit).

See `BUILD.md` for how to build the eBPF objects and the Go binary.

## License

MIT
