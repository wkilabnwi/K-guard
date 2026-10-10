# Configuration

[← Back to README](../README.md)

K-Guard accepts **YAML** and **JSON** (auto-detected by extension, with a structural fallback). Configs reload on `SIGHUP` or via a 5-second poll loop. Files are unmarshaled into Go structs, Files are unmarshaled directly into Go structs, and CEL ASTs are pre-compiled and initialized once (`sync.Once`) up front so the engine stays format-agnostic and fast at runtime.

## Full example

```yaml
rules:
  - name: "block-netcat"
    severity: "critical"
    action: "BLOCK"
    mode: "enforce"
    expression: "process.basename == 'nc'"

  - name: "tmp-exec"
    severity: "high"
    action: "KILL"
    mode: "audit"
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
  audit_log_path: "/var/log/kguard/audit.log"
  metrics_listen_addr: ":9090"
  dashboard_listen_addr: ":8080"
```

JSON uses the same keys 1:1:

```json
{
  "enforcement_enabled": true,
  "rules": [
    { "name": "Block netcat", "severity": "critical", "action": "BLOCK", "expression": "process.path == '/usr/bin/nc'" }
  ]
}
```

Rule fields are documented in [Writing rules](rules.md).

## Deduplication

Duplicate alerts for the same `(rule, pid)`, `(connect/sendto, pid, dest_ip)`, or `(event_type, pid)` (for generic sensors) within `dedup_window_seconds` are suppressed after the first. Dedup applies to alerts only; the [audit log](audit-log.md) is never deduplicated.

## Validation

K-Guard refuses to start (or reload) if the config fails validation. Common gotchas:

- **Offline CEL rule testing**: test custom CEL rules against mock data with `-test-rule` (and optional `-test-event`) from the CLI, without a running eBPF environment.
- **YAML/JSON flexibility**: the parser auto-detects YAML or JSON regardless of file extension.
- **CEL is validated up front.** Syntax errors, unparseable operators and invalid field accesses are rejected at startup/reload.
- **Expressions must return bool.**
- **Empty strings are rejected** in `suspicious_path`, `sensitive_write_paths`, `blocked_write_paths`, `allowlist`, `protected_comms`, `ignored_connect_comms` and `allowed_ptrace_attaches`. An empty pattern would match every path.
- **`protected_comms`, `ignored_connect_comms` and `allowed_ptrace_attaches` must be absolute paths**, not process names. See [Identity-based trust](identity-trust.md).
- **Symlinks and self-relocating binaries**: `os.Open` follows symlinks, so pin a maintained symlink (e.g. k3s's `/var/lib/rancher/k3s/data/current/bin/k3s`) rather than a path with a build hash that changes on upgrade. If the target changes without a reload, K-Guard keeps enforcing against the *old* identity until the next `SIGHUP`/poll reload. That is noisier, not silently permissive.
- **Strict parsing**: unknown keys are rejected in both YAML and JSON, so a typo like `enforcment_enabled` fails at load instead of silently leaving enforcement off.
- **Size limit**: files over 1 MiB, and anything that isn't a regular file (FIFOs, devices), are refused.
- **BLOCK rules and the kernel**: a `BLOCK` rule is synced to the in-kernel LSM map only if the whole expression is exactly `process.path == '<abs path>'` or `process.path.startsWith('<abs prefix>')`. Any other expression (compound conditions, negation, basename matches) is enforced post-exec via `KILL`, and a log line says so at load time.

Validate without touching the kernel:

```bash
sudo ./k-guard -config /config/rules.json -check
```

## File permissions

K-Guard refuses to read a config file if:

- it is group- or world-writable (use `chmod 600` or stricter),
- it is owned by a different UID than K-Guard runs as (skipped when running as root), or
- it is not a regular file.

A world-writable rules file would let any local user disable enforcement or allowlist their own binary.

## Reload diffing

On every hot reload K-Guard logs what actually changed (rules added/removed/modified, `enforce`/`audit` toggles, allowlist/path/comm list changes, enforcement toggles) instead of a bare "config reloaded". Auth tokens are never logged, only the fact that they changed.

## Kubernetes keys

| Key | Default | Hot-reload | Notes |
|---|---|---|---|
| `proc_path` | `/proc` | No | Override for containerized/chrooted deployments |
| `cgroup_path` | `/sys/fs/cgroup` | No | |
| `kubelet_insecure` | `false` | No | Skip TLS verification; not recommended outside testing |
| `kubelet_url` | `http://127.0.0.1:10255` | Yes | Kubelet read-only or authenticated API |
| `kubelet_cert_file` / `kubelet_key_file` | unset | Yes | Client cert/key pair for mTLS against an HTTPS Kubelet endpoint. Must both be set together, or both left unset. On k8s these are typically `/var/lib/rancher/k8s/server/tls/client-admin.crt` / `.key`; other distributions will have a different client-cert location or may use a bearer token instead |

See [Enrichment](enrichment.md) for how these are used.
