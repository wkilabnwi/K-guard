# Writing Rules

[← Back to README](../README.md)

Rules are [CEL](https://github.com/google/cel-spec) expressions evaluated against the event context. Type-safe access to `event` and `process` fields comes from Protocol Buffers bindings (`internal/pb`), so schema errors are caught when the rule is compiled.

Available fields include `process.path`, `process.basename`, `process.sha256`, `process.uid`, `event.is_suspicious_path` and `event.ancestor_filename`.

## Rule structure

| Field | Values | Description |
|---|---|---|
| `name` | string | Friendly name |
| `severity` | `low` \| `medium` \| `high` \| `critical` | |
| `action` | `ALERT` \| `KILL` \| `BLOCK` | See below |
| `mode` | `enforce` \| `audit` | Defaults to `enforce` |
| `expression` | CEL | Must return bool |
| `mitre` | optional block | See [MITRE mapping](#mitre-attck-mapping) |

**Actions**

- `ALERT`: generate an alert only.
- `KILL`: terminate the process post-exec via `pidfd_send_signal`.
- `BLOCK`: sync the path or prefix to the in-kernel LSM map for a pre-exec block. Falls back to `KILL` for expressions that can't be expressed in-kernel (e.g. basename matches). See [Configuration](configuration.md#validation).

## Examples

```yaml
rules:
  - name: "block-netcat"
    severity: "critical"
    action: "BLOCK"
    expression: "process.basename == 'nc'"
```

Test a rule offline against a mock event, with no eBPF environment needed:

```bash
./k-guard -test-rule "process.basename == 'nc'"
./k-guard -test-rule "process.path.startsWith('/tmp/')" -test-event '{"event": {"process": {"path": "/tmp/malware"}}}'
./k-guard -test-rule "process.basename == 'nc'" -test-event ./mock_event.json
```

## SHA-256 rules

- **Streaming**: executables are streamed from disk via `io.Copy` rather than read fully into memory, so large binaries don't cause memory spikes.
- **Cross-PID LRU cache**: hashes are cached (`globalHashCache`) keyed by canonical path, inode, mtime and size, so repeated executions don't re-read the disk.

## Audit / shadow mode (`mode: audit`)

Test new policies in production without risking breakage.

- **In-kernel pre-exec blocks (`BLOCK`)**: block maps carry an enforcement mode (`1 = ENFORCE`, `2 = AUDIT`). For an `audit` rule, `lsm/bprm_check_security` still emits `EVT_EXEC_BLOCKED` over the ring buffer for full telemetry, but returns `0` and the process runs normally.
- **Post-exec terminations (`KILL`)**: the alert is marked `mode: "audit"` with a `[SHADOW MODE]` detail prefix, and `pidfd_send_signal` is suppressed.
- **Audit trail**: shadow matches are written to the [audit log](audit-log.md) with MITRE tags, recording that enforcement was suppressed.

## MITRE ATT&CK mapping

Add an optional `mitre` block to any rule. Tactic, technique and tags flow into all alert outputs and the audit log.

```yaml
rules:
  - name: "block-netcat-c2"
    severity: "critical"
    action: "BLOCK"
    expression: "process.path == '/usr/bin/nc.openbsd'"
    mitre:
      tactic: "Command and Control"
      technique_id: "T1095"
      technique: "Non-Application Layer Protocol"
      tags: ["c2", "egress"]
```

## Sigma transpilation

K-Guard converts community [Sigma](https://github.com/SigmaHQ/sigma) rules into native CEL expressions and fills in MITRE metadata automatically.

```bash
./k-guard -convert-sigma rules/linux/process_creation/proc_creation_lnx_nc.yml
```

**Field mapping (process creation)**

| Sigma | K-Guard |
|---|---|
| `Image` | `process.path` |
| `OriginalFileName` / `process.basename` | `process.basename` |
| `ParentImage` | `event.ancestor_filename` |
| `Hashes.SHA256` | `process.sha256` |
| `User` | `process.uid` |

**Operators**: `|endswith`, `|startswith` and `|contains` become `.endsWith()`, `.startsWith()` and `.contains()`.

**ATT&CK tags**: Sigma `tags` (e.g. `attack.t1059.004`, `attack.execution`) are extracted into the `mitre` block.

> **Scope:** the transpiler targets Linux `process_creation` and single-event rules. Multi-event temporal correlation (`near`), aggregation pipelines, and userspace log categories (`systemd journal`, `auth.log`) are not supported. Audit those rules manually before deploying.
