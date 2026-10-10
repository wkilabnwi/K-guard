# Audit Log (SOC2 / PCI)

[← Back to README](../README.md)

K-Guard keeps a dedicated, structured audit trail of every active enforcement decision (`BLOCK`, `KILL`). It is deliberately separate from the alert stream: alerts capture all interesting telemetry and may be rate-limited or deduplicated, while the audit log is an authoritative, **un-deduplicated** control log intended for compliance frameworks (SOC2, PCI-DSS, ISO 27001).

Shadow-mode (`mode: audit`) matches are also recorded, along with MITRE tags, noting that enforcement was suppressed.

## Architecture

Audit logging is built to keep its impact on kernel event processing minimal:

- **Non-blocking async worker**: the engine pushes a small struct into a 10,000-element buffered channel and continues. Disk I/O happens on a background goroutine.
- **Allocation-light formatting**: instead of `json.Marshal` (reflection and heap allocations), the worker writes NDJSON into a reused buffer with `strconv.AppendQuote`, `strconv.AppendUint`, etc.
- **Batched flushing**: writes go through a 64KB `bufio.Writer`, batching up to ~500 events per physical write.

## Format

Newline-Delimited JSON written to `sinks.audit_log_path` (default `/var/log/kguard/audit.log`), directly ingestible by Datadog, Splunk, Vector or Elastic:

```json
{"timestamp":"2026-09-21T20:12:00.123456Z","decision":"BLOCK","event_type":"EXEC_BLOCKED","pid":16274,"ppid":11944,"uid":501,"comm":"nc","cgroup_id":123456,"target":"/usr/bin/nc","reason":"LSM pre-exec hook blocked binary execution"}
{"timestamp":"2026-09-21T20:15:22.987654Z","decision":"KILL","event_type":"EXEC","rule_name":"block-tmp-exec","pid":18201,"ppid":1402,"uid":0,"comm":"malware","cgroup_id":123456,"target":"/tmp/malware","reason":"Process killed post-exec via rule action"}
```
