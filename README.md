# K-Guard

[![K-Guard CI/CD Pipeline](https://github.com/wkilabnwi/K-guard/actions/workflows/ci.yml/badge.svg?branch=main&event=push)](https://github.com/wkilabnwi/K-guard/actions/workflows/ci.yml)
[![golangci-lint](https://img.shields.io/badge/golangci--lint-0%20issues-brightgreen)](https://golangci-lint.run/)

K-Guard is a lightweight Linux host intrusion detection and **pre-execution prevention** agent built on eBPF. It watches security-relevant kernel events, evaluates them against a hot-reloadable [CEL](https://github.com/google/cel-spec) rule engine, and either blocks the behavior in-kernel (BPF LSM) or alerts, depending on what your kernel supports.


Questions? louai.sahli1@gmail.com

## Features

- **Prevention, not just detection**: blocks exec, file writes, ptrace, kernel module loads, privilege escalation and reverse shells with `-EPERM` before they happen
- **CEL rules** in YAML or JSON, with an `audit` (shadow) mode for safe rollout
- **Sigma import** and **MITRE ATT&CK** tagging
- **Kubernetes-aware**: alerts enriched with pod, namespace and container
- **DNS correlation**: connections are tied back to resolved domain names
- **Self-protecting**: resists kill and detach attempts, and fails open if it exits
- **Many sinks**: stdout, syslog, webhook, Slack, JSON-Lines store, dashboard, Prometheus
- **Compliance audit trail** (NDJSON) for every enforcement decision

## Requirements

- Linux **5.11+** with BTF enabled (needed for kernel-side process lineage tracking)
- Root (or the relevant capabilities)
- For **prevention**: `CONFIG_BPF_LSM=y` and `bpf` in the active LSM list. Without it, K-Guard runs in detection-only mode.

## Quick start

```bash
# Build the eBPF objects and the binary: see BUILD.md

# Validate a config without touching the kernel
sudo ./k-guard -config rules.yaml -check

# Run
sudo ./k-guard -config rules.yaml
```

Minimal config:

```yaml
enforcement_enabled: true

rules:
  - name: "block-netcat"
    severity: "critical"
    action: "BLOCK"
    expression: "process.path == '/usr/bin/nc'"

sinks:
  stdout: true
```

Try a rule offline, with no eBPF needed:

```bash
./k-guard -test-rule "process.basename == 'nc'"
```

Send `SIGHUP` to reload the config immediately. `SIGINT`/`SIGTERM` shut down gracefully.

## Documentation

| Doc | Contents |
|---|---|
| [Sensors](docs/sensors.md) | Every event K-Guard watches, hooks used, PMU and io_uring notes |
| [Prevention & self-protection](docs/prevention.md) | Operating modes, LSM enforcement, kill-switches, safety guarantees, supervisor |
| [Configuration](docs/configuration.md) | Full config reference, validation rules, file permissions, hot reload |
| [Writing rules](docs/rules.md) | CEL rules, audit/shadow mode, MITRE mapping, Sigma transpiler |
| [Identity-based trust](docs/identity-trust.md) | How `protected_comms`, `ignored_connect_comms`, `allowed_ptrace_attaches` work |
| [Enrichment](docs/enrichment.md) | Kubernetes context, container escape detection, DNS correlation |
| [Sinks & metrics](docs/sinks.md) | Alert sinks, dashboard, Prometheus, auth tokens, `/healthz` |
| [Audit log](docs/audit-log.md) | SOC2/PCI-oriented enforcement audit trail |
| [Telemetry](docs/telemetry.md) | ML telemetry pipeline and anomaly dataset |
| [Development](docs/development.md) | Testing, fuzzing, troubleshooting |

## License

MIT