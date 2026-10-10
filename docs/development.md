# Development: Testing, Fuzzing & Troubleshooting

[← Back to README](../README.md)

See [`BUILD.md`](../BUILD.md) for building the eBPF objects and the Go binary.

## Testing strategy

Pure Go unit tests run anywhere without privileges. eBPF kernel integration tests run only as root on Linux.

### Unit tests (unprivileged, cross-platform)

Covers parser logic, path normalization, map byte alignment, string representation and BPF spec loading:

```bash
go test -v ./...
```

### Kernel integration tests (Linux + root)

Covers full eBPF map interactions and program loader attachment:

```bash
sudo go test -v ./internal/ebpf/...
```

These skip automatically on non-Linux platforms or non-root runners.

## Fuzzing

The config parser, Sigma converter and CEL evaluator process untrusted-ish input (config files, imported Sigma rules, rule expressions), so they are fuzzed with Go's native fuzzing.

| Target | Package | Covers |
|---|---|---|
| `FuzzParseConfig` | `internal/config` | YAML/JSON parsing, defaults, validation, BLOCK path extraction |
| `FuzzSigma` | `internal/config` | Sigma → CEL conversion (output must always compile) |
| `FuzzTestExpression` | `internal/processor` | CEL compile + evaluation against a mock event |

Each target asserts more than "doesn't panic": accepted rules must have a compiled program, extracted block paths must be clean, and parsing must finish within 500ms.

```bash
go test -fuzz=FuzzParseConfig -fuzztime=2m ./internal/config/
go test -fuzz=FuzzSigma -fuzztime=2m ./internal/config/
go test -fuzz=FuzzTestExpression -fuzztime=2m ./internal/processor/
```

Only one target can run per `-fuzz` invocation. Add `-parallel=1` on a laptop or small VM. Crashing inputs are saved to `testdata/fuzz/<Target>/` and replayed as regression tests by a plain `go test ./...`.

## Troubleshooting

**Testing LSM hooks.** Kernel credential checks (`__ptrace_may_access`) run first. Non-root users targeting root processes (like PID 1) are rejected with `-EPERM` before reaching the eBPF LSM layer. To test eBPF-level blocking and event emission, run as root or target processes owned by the same user.

**Testing the PMU sensor.** `BRANCH_MISPREDICT` can't be exercised end-to-end on most local dev VMs. Run `ls /sys/bus/event_source/devices/` and look for a `cpu*` entry before assuming it works, and check the startup log for `PMU branch-mispredict sensor`. A host without a PMU is expected in many environments and not a bug. The rest of K-Guard runs unaffected. See [Sensors](sensors.md#hardware-pmu-sensor-branch-mispredictions).

**Prevention isn't active.** Check that the kernel has `CONFIG_BPF_LSM=y` and that `bpf` appears in `/sys/kernel/security/lsm`. If not, add `lsm=...,bpf` to the kernel command line. `/healthz` reports LSM status.

**Sensor missing from `/healthz`.** The sensor didn't attach. Check the startup logs (`component=ebpf`) for the reason.
