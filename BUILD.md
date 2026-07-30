# Building K-Guard

K-Guard has two build stages: compiling the eBPF program
(`bpf/kguard.c`) into a portable BPF object with `bpf2go`, and then
building the Go binary that embeds and loads it. This is not a purely
"clone and `go build`" project, the eBPF stage needs a real C toolchain
and, for the LSM enforcement hook, a `vmlinux.h` generated from your
running kernel.

## Prerequisites

- **Go** 1.21+ (matching whatever the module's `go.mod` specifies)
- **clang** and **llvm-strip** (LLVM toolchain), used by `bpf2go` to
  compile the C source to BPF bytecode
- **Linux kernel headers** for the target kernel
- **bpftool** (only needed if you want to (re)generate `vmlinux.h` for
  LSM support, see below)
- Root or `CAP_BPF` + `CAP_PERFMON` (`CAP_SYS_ADMIN` on older kernels)
  at *runtime* to load programs and attach tracepoints/LSM hooks

The Go module already depends on `github.com/cilium/ebpf`, which
vendors `bpf2go`, you don't need to install it separately; it's
invoked via `go run` from the `go:generate` directive in
`internal/ebpf/loader.go`:

```go
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -go-package ebpf \
    -target amd64 -cc clang \
    -cflags "-DKGUARD_HAVE_VMLINUX -I../../bpf/include" \
    -type kguard_event BPF ../../bpf/kguard.c -- \
    -I../../bpf/include -I../../bpf -D__TARGET_ARCH_x86
```

## 1. Generate (or obtain) `vmlinux.h`

`bpf/kguard.c` includes `vmlinux.h` and needs it to build **at all**
even the tracepoint-only sensors reference kernel struct layout via the
shared event/scratch maps and `struct task_struct` in `fill_common()`.
The LSM hook additionally needs a `vmlinux.h` that actually matches your
kernel's BTF, since it reads real `struct linux_binprm` fields.

If your kernel exposes BTF (`/sys/kernel/btf/vlinux` present, check
with `ls /sys/kernel/btf/vmlinux`), generate it directly from the
running kernel:

```
bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/include/vmlinux.h
```

If BTF isn't available, pull a pre-generated `vmlinux.h` for your
kernel version/arch from the community collection at
https://github.com/libbpf/vmlinux.h and place it at
`bpf/include/vmlinux.h`.

Without a valid `vmlinux.h`, the whole object fails to compile, there
is no "detect-only, no vmlinux.h" build variant; the fallback to
detect-only mode described below happens at **attach time**, not
compile time.

## 2. Compile the eBPF object

From the module root:

```
go generate ./...
```

This invokes `bpf2go` against `bpf/kguard.c` and produces Go-embeddable
generated files (object bytes + generated Go bindings for maps/programs,
including the `BPFObjects` / `BPFKguardEvent` types referenced from
`internal/ebpf`) into `internal/ebpf/`.

Common failure modes here:
- `clang: command not found` : install an LLVM/clang toolchain matching
  your distro's package (e.g. `clang` + `llvm` on Debian/Ubuntu).
- Missing `bpf/bpf_helpers.h` / `bpf/bpf_tracing.h`, these come from
  `libbpf`'s bundled headers; make sure `bpf/include` contains (or
  vendors) a copy of `libbpf`'s `bpf_helpers.h`, `bpf_tracing.h`,
  `bpf_core_read.h`, etc. alongside `vmlinux.h`.
- Struct-layout mismatches (e.g. in the hand-written
  `syscall_execve_args`/`syscall_connect_args`/etc. structs in
  `kguard.c`), these are parsed from
  `/sys/kernel/tracing/events/<category>/<event>/format` and can differ
  across kernel versions/architectures; regenerate them against your
  target kernel if attachment fails or fields look wrong.

## 3. Build the Go binary

```
go build -o k-guard .
```

(adjust the package path to wherever `main.go` lives in your module
layout).

## 4. Enabling real pre-exec prevention (optional)

Tracepoint sensors work on essentially any modern kernel with BPF
support. The LSM `BLOCK` enforcement path additionally needs:

- `CONFIG_BPF_LSM=y` in the running kernel config
- `bpf` present in the active LSM stack: `cat /sys/kernel/security/lsm`
  if it's missing, append `lsm=<existing-list>,bpf` to your kernel
  command line (bootloader config) and reboot
- The BPF object built with a `vmlinux.h` matching that kernel (step 1)

If either requirement is missing, `internal/ebpf.NewManager()` logs a
warning, skips attaching `lsm_bprm_check`, and K-Guard runs in
detect-only mode automatically, this is expected, not a bug, and
requires no config changes; `BLOCK`-action rules simply fall back to a
post-exec `KILL`.

You can confirm which mode is active from the startup log line
(`Mode: PREVENTION ...` vs `Mode: DETECTION ONLY ...`) or from the
dashboard's status card.

## 5. Running / permissions

The resulting binary needs privileges to load BPF programs and attach
tracepoints/LSM hooks:

```
sudo ./k-guard -config /config/rules.json
```

or grant capabilities instead of running fully as root, on kernels new
enough to split `CAP_BPF`/`CAP_PERFMON` out from `CAP_SYS_ADMIN`:

```
sudo setcap cap_bpf,cap_perfmon,cap_sys_ptrace,cap_kill+ep ./k-guard
```

(`cap_sys_ptrace` isn't required by the BPF side, but `SafeKill`'s use
of `pidfd_send_signal` needs `cap_kill` if not running as root.)

## Regenerating after changing `kguard.c`

Any change to `bpf/kguard.c` : new event types, changed struct layout,
new maps, requires re-running `go generate ./...` before `go build`,
since the Go side (`internal/ebpf`, `types.go`'s `EventType` constants,
`event.go`'s decoding) is hand-kept in sync with the C event struct and
`EVT_*` defines rather than derived automatically. Keep
`internal/ebpf/types.go` and the `EVT_*` `#define`s in `kguard.c` in
sync manually when adding new event types.
