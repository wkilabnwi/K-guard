// +build ignore

// BUILD REQUIREMENT FOR THE LSM PROGRAM:
// lsm_bprm_check reads real kernel struct fields (struct linux_binprm) and
// therefore needs a real vmlinux.h generated from your running kernel's
// BTF.
// 
// Your kernel also needs CONFIG_BPF_LSM=y and "bpf" present in
// /sys/kernel/security/lsm (add lsm=...,bpf to the kernel cmdline if not).
// If either is missing, loader.go detects the attach failure and falls
// back to tracepoint-only (detect + kill) mode automatically. 
#include "types.h"
#include "maps.h"
#include "helpers.h"

// Include sensor modules
#include "sensors/exec.h"
#include "sensors/lsm.h"
#include "sensors/net.h"
#include "sensors/file.h"
#include "sensors/sys.h"
#include "sensors/iouring.h"


char _license[] SEC("license") = "GPL";