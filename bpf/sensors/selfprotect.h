#ifndef __KGUARD_SENSORS_SP_H
#define __KGUARD_SENSORS_SP_H

#include "../types.h"
#include "../maps.h"
#include <bpf/bpf_core_read.h>

SEC("lsm/task_kill")
int BPF_PROG(lsm_task_kill, struct task_struct *p, struct kernel_siginfo *info,
             int sig, const struct cred *cred) {
    __u32 zero = 0;
    __u32 *guard_pid = bpf_map_lookup_elem(&self_pid, &zero);
    if (!guard_pid || *guard_pid == 0) return 0; //

    __u32 target = BPF_CORE_READ(p, tgid);
    if (target != *guard_pid) return 0;

    __u64 id = bpf_get_current_pid_tgid();
    __u32 caller = (__u32)(id >> 32);
    if (caller == target || caller == 1) return 0;

    bpf_printk("kguard: blocked signal %d to self from pid %d\n", sig, caller);
    return -1;
}

SEC("lsm/bpf")
int BPF_PROG(lsm_bpf_cmd, int cmd, union bpf_attr *attr, unsigned int size) {
    switch (cmd) {
    case BPF_LINK_DETACH:
    case BPF_MAP_GET_FD_BY_ID:
    case BPF_LINK_GET_FD_BY_ID:
    case BPF_PROG_GET_FD_BY_ID:
        break;
    default:
        return 0;
    }

    __u32 zero = 0;
    __u32 *guard_pid = bpf_map_lookup_elem(&self_pid, &zero);
    if (!guard_pid || *guard_pid == 0) return 0;

    __u64 id = bpf_get_current_pid_tgid();
    __u32 caller = (__u32)(id >> 32);
    if (caller == *guard_pid) return 0;

    return -1;
}

#endif