#ifndef __KGUARD_SENSORS_SP_H
#define __KGUARD_SENSORS_SP_H

#include "../types.h"
#include "../maps.h"
#include <bpf/bpf_core_read.h>

SEC("lsm/task_kill")
int BPF_PROG(lsm_task_kill, struct task_struct *p, struct kernel_siginfo *info,
             int sig, const struct cred *cred) {
    if (self_pid == 0) return 0;

    __u32 target = BPF_CORE_READ(p, tgid);
    if (target != self_pid) return 0;

    __u64 id = bpf_get_current_pid_tgid();
    __u32 caller = (__u32)(id >> 32);
    if (caller == target || caller == 1) return 0;

    bpf_printk("kguard: blocked signal %d to self from pid %d\n", sig, caller);
    return -1;
}

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, u32);
    __type(value, u8); 
} protected_ids SEC(".maps");

SEC("lsm/bpf")
int BPF_PROG(lsm_bpf_cmd, int cmd, union bpf_attr *attr, unsigned int size) {

    // Filter relevant commands
    switch (cmd) {
    case BPF_LINK_DETACH:
    case BPF_MAP_GET_FD_BY_ID:
    case BPF_LINK_GET_FD_BY_ID:
    case BPF_PROG_GET_FD_BY_ID:
        break;
    default:
        return 0;
    }

    // Allow during startup initialization
    if (self_pid == 0) return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 caller_pid = (u32)(pid_tgid >> 32);

    if (caller_pid == self_pid || caller_pid == 1) {
        return 0;
    }

    // We extract the needed ID form the attr union

    u32 target_id = 0;
    if (cmd == BPF_MAP_GET_FD_BY_ID) {
        target_id = BPF_CORE_READ(attr, map_id);
    } else if (cmd == BPF_PROG_GET_FD_BY_ID) {
        target_id = BPF_CORE_READ(attr, prog_id);
    } else if (cmd == BPF_LINK_GET_FD_BY_ID || cmd == BPF_LINK_DETACH) {
        target_id = BPF_CORE_READ(attr, link_id);
    }

    u8 *is_protected = bpf_map_lookup_elem(&protected_ids, &target_id);
    // Block external processes from accessing K-Guard's eBPF objects
    if (is_protected && *is_protected == 1) {
        return -1; 
    }

    return 0;
}

#endif