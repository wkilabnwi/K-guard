#ifndef __KGUARD_SENSORS_SYS_H
#define __KGUARD_SENSORS_SYS_H


#include "../types.h"
#include "../helpers.h"
// ptrace() sensor 

struct syscall_ptrace_args {
    unsigned long long common_tp_fields;
    int syscall_nr;
    long request;
    long pid;
    void *addr;
    void *data;
};

SEC("tracepoint/syscalls/sys_enter_ptrace")
int tp_ptrace(struct syscall_ptrace_args *ctx) {
    struct exec_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;
    fill_common(&e->hdr, EVT_PTRACE);
    e->hdr.ret = (int)ctx->request; 
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// setuid() sensor 

struct syscall_setuid_args {
    unsigned long long common_tp_fields;
    __s32 syscall_nr;
    __u32 __pad;
    __u64 uid;   
};

SEC("tracepoint/syscalls/sys_enter_setuid")
int tp_setuid(struct syscall_setuid_args *ctx) {
    struct exec_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;
    fill_common(&e->hdr, EVT_SETUID);
    e->hdr.ret = (int)ctx->uid; // target uid being requested 
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// init_module()/finit_module() sensor

struct syscall_init_module_args {
    unsigned long long common_tp_fields;
    int syscall_nr;
    void *umod;
    unsigned long len;
    const char *uargs;
};

SEC("tracepoint/syscalls/sys_enter_init_module")
int tp_init_module(struct syscall_init_module_args *ctx) {
    struct exec_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;
    fill_common(&e->hdr, EVT_MODULE_LOAD);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// unshare() sensor

struct syscall_unshare_args {
    unsigned long long common_tp_fields;
    int syscall_nr;
    unsigned long unshare_flags;
};

SEC("tracepoint/syscalls/sys_enter_unshare")
int tp_unshare(struct syscall_unshare_args *ctx) {
    struct ns_change_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;
    fill_common(&e->hdr, EVT_NS_CHANGE);
    e->flags = (__u64)ctx->unshare_flags;
    e->nstype = 0;
    e->op = 1; // 1 = unshare
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// setns() sensor

struct syscall_setns_args {
    unsigned long long common_tp_fields;
    int syscall_nr;
    int fd;
    int nstype;
};

SEC("tracepoint/syscalls/sys_enter_setns")
int tp_setns(struct syscall_setns_args *ctx) {
    struct ns_change_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;
    fill_common(&e->hdr, EVT_NS_CHANGE);
    e->flags = (__u64)ctx->fd;
    e->nstype = (__u32)ctx->nstype;
    e->op = 2; // 2 = setns
    bpf_ringbuf_submit(e, 0);
    return 0;
}
#endif