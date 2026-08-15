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

#endif