// +build ignore

// 
// Two classes of program live here:
// 1. Tracepoint-based SENSORS (tp_execve, sched_process_exec, tp_connect, tp_openat, tp_openat2, tp_ptrace,
//  tp_setuid, tp_init_module, tp_memfd_create). These only observe; they
//  cannot block anything. They fire on syscall entry and are cheap and
//  portable.
// 
// 2. An LSM-based ENFORCER (lsm_bprm_check): it runs *before* the kernel c
//    ommits to executing a binary and return -EPERM to block the exec outright
//    instead of relying on "let it run, then SIGKILL the PID"     
// 
// BUILD REQUIREMENT FOR THE LSM PROGRAM:
// lsm_bprm_check reads real kernel struct fields (struct linux_binprm) and
// therefore needs a real vmlinux.h generated from your running kernel's
// BTF.
// 
// Your kernel also needs CONFIG_BPF_LSM=y and "bpf" present in
// /sys/kernel/security/lsm (add lsm=...,bpf to the kernel cmdline if not).
// If either is missing, loader.go detects the attach failure and falls
// back to tracepoint-only (detect + kill) mode automatically. 


#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>


// Shared event struct pushed to userspace via the ring buffer, Reused for
// every hook

#define EVT_EXEC          1  // process executed (tracepoint, after the fact)  
#define EVT_EXEC_BLOCKED  2  // process exec blocked pre-flight by the LSM hook 
#define EVT_CONNECT       3  // outbound connect() 
#define EVT_OPEN_SENSITIVE 4 // openat(), openat2() on a sensitive path 
#define EVT_PTRACE        5  // ptrace() attach/injection attempt 
#define EVT_SETUID        6  // setuid()/privilege change 
#define EVT_MODULE_LOAD   7  // init_module()/finit_module() 
#define EVT_MEMFD         8  // memfd_create(), fileless-exec precursor 

struct kguard_event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 ppid;     
    __u32 uid;
    __u32 gid;
    __u64 cgroup_id;
    __u32 event_type;
    __s32 ret;       // syscall/LSM decision: 0 = allowed, negative = denied 
    char comm[16];
    char filename[64];
    char argv0[64];  // first argv entry
    
    __u32 daddr;     // network byte order dest addr, 0 if not IPv4/unset 
    __u16 dport;     //dest port 
    __u16 family;
};

struct kguard_event *unused __attribute__((unused));

// Maps
struct {
    __uint(type, 27); // RINGBUF 
    __uint(max_entries, 1 << 18);
} rb SEC(".maps");

// Populated from userspace (config.go) with binaries/paths that should be
// hard-blocked at exec time by the LSM hook, Key = null-terminated path
// value = 1 (block). 
struct {
    __uint(type, 1); // BPF_MAP_TYPE_HASH 
    __uint(max_entries, 1024);
    __type(key, char[64]);
    __type(value, __u8);
} blocked_paths SEC(".maps");

// userspace sets this to 1 to disable ALL LSM enforcement
// instantly (example if it's misbehaving or false-positiving in production)
// without needing to detach/reload programs, Detect-only mode still runs. 
struct {
    __uint(type, 2); // BPF_MAP_TYPE_ARRAY 
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} enforcement_enabled SEC(".maps");

// Helpers

static __always_inline void fill_common(struct kguard_event *e, __u32 evt_type) {
    __u64 id = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();
    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid = (__u32)(id >> 32);
    e->uid = (__u32)uid_gid;
    e->gid = (__u32)(uid_gid >> 32);
    e->cgroup_id = bpf_get_current_cgroup_id();
    e->event_type = evt_type;
    e->ret = 0;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent;
    bpf_probe_read_kernel(&parent, sizeof(parent), &task->real_parent);
    pid_t ppid;
    bpf_probe_read_kernel(&ppid, sizeof(ppid), &parent->tgid);
    e->ppid = (__u32)ppid;
}

// execve tracepoint sensor
// struct format and var types were gotten from /sys/kernel/tracing/events/ for each tracepoint

struct exec_scratch {
    char argv0[64];
};

struct {
    __uint(type,9);
    __uint(max_entries,4096);
    __type(key, __u64);
    __type(value, struct exec_scratch);

}   exec_scratch_map SEC(".maps");

struct syscall_execve_args {
    unsigned long long common_tp_fields;
    __s32 syscall_nr;
    __u32 __pad;                
    const char *filename;       
    const char *const *argv;
    const char *const *envp;
};

SEC("tracepoint/syscalls/sys_enter_execve")
int tp_execve(struct syscall_execve_args *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    struct exec_scratch scratch = {};

    const char *argv0_ptr = NULL;
    bpf_probe_read_user(&argv0_ptr , sizeof(argv0_ptr), &ctx->argv[0]);
    if (argv0_ptr)
        bpf_probe_read_user_str(&scratch.argv0, sizeof(scratch.argv0), argv0_ptr);

    bpf_map_update_elem(&exec_scratch_map, &pid_tgid, &scratch, BPF_ANY);
    return 0;
}

// sched process sensor

struct sched_process_exec_args {
    unsigned short common_type;          
    unsigned char  common_flags;         
    unsigned char  common_preempt_count; 
    int            common_pid;           
    __u32          filename_loc;         
    pid_t          pid;                  
    pid_t          old_pid;              
};

SEC("tracepoint/sched/sched_process_exec")
int tp_schedexec (struct sched_process_exec_args *ctx) {
    struct kguard_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    fill_common(e, EVT_EXEC);

    __u16 offset = ctx->filename_loc & 0xffff;
    const char *fn = (const char *)ctx + offset;

    bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename), fn);

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct exec_scratch *scratch = bpf_map_lookup_elem(&exec_scratch_map, &pid_tgid);

    if (scratch) {
        __builtin_memcpy(e->argv0, scratch->argv0, sizeof(e->argv0));
        bpf_map_delete_elem(&exec_scratch_map, &pid_tgid); // claimed, clean up now 
    }

    bpf_ringbuf_submit(e, 0);
    return 0;



}


// LSM enforcement hook

SEC("lsm/bprm_check_security")
int BPF_PROG(lsm_bprm_check, struct linux_binprm *bprm, int ret) {
    if (ret != 0) {
        // Already denied, don't override and return
        return ret;
    }

    __u32 zero = 0;
    __u8 *enabled = bpf_map_lookup_elem(&enforcement_enabled, &zero);
    if (!enabled || *enabled == 0) {
        return 0;
    }

    char path[64] = {0};
    //  bprm->filename is a kernel-space pointer at this point (not user memory). 
    bpf_probe_read_kernel_str(&path, sizeof(path), bprm->filename);

    __u8 *blocked = bpf_map_lookup_elem(&blocked_paths, path);
    if (blocked && *blocked == 1) {
        struct kguard_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
        if (e) {
            fill_common(e, EVT_EXEC_BLOCKED);
            __builtin_memcpy(e->filename, path, sizeof(path));
            e->ret = -1; 
            bpf_ringbuf_submit(e, 0);
        }
        return -1; //kernel aborts the exec 
    }

    return 0;
}

// connect() sensor
struct sockaddr_in_min {
    __u16 sin_family;
    __u16 sin_port;   
    __u32 sin_addr;  
};

struct syscall_connect_args {
    unsigned long long common_tp_fields;
    __s32 syscall_nr;                   
    __u32 __pad;                          
    __u64 fd;                             
    struct sockaddr_in_min *uservaddr;    
    __u64 addrlen;  
};

SEC("tracepoint/syscalls/sys_enter_connect")
int tp_connect(struct syscall_connect_args *ctx) {
    struct sockaddr_in_min sa = {0};
    if (bpf_probe_read_user(&sa, sizeof(sa), ctx->uservaddr) < 0) {
        return 0;
    }

    struct kguard_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    fill_common(e, EVT_CONNECT);
    e->family = sa.sin_family;
    if (sa.sin_family == 2 ) {
        e->daddr = sa.sin_addr;
        // sin_port is network byte order in big-endian, convert to host order
        // for readability on little-endian targets. 
        e->dport = ((sa.sin_port & 0xff) << 8) | ((sa.sin_port >> 8) & 0xff);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}


// openat() sensor

struct syscall_openat_args {
    unsigned long long common_tp_fields;
    int syscall_nr;
    long dfd; // evert argument after syscall_nr
              // occupies a full 8 bytes on the wire regardless of its
              // true C type (int, short, etc). Declaring these as
              // long instead of int/short isn't cosmetic
    const char *filename;
    int flags;
    unsigned short mode;
};

static __always_inline int has_sensitive_prefix(const char *path) {
    char buf[16] = {0};
    __builtin_memcpy(buf, path, 12);

    if (__builtin_memcmp(buf, "/etc/passwd", 11) == 0) return 1;
    if (__builtin_memcmp(buf, "/etc/shadow", 11) == 0) return 1;
    if (__builtin_memcmp(buf, "/etc/sudo", 9) == 0) return 1;
    if (__builtin_memcmp(buf, "/root/.ssh", 10) == 0) return 1;
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int tp_openat(struct syscall_openat_args *ctx) {
    char path[64] = {0};
    int n = bpf_probe_read_user_str(&path, sizeof(path), ctx->filename);
    if (n <= 0) return 0;

    if (!has_sensitive_prefix(path)) {
        return 0;
    }

    struct kguard_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;
    fill_common(e, EVT_OPEN_SENSITIVE);
    __builtin_memcpy(e->filename, path, sizeof(path));
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// openat2() sensor

struct syscall_openat2_args {
    unsigned long long common_tp_fields;
    int syscall_nr;
    long dfd;
    const char *filename;
    void *how;      // pointer to struct open_how 
    unsigned long usize;
};

SEC("tracepoint/syscalls/sys_enter_openat2")
int tp_openat2(struct syscall_openat2_args *ctx) {
    char path[64] = {0};
    int n = bpf_probe_read_user_str(&path, sizeof(path), ctx->filename);
    if (n <= 0) return 0;

    if (!has_sensitive_prefix(path)) {
        return 0;
    }

    struct kguard_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;
    fill_common(e, EVT_OPEN_SENSITIVE);
    __builtin_memcpy(e->filename, path, sizeof(path));
    bpf_ringbuf_submit(e, 0);
    return 0;
}

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
    struct kguard_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;
    fill_common(e, EVT_PTRACE);
    e->ret = (int)ctx->request; 
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
    struct kguard_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;
    fill_common(e, EVT_SETUID);
    e->ret = (int)ctx->uid; // target uid being requested 
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
    struct kguard_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;
    fill_common(e, EVT_MODULE_LOAD);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// memfd_create() sensor

struct syscall_memfd_create_args {
    unsigned long long common_tp_fields;
    int syscall_nr;
    const char *uname;
    unsigned int flags;
};

SEC("tracepoint/syscalls/sys_enter_memfd_create")
int tp_memfd_create(struct syscall_memfd_create_args *ctx) {
    struct kguard_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;
    fill_common(e, EVT_MEMFD);
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), ctx->uname);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";