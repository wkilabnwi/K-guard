// +build ignore

// 
// Two classes of program live here:
// 1 - Tracepoint-based SENSORS (tp_execve, sched_process_exec, tp_connect, tp_openat, tp_openat2, tp_ptrace,
//  tp_setuid, tp_init_module, tp_memfd_create). These only observe; they
//  cannot block anything. They fire on syscall entry and are cheap and
//  portable.
// 
// 2 - An LSM-based ENFORCER (lsm_bprm_check): it runs *before* the kernel c
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
#define EVT_SENSITIVE_WRITE 9 // reserved for write events

#define O_ACCMODE_MASK 0x0003
#define O_WRONLY_ 0x0001
#define O_RDWR_   0x0002

#define PATH_BUF_SIZE 256

struct kguard_event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 ppid;     
    __u32 uid;
    __u32 gid;
    __u64 cgroup_id;
    __u32 event_type;
    __s32 ret;       
    char comm[16];
    char filename[PATH_BUF_SIZE];
    char argv0[64];  

    // connect specific args
    __u32 daddr;     
    __u8  daddr6[16];
    __u16 dport;     
    __u16 family;    
    char  unix_path[108]; 

    // openat specific args
    __u32 write_fd;
    __u64 write_count;
    char  write_buf[64]; // Preview payload

    // lineage fields
    __u8  ancestor_suspicious;
    char  ancestor_filename[PATH_BUF_SIZE];

    // saved for truncated paths
    __u8  path_truncated; 
};

struct kguard_event *unused __attribute__((unused));

// Process lineage state carried per PID
struct process_lineage {
    __u32 parent_pid;
    __u8  suspicious_ancestor;
    char  ancestor_filename[PATH_BUF_SIZE];
};

struct scratch_buffer {
    char primary[PATH_BUF_SIZE]; // caller's own path buffer (tp_openat/openat2, lsm_bprm_check)
    char walk[PATH_BUF_SIZE];   // path_in_map's private working copy for the prefix walk
    struct process_lineage lin;  
};

// Maps
struct {
    __uint(type, 27); // RINGBUF 
    __uint(max_entries, 1 << 18);
} rb SEC(".maps");

// Populated from userspace (config.go) with binaries/paths that should be
// hard-blocked at exec time by the LSM hook, Key = null-terminated path
// value = 1 (block)
struct {
    __uint(type, 1); // BPF_MAP_TYPE_HASH 
    __uint(max_entries, 1024);
    __type(key, char[PATH_BUF_SIZE]);
    __type(value, __u8);
} blocked_paths SEC(".maps");

// userspace sets this to 1 to disable all LSM enforcement
// instantly (example if it's misbehaving or false-positiving in production)
// without needing to detach/reload programs, Detect-only mode still runs. 
struct {
    __uint(type, 2); // BPF_MAP_TYPE_ARRAY 
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} enforcement_enabled SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, char[PATH_BUF_SIZE]);
    __type(value, __u8);
} suspicious_paths SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, char[PATH_BUF_SIZE]);
    __type(value, __u8);
} sensitive_write_paths SEC(".maps");

// LRU_HASH map for automatically evicted process state
struct {
    __uint(type, 9); // BPF_MAP_TYPE_LRU_HASH
    __uint(max_entries, 16384);
    __type(key, __u32);
    __type(value, struct process_lineage);
} lineage_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct scratch_buffer);
} scratch_map SEC(".maps");

// Helpers

static __always_inline int path_in_map(const char *path, void *map) {
    __u32 zero = 0;
    struct scratch_buffer *scratch = bpf_map_lookup_elem(&scratch_map, &zero);
    if (!scratch) return 0;
    char *full = scratch->walk;

    __builtin_memset(full, 0, PATH_BUF_SIZE);
    bpf_probe_read_kernel_str(full, PATH_BUF_SIZE, path);

    __u8 *found = bpf_map_lookup_elem(map, full);
    if (found && *found == 1) return 1;

    for (int len = (PATH_BUF_SIZE - 2); len >= 0; len--) {
        if (full[len] == '/') {
            full[len + 1] = '\0';
            found = bpf_map_lookup_elem(map, full);
            if (found && *found == 1) return 1;
        }
        full[len + 1] = '\0';
    }
    return 0;
}

static __always_inline long read_path(char *dst, __u32 dst_size, const void *src,
                                       int from_user, __u8 *truncated) {
    long n = from_user
        ? bpf_probe_read_user_str(dst, dst_size, src)
        : bpf_probe_read_kernel_str(dst, dst_size, src);

        if (n <= 0) {
        *truncated = 0;
        return n;
    }
    *truncated = (n == (long)dst_size) ? 1 : 0;
    return n;
}

static __always_inline void fill_common(struct kguard_event *e, __u32 evt_type) {
    // We zero out the memory before using it
    __builtin_memset(e, 0, sizeof(*e));

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

    // Looking up process lineage state
    struct process_lineage *lin = bpf_map_lookup_elem(&lineage_map, &e->pid);
    if (lin) {
        e->ancestor_suspicious = lin->suspicious_ancestor;
        __builtin_memcpy(e->ancestor_filename, lin->ancestor_filename, sizeof(e->ancestor_filename));
    } else {
        e->ancestor_suspicious = 0;
        __builtin_memset(e->ancestor_filename, 0, sizeof(e->ancestor_filename));
    }
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

// sched fork sensor

struct sched_process_fork_args {
    unsigned short common_type;          
    unsigned char  common_flags;         
    unsigned char  common_preempt_count; 
    int            common_pid;   
    char           parent_comm[16];
    pid_t          parent_pid;   
    char           child_comm[16];    
    pid_t          child_pid;  
};

SEC("tracepoint/sched/sched_process_fork")
int tp_schedfork(struct sched_process_fork_args *ctx) {
    __u32 zero = 0;
    struct scratch_buffer *scratch = bpf_map_lookup_elem(&scratch_map, &zero);
    if (!scratch) return 0;

    __u32 ppid = (__u32)ctx->parent_pid;
    __u32 cpid = (__u32)ctx->child_pid;

    struct process_lineage *child_lin = &scratch->lin; // Offloaded to map memory
    __builtin_memset(child_lin, 0, sizeof(*child_lin));
    child_lin->parent_pid = ppid;

    struct process_lineage *parent_lin = bpf_map_lookup_elem(&lineage_map, &ppid);
    if (parent_lin) {
        child_lin->suspicious_ancestor = parent_lin->suspicious_ancestor;
        __builtin_memcpy(child_lin->ancestor_filename, parent_lin->ancestor_filename, sizeof(child_lin->ancestor_filename));
    }

    bpf_map_update_elem(&lineage_map, &cpid, child_lin, BPF_ANY);
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
int tp_schedexec(struct sched_process_exec_args *ctx) {
    __u32 zero = 0;
    struct scratch_buffer *scratch = bpf_map_lookup_elem(&scratch_map, &zero);
    if (!scratch) return 0;

    char *filename = scratch->primary; // Offloaded to map memory
    __builtin_memset(filename, 0, PATH_BUF_SIZE);

    __u16 offset = ctx->filename_loc & 0xffff;
    const char *fn = (const char *)ctx + offset;
    __u8 truncated = 0;

    long n = read_path(filename, PATH_BUF_SIZE, fn, 0, &truncated);
    if (n <= 0) {
        return 0; // Abort if reading path failed
    }

    struct kguard_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    fill_common(e, EVT_EXEC);

    __builtin_memcpy(e->filename, filename, sizeof(e->filename));
    e->path_truncated = truncated;

    // We actually populate the argv0, if nothing is there it got
    // zeroed out by fill_common so we wouldn't leak stale data
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct exec_scratch *scratch2 = bpf_map_lookup_elem(&exec_scratch_map, &pid_tgid);
    if (scratch2) {
        __builtin_memcpy(e->argv0, scratch2->argv0, sizeof(e->argv0));
        bpf_map_delete_elem(&exec_scratch_map, &pid_tgid);
    }

    if (path_in_map(e->filename, &suspicious_paths)) {
        struct process_lineage *lin = bpf_map_lookup_elem(&lineage_map, &e->pid);
        struct process_lineage *updated_lin = &scratch->lin; // Offloaded to map memory
        __builtin_memset(updated_lin, 0, sizeof(*updated_lin));

        if (lin) {
            *updated_lin = *lin;
        } else {
            updated_lin->parent_pid = e->ppid;
        }

        updated_lin->suspicious_ancestor = 1;
        __builtin_memcpy(updated_lin->ancestor_filename, e->filename, sizeof(updated_lin->ancestor_filename));
        bpf_map_update_elem(&lineage_map, &e->pid, updated_lin, BPF_ANY);

        e->ancestor_suspicious = 1;
        __builtin_memcpy(e->ancestor_filename, e->filename, sizeof(e->ancestor_filename));
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}


// LSM enforcement hook

SEC("lsm/bprm_check_security")
int BPF_PROG(lsm_bprm_check, struct linux_binprm *bprm) {

    __u32 zero = 0;
    __u8 *enabled = bpf_map_lookup_elem(&enforcement_enabled, &zero);
    if (!enabled || *enabled == 0) {
        return 0;
    }

    struct scratch_buffer *scratch = bpf_map_lookup_elem(&scratch_map, &zero);
    if (!scratch) return 0;

    char *path = scratch->primary; // Offloaded to map memory
    __builtin_memset(path, 0, PATH_BUF_SIZE);

    // we use bpf_d_path to solve the problem of an attcker using .././/./.. in paths for example
    long ret = bpf_d_path(&bprm->file->f_path, path, PATH_BUF_SIZE);
    if (ret < 0) {
        return 0; // Fail-open on resolution failure to avoid locking up host
    }

    // bpf_d_path returns total path string length including null byte.
    // If length >= PATH_BUF_SIZE, the buffer reached capacity and was truncated
    __u8 truncated = (ret >= PATH_BUF_SIZE) ? 1 : 0;

    __u8 *blocked = bpf_map_lookup_elem(&blocked_paths, path);
    if (blocked && *blocked == 1) {
        struct kguard_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
        if (e) {
            fill_common(e, EVT_EXEC_BLOCKED);
            __builtin_memcpy(e->filename, path, PATH_BUF_SIZE);
            e->ret = -1; 
            e->path_truncated = truncated;

            __u64 pid_tgid = bpf_get_current_pid_tgid();
            struct exec_scratch *scratch2 = bpf_map_lookup_elem(&exec_scratch_map, &pid_tgid);
            if (scratch2) {
                __builtin_memcpy(e->argv0, scratch2->argv0, sizeof(e->argv0));
                bpf_map_delete_elem(&exec_scratch_map, &pid_tgid);
            }

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
struct sockaddr_in6_min {
    __u16 sin6_family;
    __u16 sin6_port;
    __u32 sin6_flowinfo;
    __u8  sin6_addr[16];
    __u32 sin6_scope_id;
};
 
struct sockaddr_un_min {
    __u16 sun_family;
    char  sun_path[108]; // matches real sockaddr_un's sun_path length
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
    // Every sockaddr_* variant starts with the same 2-byte family field,
    // so peek that first to know which real layout to read next instead
    // of assuming AF_INET
    __u16 family = 0;
    if (bpf_probe_read_user(&family, sizeof(family), ctx->uservaddr) < 0) {
        return 0;
    }
 
    struct kguard_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;
 
    fill_common(e, EVT_CONNECT);
    e->family = family;
    // Zero every family-specific field up front, the ring buffer doesn't
    // zero reused memory for us
    e->daddr = 0;
    __builtin_memset(e->daddr6, 0, sizeof(e->daddr6));
    e->dport = 0;
    __builtin_memset(e->unix_path, 0, sizeof(e->unix_path));
 
    if (family == 2) { 
        struct sockaddr_in_min sa = {0};
        if (bpf_probe_read_user(&sa, sizeof(sa), ctx->uservaddr) == 0) {
            e->daddr = sa.sin_addr;
            // sin_port is network byte order so we convert it
            e->dport = ((sa.sin_port & 0xff) << 8) | ((sa.sin_port >> 8) & 0xff);
        }
    } else if (family == 10) {
        struct sockaddr_in6_min sa6 = {0};
        if (bpf_probe_read_user(&sa6, sizeof(sa6), (void *)ctx->uservaddr) == 0) {
            __builtin_memcpy(e->daddr6, sa6.sin6_addr, sizeof(e->daddr6));
            e->dport = ((sa6.sin6_port & 0xff) << 8) | ((sa6.sin6_port >> 8) & 0xff);
        }
    } else if (family == 1) { // AF_UNIX
        struct sockaddr_un_min sun = {0};
        // addrlen for AF_UNIX is frequently shorter than the size of sun
        bpf_probe_read_user(&sun, sizeof(sun), (void *)ctx->uservaddr);
        __builtin_memcpy(e->unix_path, sun.sun_path, sizeof(e->unix_path));
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

SEC("tracepoint/syscalls/sys_enter_openat")
int tp_openat(struct syscall_openat_args *ctx) {
    // This change was implemented to mitigate the problem of us 
    // exceeding the BPF stack limit
    __u32 zero = 0;
    struct scratch_buffer *scratch = bpf_map_lookup_elem(&scratch_map, &zero);
    if (!scratch) return 0;
    char *path = scratch->primary;

    __u8 truncated = 0;
    long n = read_path(path, PATH_BUF_SIZE, ctx->filename, 1, &truncated);
    if (n <= 0) return 0;

    int write_intent = (ctx->flags & O_ACCMODE_MASK) == O_WRONLY_ ||
                        (ctx->flags & O_ACCMODE_MASK) == O_RDWR_;

    if (write_intent && path_in_map(path, &sensitive_write_paths)) {
        struct kguard_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
        if (e) {
            fill_common(e, EVT_SENSITIVE_WRITE);
            __builtin_memcpy(e->filename, path, PATH_BUF_SIZE);
            e->ret = ctx->flags; // stash raw flags for userspace to decode
            e->path_truncated = truncated;
            bpf_ringbuf_submit(e, 0);
        }
    }

    if (!path_in_map(path, &suspicious_paths)) {
        return 0;
    }
    struct kguard_event *e2 = bpf_ringbuf_reserve(&rb, sizeof(*e2), 0);
    if (!e2) return 0;
    fill_common(e2, EVT_OPEN_SENSITIVE);
    __builtin_memcpy(e2->filename, path, PATH_BUF_SIZE);
    e2->path_truncated = truncated;
    bpf_ringbuf_submit(e2, 0);
    return 0;
}

// openat2() sensor

struct open_how_min {
    __u64 flags;
    __u64 mode;
    __u64 resolve;
};


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
    __u32 zero = 0;
    struct scratch_buffer *scratch = bpf_map_lookup_elem(&scratch_map, &zero);
    if (!scratch) return 0;
    char *path = scratch->primary;

    __u8 truncated = 0;
    long n = read_path(path, PATH_BUF_SIZE, ctx->filename, 1, &truncated);
    if (n <= 0) return 0;

    struct open_how_min how = {0};
    __u64 flags = 0;
    if (bpf_probe_read_user(&how, sizeof(how), ctx->how) == 0) {
        flags = how.flags;
    }

    int write_intent = (flags & O_ACCMODE_MASK) == O_WRONLY_ ||
                        (flags & O_ACCMODE_MASK) == O_RDWR_;

    if (write_intent && path_in_map(path, &sensitive_write_paths)) {
        struct kguard_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
        if (e) {
            fill_common(e, EVT_SENSITIVE_WRITE);
            __builtin_memcpy(e->filename, path, PATH_BUF_SIZE);
            e->ret = (__s32)flags;
            e->path_truncated = truncated;
            bpf_ringbuf_submit(e, 0);
        }
    }

    if (!path_in_map(path, &suspicious_paths)) {
        return 0;
    }
    struct kguard_event *e2 = bpf_ringbuf_reserve(&rb, sizeof(*e2), 0);
    if (!e2) return 0;
    fill_common(e2, EVT_OPEN_SENSITIVE);
    __builtin_memcpy(e2->filename, path, PATH_BUF_SIZE);
    e2->path_truncated = truncated;
    bpf_ringbuf_submit(e2, 0);
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


struct syscall_write_args {
    unsigned long long common_tp_fields;
    int __syscall_nr;
    int __pad;
    unsigned long fd;
    const char *buf;
    unsigned long count;
};

char _license[] SEC("license") = "GPL";