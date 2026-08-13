#ifndef __KGUARD_SENSORS_EXEC_H
#define __KGUARD_SENSORS_EXEC_H

#include "../maps.h"
#include "../types.h"
#include "../helpers.h"


struct syscall_execve_args {
    unsigned long long common_tp_fields;
    __s32 syscall_nr;
    __u32 __pad;                
    const char *filename;       
    const char *const *argv;
    const char *const *envp;
};

// execve tracepoint sensor
// struct format and var types were gotten from /sys/kernel/tracing/events/ for each tracepoint

SEC("tracepoint/syscalls/sys_enter_execve")
int tp_execve(struct syscall_execve_args *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    struct exec_scratch scratch = {};

    const char *argv0_ptr = 0;
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

#endif