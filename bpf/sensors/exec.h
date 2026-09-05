#ifndef __KGUARD_SENSORS_EXEC_H
#define __KGUARD_SENSORS_EXEC_H

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "../maps.h"
#include "../types.h"
#include "../helpers.h"

// Helpers

// Helper to handle lineage updates when a suspicious binary is executed
static __always_inline void handle_suspicious_lineage(struct exec_event *e, struct scratch_buffer *scratch) {
    struct process_lineage *lin = bpf_map_lookup_elem(&lineage_map, &e->hdr.pid);
    struct process_lineage *updated_lin = &scratch->lin;
    __builtin_memset(updated_lin, 0, sizeof(*updated_lin));

    if (lin) {
        *updated_lin = *lin;
    } else {
        updated_lin->parent_pid = e->hdr.ppid;
    }

    updated_lin->suspicious_ancestor = 1;
    __builtin_memcpy(updated_lin->ancestor_filename, e->filename, sizeof(updated_lin->ancestor_filename));
    bpf_map_update_elem(&lineage_map, &e->hdr.pid, updated_lin, BPF_ANY);

    e->hdr.ancestor_suspicious = 1;
    __builtin_memcpy(e->hdr.ancestor_filename, e->filename, sizeof(e->filename));
}

// Sensor


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
        child_lin->expected_uid = parent_lin->expected_uid;
        child_lin->setuid_allowed = parent_lin->setuid_allowed;
        __builtin_memcpy(child_lin->ancestor_filename, parent_lin->ancestor_filename, sizeof(child_lin->ancestor_filename));
    } else {
        child_lin->expected_uid = (__u32)bpf_get_current_uid_gid();
        child_lin->setuid_allowed = 0;
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

    char *filename = scratch->primary;
    __builtin_memset(filename, 0, PATH_BUF_SIZE);

    __u16 offset = ctx->filename_loc & 0xffff;
    const char *fn = (const char *)ctx + offset;
    __u8 truncated = 0;

    if (read_path(filename, PATH_BUF_SIZE, fn, 0, &truncated) <= 0) {
        return 0; // Abort if path reading failed
    }

    struct exec_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    fill_common(&e->hdr, EVT_EXEC);
    __builtin_memcpy(e->filename, filename, sizeof(e->filename));
    e->path_truncated = truncated;

    // Populate command-line arguments safely from memory layout
    read_process_args(e);

    // Track lineage if the path matches suspicious criteria
    if (path_in_map(e->filename, &suspicious_paths)) {
        handle_suspicious_lineage(e, scratch);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}



#endif