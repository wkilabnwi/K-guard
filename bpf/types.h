#ifndef __KGUARD_TYPES_H
#define __KGUARD_TYPES_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

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

struct kguard_event *unused_event __attribute__((unused));

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

struct exec_scratch {
    char argv0[64];
};

#endif