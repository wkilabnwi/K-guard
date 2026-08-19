#ifndef KGUARD_HELPERS_H
#define KGUARD_HELPERS_H

#include "types.h"
#include "maps.h"
#include <bpf/bpf_core_read.h>


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

static __always_inline void fill_common(struct event_hdr *e, __u32 evt_type) {
    // We zero out the memory before we used it
    // cause someone decided giving back a pointer 
    // without zeroing the memory is a good idea !
    __builtin_memset(e, 0, sizeof(*e));

    __u64 id = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();
    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid = (__u32)(id >> 32);
    e->uid = (__u32)uid_gid;
    e->gid = (__u32)(uid_gid >> 32);
    e->cgroup_id = bpf_get_current_cgroup_id();
    e->event_type = evt_type;
    
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

// This function is the bane of my existence
// Can an eBPF contributor please fix bpf_d_path ?
static __always_inline long get_safe_path(struct path *path, char *buf, __u32 buf_size, __u8 *truncated) {
    __builtin_memset(buf, 0, buf_size);

    long ret = bpf_d_path(path, buf, buf_size);
    if (ret < 0) {
        return ret;
    }

    *truncated = (ret >= buf_size) ? 1 : 0;
    __u32 pathlen = (ret > buf_size) ? buf_size : (__u32)ret;

    __u32 word_start = (pathlen + 7) & ~7U;
    if (word_start > buf_size)
        word_start = buf_size;

    #pragma unroll
    for (__u32 i = 0; i < 8; i++) {
        __u32 idx = pathlen + i;
        if (idx < word_start && idx < buf_size)
            buf[idx] = 0;
    }

    __u64 *buf64 = (__u64 *)buf;
    #pragma unroll
    for (__u32 i = 0; i < (PATH_BUF_SIZE / 8); i++) {
        if ((i * 8) >= word_start)
            buf64[i] = 0;
    }

    return ret;
}

static __always_inline void read_process_args(struct exec_event *e) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct mm_struct *mm = BPF_CORE_READ(task, mm);
    if (!mm) return;

    unsigned long arg_start = BPF_CORE_READ(mm, arg_start);
    unsigned long arg_end = BPF_CORE_READ(mm, arg_end);
    unsigned long len = arg_end - arg_start;

    if (len == 0) return;

    if (len > sizeof(e->args) - 2) {
        len = sizeof(e->args) - 2;
    }

    if (bpf_probe_read_user(e->args, len, (const void *)arg_start) == 0) {
        e->args[len] = 0x00;
        e->args[len + 1] = 0x00;
    }
}
#endif