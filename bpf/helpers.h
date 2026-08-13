#ifndef KGUARD_HELPERS_H
#define KGUARD_HELPERS_H

#include "types.h"
#include "maps.h"


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

#endif