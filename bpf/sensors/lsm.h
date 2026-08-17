#ifndef __KGUARD_SENSORS_LSM_H
#define __KGUARD_SENSORS_LSM_H

#ifndef TMPFS_MAGIC
#define TMPFS_MAGIC 0x01021994
#endif

#include "../types.h"
#include "../maps.h"
#include "../helpers.h"


// HELPERS

static __always_inline void emit_exec_event(__u32 type, char *path, __u8 truncated, __u8 is_fileless) {
    struct exec_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return;

    fill_common(&e->hdr, type);
    __builtin_memcpy(e->filename, path, PATH_BUF_SIZE);
    e->isFileless = is_fileless;
    e->path_truncated = truncated;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct exec_scratch *scratch2 = bpf_map_lookup_elem(&exec_scratch_map, &pid_tgid);
    if (scratch2) {
        __builtin_memcpy(e->args, scratch2->args, sizeof(e->args));
        bpf_map_delete_elem(&exec_scratch_map, &pid_tgid);
    }

    bpf_ringbuf_submit(e, 0);
}

static __always_inline int check_fileless(struct linux_binprm *bprm, char *path, __u8 truncated) {
    struct file *file = BPF_CORE_READ(bprm, file);
    if (!file) return 0;

    struct inode *inode = BPF_CORE_READ(file, f_inode);
    if (!inode) return 0;

    unsigned int nlink = BPF_CORE_READ(inode, i_nlink);
    unsigned long s_magic = BPF_CORE_READ(file, f_path.dentry, d_sb, s_magic);

    // memfd / fileless payloads are unlinked and live on tmpfs
    if (nlink == 0 && s_magic == TMPFS_MAGIC) {
        emit_exec_event(EVT_EXEC, path, truncated, 1);
        return 1;
    }

    return 0;
}

// LSM HOOk

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
    __u8 truncated = 0;

    // we use bpf_d_path to solve the problem of an attcker using .././/./.. in paths for example
    if (get_safe_path(&bprm->file->f_path, path, PATH_BUF_SIZE, &truncated) < 0) {
        return 0;
    }

    if (check_fileless(bprm, path, truncated)) {
        return -1;
    }

    __u8 *blocked = bpf_map_lookup_elem(&blocked_paths, path);

    if (blocked && *blocked == 1) {
        emit_exec_event(EVT_EXEC_BLOCKED, path, truncated, 0);
        return -1;
    }

    return 0;
}



#endif