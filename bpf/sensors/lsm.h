#ifndef __KGUARD_SENSORS_LSM_H
#define __KGUARD_SENSORS_LSM_H

#ifndef TMPFS_MAGIC
#define TMPFS_MAGIC 0x01021994
#endif

#ifndef PTRACE_MODE_READ
#define PTRACE_MODE_READ 0x01
#endif

#include "../types.h"
#include "../maps.h"
#include "../helpers.h"


// HELPERS

static __always_inline void emit_kmod_event(__u32 type, __u32 load_type) {
    struct kmod_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        return;
    }

    bpf_printk("kguard: in emit kmod before fill commong, id=\n");

    fill_common(&e->hdr, type);

    bpf_printk("kguard: in emit kmod after fill commong, id=\n");
    
    // Capture the process attempting the load
    bpf_get_current_comm(&e->hdr.comm, sizeof(e->hdr.comm));
    e->load_type = load_type;

    bpf_printk("kguard: event is being submitted now type is %lu\n", load_type);

    bpf_ringbuf_submit(e, 0);
}

static __always_inline int handle_kmod_check(int id) {
    bpf_printk("kguard: handle_kmod_check called, id=%d\n", id);
    if (id != 2) {
        return 0; 
    }

    __u64 cgroup_id = bpf_get_current_cgroup_id();
    __u8 *is_container = bpf_map_lookup_elem(&container_cgroups, &cgroup_id);

    bpf_printk("kguard: cgroup check -> cgroup_id=%llu, found_in_map=%d\n", 
               cgroup_id, is_container ? *is_container : 0);
    
    if (!is_container) {
        return 0; 
    }

    __u32 zero = 0;
    __u8 *enabled = bpf_map_lookup_elem(&kmod_enforcement_enabled, &zero);

    bpf_printk("kguard: enforcement check -> map_ptr=%p, enabled_val=%d\n", 
               enabled, enabled ? *enabled : 0);

    if (!enabled || *enabled == 0) {
        return 0;
    }

    bpf_printk("kguard: BLOCKING kernel module load for container cgroup=%llu!\n", cgroup_id);

    emit_kmod_event(EVENT_KMOD_BLOCKED, 2);

    return -1;
}

static __always_inline void emit_ptrace_event(struct task_struct *child, unsigned int mode, const char *caller_comm, const char *target_comm) {
    struct ptrace_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        return;
    }

    fill_common(&e->hdr, EVENT_PTRACE_BLOCKED);

    e->target_pid = BPF_CORE_READ(child, pid);
    e->mode = mode;

    __builtin_memcpy(e->caller_comm, caller_comm, sizeof(e->caller_comm));
    __builtin_memcpy(e->target_comm, target_comm, sizeof(e->target_comm));

    bpf_ringbuf_submit(e, 0);
}

static __always_inline void emit_exec_event(__u32 type, char *path, __u8 truncated, __u8 is_fileless) {
    struct exec_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return;

    fill_common(&e->hdr, type);
    read_process_args(e);
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

SEC("lsm/ptrace_access_check")
int BPF_PROG(lsm_ptrace_access_check, struct task_struct *child, unsigned int mode) {
    __u32 zero = 0;
    __u8 *enabled = bpf_map_lookup_elem(&ptrace_enforcement_enabled, &zero);
    if (!enabled || *enabled == 0) {
        return 0;
    }

    if (mode & PTRACE_MODE_READ) {
        return 0;
    }

    struct file_id caller_id;
    if (get_current_exe_id(&caller_id) == 0) {
        __u8 *allowed = bpf_map_lookup_elem(&allowed_ptrace_attaches, &caller_id);
        if (allowed && *allowed == 1) {
            return 0;
        }
    }

    char caller_comm[64];
    bpf_get_current_comm(&caller_comm, sizeof(caller_comm));

    char target_comm[64];
    BPF_CORE_READ_STR_INTO(&target_comm, child, comm);

    emit_ptrace_event(child, mode, caller_comm, target_comm);
    return -1;
}

SEC("lsm/kernel_read_file")
int BPF_PROG(kguard_kernel_read_file, struct file *file, enum kernel_read_file_id id, bool contents) {
    return handle_kmod_check((int)id);
}

SEC("lsm/kernel_load_data")
int BPF_PROG(kguard_kernel_load_data, enum kernel_load_data_id id, bool contents) {
    return handle_kmod_check((int)id);
}


#endif