#ifndef __KGUARD_SENSORS_FILE_H
#define __KGUARD_SENSORS_FILE_H

#include "../types.h"
#include "../helpers.h"

// HELPERS

static __always_inline void emit_sensitive_write_event(char *path, __u8 truncated) {
    struct open_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return;

    fill_common(&e->hdr, EVT_BLOCKED_WRITE);
    __builtin_memcpy(e->filename, path, PATH_BUF_SIZE);
    e->path_truncated = truncated;
    e->isFileless = 0;

    bpf_ringbuf_submit(e, 0);
}

// Shared helper to evaluate and submit open/write security events
static __always_inline void handle_open_checks(char *path, __u8 truncated, int flags) {
    int write_intent = (flags & O_ACCMODE_MASK) == O_WRONLY_ ||
                        (flags & O_ACCMODE_MASK) == O_RDWR_;

    // Check for sensitive write operations
    if (write_intent && path_in_map(path, &sensitive_write_paths)) {
        struct open_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
        if (e) {
            fill_common(&e->hdr, EVT_SENSITIVE_WRITE);
            __builtin_memcpy(e->filename, path, PATH_BUF_SIZE);
            e->hdr.ret = flags; // stash raw flags for userspace to decode
            e->path_truncated = truncated;
            bpf_ringbuf_submit(e, 0);
        }
    }

    // Check for sensitive read/access operations
    if (path_in_map(path, &suspicious_paths)) {
        struct open_event *e2 = bpf_ringbuf_reserve(&rb, sizeof(*e2), 0);
        if (e2) {
            fill_common(&e2->hdr, EVT_OPEN_SENSITIVE);
            __builtin_memcpy(e2->filename, path, PATH_BUF_SIZE);
            e2->path_truncated = truncated;
            bpf_ringbuf_submit(e2, 0);
        }
    }
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

    handle_open_checks(path, truncated, ctx->flags);
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

    handle_open_checks(path, truncated,flags);
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
    __u32 zero = 0;
    struct scratch_buffer *scratch = bpf_map_lookup_elem(&scratch_map, &zero);
    if (!scratch) return 0;
    
    char *memfd_name = scratch->primary;
    __builtin_memset(memfd_name, 0, PATH_BUF_SIZE);
    
    bpf_probe_read_user_str(memfd_name, PATH_BUF_SIZE, ctx->uname);

    struct open_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;
    fill_common(&e->hdr, EVT_MEMFD);
    __builtin_memcpy(e->filename, memfd_name, PATH_BUF_SIZE);
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



SEC("lsm/file_open")
int BPF_PROG(lsm_file_open, struct file *file) {
    __u32 zero = 0;
    if (!enforcement_enabled) return 0;

    unsigned int f_flags = BPF_CORE_READ(file, f_flags);

    // Check if the file is being opened for writing
    int write_intent = (f_flags & O_ACCMODE_MASK) == O_WRONLY_ ||
                       (f_flags & O_ACCMODE_MASK) == O_RDWR_;
    if (!write_intent) {
        return 0;
    }

    // Resolve the absolute path 
    struct scratch_buffer *scratch = bpf_map_lookup_elem(&scratch_map, &zero);
    if (!scratch) return 0;

    char *path = scratch->primary;
    __builtin_memset(path, 0, PATH_BUF_SIZE);
    __u8 truncated = 0;

    if (get_safe_path(&file->f_path, path, PATH_BUF_SIZE, &truncated) < 0) {
        return 0;
    }

    __u8 *sensitive = bpf_map_lookup_elem(&blocked_write_paths, path);
    if (sensitive && *sensitive == 1) {
        emit_sensitive_write_event(path, truncated);
        return -1; 
    }

    return 0;
}


#endif 
