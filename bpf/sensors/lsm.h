#ifndef __KGUARD_SENSORS_LSM_H
#define __KGUARD_SENSORS_LSM_H

#include "../types.h"
#include "../maps.h"
#include "../helpers.h"

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

    __u8 truncated = (ret >= PATH_BUF_SIZE) ? 1 : 0;
// Clamp into a verifier-provable bounded range BEFORE any pointer math
    __u32 pathlen = (__u32)ret;
    if (pathlen > PATH_BUF_SIZE)
        pathlen = PATH_BUF_SIZE;

    __u32 word_start = (pathlen + 7) & ~7U;
    if (word_start > PATH_BUF_SIZE)
        word_start = PATH_BUF_SIZE;

    // clear the single word straddling ret
   #pragma unroll
    for (__u32 i = 0; i < 8; i++) {
        __u32 idx = pathlen + i;
        if (idx < word_start && idx < PATH_BUF_SIZE)
            path[idx] = 0;
    }

    // clear every full word from word_start onward 
    __u64 *path64 = (__u64 *)path;
#pragma unroll
for (__u32 i = 0; i < (PATH_BUF_SIZE / 8); i++) {
    if ((i * 8) >= word_start)
        path64[i] = 0;
}
    // bpf_d_path returns total path string length including null byte.
    // If length >= PATH_BUF_SIZE, the buffer reached capacity and was truncated
    


    __u8 *blocked = bpf_map_lookup_elem(&blocked_paths, path);

    if (blocked && *blocked == 1) {
        struct exec_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
        if (e) {
            fill_common(&e->hdr, EVT_EXEC_BLOCKED);
            __builtin_memcpy(e->filename, path, PATH_BUF_SIZE);
            e->path_truncated = truncated;

            __u64 pid_tgid = bpf_get_current_pid_tgid();
            struct exec_scratch *scratch2 = bpf_map_lookup_elem(&exec_scratch_map, &pid_tgid);
            if (scratch2) {
                __builtin_memcpy(e->args, scratch2->args, sizeof(e->args));
                bpf_map_delete_elem(&exec_scratch_map, &pid_tgid);
            }

            bpf_ringbuf_submit(e, 0);
        }
        return -1; //kernel aborts the exec 
    }

    return 0;
}

#endif