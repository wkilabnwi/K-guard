#ifndef __KGUARD_MAPS_H
#define __KGUARD_MAPS_H

#include "types.h"

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

struct {
    __uint(type,9);
    __uint(max_entries,4096);
    __type(key, __u64);
    __type(value, struct exec_scratch);

}   exec_scratch_map SEC(".maps");

#endif