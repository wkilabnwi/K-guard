
#ifndef __KGUARD_SENSORS_NET_H
#define __KGUARD_SENSORS_NET_H

#include "../types.h"
#include "../helpers.h"

// connect() sensor

struct sockaddr_in_min {
    __u16 sin_family;
    __u16 sin_port;   
    __u32 sin_addr;  
};
struct sockaddr_in6_min {
    __u16 sin6_family;
    __u16 sin6_port;
    __u32 sin6_flowinfo;
    __u8  sin6_addr[16];
    __u32 sin6_scope_id;
};
 
struct sockaddr_un_min {
    __u16 sun_family;
    char  sun_path[108]; // matches real sockaddr_un's sun_path length
};
 
struct syscall_connect_args {
    unsigned long long common_tp_fields;
    __s32 syscall_nr;                   
    __u32 __pad;                          
    __u64 fd;                             
    struct sockaddr_in_min *uservaddr;    
    __u64 addrlen;  
};
 
SEC("tracepoint/syscalls/sys_enter_connect")
int tp_connect(struct syscall_connect_args *ctx) {
    // Every sockaddr_* variant starts with the same 2-byte family field,
    // so peek that first to know which real layout to read next instead
    // of assuming AF_INET
    __u16 family = 0;
    if (bpf_probe_read_user(&family, sizeof(family), ctx->uservaddr) < 0) {
        return 0;
    }
 
    struct kguard_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;
 
    fill_common(e, EVT_CONNECT);
    e->family = family;
    // Zero every family-specific field up front, the ring buffer doesn't
    // zero reused memory for us
    e->daddr = 0;
    __builtin_memset(e->daddr6, 0, sizeof(e->daddr6));
    e->dport = 0;
    __builtin_memset(e->unix_path, 0, sizeof(e->unix_path));
 
    if (family == 2) { 
        struct sockaddr_in_min sa = {0};
        if (bpf_probe_read_user(&sa, sizeof(sa), ctx->uservaddr) == 0) {
            e->daddr = sa.sin_addr;
            // sin_port is network byte order so we convert it
            e->dport = ((sa.sin_port & 0xff) << 8) | ((sa.sin_port >> 8) & 0xff);
        }
    } else if (family == 10) {
        struct sockaddr_in6_min sa6 = {0};
        if (bpf_probe_read_user(&sa6, sizeof(sa6), (void *)ctx->uservaddr) == 0) {
            __builtin_memcpy(e->daddr6, sa6.sin6_addr, sizeof(e->daddr6));
            e->dport = ((sa6.sin6_port & 0xff) << 8) | ((sa6.sin6_port >> 8) & 0xff);
        }
    } else if (family == 1) { // AF_UNIX
        struct sockaddr_un_min sun = {0};
        // addrlen for AF_UNIX is frequently shorter than the size of sun
        bpf_probe_read_user(&sun, sizeof(sun), (void *)ctx->uservaddr);
        __builtin_memcpy(e->unix_path, sun.sun_path, sizeof(e->unix_path));
    }
 
    bpf_ringbuf_submit(e, 0);
    return 0;
}

#endif