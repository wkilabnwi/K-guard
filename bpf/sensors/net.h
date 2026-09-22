
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
 
    struct connect_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;
 
    fill_common(&e->hdr, EVT_CONNECT);
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

// sendto() sensor for unconnected socket egress

struct syscall_sendto_args {
    unsigned long long common_tp_fields;
    __s32 syscall_nr;
    __u32 __pad;
    __u64 fd;
    const void *buff;
    __u64 len;
    __u64 flags;
    struct sockaddr_in_min *addr;
    __u64 addr_len;
};

SEC("tracepoint/syscalls/sys_enter_sendto")
int tp_sendto(struct syscall_sendto_args *ctx) {
    // sendto on a connected socket passes NULL for dest_addr.
    // We only inspect unconnected sendto calls (explicit dest address).
    if (!ctx->addr || ctx->addr_len == 0) {
        return 0;
    }

    __u16 family = 0;
    if (bpf_probe_read_user(&family, sizeof(family), ctx->addr) < 0) {
        return 0;
    }

    struct connect_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    fill_common(&e->hdr, EVT_SENDTO);
    e->family = family;
    e->daddr = 0;
    __builtin_memset(e->daddr6, 0, sizeof(e->daddr6));
    e->dport = 0;
    __builtin_memset(e->unix_path, 0, sizeof(e->unix_path));

    if (family == 2) { // AF_INET
        struct sockaddr_in_min sa = {0};
        if (bpf_probe_read_user(&sa, sizeof(sa), ctx->addr) == 0) {
            e->daddr = sa.sin_addr;
            e->dport = ((sa.sin_port & 0xff) << 8) | ((sa.sin_port >> 8) & 0xff);
        }
    } else if (family == 10) { // AF_INET6
        struct sockaddr_in6_min sa6 = {0};
        if (bpf_probe_read_user(&sa6, sizeof(sa6), (void *)ctx->addr) == 0) {
            __builtin_memcpy(e->daddr6, sa6.sin6_addr, sizeof(e->daddr6));
            e->dport = ((sa6.sin6_port & 0xff) << 8) | ((sa6.sin6_port >> 8) & 0xff);
        }
    } else if (family == 1) { // AF_UNIX
        struct sockaddr_un_min sun = {0};
        bpf_probe_read_user(&sun, sizeof(sun), (void *)ctx->addr);
        __builtin_memcpy(e->unix_path, sun.sun_path, sizeof(e->unix_path));
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}



SEC("tc")
int tc_egress_dns(struct __sk_buff *skb) {
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end || eth->h_proto != __builtin_bswap16(0x0800)) 
        return 0; // TC_ACT_OK

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end || ip->protocol != 17) 
        return 0;

    __u32 ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || (void *)ip + ip_hdr_len > data_end) 
        return 0;

    struct udphdr *udp = (void *)((char *)ip + ip_hdr_len);
    if ((void *)(udp + 1) > data_end || udp->dest != __builtin_bswap16(53)) 
        return 0;

    void *dns = (void *)(udp + 1);
    if (dns + 12 > data_end) return 0;

    __u16 txid = *(__u16 *)dns;

    struct dns_tx_key key = {
        .resolver_ip = ip->daddr,
        .client_port = udp->source,
        .txid        = txid,
    };

    struct dns_tx_val val = {0};
    val.cgroup_id = bpf_get_current_cgroup_id();
    bpf_probe_read_kernel(val.qname, sizeof(val.qname), dns + 12);

    bpf_map_update_elem(&dns_pending_tx, &key, &val, BPF_ANY);
    return 0;
}

SEC("tc")
int tc_ingress_dns(struct __sk_buff *skb) {
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end || eth->h_proto != __builtin_bswap16(0x0800)) 
        return 0;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end || ip->protocol != 17) 
        return 0;

    __u32 ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || (void *)ip + ip_hdr_len > data_end) 
        return 0;

    struct udphdr *udp = (void *)((char *)ip + ip_hdr_len);
    if ((void *)(udp + 1) > data_end || udp->source != __builtin_bswap16(53)) 
        return 0;

    void *dns = (void *)(udp + 1);
    if (dns + 12 > data_end) return 0;

    __u16 txid = *(__u16 *)dns;
    __u8 *hdr_bytes = (__u8 *)dns;
    __u16 ancount = ((__u16)hdr_bytes[6] << 8) | hdr_bytes[7];

    struct dns_tx_key key = {
        .resolver_ip = ip->saddr,
        .client_port = udp->dest,
        .txid        = txid,
    };

    struct dns_tx_val *val = bpf_map_lookup_elem(&dns_pending_tx, &key);
    if (!val) return 0;

    if (ancount == 0) {
        bpf_map_delete_elem(&dns_pending_tx, &key);
        return 0;
    }

    // Skip DNS Question Section (max 16 label jumps)
    void *qptr = dns + 12;
    #pragma unroll
    for (int i = 0; i < 16; i++) {
        if (qptr + 1 > data_end) { bpf_map_delete_elem(&dns_pending_tx, &key); return 0; }
        __u8 len = *(__u8 *)qptr;
        qptr += 1;
        if (len == 0) break;
        if ((len & 0xc0) == 0xc0) { qptr += 1; break; }
        
        __u32 safe_len = len & 0x3f;
        if (qptr + safe_len > data_end) { bpf_map_delete_elem(&dns_pending_tx, &key); return 0; }
        qptr += safe_len;
    }

    // Skip QTYPE (2) + QCLASS (2)
    if (qptr + 4 > data_end) {
        bpf_map_delete_elem(&dns_pending_tx, &key);
        return 0;
    }
    qptr += 4;

    struct dns_answer_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        bpf_map_delete_elem(&dns_pending_tx, &key);
        return 0;
    }

    __builtin_memset(&e->hdr, 0, sizeof(e->hdr));
    e->hdr.timestamp_ns = bpf_ktime_get_ns();
    e->hdr.event_type = EVT_DNS_ANSWER;
    e->hdr.cgroup_id = val->cgroup_id;

    e->daddr = 0;
    __builtin_memset(e->daddr6, 0, sizeof(e->daddr6));
    e->family = 0;
    __builtin_memcpy(e->qname, val->qname, sizeof(e->qname));

    // Inspect first 2 Answer Resource Records
    void *aptr = qptr;
    #pragma unroll
    for (int i = 0; i < 2; i++) {
        if (aptr + 2 > data_end) break;

        __u8 name0 = *(__u8 *)aptr;
        if ((name0 & 0xc0) == 0xc0) { // Compressed pointer (standard 0xc0xx)
            aptr += 2;
        } else {
            // Uncompressed name label walker
            #pragma unroll
            for (int j = 0; j < 8; j++) {
                if (aptr + 1 > data_end) break;
                __u8 l = *(__u8 *)aptr;
                aptr += 1;
                if (l == 0) break;
                if ((l & 0xc0) == 0xc0) { aptr += 1; break; }
                __u32 safe_l = l & 0x3f;
                if (aptr + safe_l > data_end) break;
                aptr += safe_l;
            }
        }

        if (aptr + 10 > data_end) break;

        __u8 *rrhdr = aptr;
        __u16 rtype = ((__u16)rrhdr[0] << 8) | rrhdr[1];
        __u16 rdlen = ((__u16)rrhdr[8] << 8) | rrhdr[9];
        void *rdata = aptr + 10;


        if (rtype == 1 && rdlen == 4) { // A record (IPv4)
            if (rdata + 4 <= data_end) {
                e->daddr = *(__u32 *)rdata;
                e->family = 2;
                break;
            }
        } else if (rtype == 28 && rdlen == 16) { // AAAA record (IPv6)
            if (rdata + 16 <= data_end) {
                __builtin_memcpy(e->daddr6, rdata, 16);
                e->family = 10;
                break;
            }
        }

        __u32 safe_rdlen = rdlen & 0xff;
        if (rdata + safe_rdlen > data_end) break;
        aptr = rdata + safe_rdlen;
    }

    bpf_map_delete_elem(&dns_pending_tx, &key);

    if (e->family == 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

#endif