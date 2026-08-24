#ifndef __KGUARD_SENSORS_IOURING_H
#define __KGUARD_SENSORS_IOURING_H

#include "../types.h"
#include "../helpers.h"

SEC("tracepoint/io_uring/io_uring_submit_req")
int tp_io_uring_submit_req(struct trace_event_raw_io_uring_submit_req *ctx) {
    bpf_printk("kguard_debug: tp_io_uring_submit_req HIT! opcode=%d\n", ctx->opcode);

    __u8 opcode = ctx->opcode;
    if (opcode == 18 || opcode == 16 || opcode == 28) {
        struct iouring_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
        if (!e) return 0;

        fill_common(&e->hdr, EVT_IO_URING);
        e->opcode = opcode;
        bpf_ringbuf_submit(e, 0);
    }
    return 0;
}

#endif