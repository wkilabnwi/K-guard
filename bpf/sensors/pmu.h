#ifndef __KGUARD_SENSORS_PMU_H
#define __KGUARD_SENSORS_PMU_H

#include "../types.h"
#include "../maps.h"
#include "../helpers.h"

SEC("perf_event")
int on_branch_mispredict(struct bpf_perf_event_data *ctx) {
    struct pmu_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    fill_common(&e->hdr, EVT_BRANCH_MISPREDICT);
    e->mispred_count = ctx->sample_period;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

#endif