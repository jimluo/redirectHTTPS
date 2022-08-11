/*
 * Data metrics collection functions
 *
 */
#ifndef __LIB_METRICS__
#define __LIB_METRICS__

#include "api.h"

// #include "utils.h"
// #include "dbg.h"

enum metrics_index {
    METRICS_PKT_COUNT,  // 0; count all capture packages
	METRICS_HOST_COUNT,  
	METRICS_IPV4, 
	METRICS_TCP, 
    METRICS_HTTP,
    METRICS_OS_LINUX,   // 5
	METRICS_OS_WIN,     // 6
    METRICS_ETH_ERR,    // 7; not IP 0x0800, maybe ARP 0x0806
    METRICS_IPV4_ERR,   // not TCP 6, maybe UDP 0x11(17)
    METRICS_TCP_ERR,
    METRICS_HTTP_ERR,   // 10; not http, maybe only tcp syn
    METRICS_CONFIG_MAP_ERR,
    METRICS_REDIRECT_MAP_ERR
};

struct BPF_MAP METRICS_MAP = { 
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(__u64),
	.max_entries = 16,
};

/**
 * Update the metrics map.
 */
BPF_INLINE void update_metrics(__u32 index) {
    __u64 new_count = 1;
    __u64 *count = bpf_map_lookup_elem(&METRICS_MAP, &index);

    if (count) {
        *count += 1;
    } else {    
        bpf_map_update_elem(&METRICS_MAP, &index, &new_count, 0);
    }
}

#endif /* __LIB_METRICS__ */
