#ifndef __LIB_DBG__
#define __LIB_DBG__

// struct BPF_MAP DBG_EVENTS_MAP = {
//     .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY, .key_size = sizeof(int), .value_size = sizeof(__u32),
//     // .max_entries = 1,
// };

struct BPF_MAP PKT_INFO_EVENTS_MAP = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY, .key_size = sizeof(int), .value_size = sizeof(__u32),
    // .max_entries = 1,
};

#ifdef DEBUG
#define printk(fmt, ...)                                                                           \
    ({                                                                                             \
        const char ____fmt[] = fmt;                                                                \
        bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__);                                 \
    })
#else
#define printk(fmt, ...)                                                                           \
    do {                                                                                           \
    } while (0)
#endif

struct pkt_info {
    __be32 saddr;
    __be32 daddr;
    __u8 ttl;
    __u8 flags;
	__u8 dbg_t;
	__u32 dbg_info;
} __packed;

BPF_INLINE void send_pkt_info(struct xdp_md* ctx, struct pkthdr* pkt, __u8 dbg_t, __u32 dbg_info) {
    struct tcphdr *tcp = pkt->tcp;
    struct pkt_info pi = {
		.saddr = pkt->ipv4->saddr,
		.daddr = pkt->ipv4->daddr,
		.ttl = pkt->ipv4->ttl,
		// .flags = *((__u8*)tcp + 13),// (tcp->fin << 2) + tcp->syn, //rst
        .flags = tcp_flag_word(tcp),
		.dbg_t = dbg_t,
		.dbg_info = dbg_info
	};

	bpf_perf_event_output(ctx, &PKT_INFO_EVENTS_MAP, BPF_F_CURRENT_CPU, &pi, sizeof(pi));
}


#endif /* __LIB_DBG__ */
