#ifndef __LIB_IPV4__
#define __LIB_IPV4__

// #include <linux/ip.h>

// #include "api.h"
// #include "dbg.h"
// #include "metrics.h"


BPF_INLINE int ipv4_parse(struct pkthdr* pkt) {
    struct iphdr* h = (struct iphdr*)(pkt->data_cursor);
    int h_size = h->ihl * 4; // sizeof(struct iphdr) + len(options)
    void* h_end = (void*)h + sizeof(struct iphdr);

    if (h_end > pkt->data_end) {
        // printk("error ip_parse 1: h_end %p end %p", (void*)h_end, pkt->data_end);
        return -1;
    }

    /* Sanity check packet field is valid */
    if (h_size < sizeof(struct iphdr)) {
        // printk("ip_parse 2: h_size %d size_h %d", h_size, sizeof(struct iphdr));
        return -1;
    }

    /* Variable-length IPv4 header, need to use byte-based arithmetic */
    if (pkt->data_cursor + h_size > pkt->data_end) {
        // printk("ip_parse 3: cursor %p h_size %d end %p", pkt->data_cursor, h_size, pkt->data_end);
        return -1;
    }

    pkt->data_cursor += h_size;
    pkt->ipv4 = h;

    // printk("ip_parse: cursor %p h_size %d end %p", pkt->data_cursor, h_size, pkt->data_end);

    return h->protocol;
}

/*
 * Swaps destination and source IPv4 addresses inside an IPv4 header
 */
BPF_INLINE void ipv4_swap_ip(struct iphdr* ipv4) {
    __be32 tmp = ipv4->saddr;

    ipv4->saddr = ipv4->daddr;
    ipv4->daddr = tmp;
}

/* Calculates the IP checksum */
static __always_inline int calc_ip_csum(struct iphdr *oldip, struct iphdr *ip,
					__u32 oldcsum)
{
	__u32 size = sizeof(struct iphdr);
	__u32 csum = bpf_csum_diff((__be32 *)oldip, size, (__be32 *)ip, size,
				   ~oldcsum);
	__u32 sum = (csum >> 16) + (csum & 0xffff);
	sum += (sum >> 16);
	return sum;
}

// BPF_INLINE __u16 csum_fold_helper(__u32 csum) {
//     return ~((csum & 0xffff) + (csum >> 16));
// }

// __u32 csum = 0;
// ipv4_csum(icmp_hdr, ICMP_TOOBIG_PAYLOAD_SIZE, &csum);
// icmp_hdr->checksum = csum;
// csum = 0;
// ipv4_csum(iph, sizeof(struct iphdr), &csum);
// iph->check = csum;

// bpf_csum_diff(__be32 *from, u32 data_start, __be32 *to, u32 data_size, __wsum seed)
// pushing new data: data_start == 0, data_size > 0 and seed set to checksum,
// removing exist data: data_start > 0, data_size == 0 and seed set to checksum,
// compute a diff: data_start > 0, data_size > 0 and seed set to 0

// BPF_INLINE void csum(void* data_start, int data_size, __u32* csum) {
//     *csum = bpf_csum_diff(0, 0, data_start, data_size, *csum);
//     *csum = csum_fold_helper(*csum);
// }

// BPF_INLINE __u16 ipv4_csum(struct iphdr* ipv4) {
// 	__u32 csum = bpf_csum_diff(0, 0, (__be32 *)ipv4, ipv4->ihl * 4, 1);
//     return csum; //csum_fold_helper(csum);
// }
// //
// BPF_INLINE void ipv4_update(struct iphdr* ip4, __u16 payloadlen) {
//     ip4->tot_len = bpf_htons(MAX_IPOPTLEN + payloadlen);
//     // ipv4->check = ipv4_csum_u16(ipv4, ipv4_hdrlen(ipv4), 0);
//     // (__be32 *from, u32 from_size, __be32 *to, u32 to_size, __wsum seed)
//     ip4->check = bpf_csum_diff(0, 0, (__be32*)&ip4->tot_len, sizeof(ip4->tot_len), 0);
// }

// BPF_INLINE __u16 csum_fold_helper(__u64 csum) {
//     int i;
// #pragma unroll
//     for (i = 0; i < 4; i++) {
//         if (csum >> 16)
//             csum = (csum & 0xffff) + (csum >> 16);
//     }
//     return ~csum;
// }

// BPF_INLINE __u16 ipv4_csum_u16(void* data, int data_size, __u64 seed) {
//     // __u64 sum = bpf_csum_diff(0, 0, data, data_size, seed);
//     __u64 sum = 0;
//     return csum_fold_helper(sum);
// }

// BPF_INLINE void ipv4_csum(void* data_start, int data_size, __u64* csum) {
//     *csum = bpf_csum_diff(0, 0, (__be32*)data_start, data_size, *csum);
//     *csum = csum_fold_helper(*csum);
// }

// // better perfomance
// BPF_INLINE void ipv4_csum_inline(void* iph, __u64* csum) {
//     __u16* next_iph_u16 = (__u16*)iph;
// #pragma clang loop unroll(full)
//     for (int i = 0; i < sizeof(struct iphdr) >> 1; i++) {
//         *csum += *next_iph_u16++;
//     }
//     *csum = csum_fold_helper(*csum);
// }

// // best perfomance
// BPF_INLINE void ipv4_l4_csum(struct iphdr* ipv4, void* data_start, int data_size, __u64* csum) {
// 	// ip: saddr daddr
//     *csum = bpf_csum_diff(0, 0, &ipv4->saddr, sizeof(__be32), *csum);
//     *csum = bpf_csum_diff(0, 0, &ipv4->daddr, sizeof(__be32), *csum);

// 	// protocol
//     __u32 tmp = __builtin_bswap32((__u32)(ipv4->protocol));
//     *csum = bpf_csum_diff(0, 0, &tmp, sizeof(__u32), *csum);

// 	// data_size
//     tmp = __builtin_bswap32((__u32)(data_size));
//     *csum = bpf_csum_diff(0, 0, &tmp, sizeof(__u32), *csum);

//     *csum = bpf_csum_diff(0, 0, (__be32*)data_start, data_size, *csum);
//     *csum = csum_fold_helper(*csum);
// }

#endif /* __LIB_IPV4__ */
