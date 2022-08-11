#ifndef __LIB_ETH__
#define __LIB_ETH__

// #include <linux/if_ether.h>

// #include "api.h"
// #include "dbg.h"
// #include "metrics.h"

/*
 *	struct vlan_hdr - vlan header
 *	@h_vlan_TCI: priority and VLAN ID
 *	@h_vlan_encapsulated_proto: packet type ID or len
 */
struct vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

/* Allow users of header file to redefine VLAN max depth */
#ifndef VLAN_MAX_DEPTH
#define VLAN_MAX_DEPTH 2
#endif

// #define VLAN_VID_MASK 0x0fff /* VLAN Identifier */
// /* Struct for collecting VLANs after parsing via parse_ethhdr_vlan */
// struct collect_vlans {
//     __u16 id[VLAN_MAX_DEPTH];
// };

BPF_INLINE int proto_is_vlan(__u16 h_proto) {
    return !!(h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD));
}

/* Notice, parse_ethhdr() will skip VLAN tags, by advancing nh->pos and returns
 * next header EtherType, BUT the ethhdr pointer supplied still points to the
 * Ethernet header. Thus, caller can look at eth->h_proto to see if this was a
 * VLAN tagged packet.
 */
BPF_INLINE int eth_parse(struct pkthdr *pkt) {
    struct ethhdr* h = (struct ethhdr*)(pkt->data_cursor);
    const int h_size = sizeof(struct ethhdr);
	void *h_end = (void*)h + h_size;
    __u16 h_proto = h->h_proto;

    struct vlan_hdr* vlh = (struct vlan_hdr*)h_end;
	// void *vlh_end = (void*)(vlh + 1);

    /* Byte-count bounds check; check if current pointer + size of header
     * is after data_end.
     */
    if (h_end > pkt->data_end) {
        // printk("eth_parse: cursor=%p headsize=%d data_end=%p", pkt->data_cursor, h_size, pkt->data_end);
        return -1;
    }

    pkt->data_cursor = h_end;
    pkt->eth = h;

/* Use loop unrolling to avoid the verifier restriction on loops;
 * support up to VLAN_MAX_DEPTH layers of VLAN encapsulation.
 */
#pragma unroll
    for (int i = 0; i < VLAN_MAX_DEPTH; i++) {
        if (!proto_is_vlan(h_proto)) {
            // printk("eth_parse vlan: proto_is_vlan=%d", h_proto);
            break;
        }

        if ((void*)(vlh + 1) > pkt->data_end) {
            // printk("eth_parse vlan: vlh_end=%p", vlh_end);
            break;
        }

        h_proto = vlh->h_vlan_encapsulated_proto;
        // if (vlans) /* collect VLAN ids */
        //     vlans->id[i] = (bpf_ntohs(vlh->h_vlan_TCI) & VLAN_VID_MASK);
        // printk("eth_parse vlan: proto=%d", h_proto);

        vlh++;
    }

    pkt->data_cursor = vlh;

    // bpf_printk("eth_parse: cursor=%04x begin=%04p headsize=%d", pkt->data_cursor, pkt->eth, h_size);

    return h_proto; /* network-byte-order */
}

/*
 * Swaps destination and source MAC addresses inside an Ethernet header
 */
BPF_INLINE void eth_swap_mac(struct ethhdr* eth) {
    __u8 h_tmp[ETH_ALEN];

    __builtin_memcpy(h_tmp, eth->h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, h_tmp, ETH_ALEN);
}

/* Pops the outermost VLAN tag off the packet. Returns the popped VLAN ID on
 * success or negative errno on failure.
 */
// BPF_INLINE int vlan_tag_pop(struct xdp_md* ctx, struct ethhdr* eth) {
//     void* data_end = (void*)(long)ctx->data_end;
//     struct ethhdr eth_cpy;
//     struct vlan_hdr* vlh;
//     __be16 h_proto;
//     int vlid;

//     if (!proto_is_vlan(eth->h_proto))
//         return -1;

//     /* Careful with the parenthesis here */
//     vlh = (void*)(eth + 1);

//     /* Still need to do bounds checking */
//     if ((void*)(vlh + 1) > data_end)
//         return -1;

//     /* Save vlan ID for returning, h_proto for updating Ethernet header */
//     vlid = bpf_ntohs(vlh->h_vlan_TCI);
//     h_proto = vlh->h_vlan_encapsulated_proto;

//     /* Make a copy of the outer Ethernet header before we cut it off */
//     __bpf_memcpy(&eth_cpy, eth, sizeof(eth_cpy));

//     /* Actually adjust the head pointer */
//     if (bpf_xdp_adjust_head(ctx, (int)sizeof(*vlh)))
//         return -1;

//     /* Need to re-evaluate data *and* data_end and do new bounds checking
//      * after adjusting head
//      */
//     eth = (void*)(long)ctx->data;
//     data_end = (void*)(long)ctx->data_end;
//     if ((void*)(eth + 1) > data_end)
//         return -1;

//     /* Copy back the old Ethernet header and update the proto type */
//     __bpf_memcpy(eth, &eth_cpy, sizeof(*eth));
//     eth->h_proto = h_proto;

//     return vlid;
// }

/* Pushes a new VLAN tag after the Ethernet header. Returns 0 on success,
 * -1 on failure.
 */
// BPF_INLINE int vlan_tag_push(struct xdp_md* ctx, struct ethhdr* eth, int vlid) {
//     void* data_end = (void*)(long)ctx->data_end;
//     struct ethhdr eth_cpy;
//     struct vlan_hdr* vlh;

//     /* First copy the original Ethernet header */
//     __bpf_memcpy(&eth_cpy, eth, sizeof(eth_cpy));

//     /* Then add space in front of the packet */
//     if (bpf_xdp_adjust_head(ctx, 0 - (int)sizeof(*vlh)))
//         return -1;

//     /* Need to re-evaluate data_end and data after head adjustment, and
//      * bounds check, even though we know there is enough space (as we
//      * increased it).
//      */
//     data_end = (void*)(long)ctx->data_end;
//     eth = (void*)(long)ctx->data;

//     if ((void*)(eth + 1) > data_end)
//         return -1;

//     /* Copy back Ethernet header in the right place, populate VLAN tag with
//      * ID and proto, and set outer Ethernet header to VLAN type.
//      */
//     __bpf_memcpy(eth, &eth_cpy, sizeof(*eth));

//     vlh = (void*)(eth + 1);

//     if ((void*)(vlh + 1) > data_end)
//         return -1;

//     vlh->h_vlan_TCI = bpf_htons(vlid);
//     vlh->h_vlan_encapsulated_proto = eth->h_proto;

//     eth->h_proto = bpf_htons(ETH_P_8021Q);
//     return 0;
// }

#endif /* __LIB_ETH__ */