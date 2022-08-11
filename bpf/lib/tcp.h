#ifndef __LIB_TCP_H_
#define __LIB_TCP_H_

// #include "api.h"

/* tcp options kind */
#define TCPOPT_NOP 1       /* Padding */
#define TCPOPT_EOL 0       /* End of options */
#define TCPOPT_MSS 2       /* Segment size negotiating */
#define TCPOPT_WINDOW 3    /* Window scaling */
#define TCPOPT_TIMESTAMP 8 /* Better RTT estimations/PAWS */
#define TCPOPT_SACK_PERM 4 /* SACK Permitted */
#define TCPOPT_SACK 5      /* SACK Block */

struct pseudo_hdr {
    __u32 saddr;
    __u32 daddr;
    __u8 reserved;
    __u8 proto;
    __u16 len;
};

/*
 * parse_tcphdr: parse and return the length of the tcp header
 */
BPF_INLINE int tcp_parse(struct pkthdr* pkt) {
    struct tcphdr* h = (struct tcphdr*)(pkt->data_cursor);
    int h_size = h->doff * 4; // sizeof(struct tcphdr) + len(options)
    void* h_end = (void*)h + sizeof(struct tcphdr);

    if (h_end > pkt->data_end) {
        // printk("error tcp_parse 1: h_end %p end %p", (void*)h_end, pkt->data_end);
        return -1;
    }

    /* Sanity check packet field is valid */
    if (h_size < sizeof(struct tcphdr)) {
        // printk("error tcp_parse 2: h_size %d end %p", h_size, pkt->data_end);
        return -1;
    }

    /* Variable-length TCP header, need to use byte-based arithmetic */
    if (pkt->data_cursor + h_size > pkt->data_end) {
        // printk("erro tcp_parse 3: cursor %p h_size %d end %p", pkt->data_cursor, h_size, pkt->data_end);
        return -1;
    }

    pkt->data_tcp_opts = pkt->data_cursor + sizeof(struct tcphdr);
    pkt->data_cursor += h_size;
    pkt->tcp = h;

    // printk("tcp_parse: cursor %p h_size %d end %p", pkt->data_cursor, h_size, pkt->data_end);

    return h_size;
}

BPF_INLINE bool is_tcp_data(struct pkthdr* pkt) {
    struct tcphdr* tcp = pkt->tcp;
    // PSH + ACK报文代表发送数据, 其余忽略
    if (tcp->psh == 0 || tcp->ack == 0) {
        // printk("err check tcp psh & ack: %d %d", tcp->psh, tcp->ack);
        return false;
    }

    return true;
}

/*
 * Swaps destination and source TCP ports inside an TCP header
 */
BPF_INLINE void tcp_swap_port(struct tcphdr* tcp) {
    __be16 tmp = tcp->source;

    tcp->source = tcp->dest;
    tcp->dest = tmp;
}

// BPF_INLINE __u16 csum_fold_helper(__u32 csum) {
//     return ~((csum & 0xffff) + (csum >> 16));
// }

BPF_INLINE __u16 csum_fold_helper(__u64 csum) {
    int i;
#pragma unroll
    for (i = 0; i < 4; i++) {
        if (csum >> 16)
            csum = (csum & 0xffff) + (csum >> 16);
    }
    return ~csum;
}

BPF_INLINE __u16 ipv4_csum(void* data, int data_size, __u64 seed) {
    __u64 sum = bpf_csum_diff(0, 0, data, data_size, seed);
    return csum_fold_helper(sum);
}

BPF_INLINE __u16 tcp_checksum(struct tcphdr* tcph, struct iphdr* iph, void* data, __u8 data_size) {
    struct pseudo_hdr pseudo_hdr;
    __u64 csum = 0;
    __u8 len_tcph_opts = tcph->doff * 4;

    pseudo_hdr.saddr = iph->saddr;
    pseudo_hdr.daddr = iph->daddr;
    __builtin_memset(&pseudo_hdr.reserved, 0, sizeof(pseudo_hdr.reserved));
    pseudo_hdr.proto = IPPROTO_TCP;
    pseudo_hdr.len = bpf_ntohs(len_tcph_opts + data_size); // 伪头部len是TCP头部长度+Payload长度

    __u8 len_opts = len_tcph_opts - sizeof(struct tcphdr);
    if (len_opts > 0) {
        printk("tcp_checksum: has options len %d, ttl %d", len_opts, iph->ttl);
    }

    // 先计算Payload校验和后增量计算整体校验和
    if (data_size > 0) {
        csum = bpf_csum_diff(0, 0, data, data_size, csum); // 1 payload
    }
    csum = bpf_csum_diff(0, 0, (__be32*)&pseudo_hdr, sizeof(struct pseudo_hdr),
                         csum);                                             // 2 tcp pseudo header
    csum = bpf_csum_diff(0, 0, (__be32*)tcph, sizeof(struct tcphdr), csum); // 3 tcp header

    return csum_fold_helper(csum);
    // return ipv4_csum(buffer, sizeof(buffer), payload_chksum);
}

BPF_INLINE void tcp_refact(struct pkthdr* pkt, int len_http_payload) {
    struct iphdr* ipv4 = pkt->ipv4;
    struct tcphdr* tcp = pkt->tcp;
    // 对调3个源和目的
    eth_swap_mac(pkt->eth);
    ipv4_swap_ip(ipv4);
    tcp_swap_port(tcp);

    // __u16 len_header = sizeof(struct iphdr) + tcp->doff * 4;
    // printk("tcp_refact: %d %d", tcp->doff * 4, len_http_payload);

    // ipv4->tot_len = bpf_htons(len_header + len_http_payload); // 40 = sizeof(iphdr + tcphdr)
    ipv4->tot_len = bpf_htons(40 + len_http_payload); // 40 = sizeof(iphdr + tcphdr)
    ipv4->check = 0;
    ipv4->check = ipv4_csum(ipv4, 20, 0); // 20 = sizeof(iphdr)

    tcp->doff = 5;
    tcp->urg = 0;
    tcp->fin = 0;
    tcp->check = 0;

    // data_end - nh.pos - options_len是TCP Payload长度
    __u32 len_tcp_options = tcp->doff * 4 - sizeof(struct tcphdr);
    __u32 len_payload = (__u32)((__u32*)pkt->data_end - (__u32*)pkt->data_begin) - len_tcp_options;
    __u32 new_ack = bpf_htonl(bpf_ntohl(tcp->seq) + len_payload);
    tcp->seq = tcp->ack_seq; // new_seq;
    tcp->ack_seq = new_ack;
}

#define MAX_TCP_OPTIONS 10

BPF_INLINE int tcp_filter_options(__u8* opts, __u8* opts_end, __u8* data_end, __u8 kind) { //, __u64* val) {
    __u8* pos = opts;
    __u8 i;
    __u8 opt_kind;
    volatile __u8 opt_len;

    printk("0 tcp_filter_options()  %x %x %x", opts, opts_end, data_end);

    if (opts + 1 > opts_end) {// || opts_end + 1 > data_end) {
        return -1;
    }

#pragma unroll
    for (i = 0; i < MAX_TCP_OPTIONS; i++) {
        if (pos + 1 > opts_end || pos + 1 > data_end) {
            return -1;
        }

        opt_kind = *pos;
        if (kind == TCPOPT_EOL) { // TCPOPT_EOL = 0
            return -1;
        }

        if (opt_kind == TCPOPT_NOP) { // TCPOPT_NOP = 1
            pos++;
            continue;
        }

        if (pos + 2 > opts_end || pos + 2 > data_end) { // overflow
            return -1;
        }

        opt_len = *(pos + 1);
        if (opt_len < 2) {
            return -1;
        }

        if (opt_kind == kind) {
            if (pos + opt_len > opts_end || pos + opt_len > data_end) { // overflow
                return -1;
            }
            printk("tcp_filter_options() found kind %d %d %d", opt_kind, opt_len, pos[1]);
            // val = pos[1];
            pos += 2; 
            if (pos > opts_end || pos > data_end) { // overflow
                return -1;
            }

            // *val = pos[2]; //*(__u64 *)(pos + 2);
            return opt_len;
        }

        pos += opt_len;
    }

    printk("tcp_filter_options() not found kind %d", kind);

    return -1;
}
// struct opts_t {
//     __u8 kind;
//     __u8 length;
//     __u8 *value;
// };

// BPF_INLINE __u8* tcp_filter_options(__u8* opts, __u8* opts_end, int opt_kind) {
//     // if (opts + 2 >= opts_end) {
//     //     return NULL;
//     // }
//     // struct opts_t *opt = (struct opts_t *)opts;
//     // printk("opt_filter %d %d %d", opts[0], opt->kind, opt->length);

//     __u8 i;
//     // __u8 len;
//     __u8 kind;
//     __u8 buf[32];
//     __builtin_memcpy(buf, opts, 10);

// #pragma unroll
//     for (i = 0; i < 10; i++) { // 40 = max tcp sizeof options
//         kind = buf[0];
//         buf[0] = kind;

// //         len = (kind == TCPOPT_EOL) ? 1 : buf[1];
//         // printk("opt_filter %d %d", kind, len);
//         printk("opt_filter %d", kind);
// //         if (kind == opt_kind) {
// //             return opts;
// //         }
// //         i += len;
//         // opt_cursor += length;
//         // kind = *opt_cursor;
//         // if (opt_cursor + 1 > opt_end) {
//         //     return false;
//         // }
//         // opt = (struct opts_t*)((__u8*)opt + opt->length);
//         // if ((__u8*)opt >= opts_end) {
//         //     return false;
//         // }
//         // printk("opt_filter %d %d", opt->kind, opt->length);

// //     }
// //     return NULL;
// // }

// BPF_INLINE bool tcp_reset(struct pkthdr* pkt) {
//     struct tcphdr* tcp = pkt->tcp;

//     tcp->rst = 1;
//     tcp->syn = 0;
//     tcp->ack = 0;
//     tcp->psh = 0;
//     tcp->window = 0;

//     tcp_refact(pkt, 0);

//     tcp->check = tcp_checksum(tcp, pkt->ipv4, NULL, 0);

//     return true;
// }

#endif // __LIB_TCP_H_
