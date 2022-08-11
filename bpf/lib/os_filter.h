#ifndef __LIB_OS_FILTER_H_
#define __LIB_OS_FILTER_H_

#include "../maps.h"

BPF_INLINE void save_token(struct pkthdr* pkt) {
    if (pkt->tcp->syn == 1 && pkt->tcp->ack == 0) { // syn only have options
        printk("save_token %d %d", pkt->tcp->syn, pkt->tcp->ack);
        __u8 token = 0x03; // debug
        __u8 opt_len = tcp_filter_options(pkt->data_tcp_opts, pkt->data_cursor, pkt->data_end, token);
        if (opt_len > 1) {
            const __u32 os_type = 1;
            __u32* os = bpf_map_lookup_elem(&oken_user_map, &pkt->ipv4->saddr);
            if (os == NULL) {
                bpf_map_update_elem(&token_user_map, &pkt->ipv4->saddr, &os_type, BPF_ANY);
            }
            printk("find token %d and save into hashmap %d", token, opt_len);
        }
    }
}

BPF_INLINE bool is_token(__be32 saddr) {
    __u32* os = bpf_map_lookup_elem(&token_user_map, &saddr);
    if (os != NULL) {
        return true;
    }
    return false;
}

BPF_INLINE bool is_linux(struct pkthdr* pkt) {
    if (pkt->ipv4->ttl < 64) { // native linux
        // tcphdr->window != 1380 //win7
        // tcphdr->ts == 1
        return true;
    }

    return false;
}

#endif // __LIB_OS_FILTER_H_