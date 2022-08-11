#ifndef __LIB_HTTP_H_
#define __LIB_HTTP_H_

// #include "api.h"

#define GET 0x20544547    // G47 E45 T54 20
#define POST 0x54534F50   // P50 O4F S53 T54
#define PUT 0x20545550    // P50 U55 T54 20
#define DELETE 0x454C4544 // D44 E45 L4C T45
#define HEAD 0x44414548   // H48 E45 A41 D44

#define MAX_SIZE_REDIRECT_URL 120
#define MIN_HTTP_REQ_HEADER 26

BPF_INLINE bool is_http_reqest(struct pkthdr* pkt) {
    // 最小http payload：GET / HTTP/1.0\r\n\r\n
    void* min_data_end = pkt->data_cursor + MIN_HTTP_REQ_HEADER;
    if (min_data_end > pkt->data_end) {
        printk("error http reqest payload len: %x %x", min_data_end, pkt->data_end);
        return false;
    }

    __u32 m = *(__u32*)(pkt->data_cursor); // method
    if (m == GET || m == POST || m == PUT || m == DELETE || m == HEAD) {
        // printk("http: OK, %x", m);
        return true;
    }

    return false;
}


BPF_INLINE void http_redirect(struct pkthdr* pkt, __u8 *url, __u8 len_url) {
    if (pkt->data_cursor + MAX_SIZE_REDIRECT_URL > pkt->data_end) {
        printk("Err: Payload > data_end %x %x", pkt->data_cursor + MAX_SIZE_REDIRECT_URL, pkt->data_end);
        return;
    }

    __builtin_memcpy(pkt->data_cursor, url, MAX_SIZE_REDIRECT_URL); // 本机debug时关闭


    struct tcphdr* tcp = pkt->tcp;
    tcp->rst = 0;
    tcp->syn = 0;
    tcp->ack = 1;
    tcp->psh = 1;

    tcp_refact(pkt, len_url);

    tcp->check = tcp_checksum(tcp, pkt->ipv4, pkt->data_cursor, len_url);
}

#endif // __LIB_HTTP_H_