
#include "pkt.h"

extern void eth_swap_mac(struct ethhdr* eth);
extern void ipv4_swap_ip(struct iphdr* ipv4);
extern __u16 tcp_checksum(struct tcphdr* tcph, struct iphdr* iph, void* data, int data_size);
extern void tcp_refact(struct pkthdr* pkt, int len_http_payload);

#include "../lib/http.h"

TEST_GROUP(http_test) {
};

TEST(http_test, is_http_reqest_method_post_success) {
    pkt.data_cursor = data_req + HTTP_BEGIN;
    strncpy((char*)(pkt.data_cursor), "POST", strlen("POST"));

    bool is_http_req = is_http_reqest(&pkt);
    CHECK_TRUE(is_http_req);

    strncpy((char*)(pkt.data_cursor), "GET ", strlen("GET "));
}

TEST(http_test, is_http_reqest_min_header_failed) {
    pkt.data_cursor = data_req + HTTP_BEGIN - 1;
    bool is_http_req = is_http_reqest(&pkt);
    CHECK_FALSE(is_http_req);
}

TEST(http_test, is_http_reqest_method_failed) {
    pkt.data_cursor = data_req + HTTP_BEGIN + 1; // GET => ET /
    bool is_http_req = is_http_reqest(&pkt);
    CHECK_FALSE(is_http_req);
}