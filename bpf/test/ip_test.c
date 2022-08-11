#include "pkt.h"
#include "../lib/ipv4.h"

TEST_GROUP(ip_test){};

TEST(ip_test, ip_parse_ip_success) {
    pkt.data_cursor = data_req + IP_BEGIN;
    int proto = ipv4_parse(&pkt);
    CHECK_EQUAL(proto, IPPROTO_TCP);
}

TEST(ip_test, ip_parse_hend_failed) {
    pkt.data_cursor = data_req + pkt_END - 10;
    int proto = ipv4_parse(&pkt);
    CHECK_EQUAL(proto, -1);
}

TEST(ip_test, ip_parse_hsize_lessthan_failed) {
    pkt.data_cursor = data_req + IP_BEGIN;
    struct iphdr* h = (struct iphdr*)(pkt.data_cursor);
    h->ihl = 1;

    int proto = ipv4_parse(&pkt);
    CHECK_EQUAL(proto, -1);

    h->ihl = 5;
}

TEST(ip_test, ip_parse_hsize_morethan_failed) {
    pkt.data_cursor = data_req + IP_BEGIN;
    pkt.data_end = data_req + (TCP_BEGIN - 1);
    struct iphdr* h = (struct iphdr*)(pkt.data_cursor);
    h->ihl = 6;

    int proto = ipv4_parse(&pkt);
    CHECK_EQUAL(proto, -1);

    h->ihl = 5;
    pkt.data_end = data_req + pkt_END;
}

TEST(ip_test, ip_swap_ip_success) {
    struct iphdr* ip = (struct iphdr*)(data_req + IP_BEGIN);

    __be32 saddr = ip->saddr;

    ipv4_swap_ip(ip);
    CHECK_EQUAL(ip->daddr, saddr);

    ipv4_swap_ip(ip);
    CHECK_EQUAL(ip->saddr, saddr);
}

static __u32 do_csum(__u16* buff, int len) {
    __u32 csum = 0;
    for (int i = 0; i < len; i++) {
        csum += buff[i];
    }
    printf("csum=%d\n", csum);
    csum = (csum >> 16) + (csum & 0xffff);
    csum += (csum >> 16);
    csum = 0xffff - csum;
    printf("csum=%04x\n", csum);
    return csum;
}

TEST(ip_test, ipv4_csum_success) {
    struct iphdr* ip = (struct iphdr*)(data_req + IP_BEGIN);
    __u16 check = ip->check;
    ip->check = 0;
    __u16 csum = do_csum((__u16*)ip, ip->ihl * 4 / 2);

    CHECK_EQUAL(check, csum);
    
    ip->check = check;
}

TEST(ip_test, ipv4_csum_exchange_ip_success) {
    struct iphdr* ip = (struct iphdr*)(data_req + IP_BEGIN);
    __u16 check = ip->check;
    __u32 tmp = ip->saddr;
    ip->saddr = ip->daddr;
    ip->daddr = tmp;
    ip->check = 0;
    __u16 csum = do_csum((__u16*)ip, ip->ihl * 4 / 2);

    CHECK_EQUAL(check, csum);

    ip->check = check;
}