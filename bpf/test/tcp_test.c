#include "pkt.h"

extern void eth_swap_mac(struct ethhdr* eth);
extern void ipv4_swap_ip(struct iphdr* ipv4);

static __u64 bpf_csum_diff(__be32 *from, __u32 from_size, __be16 *to, __u32 to_size, __wsum seed) {
    __u64 sum = 0;
    // 计算所有数据的16bit对之和
    while (to_size > 1) {
        sum += *to++;
        to_size -= 2;
    }

    // 如果数据长度为奇数，在该字节之后补一个字节(0), 然后将其转换为16bit整数，加到上面计算的校验和中。
    if (to_size > 0) {
        char left_over[2] = { 0 };
        left_over[0] = *to;
        sum += *(unsigned short*)left_over;
    }

    long s = sum;
    while (s >> 16)
        s = (s & 0xffff) + (s >> 16);
    printf("s %ld", s);

    return sum;
}

#include "../lib/tcp.h"

// https://blog.csdn.net/qq_15437629/article/details/79183076
// unsigned short tcp_checksum(unsigned short* addr, int count) {
//     long sum = 0;
//     // 计算所有数据的16bit对之和
//     while (count > 1) {
//         sum += *(unsigned short*)addr++;
//         count -= 2;
//     }

//     // 如果数据长度为奇数，在该字节之后补一个字节(0), 然后将其转换为16bit整数，加到上面计算的校验和中。
//     if (count > 0) {
//         char left_over[2] = { 0 };
//         left_over[0] = *addr;
//         sum += *(unsigned short*)left_over;
//     }

//     //  将32bit数据压缩成16bit数据，即将进位加大校验和的低字节上，直到没有进位为止。
//     while (sum >> 16)
//         sum = (sum & 0xffff) + (sum >> 16);

//     return ~sum;
// }

TEST_GROUP(tcp_test){};

TEST(tcp_test, tcp_parse_ip_success) {
    pkt.data_cursor = data_req + TCP_BEGIN;
    int len = tcp_parse(&pkt);
    CHECK_EQUAL(len, sizeof(struct tcphdr)); // size=20
}

TEST(tcp_test, tcp_parse_hend_failed) {
    pkt.data_cursor = data_req + pkt_END - 10;
    int proto = tcp_parse(&pkt);
    CHECK_EQUAL(proto, -1);
}

TEST(tcp_test, tcp_parse_hsize_lessthan_failed) {
    pkt.data_cursor = data_req + TCP_BEGIN;
    struct tcphdr* h = (struct tcphdr*)(pkt.data_cursor);
    h->doff = 1;

    int proto = tcp_parse(&pkt);
    CHECK_EQUAL(proto, -1);

    h->doff = 5;
}

TEST(tcp_test, tcp_parse_hsize_morethan_failed) {
    pkt.data_cursor = data_req + TCP_BEGIN;
    pkt.data_end = data_req + (HTTP_BEGIN - 1);
    struct tcphdr* h = (struct tcphdr*)(pkt.data_cursor);
    h->doff = 6;

    int proto = tcp_parse(&pkt);
    CHECK_EQUAL(proto, -1);

    h->doff = 5;
    pkt.data_end = data_req + pkt_END;
}

// TEST(tcp_test, tcp_checksum_success) {
//     pkt.data_cursor = data_req + TCP_BEGIN;
//     struct tcphdr* h = (struct tcphdr*)(pkt.data_cursor);
//     __sum16 tmp = h->check;
//     h->check = 0;

//     int check = tcp_checksum(h, pkt.ipv4, NULL, 0);
//     CHECK_EQUAL(check, tmp);

//     h->check = tmp;
// }