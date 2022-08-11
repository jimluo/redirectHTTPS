#include "pkt.h"
#include "../lib/eth.h"

TEST_GROUP(eth_test) {
};

TEST(eth_test, eth_parse_ip_success) {
    pkt.data_cursor = data_req;
    int proto = eth_parse(&pkt);
    CHECK_EQUAL(proto, bpf_htons(ETH_P_IP));
}

TEST(eth_test, eth_parse_cursor_success) {
    pkt.data_cursor = data_req;
    eth_parse(&pkt);
    CHECK_EQUAL(pkt.data_begin + IP_BEGIN, pkt.data_cursor);
}

TEST(eth_test, eth_parse_hsize_failed) {
    pkt.data_cursor = data_req + pkt_END - 1;
    int proto = eth_parse(&pkt);
    CHECK_EQUAL(proto, -1);
}

TEST(eth_test, eth_parse_vlan_success) {
    const int END = 18;
    __u8 eth[END] = {
        0x00, 0x15, 0x5d, 0x71, 0xc9, 0xe1, 0x00, 0x15, 0x5d, 0xb1, 0x37, 0xf1, 0x81, 0x00, // eth ETH_P_8021Q
        0x01, 0x0c, 0x08, 0x00 // vlan [TPID PCP CFI VID] ETH_P_IP
    };

    struct pkthdr pkt_eth = { 
        .eth = (struct ethhdr*)eth,
        .data_end = (void*)(eth) + END,
        .data_cursor = (void*)eth
    };

    int proto = eth_parse(&pkt_eth);
    CHECK_EQUAL(proto, bpf_htons(ETH_P_IP));
}


TEST(eth_test, eth_parse_vlan_vlan_success) {
    const int END = 22;
    __u8 eth[END] = {
        0x00, 0x15, 0x5d, 0x71, 0xc9, 0xe1, 0x00, 0x15, 0x5d, 0xb1, 0x37, 0xf1, 0x81, 0x00, // eth ETH_P_8021Q
        0x01, 0x0c, 0x81, 0x00, // vlan [TPID PCP CFI VID] ETH_P_8021Q
        0x01, 0x0c, 0x08, 0x00 // vlan [TPID PCP CFI VID] ETH_P_IP
    };

    struct pkthdr pkt_eth = { 
        .eth = (struct ethhdr*)eth,
        .data_end = (void*)(eth) + END,
        .data_cursor = (void*)eth
    };

    int proto = eth_parse(&pkt_eth);
    CHECK_EQUAL(proto, bpf_htons(ETH_P_IP));
}