#ifndef __BPF_API__
#define __BPF_API__


/* 2/3/4 layer Header all in */
struct pkthdr {
    struct ethhdr* eth;
    struct iphdr* ipv4;
    struct tcphdr* tcp;

    void* data_begin;
    void* data_end;
    void* data_cursor;
    void* data_tcp_opts; // for opts csum
} __packed;

#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include "stddef.h"
#include "bpf_endian.h"
#include "bpf_helpers.h"
// #include "builtins.h"
#include "compiler.h"
#include "utils.h"
#include "time.h"
#include "metrics.h"
#include "dbg.h"
#include "static_data.h"
#include "eth.h"
#include "ipv4.h"
#include "tcp.h"
#include "dhcp.h"
#include "http.h"
#include "os_filter.h"


#endif /* __BPF_API__ */
