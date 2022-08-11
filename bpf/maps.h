#ifndef __redirectHTTPS_MAPS_H
#define __redirectHTTPS_MAPS_H

#include <linux/in.h>
#include <linux/ip.h>

#define SIZE_REDIRECT_URL 120

struct config {
    __u8 redirect_url_linux[SIZE_REDIRECT_URL];
    __be32 ip_host;
    __u8 machost[ETH_ALEN];
} __packed;

struct BPF_MAP config_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct config),
    .max_entries = 1,
};

struct BPF_MAP token_user_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__be32),	// IP
	.value_size = sizeof(__u32),	// os type
	.max_entries = 1024,
};

// // Portal URL
// struct redirect_url {
//     char url[64];
// };

// // Portal配置MAP
// struct BPF_MAP redirect_map = {
//     .type = BPF_MAP_TYPE_ARRAY,
//     .key_size = sizeof(__u32),
//     .value_size = sizeof(struct redirect_url),
//     .max_entries = 8,
// };

// 认证用户MAP
// struct BPF_MAP authuser_map = {
// 	.type = BPF_MAP_TYPE_HASH,
// 	.key_size = sizeof(__be32), // IP
// 	.value_size = sizeof(__u32), // 角色ID
// 	.max_entries = 128,
// };

// 角色安全域 黑白名单
// struct role_domain {
// 	__u32 allow_domain[8]; // 存储security_map的key
// 	__u32 deny_domain[8];
// };

// 角色MAP
// struct BPF_MAP role_map = {
// 	.type = BPF_MAP_TYPE_HASH,
// 	.key_size = sizeof(__u32),
// 	.value_size = sizeof(struct role_domain),
// 	.max_entries = 64,
// };

// 安全域IP范围
// struct domain_range {
// 	__u32 l, r;
// };

// 安全域MAP
// struct BPF_MAP security_map = {
// 	.type = BPF_MAP_TYPE_HASH,
// 	.key_size = sizeof(__u32),
// 	.value_size = sizeof(struct domain_range) * 8,
// 	.max_entries = 64,
// };

// struct violation {
// 	__u64 timeat;
// 	__be32 ip_src;
// 	__be32 ip_dst;
// 	__be16 port_src;
// 	__be16 port_dst;
// 	__u32 src_or_dst;
// 	__u8 mac_dst[6];
// 	__u8 mac_src[6];
// };

// 阻断记录MAP
// struct BPF_MAP violation_map = {
// 	.type = BPF_MAP_TYPE_HASH,
// 	.key_size = sizeof(__be32), // ip
// 	.value_size = sizeof(struct violation),
// 	.max_entries = 64
// };

#endif
