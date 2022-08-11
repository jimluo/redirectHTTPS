#ifndef __LIB_DHCP_H_
#define __LIB_DHCP_H_

#include "api.h"

#define DHCP_SNAME_LEN 64
#define DHCP_FILE_LEN 128

#define DHO_DHCP_AGENT_OPTIONS 82
#define RAI_CIRCUIT_ID 1
#define RAI_REMOTE_ID 2
#define RAI_OPTION_LEN 2

#define DEST_PORT 67  /* UDP destination port for dhcp */
#define MAX_BYTES 280 /* Max bytes supported by xdp load/store apis */

/* structure for sub-options in option 82*/
struct sub_option {
	__u8 option_id;
	__u8 len;
	__u16 val;
};

/*structure for dhcp option 82 */
struct dhcp_option_82 {
	__u8 t;
	__u8 len;
	struct sub_option circuit_id;
	struct sub_option remote_id;
};

struct dhcp_packet {
	__u8 op; /* 0: Message opcode/type */
	__u8 htype; /* 1: Hardware addr type (net/if_types.h) */
	__u8 hlen; /* 2: Hardware addr length */
	__u8 hops; /* 3: Number of relay agent hops from client */
	__u32 xid; /* 4: Transaction ID */
	__u16 secs; /* 8: Seconds since client started looking */
	__u16 flags; /* 10: Flag bits */
	struct in_addr ciaddr; /* 12: Client IP address (if already in use) */
	struct in_addr yiaddr; /* 16: Client IP address */
	struct in_addr siaddr; /* 18: IP address of next server to talk to */
	struct in_addr giaddr; /* 20: DHCP relay agent IP address */
	unsigned char chaddr[16]; /* 24: Client hardware address */
	char sname[DHCP_SNAME_LEN]; /* 40: Server name */
	char file[DHCP_FILE_LEN]; /* 104: Boot filename */
	__u32 cookie; /* 232: Magic cookie */
	unsigned char options[0];
	/* 236: Optional parameters
              (actual length dependent on MTU). */
};

// Inserts DHCP option 82 into the received dhcp packet at the specified offset.
// BPF_INLINE int write_dhcp_option(void *ctx, int offset, struct collect_vlans *vlans)
// {
// 	struct dhcp_option_82 option;

// 	option.t = DHO_DHCP_AGENT_OPTIONS;
// 	option.len = 8;
// 	option.circuit_id.option_id = RAI_CIRCUIT_ID;
// 	option.circuit_id.len = RAI_OPTION_LEN;
// 	option.circuit_id.val = bpf_htons(vlans->id[0]);
// 	option.remote_id.option_id = RAI_REMOTE_ID;
// 	option.remote_id.len = RAI_OPTION_LEN;
// 	option.remote_id.val = bpf_htons(vlans->id[1]);

// 	return xdp_store_bytes(ctx, offset, &option, sizeof(option), 0);
// }


/* Offset to DHCP Options part of the packet */
#define static_offset                                                          \
	sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + \
		offsetof(struct dhcp_packet, options)

/* Delta value to be adjusted at xdp head*/
#define delta sizeof(struct dhcp_option_82)

/* buf needs to be a static global var because the verifier won't allow
 * unaligned stack accesses
*/
// static __u8 buf[static_offset + VLAN_MAX_DEPTH * sizeof(struct vlan_hdr)];

/* XDP program for parsing the DHCP packet and inserting the option 82*/
BPF_INLINE int dhcp_filter_deviceinfo(struct xdp_md* ctx, struct pkthdr* pkt)
{
	// __u32 *dhcp_srv;
	// int rc = XDP_PASS;
	// __u16 offset = static_offset;
	// __u16 ip_offset = 0;
	// int i = 0;

	/* Check at least two vlan tags are present */
	// if (vlans.id[1] == 0)
	// 	goto out;

	// if (xdp_load_bytes(ctx, 0, buf, static_offset))
	// 	goto out;

	// for (i = 0; i < VLAN_MAX_DEPTH; i++) {
		// if (vlans.id[i]) {
			// if (xdp_load_bytes(ctx, offset, buf + offset, 4))
			// 	goto out;
		// 	offset += 4;
		// }
	// }

	/* adjusting the packet head by delta size to insert option82 */
	// if (bpf_xdp_adjust_head(ctx, 0 - delta) < 0)
	// 	return XDP_ABORTED;

	// data_end = (void *)(long)ctx->data_end;
	// data = (void *)(long)ctx->data;

	// if (data + offset > data_end)
	// 	return XDP_ABORTED;

	// if (xdp_store_bytes(ctx, 0, buf, static_offset, 0))
	// 	return XDP_ABORTED;

	// if (offset > static_offset) {
	// 	offset = static_offset;
	// 	for (i = 0; i < VLAN_MAX_DEPTH; i++) {
	// 		if (vlans.id[i]) {
	// 			if (xdp_store_bytes(ctx, offset, buf + offset,
	// 					    4, 0))
	// 				return XDP_ABORTED;
	// 			offset += 4;
	// 		}
	// 	}
	// }

	// if (write_dhcp_option(ctx, offset, &vlans))
	// 	return XDP_ABORTED;
	return 0;
}

#endif // __LIB_DHCP_H_
