#include <stdio.h>
#include <pcap.h>

#include "build.h"
#include "capture.h"
#include "adapter.h"

void encapVxLAN(const u_char *pkt_data)
{
	// ip_header *ih;
	// size_t original_packet_len;

	// /* Calculate original packet length */
	// ih = (ip_header *)(pkt_data + ETHERNET_HEADER_LENGTH);
	// original_packet_len = ntohs(ih->tlen) + ETHERNET_HEADER_LENGTH;

	// // Fragment packet if it is too large
	// if ((original_packet_len) > MAX_VXLAN_INNER_LEN)
	// 	vxlan_fragment_pkt_handler(pkt_data, original_packet_len);
	// else
	// 	vxlan_pkt_handler(pkt_data, original_packet_len);

	// return;
}

void vxlan_pkt_handler(const u_char *pkt_data, size_t pkt_len)
{
	// if (!pkt_data)
	// 	return;
	
	// build_vxlan_single_pkt(pkt_data, pkt_len, pkt_len, IP_HEADER_ID, IP_HEADER_FLAGS_OFFSET);
	// return;
}