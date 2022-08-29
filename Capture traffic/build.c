#include <stdio.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "build.h"
#include "capture.h"

size_t MAX_VXLAN_INNER_LEN = DEFAULT_MAX_VXLAN_INNER_LEN;
size_t MTU = DEFAULT_MTU;

int get_mtu(const char *if_name)
{
	FILE *fp;
    int status;
    char output[1024];
	char command[1024];
	char mtu_val[10];

	sprintf(command, "ip link show %s | grep mtu", if_name);

    fp = popen(command, "r");
    if (fp == NULL) return -1;

	int is_mtu = 0;

    while (fgets(output, sizeof(output), fp) != NULL) 
    {
        char *token = strtok(output, " ");
        // loop through the string to extract all other tokens
        while( token != NULL ) {
            token = strtok(NULL, " ");
			if (is_mtu == 1) {
				strcpy(mtu_val, token);
				break;
			}
			if (strcmp(token, "mtu") == 0) is_mtu = 1;
        }
    }

	char *p;
	long res = strtol(mtu_val, &p, 10);

	MTU = res;
	MAX_VXLAN_INNER_LEN = (MTU - MIN_IP_HEADER_LENGTH - UDP_HEADER_LENGTH - VXLAN_HEADER_LENGTH);

    status = pclose(fp);
    if (status == -1) {
        return status;
    } else {
        return res;
    }
}

int build_ethernet_header(u_char *packet, u_char *src_mac, u_char *dst_mac)
{
	ethernet_header *eh;
	if (!packet || !src_mac || !dst_mac)
	{
		fprintf(stderr, "%s err!\n", __FUNCTION__);
		return -1;
	}

	eh = (ethernet_header*)packet;
	memcpy(eh->src_mac, src_mac, ETHER_ADDR_LEN);
	memcpy(eh->dst_mac, dst_mac, ETHER_ADDR_LEN);
	eh->ether_type = htons(IP_FRAMES);

	return 0;
}

int build_IP_header(u_char *packet, size_t packet_len, struct in_addr src_ip, struct in_addr dst_ip, u_short ip_identification, u_short ip_fragement)
{
	if (!packet || packet_len == 0)
	{
		fprintf(stderr, "%s err!\n", __FUNCTION__);
		return -1;
	}

	ip_header *ih;
	ih = (ip_header*)(packet + ETHERNET_HEADER_LENGTH);
	ih->ver_ihl = IP_HEADER_VERION_HEADER_LENGTH;
	ih->tos = 0;
	ih->tlen = htons(packet_len - ETHERNET_HEADER_LENGTH);

	ih->identification = htons(ip_identification);
	ih->flags_fo = htons(ip_fragement);
	
	ih->ttl = IP_HEADER_TTL;
	ih->proto = UDP_PROTOCOL;
	ih->saddr = src_ip;
	ih->daddr = dst_ip;

	// Calculate checksum
	ih->crc = 0;
	ih->crc = ip_checksum((u_short*)ih, sizeof(ip_header));

	return 0;
}

int build_UDP_header(u_char *packet, const u_char *original_pkt_data, size_t original_total_len)
{
	udp_header *uh;
	ip_header *ih;
	u_char *original_uh;
	size_t original_udp_len = original_total_len + VXLAN_HEADER_LENGTH + UDP_HEADER_LENGTH;
	size_t checksum_len = original_udp_len;

	if (!packet)
	{
		fprintf(stderr, "%s err!\n", __FUNCTION__);
		return -1;
	}

	ih = (ip_header*)(packet + ETHERNET_HEADER_LENGTH);
	uh = (udp_header*)(packet + ETHERNET_HEADER_LENGTH + MIN_IP_HEADER_LENGTH);

	uh->sport = htons(UDP_SPORT);
	uh->dport = htons(UDP_DPORT);
	uh->len = htons(original_udp_len);
	uh->crc = 0;

	if (original_total_len > MAX_VXLAN_INNER_LEN) // need flagment
	{
		if ((original_uh = (u_char *)malloc(original_udp_len * sizeof(u_char))) == NULL)
		{
			fprintf(stderr, "[%s] Allocation failed!\n", __FUNCTION__);
			return -1;
		}

		// copy UDP + VxLAN header info
		memcpy(original_uh, packet + ETHERNET_HEADER_LENGTH + MIN_IP_HEADER_LENGTH, UDP_HEADER_LENGTH + VXLAN_HEADER_LENGTH);
		// copy original packet data
		memcpy(original_uh + UDP_HEADER_LENGTH + VXLAN_HEADER_LENGTH, original_pkt_data, original_total_len);
	}
	else
	{
		original_uh = packet + ETHERNET_HEADER_LENGTH + MIN_IP_HEADER_LENGTH;
	}

	uh->crc = udp_checksum((u_short *)original_uh, checksum_len, ih->saddr, ih->daddr);

	if ((original_total_len > MAX_VXLAN_INNER_LEN) && original_uh)
		free(original_uh);

	return 0;
}

u_short ip_checksum(u_short *ptr, int nbytes)
{
	register long sum;
	u_short oddbyte;
	register short answer;

	sum = 0;
	while (nbytes>1) {
		sum += *ptr++;
		nbytes -= 2;
	}
	if (nbytes == 1) {
		oddbyte = 0;
		*((u_char*)&oddbyte) = *(u_char*)ptr;
		sum += oddbyte;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum = sum + (sum >> 16);
	answer = (short)(~sum);

	return(answer);
}

u_short udp_checksum(const u_short *udp_packet, size_t len, struct in_addr src_ip, struct in_addr dst_ip)
{
	u_short *ip_src = (void *)&src_ip, *ip_dst = (void *)&dst_ip;
	u_int sum;
	size_t length = len;

	// Calculate the sum   
	sum = 0;
	while (len > 1)
	{
		sum += *udp_packet++;
		if (sum & 0x80000000)
			sum = (sum & 0xFFFF) + (sum >> 16);
		len -= 2;
	}

	if (len & 1)
		// Add the padding if the packet lenght is odd 
		sum += *((u_char *)udp_packet);

	// Add the pseudo-header
	sum += *(ip_src++);
	sum += *ip_src;

	sum += *(ip_dst++);
	sum += *ip_dst;

	sum += htons(UDP_PROTOCOL);
	sum += htons(length);

	// Add the carries
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	// Return the one's complement of sum 
	return ((u_short)(~sum));
}

int build_VxLAN_header(u_char *packet)
{
	vxlan_header *vxlanh;

	if (!packet)
	{
		fprintf(stderr, "%s err!\n", __FUNCTION__);
		return -1;
	}

	vxlanh = (vxlan_header*)(packet + ETHERNET_HEADER_LENGTH + MIN_IP_HEADER_LENGTH + UDP_HEADER_LENGTH);
	vxlanh->flags_reserved = htons(VXLAN_FLAGS);
	vxlanh->group_policy_id = VXLAN_GROUP_POLICY_ID;
	vxlanh->vni = htonl(VXLAN_VNI);

	return 0;
}

int build_vxlan_payload(u_char *packet, const u_char *pkt_data, size_t payload_len)
{
	u_char *payload;

	if (!packet || !pkt_data)
	{
		fprintf(stderr, "%s err!\n", __FUNCTION__);
		return -1;
	}

	payload = packet + ETHERNET_HEADER_LENGTH + MIN_IP_HEADER_LENGTH + UDP_HEADER_LENGTH + VXLAN_HEADER_LENGTH;
	memcpy(payload, pkt_data, payload_len);

	return 0;
}

int build_payload(u_char *packet, const u_char *pkt_data, size_t payload_len)
{
	u_char *payload;

	if (!packet || !pkt_data)
	{
		fprintf(stderr, "%s err!\n", __FUNCTION__);
		return -1;
	}

	payload = packet + ETHERNET_HEADER_LENGTH + MIN_IP_HEADER_LENGTH;
	memcpy(payload, pkt_data, payload_len);

	return 0;
}

void encapVxLAN(const u_char *pkt_data, addr_info vxlan_src, addr_info vxlan_dst, pcap_t *descr)
{
	ip_header *ih;
	size_t original_packet_len;

	/* Calculate original packet length */
	ih = (ip_header *)(pkt_data + ETHERNET_HEADER_LENGTH);
	original_packet_len = ntohs(ih->tlen) + ETHERNET_HEADER_LENGTH;

	// Fragment packet if it is too large
	if ((original_packet_len) > MAX_VXLAN_INNER_LEN)
		vxlan_fragment_pkt_handler(pkt_data, original_packet_len, vxlan_src, vxlan_dst, descr);
	else
		vxlan_pkt_handler(pkt_data, original_packet_len, vxlan_src, vxlan_dst, descr);

	return;
}

void vxlan_pkt_handler(const u_char *pkt_data, size_t pkt_len, addr_info vxlan_src, addr_info vxlan_dst, pcap_t *descr)
{
	if (!pkt_data)
		return;
	
	build_vxlan_single_pkt(pkt_data, pkt_len, pkt_len, IP_HEADER_ID, IP_HEADER_FLAGS_OFFSET, vxlan_src, vxlan_dst, descr);
	return;
}

int build_vxlan_single_pkt(const u_char *pkt_data, size_t pkt_len, size_t original_total_len, u_short id, u_short fragment, addr_info vxlan_src, addr_info vxlan_dst, pcap_t *descr)
{
	u_char *VxLAN_packet;
	size_t VxLAN_packet_len = ETHERNET_HEADER_LENGTH + MIN_IP_HEADER_LENGTH + UDP_HEADER_LENGTH + VXLAN_HEADER_LENGTH + pkt_len;

	if (!pkt_data)
		return -1;

	/* Build VxLAN packet*/
	VxLAN_packet = (u_char*)malloc(VxLAN_packet_len * sizeof(u_char));

	// Outer Ethernet Header
	if (build_ethernet_header(VxLAN_packet, vxlan_src.mac, vxlan_dst.mac) < 0)
	{
		free(VxLAN_packet);
		return -1;
	}

	// Outer IP Header
	if (build_IP_header(VxLAN_packet, VxLAN_packet_len, vxlan_src.ip, vxlan_dst.ip, id, fragment) < 0)
	{
		free(VxLAN_packet);
		return -1;
	}

	// VxLAN header
	if (build_VxLAN_header(VxLAN_packet) < 0)
	{
		free(VxLAN_packet);
		return -1;
	}

	// Payload
	if (build_vxlan_payload(VxLAN_packet, pkt_data, pkt_len) < 0)
	{
		free(VxLAN_packet);
		return -1;
	}

	// Outer UDP Header: udp header length + checksum still keeps original info eventhough it is fragemented.
	if (build_UDP_header(VxLAN_packet, pkt_data, original_total_len) < 0)
	{
		free(VxLAN_packet);
		return -1;
	}

	/* Send packet */
	if (pcap_sendpacket(descr,	// Adapter
		VxLAN_packet, // buffer with the packet
		VxLAN_packet_len // size
		) != 0)
	{
		fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(descr));
		free(VxLAN_packet);
		return - 1;
	}

	free(VxLAN_packet);
	return 0;
}

int build_single_fragment_pkt(const u_char *pkt_data, size_t pkt_len, u_short id, u_short fragment, addr_info vxlan_src, addr_info vxlan_dst, pcap_t *descr)
{
	u_char *packet;
	size_t total_pkt_len = ETHERNET_HEADER_LENGTH + MIN_IP_HEADER_LENGTH + pkt_len;

	if (!pkt_data)
		return -1;

	/* Build VxLAN packet*/
	packet = (u_char*)malloc(total_pkt_len * sizeof(u_char));

	// Ethernet Header
	if (build_ethernet_header(packet, vxlan_src.mac, vxlan_dst.mac) < 0)
	{
		free(packet);
		return -1;
	}

	// IP Header
	if (build_IP_header(packet, total_pkt_len, vxlan_src.ip, vxlan_dst.ip, id, fragment) < 0)
	{
		free(packet);
		return -1;
	}

	// Payload
	if (build_payload(packet, pkt_data, pkt_len) < 0)
	{
		free(packet);
		return -1;
	}

	/* Send packet */
	if (pcap_sendpacket(descr,	// Adapter
		packet, // buffer with the packet
		total_pkt_len // size
		) != 0)
	{
		fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(descr));
		free(packet);
		return -1;
	}

	free(packet);
	return 0;
}


u_short calculate_id()
{
	static u_short offset = 0;

	if (offset < 65535)
		offset += 1;
	else
		offset = 0;

	srand((u_int)time(0));
	return (u_short)((rand() + offset) % 65536);
}

u_short calculate_fragment(u_short more_fragment, u_short offset)
{
	return (u_short)((more_fragment << 13) + (offset / 8));
}

void vxlan_fragment_pkt_handler(const u_char *pkt_data, size_t pkt_len, addr_info vxlan_src, addr_info vxlan_dst, pcap_t *descr)
{
	size_t fragment_pkt_len, remaining_pkt_len;
	u_short ip_header_id;
	u_short ip_header_fragment, fragment_offset;
	const u_char *fragment_pkt_data;

	if (!pkt_data)
		return;

	ip_header_id = calculate_id();
	fragment_offset = 0;

	/* 1. Build 1st packet */
	fragment_pkt_data = pkt_data;
	fragment_pkt_len = MTU - MIN_IP_HEADER_LENGTH - UDP_HEADER_LENGTH - VXLAN_HEADER_LENGTH;
	ip_header_fragment = calculate_fragment(1, fragment_offset);

	if (build_vxlan_single_pkt(fragment_pkt_data, fragment_pkt_len, pkt_len, ip_header_id, ip_header_fragment, vxlan_src, vxlan_dst, descr) < 0)
		return;

	/* 2. Build middle packets */
	remaining_pkt_len = pkt_len - fragment_pkt_len;
	while (remaining_pkt_len > (MTU - MIN_IP_HEADER_LENGTH))
	{
		fragment_pkt_data += fragment_pkt_len;
		fragment_pkt_len = MTU - MIN_IP_HEADER_LENGTH;
		fragment_offset += (MTU - MIN_IP_HEADER_LENGTH);
		ip_header_fragment = calculate_fragment(1, fragment_offset);

		if (build_single_fragment_pkt(fragment_pkt_data, fragment_pkt_len, ip_header_id, ip_header_fragment, vxlan_src, vxlan_dst, descr) < 0)
			return;

		remaining_pkt_len -= fragment_pkt_len;
	}

	/* Build last packet */
	fragment_pkt_data += fragment_pkt_len;
	fragment_pkt_len = remaining_pkt_len;
	fragment_offset += (MTU - MIN_IP_HEADER_LENGTH);
	ip_header_fragment = calculate_fragment(0, fragment_offset);

	build_single_fragment_pkt(fragment_pkt_data, fragment_pkt_len, ip_header_id, ip_header_fragment, vxlan_src, vxlan_dst, descr);
	return;
}