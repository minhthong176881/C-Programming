#ifndef __BUILD_H__
#define __BUILD_H__
#include <pcap.h>
#include <netinet/in.h>
#include <net/ethernet.h>

#include "helper.h"

/* Ethernet header */
typedef struct ethernet_header
{
	u_char dst_mac[ETHER_ADDR_LEN];
	u_char src_mac[ETHER_ADDR_LEN];
	u_short ether_type;
} ethernet_header;

/* IPv4 header */
typedef struct ip_header
{
	u_char	ver_ihl;		// Version (4 bits) + Internet header length (4 bits)
	u_char	tos;			// Type of service 
	u_short tlen;			// Total length 
	u_short identification; // Identification
	u_short flags_fo;		// Flags (3 bits) + Fragment offset (13 bits)
	u_char	ttl;			// Time to live
	u_char	proto;			// Protocol
	u_short crc;			// Header checksum
	struct in_addr	saddr;		// Source address
	struct in_addr	daddr;		// Destination address
	//	u_int	op_pad;			// Option + Padding
} ip_header;

/* UDP header*/
typedef struct udp_header
{
	u_short sport;			// Source port
	u_short dport;			// Destination port
	u_short len;			// Datagram length
	u_short crc;			// Checksum
} udp_header;

/* VxLAN header */
typedef struct vxlan_header
{
	u_short flags_reserved;
	u_short group_policy_id;
	u_int vni;				// 24 bit VNI + 8 bit reserved 2
} vxlan_header;

int get_mtu(const char *if_name);
int build_ethernet_header(u_char *packet, u_char *src_mac, u_char *dst_mac);
int build_IP_header(u_char *packet, size_t packet_len, struct in_addr src_ip, struct in_addr dst_ip, u_short ip_identification, u_short ip_fragement);
int build_UDP_header(u_char *packet, const u_char *original_pkt_data, size_t original_total_len);
int build_VxLAN_header(u_char *packet);
int build_vxlan_payload(u_char *packet, const u_char *pkt_data, size_t payload_len);
void encapVxLAN(const u_char *pkt_data, addr_info vxlan_src, addr_info vxlan_dst, pcap_t *descr);
void vxlan_pkt_handler(const u_char *pkt_data, size_t pkt_len, addr_info vxlan_src, addr_info vxlan_dst, pcap_t *desc);
void vxlan_fragment_pkt_handler(const u_char *pkt_data, size_t pkt_len, addr_info vxlan_src, addr_info vxlan_dst, pcap_t *descr);
int build_single_fragment_pkt(const u_char *pkt_data, size_t pkt_len, u_short id, u_short fragment, addr_info vxlan_src, addr_info vxlan_dst, pcap_t *descr);
int build_vxlan_single_pkt(const u_char *pkt_data, size_t pkt_len, size_t original_total_len, u_short id, u_short fragment, addr_info vxlan_src, addr_info vxlan_dst, pcap_t *descr);
u_short calculate_id();
u_short ip_checksum(u_short *ptr, int nbytes);
u_short udp_checksum(const u_short *udp_packet, size_t len, struct in_addr src_ip, struct in_addr dst_ip);
u_short calculate_fragment(u_short more_fragment, u_short offset);

#endif