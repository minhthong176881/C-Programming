#ifndef __BUILD_H__
#define __BUILD_H__
#include <pcap.h>

int build_ethernet_header(u_char *packet, u_char *src_mac, u_char *dst_mac);
int build_IP_header(u_char *packet, size_t packet_len, struct in_addr src_ip, struct in_addr dst_ip, u_short ip_identification, u_short ip_fragement);
int build_UDP_header(u_char *packet, size_t original_total_len);
int build_VxLAN_header(u_char *packet);
int build_vxlan_payload(u_char *packet, const u_char *pkt_data, size_t payload_len);
void encapVxLAN(const u_char *pkt_data);
void vxlan_pkt_handler(const u_char *pkt_data, size_t pkt_len);
void vxlan_fragment_pkt_handler(const u_char *pkt_data, size_t pkt_len);
int build_single_fragment_pkt(const u_char *pkt_data, size_t pkt_len, u_short id, u_short fragment);
int build_vxlan_single_pkt(const u_char *pkt_data, size_t pkt_len, size_t original_total_len, u_short id, u_short fragment);
u_short calculate_id();
u_short calculate_fragment(u_short more_fragment, u_short offset);

#endif