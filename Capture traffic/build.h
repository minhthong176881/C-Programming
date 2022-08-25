#ifndef __BUILD_H__
#define __BUILD_H__
#include <pcap.h>

int build_ethernet_header(u_char *packet, u_char *src_mac, u_char *dst_mac);
// int build_IP_header(u_char *packet, size_t packet_len, IN_ADDR src_ip, IN_ADDR dst_ip);
void encapVxLAN(const u_char *pkt_data);

#endif