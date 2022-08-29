#ifndef __CAPTURE_H__
#define __CAPTURE_H__

#include <pcap.h>
#include <netinet/if_ether.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "helper.h"

int setup_capture(pcap_if_t *alldevs, pcap_t *mirror_descr, pcap_t *send_descr, pcap_if_t *dev1, pcap_if_t *dev2);
int get_ip_address(pcap_if_t *dev, addr_info *address);
int get_gateway_address(struct in_addr ip, char *gatewayip);
int get_devices(pcap_if_t *alldevs);
void parse_device(pcap_if_t *dev, int num);
int setup_filter(pcap_t *adhandle, pcap_if_t *dev, char *packet_filter);

#endif