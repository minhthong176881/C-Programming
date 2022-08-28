#ifndef __HELPER_H__
#define __HELPER_H__

#include <pcap.h>

#include "adapter.h"

// Define a struct for ARP header
typedef struct _arp_hdr arp_hdr;
struct _arp_hdr
{
    uint16_t htype;
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
    uint16_t opcode;
    uint8_t sender_mac[6];
    uint8_t sender_ip[4];
    uint8_t target_mac[6];
    uint8_t target_ip[4];
};

// Define some constants.
#define ETH_HDRLEN 14   // Ethernet header length
#define IP4_HDRLEN 20   // IPv4 header length
#define ARP_HDRLEN 28   // ARP header length
#define ARPOP_REQUEST 1 // Taken from <linux/if_arp.h>
#define ARPOP_REPLY 2

void signal_handler(int signal);
char *get_signal_name(int signal);
void free_resource(pcap_if_t **alldevs, pcap_t *mirror_descr, pcap_t *send_descr);
int setup_interface(pcap_if_t *alldevs, pcap_t **descr, pcap_if_t **dev, int inum, int max);
char *allocate_strmem(int len);
uint8_t *allocate_ustrmem(int len);
int send_arp(pcap_if_t *dev, char *src_ip_addr, char *dst_ip, u_int *src_mac_addr, u_int *dst_mac_addr);

#endif