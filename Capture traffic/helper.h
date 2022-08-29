#ifndef __HELPER_H__
#define __HELPER_H__

#include <pcap.h>

#ifdef VCS_DEBUG
#define VCS_PRINT(fmt, ...)       \
    do                            \
    {                             \
        printf(fmt, __VA_ARGS__); \
    } while (0)
#define VCS_PRINT_ERR(fmt, ...)            \
    do                                     \
    {                                      \
        fprintf(stderr, fmt, __VA_ARGS__); \
    } while (0)
#else
#define VCS_PRINT(fmt, ...)
#define VCS_PRINT_ERR(fmt, ...)
#endif

#define ETHERNET_HEADER_LENGTH 14
#define MIN_IP_HEADER_LENGTH 20
#define UDP_HEADER_LENGTH 8
#define VXLAN_HEADER_LENGTH 8
// #define ETHER_ADDR_LEN			6

#define DEFAULT_FILTER "not host 8.8.8.8"
#define DEFAULT_SENSOR_IP "8.8.8.8" //"192.168.234.129"
#define IP_FRAMES 0x0800
#define IP_HEADER_VERION_HEADER_LENGTH 0x45 // Version: 4 - Header: 5x4=20
#define IP_HEADER_ID 0x0002
#define IP_HEADER_TTL 64
#define IP_HEADER_FLAGS_OFFSET 0x0000 // 0x4000: Don't fragment
#define UDP_PROTOCOL 0x11
#define UDP_DPORT 4789
#define UDP_SPORT 14789

#define VXLAN_FLAGS 0x0800 // VXLAN Network ID: 1
#define VXLAN_GROUP_POLICY_ID 0x0000
#define VXLAN_VNI ((108 << 8) + 0x00) // VXLAN ID: 108; Reserved2: 0

#define DEFAULT_MTU 1500 // TODO: get exact MTU, may from SYN + SYN/ACK packets with Maximum Segment Size (MSS) info

/* if MTU = 1500, maximum payload length = 1464,  remaining bytes are from VXLAN header */
#define DEFAULT_MAX_VXLAN_INNER_LEN (DEFAULT_MTU - MIN_IP_HEADER_LENGTH - UDP_HEADER_LENGTH - VXLAN_HEADER_LENGTH)

typedef struct addr_info
{
    u_char mac[ETHER_ADDR_LEN];
    struct in_addr ip;
    struct in_addr netmask;
} addr_info;

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
char *get_ip_str(const struct sockaddr *sa, char *s, size_t maxlen);
int is_same_subnet(addr_info src, addr_info dst);
void free_resource(pcap_if_t **alldevs, pcap_t *mirror_descr, pcap_t *send_descr);
int setup_interface(pcap_if_t *alldevs, pcap_t **descr, pcap_if_t **dev, int inum, int max);
char *allocate_strmem(int len);
uint8_t *allocate_ustrmem(int len);
int send_arp(pcap_if_t *dev, char *src_ip_addr, char *dst_ip, u_char *src_mac_addr, u_char *dst_mac_addr);

#endif