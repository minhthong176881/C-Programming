#ifndef ADAPTER_HEADER
#define ADAPTER_HEADER

#include <pcap.h>
#include <netinet/in.h>
#include <net/ethernet.h>

// #define VCS_DEBUG 1 // Enable debugging

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

#define MTU 1500 // TODO: get exact MTU, may from SYN + SYN/ACK packets with Maximum Segment Size (MSS) info

/* if MTU = 1500, maximum payload length = 1464,  remaining bytes are from VXLAN header */
#define MAX_VXLAN_INNER_LEN (MTU - MIN_IP_HEADER_LENGTH - UDP_HEADER_LENGTH - VXLAN_HEADER_LENGTH)

typedef struct addr_info
{
    u_char mac[ETHER_ADDR_LEN];
    struct in_addr ip;
    struct in_addr netmask;
} addr_info;

int setup_interface(pcap_if_t *alldevs, pcap_t **adhandle, pcap_if_t **dev, int inum, int max);
int setup_filter(pcap_t *adhandle, pcap_if_t *dev, char *packet_filter);
void ifprint(pcap_if_t *d, int num);
char *get_ip_str(const struct sockaddr *sa, char *s, size_t maxlen);
// int GetMacAddress(u_char *mac, IN_ADDR destip);
// int GetIPAddress(pcap_if_t *dev, addr_info *address);
// int GetGateway(struct in_addr ip, IN_ADDR *gatewayip);
// int isSameSubnet(addr_info src, addr_info dst);
// u_short udp_checksum(const u_short *udp_packet, size_t len, IN_ADDR src_ip, IN_ADDR dst_ip);
// u_short ip_checksum(u_short *ptr, int nbytes);

#endif