#ifndef __CAPTURE_H__
#define __CAPTURE_H__

#include <pcap.h>
#include <netinet/if_ether.h>
#include <sys/socket.h>
#include <netinet/in.h>

struct ip_header {
	u_int8_t	ip_vhl;		/* header length, version */
#define IP_V(ip)	(((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip)	((ip)->ip_vhl & 0x0f)
	u_int8_t	ip_tos;		/* type of service */
	u_int16_t	ip_len;		/* total length */
	u_int16_t	ip_id;		/* identification */
	u_int16_t	ip_off;		/* fragment offset field */
#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
	u_int8_t	ip_ttl;		/* time to live */
	u_int8_t	ip_p;		/* protocol */
	u_int16_t	ip_sum;		/* checksum */
	struct	in_addr ip_src,ip_dst;	/* source and dest address */
};

void capture();
void get_devices(pcap_if_t *alldevs);
void packet_handler(u_char *agrs, const struct pcap_pkthdr *header, const u_char *packet);
void print_packet_info(u_char *agrs, const struct pcap_pkthdr *header, const u_char *pkt_data);
void parse_device(pcap_if_t *dev, int num);
u_int16_t parse_ethernet_header(u_char *agrs, const struct pcap_pkthdr *header, const u_char *packet);
u_char* parse_IP(u_char *agrs, const struct pcap_pkthdr *header, const u_char *packet);

#endif