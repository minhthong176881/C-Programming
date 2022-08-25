/**************************************************************************************************
	- Author: tantv12@viettel.com.vn
	- Version: 1.0.0
	- Date: 08/22/2022
	- Description:
	This program is to capture packets from an interface, encapsulate them into VxLAN header,
	and then send encapsulated packets to monitor device using this interface or others.

	TO-DO:
		- Build mirror filters
		- MTU is being fixed as 1500
		- Source port is being fixed as 14789
		- When fragment packet, identification is being calculated by random function
		=> This value maybe occupied by others
**************************************************************************************************/

#ifdef _MSC_VER
/*
* we do not want the warnings about the old deprecated and unsecure CRT functions
* since these examples can be compiled under *nix as well
*/
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <time.h>
#include "adapter.h"
#include <signal.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

#ifdef _WIN32
#include <tchar.h>
BOOL LoadNpcapDlls()
{
	_TCHAR npcap_dir[512];
	UINT len;
	len = GetSystemDirectory(npcap_dir, 480);
	if (!len) {
		fprintf(stderr, "Error in GetSystemDirectory: %x", GetLastError());
		return FALSE;
	}
	_tcscat_s(npcap_dir, 512, _T("\\Npcap"));
	if (SetDllDirectory(npcap_dir) == 0) {
		fprintf(stderr, "Error in SetDllDirectory: %x", GetLastError());
		return FALSE;
	}
	return TRUE;
}
#endif

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
void encapVxLAN(const u_char *pkt_data);
void free_resource(pcap_if_t **alldevs);
void signalHandler(int signal);

BOOL stop_capture = FALSE;
pcap_t *adhandle1 = NULL, *adhandle2 = NULL;
pcap_if_t *dev1 = NULL, *dev2 = NULL;
addr_info vxlan_src, vxlan_dst;

int main()
{
	pcap_if_t *alldevs;
	pcap_if_t *dev;
	int inum1, inum2;
	int i = 0;
	char errbuf[PCAP_ERRBUF_SIZE];
	char sensor_ip[32], packet_filter[256];;
	
#ifdef _WIN32
	/* Load Npcap and its functions. */
	if (!LoadNpcapDlls())
	{
		fprintf(stderr, "Couldn't load Npcap\n");
		exit(1);
	}
#endif

	signal(SIGINT, signalHandler);
	signal(SIGTERM, signalHandler);
	signal(SIGABRT, signalHandler);

	/* Build sensor param */
	memset(sensor_ip, 0, sizeof(sensor_ip));
	printf("Enter sensor IP (%s):", DEFAULT_SENSOR_IP);
	scanf("%s", sensor_ip);

	if (inet_pton(AF_INET, sensor_ip, &(vxlan_dst.ip)) < 1)
	{
		fprintf(stderr, "Sensor IP is invalid!\n");
		return -1;
	}

	_snprintf(packet_filter, sizeof(packet_filter), "not host %s", sensor_ip);

	/* Retrieve the device list */
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* Scan the list printing every entry */

	for (dev = alldevs; dev; dev = dev->next)
	{
		ifprint(dev, ++i);
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure Npcap is installed.\n");
		return -1;
	}

	/* Monitor interface */
	printf("Enter the monitor interface number (1-%d):", i);
	scanf("%d", &inum1);

	if (setup_interface(alldevs, &adhandle1, &dev1, inum1, i) < 0)
	{
		free_resource(&alldevs);
		return -1;
	}

	VCS_PRINT("\nSetup monitor interface done!\n");

	/* Setup filter */
	if (setup_filter(adhandle1, dev1, packet_filter) < 0)
	{
		free_resource(&alldevs);
		return -1;
	}

	VCS_PRINT("\nSetup filter done!\n");

	/* Sending interface */
	printf("Enter the sending interface number (1-%d):", i);
	scanf("%d", &inum2);

	if (inum2 != inum1)
	{
		if (setup_interface(alldevs, &adhandle2, &dev2, inum2, i) < 0)
		{
			free_resource(&alldevs);
			return -1;
		}
	}
	else
	{
		VCS_PRINT("We are using same interface to capture ingress/egress packets and send them to sensor\n");
		adhandle2 = adhandle1;
		dev2 = dev1;
	}

	if (GetIPAddress(dev2, &vxlan_src) < 0)
	{
		free_resource(&alldevs);
		return -1;
	}

	if (GetMacAddress(vxlan_src.mac, vxlan_src.ip) < 0)
	{
		free_resource(&alldevs);
		return -1;
	}

	printf("\nSending IP: %d:%d:%d:%d, MAC: %02X-%02X-%02X-%02X-%02X-%02X\n",
		vxlan_src.ip.S_un.S_un_b.s_b1, vxlan_src.ip.S_un.S_un_b.s_b2, vxlan_src.ip.S_un.S_un_b.s_b3, vxlan_src.ip.S_un.S_un_b.s_b4,
		vxlan_src.mac[0], vxlan_src.mac[1], vxlan_src.mac[2], vxlan_src.mac[3], vxlan_src.mac[4], vxlan_src.mac[5]);

	VCS_PRINT("Setup sending interface done!\n");

	// If sending interface and sensor are not in same subnet => Send packet to Default gw
	if (isSameSubnet(vxlan_src, vxlan_dst) == FALSE)
	{
		IN_ADDR gatewayIP;

		if (GetGateway(vxlan_src.ip, &gatewayIP) < 0)
		{
			free_resource(&alldevs);
			return -1;
		}

		if (GetMacAddress(vxlan_dst.mac, gatewayIP) < 0)
		{
			free_resource(&alldevs);
			return -1;
		}
	}
	//  If sending interface and sensor are in same subnet => Send packet directly to sensor IP
	else if(GetMacAddress(vxlan_dst.mac, vxlan_dst.ip) < 0)
	{
		free_resource(&alldevs);
		return -1;
	}

	printf("Sensor IP: %d:%d:%d:%d, MAC: %02X-%02X-%02X-%02X-%02X-%02X\n",
		vxlan_dst.ip.S_un.S_un_b.s_b1, vxlan_dst.ip.S_un.S_un_b.s_b2, vxlan_dst.ip.S_un.S_un_b.s_b3, vxlan_dst.ip.S_un.S_un_b.s_b4,
		vxlan_dst.mac[0], vxlan_dst.mac[1], vxlan_dst.mac[2], vxlan_dst.mac[3], vxlan_dst.mac[4], vxlan_dst.mac[5]);

	printf("Mirroring packet filter: %s\n", packet_filter);

	printf("\nListening on monitor interface %s...\n", dev1->description);
	/* start the capture */
	pcap_loop(adhandle1, 0, packet_handler, NULL);

	free_resource(&alldevs);
	return 0;
}

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
#ifdef VCS_DEBUG
	struct tm *ltime;
	char timestr[16];
	ip_header *ih;
	udp_header *uh;
	u_int ip_len;
	u_short sport, dport;
	time_t local_tv_sec;

	/*
	* unused parameter
	*/
	(VOID)(param);

	/* convert the timestamp to readable format */
	local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

	/* print timestamp and length of the packet */
	printf("%s.%.6d len:%d ", timestr, header->ts.tv_usec, header->len);

	/* retireve the position of the ip header */
	ih = (ip_header *)(pkt_data +
		ETHERNET_HEADER_LENGTH); //length of ethernet header

	/* retireve the position of the udp header */
	ip_len = (ih->ver_ihl & 0x0f) * 4;
	uh = (udp_header *)((u_char*)ih + ip_len);

	/* convert from network byte order to host byte order */
	sport = ntohs(uh->sport);
	dport = ntohs(uh->dport);

	/* print ip addresses and udp ports */
	VCS_PRINT("%d.%d.%d.%d.%d -> %d.%d.%d.%d.%d\n",
		ih->saddr.S_un.S_un_b.s_b1,
		ih->saddr.S_un.S_un_b.s_b2,
		ih->saddr.S_un.S_un_b.s_b3,
		ih->saddr.S_un.S_un_b.s_b4,
		sport,
		ih->daddr.S_un.S_un_b.s_b1,
		ih->daddr.S_un.S_un_b.s_b2,
		ih->daddr.S_un.S_un_b.s_b3,
		ih->daddr.S_un.S_un_b.s_b4,
		dport);

	VCS_PRINT("Captured packet length: %d\n", header->len);
#endif

	encapVxLAN(pkt_data);
	return;
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

/* Risk: id from this function can be occupied by others in advance */
/* TODO: fix it */
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

int build_IP_header(u_char *packet, size_t packet_len, IN_ADDR src_ip, IN_ADDR dst_ip, u_short ip_identification, u_short ip_fragement)
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

int build_UDP_header(u_char *packet, size_t original_total_len)
{
	udp_header *uh;
	ip_header *ih;

	if (!packet)
	{
		fprintf(stderr, "%s err!\n", __FUNCTION__);
		return -1;
	}

	ih = (ip_header*)(packet + ETHERNET_HEADER_LENGTH);
	uh = (udp_header*)(packet + ETHERNET_HEADER_LENGTH + MIN_IP_HEADER_LENGTH);

	uh->sport = htons(UDP_SPORT);
	uh->dport = htons(UDP_DPORT);
	uh->len = htons(original_total_len + VXLAN_HEADER_LENGTH + UDP_HEADER_LENGTH);
	uh->crc = 0;
	uh->crc = udp_checksum((u_short *)uh, UDP_HEADER_LENGTH, ih->saddr, ih->daddr);

	return 0;
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

/*
build_single_fragment_pkt(): build fragment packet
- pkt_data: fragment data
- pkt_len: length of fragment data
- id: ip header identificatin
- fragment: flags + offset
*/

int build_single_fragment_pkt(const u_char *pkt_data, size_t pkt_len, u_short id, u_short fragment)
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
	if (pcap_sendpacket(adhandle2,	// Adapter
		packet, // buffer with the packet
		total_pkt_len // size
		) != 0)
	{
		fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(adhandle2));
		free(packet);
		return -1;
	}

	free(packet);
	return 0;
}

/*
build_vxlan_single_pkt(): encapsulate VxLAN to original packet
- pkt_data: original packet
	+ ethernet header
	+ IP header
	+ payload
- pkt_len: length of packet need to be sent
- original_total_len: total original packet length
- id: ip header identificatin
- fragment: flags + offset
*/

int build_vxlan_single_pkt(const u_char *pkt_data, size_t pkt_len, size_t original_total_len, u_short id, u_short fragment)
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

	// Outer UDP Header: udp header length still keeps original packet length eventhough it is fragemented.
	if (build_UDP_header(VxLAN_packet, original_total_len) < 0)
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

	/* Send packet */
	if (pcap_sendpacket(adhandle2,	// Adapter
		VxLAN_packet, // buffer with the packet
		VxLAN_packet_len // size
		) != 0)
	{
		fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(adhandle2));
		free(VxLAN_packet);
		return - 1;
	}

	free(VxLAN_packet);
	return 0;
}

void vxlan_pkt_handler(const u_char *pkt_data, size_t pkt_len)
{
	if (!pkt_data)
		return;
	
	build_vxlan_single_pkt(pkt_data, pkt_len, pkt_len, IP_HEADER_ID, IP_HEADER_FLAGS_OFFSET);
	return;
}

/*vxlan_fragment_pkt_handler: fragment packet and send them to sensor 
- pkt_data: original packet
		+ ethernet header
		+ IP header
		+ payload
- pkt_len: length of original packet

Example: pkt_len = 3000, MTU = 1500
=> 1st packet including VxLAN: 20 bytes outer IP + 1480 bytes (8 bytes outer UDP + 8 bytes VxLAN + 1464 pkt_len)
	IP header:
		+ Identification: A
		+ More Fragment: 1
		+ Fragment Offset: 0

=> 2nd packet: 20 bytes outer IP + 1480 pkt_len
	IP header:
		+ Identification: A
		+ More Fragment: 1
		+ Fragment Offset: 1480
	
=> 3rd packet: 20 bytes outer IP + 56 pkt_len
	IP header:
		+ Identification: A
		+ More Fragment: 0
		+ Fragment Offset: 2960
*/

void vxlan_fragment_pkt_handler(const u_char *pkt_data, size_t pkt_len)
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

	if (build_vxlan_single_pkt(fragment_pkt_data, fragment_pkt_len, pkt_len, ip_header_id, ip_header_fragment) < 0)
		return;

	/* 2. Build middle packets */
	remaining_pkt_len = pkt_len - fragment_pkt_len;
	while (remaining_pkt_len > (MTU - MIN_IP_HEADER_LENGTH))
	{
		fragment_pkt_data += fragment_pkt_len;
		fragment_pkt_len = MTU - MIN_IP_HEADER_LENGTH;
		fragment_offset += (MTU - MIN_IP_HEADER_LENGTH);
		ip_header_fragment = calculate_fragment(1, fragment_offset);

		if (build_single_fragment_pkt(fragment_pkt_data, fragment_pkt_len, ip_header_id, ip_header_fragment) < 0)
			return;

		remaining_pkt_len -= fragment_pkt_len;
	}

	/* Build last packet */
	fragment_pkt_data += fragment_pkt_len;
	fragment_pkt_len = remaining_pkt_len;
	fragment_offset += (MTU - MIN_IP_HEADER_LENGTH);
	ip_header_fragment = calculate_fragment(0, fragment_offset);

	build_single_fragment_pkt(fragment_pkt_data, fragment_pkt_len, ip_header_id, ip_header_fragment);
	return;
}

/*
Outer Ethernet Header | Outer IP header | Outer UDP header | VxLAN header | Original payload
		14 bytes			20 bytes			8 bytes			8 bytes
*/

void encapVxLAN(const u_char *pkt_data)
{
	ip_header *ih;
	size_t original_packet_len;

	/* Calculate original packet length */
	ih = (ip_header *)(pkt_data + ETHERNET_HEADER_LENGTH);
	original_packet_len = ntohs(ih->tlen) + ETHERNET_HEADER_LENGTH;

	// Fragment packet if it is too large
	if ((original_packet_len) > MAX_VXLAN_INNER_LEN)
		vxlan_fragment_pkt_handler(pkt_data, original_packet_len);
	else
		vxlan_pkt_handler(pkt_data, original_packet_len);

	return;
}

void free_resource(pcap_if_t **alldevs)
{
	if (alldevs && *alldevs)
		pcap_freealldevs(*alldevs);

	// For openning 2 devices case
	if (adhandle2 && (adhandle2 != adhandle1))
		pcap_close(adhandle2);

	if (adhandle1)
		pcap_close(adhandle1);

	printf("Free resource done!\n");
	return;
}

char* signal_name(int signal)
{
	switch (signal)
	{
	case SIGINT:
		return "SIGINT";
	case SIGTERM:
		return "SIGTERM";
	case SIGABRT:
		return "SIGABRT";
	default:
		return "Unknown";
	}

	return "Unknown";
}

void signalHandler(int signal)
{
	if (signal == SIGINT || signal == SIGTERM || signal == SIGABRT) {
		printf("Detect %s signal. Stop capturing!\n", signal_name(signal));

		if (adhandle1)
			pcap_breakloop(adhandle1);
	}

	return;
}