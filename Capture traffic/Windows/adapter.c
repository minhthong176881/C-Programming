#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include "adapter.h"
#include <iphlpapi.h>
#include <winsock2.h>
#include <inaddr.h>

#pragma comment(lib, "IPHLPAPI.lib")

int setup_interface(pcap_if_t *alldevs, pcap_t **adhandle, pcap_if_t **dev, int inum, int max)
{
	int i = 0;
	char errbuf[PCAP_ERRBUF_SIZE];

	if (!alldevs)
	{
		printf("\nThere is no device.\n");
		return -1;
	}

	/* Check if the user specified a valid adapter */
	if (inum < 1 || inum > max)
	{
		printf("\nAdapter number out of range.\n");
		return -1;
	}

	/* Jump to the selected adapter */
	for ((*dev) = alldevs, i = 0; i< inum - 1; *dev = (*dev)->next, i++);

	/* Open the adapter */
	if ((*adhandle = pcap_open_live((*dev)->name,	// name of the device
		65536,			// portion of the packet to capture. 
		// 65536 grants that the whole packet will be captured on all the MACs.
		1,				// promiscuous mode (nonzero means promiscuous)
		1000,			// read timeout
		errbuf			// error buffer
		)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter: %s\n", errbuf);
		return -1;
	}

	VCS_PRINT("\nOpenning interface: %s\n", (*dev)->description);

	/* Check the link layer. We support only Ethernet for simplicity. */
	if (pcap_datalink(*adhandle) != DLT_EN10MB)
	{
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		return -1;
	}

	return 0;
}

int setup_filter(pcap_t *adhandle, pcap_if_t *dev, char *packet_filter)
{
	u_int netmask;
	struct bpf_program fcode;

	if (!adhandle || !dev)
	{
		fprintf(stderr, "\nSomething has problem!\n");
		return -1;
	}

	if (dev->addresses != NULL)
		/* Retrieve the mask of the first address of the interface */
		netmask = ((struct sockaddr_in *)(dev->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* If the interface is without addresses we suppose to be in a C class network */
		netmask = 0xffffff;

	//compile the filter
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) <0)
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax: \"%s\"\n", packet_filter);
		return -1;
	}

	//set the filter
	if (pcap_setfilter(adhandle, &fcode) < 0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		return -1;
	}

	return 0;
}

int GetMacAddress(u_char *mac, IN_ADDR destip)
{
	DWORD ret;
	IN_ADDR srcip;
	u_long MacAddr[2];
	u_long PhyAddrLen = 6;  /* default to length of six bytes */

	if (!mac)
	{
		fprintf(stderr, "%s error", __FUNCTIONW__);
		return -1;
	}

	srcip.S_un.S_addr = 0;

	//Send an arp packet
	ret = SendARP(destip.S_un.S_addr, srcip.S_un.S_addr, &MacAddr, &PhyAddrLen);

	//Prepare the mac address
	if (ret == NO_ERROR && PhyAddrLen > 0)
	{
		BYTE *bMacAddr = (BYTE *)& MacAddr;
		for (int i = 0; i < (int)PhyAddrLen; i++)
		{
			mac[i] = (char)bMacAddr[i];
		}

		return 0;
	}

	fprintf(stderr, "Cannot get MAC address with IP: %d.%d.%d.%d\n",
		destip.S_un.S_un_b.s_b1, destip.S_un.S_un_b.s_b2, destip.S_un.S_un_b.s_b3, destip.S_un.S_un_b.s_b4);
	return -1;
}

int GetIPAddress(pcap_if_t *dev, addr_info *address)
{
	pcap_addr_t *a;

	if (!dev || !address)
	{
		fprintf(stderr, "%s error", __FUNCTIONW__);
		return -1;
	}

	/* IP addresses */
	for (a = dev->addresses; a; a = a->next) {
		if (a->addr->sa_family == AF_INET)
		{
			address->ip = ((struct sockaddr_in *)a->addr)->sin_addr;
			address->netmask = ((struct sockaddr_in *)a->netmask)->sin_addr;
			return 0;
		}
	}

	fprintf(stderr, "Cannot get IPv4 info of interface: %s\n", dev->description);
	return -1;
}

int GetGateway(struct in_addr ip, IN_ADDR *gatewayip)
{
	char sgatewayip[16];
	PIP_ADAPTER_INFO pAdapterInfo;
	PIP_ADAPTER_INFO  pAdapter = NULL;
	u_long OutBufLen = sizeof(IP_ADAPTER_INFO);
	struct in_addr tmpIP;
	u_long ret;

	if (!gatewayip)
		return -1;

	if ((pAdapterInfo = (IP_ADAPTER_INFO *)malloc(sizeof (IP_ADAPTER_INFO))) == NULL)
	{
		printf("Error allocating memory needed to call GetAdaptersinfo\n");
		return -1;
	}

	if ((ret = GetAdaptersInfo((PIP_ADAPTER_INFO)pAdapterInfo, &OutBufLen)) == ERROR_BUFFER_OVERFLOW)
	{
		free(pAdapterInfo);
		pAdapterInfo = (IP_ADAPTER_INFO *)malloc(OutBufLen);
		if (pAdapterInfo == NULL) {
			printf("Error allocating memory needed to call GetAdaptersinfo\n");
			return -1;
		}

		ret = GetAdaptersInfo((PIP_ADAPTER_INFO)pAdapterInfo, &OutBufLen);
	}

	if (ret != ERROR_SUCCESS)
	{
		switch (ret)
		{
		case ERROR_BUFFER_OVERFLOW:
			printf("ERROR_BUFFER_OVERFLOW\n");
			break;
		case ERROR_INVALID_DATA:
			printf("ERROR_INVALID_DATA\n");
			break;
		case ERROR_INVALID_PARAMETER:
			printf("ERROR_INVALID_PARAMETER\n");
			break;
		case ERROR_NO_DATA:
			printf("ERROR_NO_DATA\n");
			break;
		case ERROR_NOT_SUPPORTED:
			printf("ERROR_NOT_SUPPORTED\n");
			break;
		default:
			printf("Others\n");
			break;
		}

		fprintf(stderr, "Cannot get default gateway\n");
		return -1;
	}

	for (pAdapter = (PIP_ADAPTER_INFO)pAdapterInfo; pAdapter; pAdapter = pAdapter->Next)
	{
		inet_pton(AF_INET, pAdapter->IpAddressList.IpAddress.String, &tmpIP);
		if (ip.s_addr == tmpIP.s_addr)
		{
			strcpy_s(sgatewayip, sizeof(sgatewayip), pAdapter->GatewayList.IpAddress.String);
			inet_pton(AF_INET, sgatewayip, gatewayip);
			VCS_PRINT("Default gateway of IP : %u.%u.%u.%u is %u.%u.%u.%u\n",
				ip.S_un.S_un_b.s_b1, ip.S_un.S_un_b.s_b2, ip.S_un.S_un_b.s_b3, ip.S_un.S_un_b.s_b4,
				gatewayip->S_un.S_un_b.s_b1, gatewayip->S_un.S_un_b.s_b2, gatewayip->S_un.S_un_b.s_b3, gatewayip->S_un.S_un_b.s_b4);

			free(pAdapterInfo);
			return 0;
		}
	}

	printf("Cannot get default gateway of IP: %u.%u.%u.%u\n",
		ip.S_un.S_un_b.s_b1, ip.S_un.S_un_b.s_b2, ip.S_un.S_un_b.s_b3, ip.S_un.S_un_b.s_b4);
	free(pAdapterInfo);
	return -1;
}

BOOL isSameSubnet(addr_info src, addr_info dst)
{
	u_long netmask = src.netmask.S_un.S_addr;

	if (netmask > 0 && (src.ip.S_un.S_addr & netmask) == (dst.ip.S_un.S_addr & netmask))
	{
		VCS_PRINT("\nSending interface IP and sensor IP are in same subnet\n");
		return TRUE;
	}
	else
	{
		VCS_PRINT("\nSending interface IP and sensor IP are not in same subnet\n");
		return FALSE;
	}
}

#if 0
void compute_ip_checksum(ip_header *ih)
{
	u_short* begin = (u_short*)ih;
	u_short* end = begin + MIN_IP_HEADER_LENGTH / 2;
	u_int checksum = 0, first_half, second_half;

	ih->crc = 0;
	for (; begin != end; begin++){
		checksum += *begin;
	}

	first_half = (u_short)(checksum >> 16);
	while (first_half){
		second_half = (u_short)((checksum << 16) >> 16);
		checksum = first_half + second_half;
		first_half = (u_short)(checksum >> 16);
	}

	ih->crc = ~checksum;
}
#endif

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
	answer = (SHORT)~sum;

	return(answer);
}

u_short udp_checksum(const u_short *udp_packet, size_t len, IN_ADDR src_ip, IN_ADDR dst_ip)
{
	u_short *ip_src = (void *)&src_ip, *ip_dst = (void *)&dst_ip;
	u_int sum;
	size_t length = len;

	// Calculate the sum                                            //
	sum = 0;
	while (len > 1)
	{
		sum += *udp_packet++;
		if (sum & 0x80000000)
			sum = (sum & 0xFFFF) + (sum >> 16);
		len -= 2;
	}

	if (len & 1)
		// Add the padding if the packet lenght is odd          //
		sum += *((u_char *)udp_packet);

	// Add the pseudo-header                                        //
	sum += *(ip_src++);
	sum += *ip_src;

	sum += *(ip_dst++);
	sum += *ip_dst;

	sum += htons(UDP_PROTOCOL);
	sum += htons(length);

	// Add the carries                                              //
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	// Return the one's complement of sum                           //
	return ((u_short)(~sum));
}

/* Print all the available information on the given interface */
void ifprint(pcap_if_t *d, int num)
{
	pcap_addr_t *a;
	char buf[64];

	/* Name */
	printf("%d. Name: %s\n", num, d->name);

	/* Description */
	if (d->description)
		printf("\tDescription: %s\n", d->description);

	/* Loopback Address*/
	printf("\tLoopback: %s\n", (d->flags & PCAP_IF_LOOPBACK) ? "yes" : "no");

	/* IP addresses */
	for (a = d->addresses; a; a = a->next) {
		printf("\tAddress Family: #%d\n", a->addr->sa_family);

		switch (a->addr->sa_family)
		{
		case AF_INET:
			printf("\tAddress Family Name: AF_INET\n");
			break;

		case AF_INET6:
			printf("\tAddress Family Name: AF_INET6\n");
			break;

		default:
			printf("\tAddress Family Name: Unknown\n");
			break;
		}
		if (a->addr && a->addr->sa_family > 0)
			printf("\tAddress: %s\n", get_ip_str(a->addr, buf, sizeof(buf)));
		if (a->netmask && a->netmask->sa_family > 0)
			printf("\tNetmask: %s\n", get_ip_str(a->netmask, buf, sizeof(buf)));
		if (a->broadaddr && a->broadaddr->sa_family > 0)
			printf("\tBroadcast Address: %s\n", get_ip_str(a->broadaddr, buf, sizeof(buf)));
		if (a->dstaddr && a->dstaddr->sa_family > 0)
			printf("\tDestination Address: %s\n", get_ip_str(a->dstaddr, buf, sizeof(buf)));
	}
	printf("\n");
}

char *get_ip_str(const struct sockaddr *sa, char *s, size_t maxlen)
{
	if (!sa || !s)
		return "Unknown AF";

	memset(s, 0, maxlen);

	switch (sa->sa_family) {
	case AF_INET:
		inet_ntop(AF_INET, &(((struct sockaddr_in *)sa)->sin_addr),
			s, maxlen);
		break;

	case AF_INET6:
		inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)sa)->sin6_addr),
			s, maxlen);
		break;

	default:
		strcpy_s(s, maxlen, "Unknown AF");
		return NULL;
	}

	return s;
}