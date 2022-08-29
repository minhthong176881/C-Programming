#include <stdio.h>
#include <stdlib.h>
#include <pcap.h> /* if this gives you an error try pcap/pcap.h */
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <string.h>

#include "capture.h"
#include "helper.h"
// #include "build.h"

int setup_capture(pcap_if_t *alldevs, pcap_t *mirror_descr, pcap_t *send_descr, pcap_if_t *dev1, pcap_if_t *dev2)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    int i = 0;
    int inum1, inum2;

    pcap_findalldevs(&alldevs, errbuf);

    i = get_devices(alldevs);

    if (i < 0)
        return -1;

    do
    {
        printf("Enter the monitor interface number (1-%d):", i);
        scanf("%d", &inum1);
        if (inum1 < 1 || inum1 > i)
            printf("Interface number out of range.\n");
    } while (inum1 < 1 || inum1 > i);

    if (setup_interface(alldevs, &mirror_descr, &dev1, inum1, i) < 0)
    {
        free_resource(&alldevs, mirror_descr, send_descr);
        return -1;
    }

    do
    {
        printf("Enter the sending interface number (1-%d):", i);
        scanf("%d", &inum2);
        if (inum2 < 1 || inum2 > i)
            printf("Interface number out of range.\n");
    } while (inum2 < 1 || inum2 > i);

    if (inum2 != inum1)
    {
        if (setup_interface(alldevs, &send_descr, &dev2, inum2, i) < 0)
        {
            free_resource(&alldevs, mirror_descr, send_descr);
            return -1;
        }
    }
    else
    {
        VCS_PRINT("We are using same interface to capture ingress/egress packets and send them to sensor\n");
        send_descr = mirror_descr;
        dev2 = dev1;
    }

    return 1;
}

int get_devices(pcap_if_t *alldevs)
{
    pcap_if_t *dev;
    int i = 0;

    /* grab a device to peak into... */
    // dev = pcap_lookupdev(errbuf);

    for (dev = alldevs; dev; dev = dev->next)
    {
        if (dev == NULL)
            return -1;
        parse_device(dev, ++i);
    }

    if (i == 0)
    {
        printf("No interface found!");
        return -1;
    }

    printf("--------------------------------------------------\n");
    return i;
}

void parse_device(pcap_if_t *d, int num)
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
    for (a = d->addresses; a; a = a->next)
    {
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

int get_ip_address(pcap_if_t *dev, addr_info *address)
{
    pcap_addr_t *a;

    if (!dev || !address)
    {
        fprintf(stderr, "%s error\n", __FUNCTION__);
        return -1;
    }

    /* IP addresses */
    for (a = dev->addresses; a; a = a->next)
    {
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

int get_gateway_address(struct in_addr ip, char *gatewayip)
{
    FILE *fp;
    int status;
    char output[1024];

    fp = popen("ip route show | grep default", "r");
    if (fp == NULL) return -1;

    while (fgets(output, sizeof(output), fp) != NULL) 
    {
        char *token = strtok(output, " ");
        int i = 0;
        // loop through the string to extract all other tokens
        while( token != NULL ) {
            if (i == 2) {
                strcpy(gatewayip, token);
                break;
            }
            // printf( "%s\n", token ); //printing each token
            token = strtok(NULL, " ");
            i++;
        }
    }

    status = pclose(fp);
    if (status == -1) {
        return status;
    } else {
        return 1;
    }
}

int setup_filter(pcap_t *descr, pcap_if_t *dev, char *packet_filter)
{
    u_int netmask;
	struct bpf_program fcode;

	if (!descr || !dev)
	{
		fprintf(stderr, "\nSomething went wrong!\n");
		return -1;
	}

	if (dev->addresses != NULL) {
        if (dev->addresses->netmask != NULL)
        /* Retrieve the mask of the first address of the interface */
		    netmask = ((struct sockaddr_in *)(dev->addresses->netmask))->sin_addr.s_addr;
    }
	else
		/* If the interface is without addresses we suppose to be in a C class network */
		netmask = 0xffffff;

	//compile the filter
	if (pcap_compile(descr, &fcode, packet_filter, 1, netmask) < 0)
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax: \"%s\"\n", packet_filter);
		return -1;
	}

	//set the filter
	if (pcap_setfilter(descr, &fcode) < 0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		return -1;
	}

	return 0;
}