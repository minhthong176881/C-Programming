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
#include "adapter.h"
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

void packet_handler(u_char *agrs, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
#ifdef VCS_DEBUG
#endif

    // encapVxLAN(pkt_data);
    print_packet_info(agrs, header, pkt_data);
}

void print_packet_info(u_char *agrs, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    u_int16_t type = parse_ethernet_header(agrs, header, pkt_data);
    if (type == ETHERTYPE_IP)
    {
        parse_IP(agrs, header, pkt_data);
    }
}

u_int16_t parse_ethernet_header(u_char *agrs, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    u_int caplen = header->caplen;
    u_int length = header->len;
    struct ether_header *eptr;
    u_short ether_type;

    // struct ether_addr *addr;

    if (caplen < ETHER_HDR_LEN)
    {
        fprintf(stdout, "Packet length less than ethernet header length\n");
        return -1;
    }

    /* lets start with the ether header... */
    eptr = (struct ether_header *)pkt_data;
    ether_type = ntohs(eptr->ether_type);

    /* Lets print SOURCE DEST TYPE LENGTH */
    // fprintf(stdout,"ETH: ");
    // fprintf(stdout, "%s ", parse_ethernet_address(eptr->ether_shost));
    // fprintf(stdout, "%s ", parse_ethernet_address(eptr->ether_dhost));
    // fprintf(stdout,"%s ", ether_ntoa((struct ether_addr*)eptr->ether_shost));
    // fprintf(stdout,"%s ", ether_ntoa((struct ether_addr*)eptr->ether_dhost));

    /* check to see if we have an ip packet */
    if (ether_type == ETHERTYPE_IP)
    {
        fprintf(stdout, "(IP)");
    }
    else if (ether_type == ETHERTYPE_ARP)
    {
        fprintf(stdout, "(ARP)");
    }
    else if (eptr->ether_type == ETHERTYPE_REVARP)
    {
        fprintf(stdout, "(RARP)");
    }
    else
    {
        fprintf(stdout, "(?)");
    }
    fprintf(stdout, " %d\n", length);

    return ether_type;
}

char *parse_ethernet_address(uint8_t *address)
{
    int i = 0;
    i = ETHER_ADDR_LEN;
    char *addr = "";
    printf(" Destination Address:  ");
    do
    {
        char *x = "";
        sprintf(x, "%02x", *address++);
        if (i == ETHER_ADDR_LEN)
        {
            strcat(addr, " ");
        }
        else
            strcat(addr, ":");
        strcat(addr, x);
        // printf("%s%02x",(i == ETHER_ADDR_LEN) ? " " : ":",*address++);
    } while (--i > 0);
    return addr;
}

u_char *parse_IP(u_char *agrs, const struct pcap_pkthdr *header, const u_char *packet)
{
    const struct ip_header *ip;
    u_int length = header->len;
    u_int hlen, off, version;

    int len;

    /* jump pass the ethernet header */
    ip = (struct ip_header *)(packet + sizeof(struct ether_header));
    length -= sizeof(struct ether_header);

    /* check to see we have a packet of valid length */
    if (length < sizeof(struct ip_header))
    {
        printf("truncated ip %d", length);
        return NULL;
    }

    len = ntohs(ip->ip_len);
    hlen = IP_HL(ip);   /* header length */
    version = IP_V(ip); /* ip version */

    /* check version */
    if (version != 4)
    {
        fprintf(stdout, "Unknown version %d\n", version);
        return NULL;
    }

    /* check header length */
    if (hlen < 5)
    {
        fprintf(stdout, "bad-hlen %d \n", hlen);
    }

    /* see if we have as much packet as we should */
    if (length < len)
        printf("\ntruncated IP - %d bytes missing\n", len - length);

    /* Check to see if we have the first fragment */
    off = ntohs(ip->ip_off);
    if ((off & 0x1fff) == 0) /* aka no 1's in first 13 bits */
    {                        /* print SOURCE DESTINATION hlen version len offset */
        fprintf(stdout, "IP: ");
        fprintf(stdout, "%s ",
                inet_ntoa(ip->ip_src));
        fprintf(stdout, "%s %d %d %d %d\n",
                inet_ntoa(ip->ip_dst),
                hlen, version, len, off);
    }

    return NULL;
}