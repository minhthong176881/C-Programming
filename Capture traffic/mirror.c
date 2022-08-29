#include <stdio.h>
#include <pcap.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <signal.h>

#include "capture.h"
#include "helper.h"
#include "build.h"

int stop_capture = 0;
pcap_if_t *alldevs;
pcap_t *mirror_descr = NULL, *send_descr = NULL;
pcap_if_t *dev1 = NULL, *dev2 = NULL;
addr_info vxlan_src, vxlan_dst;

void packet_handler(u_char *agrs, const struct pcap_pkthdr *header, const u_char *pkt_data);

int main(int argc, char **argv)
{
    char sensor_ip[32];
    char packet_filter[256];
    int is_sensor_ip_valid = 0;

    // signal(SIGINT, signal_handler);
    // signal(SIGTERM, signal_handler);
    // signal(SIGABRT, signal_handler);

    /* Build sensor param */
    do
    {
        memset(sensor_ip, 0, sizeof(sensor_ip));
        printf("Enter sensor IP (%s): ", DEFAULT_SENSOR_IP);
        scanf("%s", sensor_ip);

        if (inet_pton(AF_INET, sensor_ip, &(vxlan_dst.ip)) < 1)
        {
            fprintf(stderr, "Sensor IP is invalid!\n");
            is_sensor_ip_valid = 0;
        }
        else
            is_sensor_ip_valid = 1;
    } while (is_sensor_ip_valid == 0);

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

    sprintf(packet_filter, "not host %s", sensor_ip);

    /* Setup filter */
	if (setup_filter(mirror_descr, dev1, packet_filter) < 0)
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

	if (get_mtu(dev2->name) < 0)
	{
        free_resource(&alldevs, mirror_descr, send_descr);
        return -1;
	}

    if (get_ip_address(dev2, &vxlan_src) < 0)
    {
        free_resource(&alldevs, mirror_descr, send_descr);
        return -1;
    }

    char src_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &vxlan_src.ip, src_ip, sizeof(src_ip));

    int subnet = is_same_subnet(vxlan_src, vxlan_dst);
    if (subnet == 1) {
        if (send_arp(dev1, src_ip, sensor_ip, vxlan_src.mac, vxlan_dst.mac) < 0) 
        {
            fprintf(stderr, "Cannot send ARP\n");
            return -1;
        }
    } else {
        char gateway[32];
        if (get_gateway_address(vxlan_src.ip, gateway) < 0)
        {
            free_resource(&alldevs, mirror_descr, send_descr);
            return -1;
        }
        if (send_arp(dev1, src_ip, gateway, vxlan_src.mac, vxlan_dst.mac) < 0) 
        {
            fprintf(stderr, "Cannot send ARP\n");
            return -1;
        }
    }

    printf("--------------------------------------------------\n");

    printf("Sending IP: %s, MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
		src_ip, vxlan_src.mac[0], vxlan_src.mac[1], vxlan_src.mac[2], vxlan_src.mac[3], vxlan_src.mac[4], vxlan_src.mac[5]);

    printf("Sensor IP : %s, MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
		sensor_ip, vxlan_dst.mac[0], vxlan_dst.mac[1], vxlan_dst.mac[2], vxlan_dst.mac[3], vxlan_dst.mac[4], vxlan_dst.mac[5]);

    printf("Mirroring packet filter: %s\n", packet_filter);

    printf("\nListening on monitor interface %s...\n", dev1->name);
	/* start the capture */
	pcap_loop(mirror_descr, 0, packet_handler, NULL);

	free_resource(&alldevs, mirror_descr, send_descr);

    return 1;
}

void signal_handler(int signal)
{
    if (signal == SIGINT || signal == SIGTERM || signal == SIGABRT)
    {
        printf("Detect %s signal. Stop capturing!\n", get_signal_name(signal));

        if (mirror_descr)
            pcap_breakloop(mirror_descr);
    }

    return;
}

void packet_handler(u_char *agrs, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
#ifdef VCS_DEBUG
#endif

    encapVxLAN(pkt_data, vxlan_src, vxlan_dst, send_descr);
}