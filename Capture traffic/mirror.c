#include <stdio.h>
#include <pcap.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>

#include "adapter.h"
#include "capture.h"
#include "helper.h"

int stop_capture = 0;
pcap_if_t *alldevs;
pcap_t *mirror_descr = NULL, *send_descr = NULL;
pcap_if_t *dev1 = NULL, *dev2 = NULL;
addr_info vxlan_src, vxlan_dst;

int main(int argc, char **argv)
{
    char sensor_ip[32];
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

    // if (setup_capture(alldevs, mirror_descr, send_descr, dev1, dev2) < 0)
    // {
    //     free_resource(&alldevs, mirror_descr, send_descr);
    //     return -1;
    // };

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

    if (get_ip_address(dev2, &vxlan_src) < 0)
    {
        free_resource(&alldevs, mirror_descr, send_descr);
        return -1;
    }

    // pthread_t receive_arp_thread;
    // if (pthread_create(&receive_arp_thread, NULL, receive_arp, &vxlan_dst.mac) < 0) 
    // {
    //     perror("Could not create thread!");
    //     return -1;
    // }

    char src_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &vxlan_src.ip, src_ip, sizeof(src_ip));

    if (send_arp(dev1, src_ip, sensor_ip, &vxlan_dst.mac) < 0) 
    {
        fprintf(stderr, "Cannot send ARP\n");
        return -1;
    }

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