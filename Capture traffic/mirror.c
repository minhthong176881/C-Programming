#include <stdio.h>
#include <pcap.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>

#include "adapter.h"
#include "capture.h"
#include "helper.h"

int stop_capture = 0;
pcap_t *mirror_descr = NULL, *send_descr = NULL;
pcap_if_t *dev1 = NULL, *dev2 = NULL;
struct sockaddr_in vxlan_src, vxlan_dst;

int main(int argc, char **argv) {
    char sensor_ip[32];
    /* Build sensor param */
	memset(sensor_ip, 0, sizeof(sensor_ip));
	printf("Enter sensor IP (%s): ", DEFAULT_SENSOR_IP);
	scanf("%s", sensor_ip);

	if (inet_pton(AF_INET, sensor_ip, &(vxlan_dst.sin_addr)) < 1)
	{
		fprintf(stderr, "Sensor IP is invalid!\n");
		return -1;
	}

    capture();
    return 1;
}