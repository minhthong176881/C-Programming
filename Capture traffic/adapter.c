#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>

#include "adapter.h"

char *get_ip_str(const struct sockaddr *sa, char *s, size_t maxlen)
{
    if (!sa || !s)
        return "Unknown AF";

    memset(s, 0, maxlen);

    switch (sa->sa_family)
    {
    case AF_INET:
        inet_ntop(AF_INET, &(((struct sockaddr_in *)sa)->sin_addr), s, maxlen);
        break;

    case AF_INET6:
        inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)sa)->sin6_addr),
                  s, maxlen);
        break;

    default:
        strcpy(s, "Unknown AF");
        return NULL;
    }

    return s;
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
    if (fp == NULL)
        /* Handle error */;

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

int is_same_subnet(addr_info src, addr_info dst)
{
    uint32_t netmask = src.netmask.s_addr;

    if (netmask > 0 && (src.ip.s_addr & netmask) == (dst.ip.s_addr & netmask))
    {
        VCS_PRINT("\nSending interface IP and sensor IP are in same subnet\n");
        return 1;
    }
    else
    {
        VCS_PRINT("\nSending interface IP and sensor IP are not in same subnet\n");
        return 0;
    }
}