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