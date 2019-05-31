
#include <stdio.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <net/if.h>
#include <string.h>
#include <arpa/inet.h>
#include <netpacket/packet.h>
#include "arpspoof.h"

inline void print_iface_hardware_addr(t_addr *addr)
{
    for (int i = 0; i < addr->hardware_len; ++i)
        printf("%02X%c", addr->hardware[i], (i + 1 != addr->hardware_len) ? ':' : '\0');
}

inline void print_iface_ip_addr(t_addr *addr)
{
    printf("%i.%i.%i.%i", (addr->ip >> 0) & 0xFF, (addr->ip >> 8) & 0xFF, (addr->ip >> 16) & 0xFF, (addr->ip >> 24) & 0xFF);
}

void print_iface_infos(t_addrs *addrs)
{
    if (CHECK_LOG_LEVEL(ll_info))
    {
        printf("Ip address of %s:         ", addrs->ifa_name);
        print_iface_ip_addr(&addrs->src);
        printf("\nBcast address of %s:      ", addrs->ifa_name);
        print_iface_ip_addr(&addrs->broadcast);
        printf("\nMac address of %s:        ", addrs->ifa_name);
        print_iface_hardware_addr(&addrs->src);

        printf("\n\n\n");
    }
}

void print_ifaces_list(struct ifaddrs *ifa)
{
    if (CHECK_LOG_LEVEL(ll_info))
    {
        if (ifa != NULL)
        {
            printf("IFACES:\n\n");
            printf("%-12s %-8s %-17s %-17s %s\n", "Name", "State", "IPv4", "Broadcast", "Physical");
            printf("-------------------------------------------------------------------------------\n");
        }
        else
            printf("Did not find any interface.");

        for (; ifa != NULL; ifa = ifa->ifa_next)
        {
            if (ifa->ifa_addr)
            {
                struct sockaddr_in *s1 = (struct sockaddr_in *)ifa->ifa_addr;
                struct sockaddr_ll *s2 = (struct sockaddr_ll *)ifa->ifa_addr;

                // info
                printf("%-12s ", ifa->ifa_name);
                printf("%-8s ", (ifa->ifa_flags & IFF_UP) == IFF_UP ? "up" : "down");

                // ip
                if (ifa->ifa_addr->sa_family == AF_INET)
                    printf("%-17s ", inet_ntoa(s1->sin_addr)); // inet_ntoa is deprecated
                else
                    printf("%-17s ", "");

                if (ifa->ifa_addr->sa_family == AF_INET && ifa->ifa_ifu.ifu_broadaddr != NULL && ifa->ifa_ifu.ifu_broadaddr->sa_family == AF_INET)
                    printf("%-17s ", inet_ntoa(((struct sockaddr_in *)(ifa->ifa_ifu.ifu_broadaddr))->sin_addr)); // inet_ntoa is deprecated
                else
                    printf("%-17s ", "");

                // mac
                if (ifa->ifa_addr->sa_family == AF_PACKET)
                    for (int i = 0; i < s2->sll_halen; i++)
                        printf("%02X%c", (s2->sll_addr[i]), (i + 1 != s2->sll_halen) ? ':' : '\0');

                printf("\n");
            }
        }
        printf("\n\n");
    }
}

int get_local_addrs(t_addrs *addrs, char *if_name)
{
    addrs->ifa_name = NULL;
    struct ifaddrs *ifaddr = NULL;

    if (getifaddrs(&ifaddr) == -1)
        return -1;

    print_ifaces_list(ifaddr);

    for (struct ifaddrs *ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
    {
        if (ifa->ifa_addr && (ifa->ifa_flags & IFF_UP) == IFF_UP && strcmp(ifa->ifa_name, if_name) == 0)
        {
            // here, we found the right iface

            addrs->ifa_name = if_name;
            addrs->ifa_index = if_nametoindex(addrs->ifa_name);
            memset(addrs->broadcast.hardware, 0xFF, 6);
            addrs->broadcast.hardware_len = 6;

            // get ip
            if (ifa->ifa_addr->sa_family == AF_INET)
                addrs->src.ip = ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr;

            // get mac
            if (ifa->ifa_addr->sa_family == AF_PACKET)
            {
                struct sockaddr_ll *s = (struct sockaddr_ll *)ifa->ifa_addr;
                memcpy(addrs->src.hardware, s->sll_addr, s->sll_halen);
                addrs->src.hardware_len = s->sll_halen;
            }

            // get broadcast infos
            if (ifa->ifa_ifu.ifu_broadaddr != NULL && ifa->ifa_ifu.ifu_broadaddr->sa_family == AF_INET && (struct sockaddr_in *)(ifa->ifa_ifu.ifu_broadaddr) != NULL)
                addrs->broadcast.ip = ((struct sockaddr_in *)(ifa->ifa_ifu.ifu_broadaddr))->sin_addr.s_addr;
        }
    }
    freeifaddrs(ifaddr);

    if (addrs->ifa_name == NULL)
        return -1;

    print_iface_infos(addrs);

    return 0;
}
