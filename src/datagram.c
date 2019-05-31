
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "arpspoof.h"

void print_datagram_info(const t_datagram *datagram)
{
    if (CHECK_LOG_LEVEL(ll_debug))
    {
        printf("Layers lengths\n\t=> lvl2 ethernet header: %ld\n\t=> arp packet: %ld\n\t=> Frame check sequence: %ld", sizeof(t_lvl2_ethernet_header), sizeof(t_arp_packet), sizeof(t_frame_check_sequence));
        printf("\n\t=> total: %d\n\n", datagram->len);
        show_mem(datagram->data, datagram->len);
        printf("\n");
    }
}

int datagram_serialize(t_datagram *datagram, const t_addrs *addrs)
{
    // align memory of datagram with ethernet header and arp request
    t_lvl2_ethernet_header *ethernet_header = datagram->data;
    t_arp_packet *req = datagram->data + sizeof(t_lvl2_ethernet_header);
    t_frame_check_sequence *checksum = datagram->data + sizeof(t_lvl2_ethernet_header) + sizeof(t_arp_packet);

    arp_serialize(req, ARP_OP_REQUEST, &addrs->src, &addrs->dest);
    ethernet_II_serialize(ethernet_header, &addrs->src, &addrs->broadcast);
    checksum->crc = htonl(ethernet_II_crc32_compute(datagram->data, datagram->len - sizeof(t_frame_check_sequence)));

    print_datagram_info(datagram);

    return 0;
}

int datagram_unserialize(const t_datagram *datagram, t_addrs *addrs)
{
    t_lvl2_ethernet_header *ethernet_header = datagram->data;
    t_arp_packet *reply = datagram->data + sizeof(t_lvl2_ethernet_header);
    t_frame_check_sequence *checksum = datagram->data + sizeof(t_lvl2_ethernet_header) + sizeof(t_arp_packet);

    // do some checks here
    ethernet_header = ethernet_header;
    checksum = checksum;

    memcpy(addrs->dest.hardware, reply->hdw_addr_src, reply->hdw_addr_len);
    addrs->dest.hardware_len = reply->hdw_addr_len;

    print_datagram_info(datagram);

    return 0;
}
