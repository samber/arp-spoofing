
#include <string.h>
#include <arpa/inet.h>
#include "arpspoof.h"

int arp_serialize(t_arp_packet *pkt, const enum arp_operation op, const t_addr *src, const t_addr *dest)
{
    bzero(pkt, sizeof(t_arp_packet));

    pkt->hdw_type = htons(1);              // ethernet
    pkt->proto_type = htons(0x0800);       // ip
    pkt->hdw_addr_len = src->hardware_len; // size hardware address in bytes
    pkt->proto_addr_len = 4;               // size of ip address in byte

    pkt->operation = htons((uint16_t)op); // 1 for request, 2 for reply

    // src addrs
    if (src->hardware_len == 6)
        memcpy(pkt->hdw_addr_src, src->hardware, src->hardware_len);
    pkt->proto_addr_src = src->ip;

    // dest addrs
    if (dest->hardware_len == 6 && op == ARP_OP_REPLY)
        memcpy(pkt->hdw_addr_dest, dest->hardware, dest->hardware_len);
    pkt->proto_addr_dest = dest->ip;

    return 0;
}
