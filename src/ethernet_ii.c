
#include <string.h>
#include <arpa/inet.h>
#include "arpspoof.h"

int ethernet_II_serialize(t_lvl2_ethernet_header *hdr, const t_addr *src, const t_addr *dest)
{
    bzero(hdr, sizeof(t_lvl2_ethernet_header));

    memcpy(hdr->hdw_addr_dest, dest->hardware, dest->hardware_len);
    memcpy(hdr->hdw_addr_src, src->hardware, src->hardware_len);
    hdr->ether_type = htons(0x0806); // arp

    src = src;
    dest = dest;
    return 0;
}

// int ethernet_II_unserialize()
// {
//     return 0;
// }

// simple wrapper of the system crc32 checkum
inline uint32_t ethernet_II_crc32_compute(void const *frame, const size_t len)
{
    return is_big_endian() ? crc32_be(~0, frame, len) : crc32_le(~0, frame, len);
}

uint32_t crc32_le(uint32_t crc, void const *p, size_t len)
{
    int i;
    while (len--)
    {
        crc ^= *(uint8_t *)p++;
        for (i = 0; i < 8; i++)
            crc = (crc >> 1) ^ ((crc & 1) ? CRCPOLY_LE : 0);
    }
    return crc;
}

uint32_t crc32_be(uint32_t crc, void const *p, size_t len)
{
    int i;
    while (len--)
    {
        crc ^= *(uint8_t *)p++ << 24;
        for (i = 0; i < 8; i++)
            crc = (crc << 1) ^ ((crc & 0x80000000) ? CRCPOLY_BE : 0);
    }
    return crc;
}