
#ifndef MYCHAP_H__
#define MYCHAP_H__

#include <stdint.h>
#include <stddef.h>

enum log_level
{
    ll_error = 0,
    ll_info = 1,
    ll_debug = 2,
};

#define __LOG_LEVEL__ ll_debug
#define CHECK_LOG_LEVEL(lvl) ((__LOG_LEVEL__) >= (lvl))

typedef struct
{
    uint8_t hardware[255];
    uint8_t hardware_len;
    uint32_t ip;
} t_addr;

typedef struct
{
    char *ifa_name;
    int ifa_index;
    uint32_t spoofed_ip;

    t_addr src;
    t_addr dest;
    t_addr broadcast;
} t_addrs;

typedef struct
{
    void *data;
    unsigned int len;
} t_datagram;

enum arp_operation
{
    ARP_OP_REQUEST = 1,
    ARP_OP_REPLY = 2,
};

typedef struct
{
    uint16_t hdw_type;
    uint16_t proto_type;

    uint8_t hdw_addr_len;
    uint8_t proto_addr_len;

    uint16_t operation;

    uint8_t hdw_addr_src[6];
    uint32_t proto_addr_src;
    uint8_t hdw_addr_dest[6];
    uint32_t proto_addr_dest;
} __attribute__((packed)) t_arp_packet;

typedef struct
{
    // uint64_t preamble_and_sfd;   // this is layer1 header

    uint8_t hdw_addr_dest[6];
    uint8_t hdw_addr_src[6];

    uint16_t ether_type;

    // uint8_t interpacket_gap[12]; // this is layer1 header
} __attribute__((packed)) t_lvl2_ethernet_header;

#define CRCPOLY_LE 0xedb88320
#define CRCPOLY_BE 0x04c11db7
typedef struct
{
    uint32_t crc;
} __attribute__((packed)) t_frame_check_sequence;

// interface and socket stuffs
int get_local_addrs(t_addrs *addrs, char *if_name);
int get_mac_by_ip(int sock, t_addrs *addrs);
int spoof_remote_arp_table(t_addrs *addrs);

// datagram manipulations
int datagram_serialize(t_datagram *datagram, const t_addrs *addrs);
int datagram_unserialize(const t_datagram *datagram, t_addrs *addrs);
void print_datagram_info(const t_datagram *datagram);

// arp (un)marshalling
int arp_serialize(t_arp_packet *pkt, const enum arp_operation op, const t_addr *src, const t_addr *dest);

// ethernet (un)marshalling
int ethernet_II_serialize(t_lvl2_ethernet_header *hdr, const t_addr *src, const t_addr *dest);
uint32_t ethernet_II_crc32_compute(const void *frame, const size_t size);
uint32_t crc32_le(uint32_t crc, void const *p, size_t len) __attribute__((pure));
uint32_t crc32_be(uint32_t crc, void const *p, size_t len) __attribute__((pure));

// utils
void show_mem(void *ptr, size_t len);
int is_big_endian();
void print_iface_hardware_addr(t_addr *addr);
void print_iface_ip_addr(t_addr *addr);

#endif
