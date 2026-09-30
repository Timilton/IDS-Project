#include "parser.h"

#include <string.h>
#include <sys/socket.h>

/*
 * Wire-format header structs. Kept private to this module since nobody else
 * needs them. Same overlay-on-raw-bytes technique as M1.
 */

struct eth_header {
    unsigned char  dest[6];
    unsigned char  src[6];
    unsigned short type;
} __attribute__((packed));

struct ip_header {
    unsigned char  ver_ihl;
    unsigned char  tos;
    unsigned short total_length;
    unsigned short id;
    unsigned short flags_fo;
    unsigned char  ttl;
    unsigned char  protocol;
    unsigned short checksum;
    unsigned int   src_addr;
    unsigned int   dst_addr;
} __attribute__((packed));

struct tcp_header {
    unsigned short src_port;
    unsigned short dst_port;
    unsigned int   seq;
    unsigned int   ack;
    unsigned char  offset_reserved;
    unsigned char  flags;
    unsigned short window;
    unsigned short checksum;
    unsigned short urgent_ptr;
} __attribute__((packed));

struct udp_header {
    unsigned short src_port;
    unsigned short dst_port;
    unsigned short length;
    unsigned short checksum;
} __attribute__((packed));

#define ETH_P_IP_CUSTOM  0x0800
#define PROTO_ICMP       1
#define PROTO_TCP        6
#define PROTO_UDP        17

int parse_packet(const unsigned char *buffer, ssize_t buffer_len, parsed_packet_t *pkt) {
    if (buffer_len < (ssize_t)sizeof(struct eth_header)) return -1;

    struct eth_header *eth = (struct eth_header *)buffer;
    if (ntohs(eth->type) != ETH_P_IP_CUSTOM) return -1;

    struct ip_header *ip = (struct ip_header *)(buffer + sizeof(struct eth_header));
    int ip_header_len = (ip->ver_ihl & 0x0F) * 4;

    struct in_addr src_addr, dst_addr;
    src_addr.s_addr = ip->src_addr;
    dst_addr.s_addr = ip->dst_addr;

    inet_ntop(AF_INET, &src_addr, pkt->src_ip, sizeof(pkt->src_ip));
    inet_ntop(AF_INET, &dst_addr, pkt->dst_ip, sizeof(pkt->dst_ip));
    pkt->src_ip_raw = ip->src_addr;
    pkt->length = ntohs(ip->total_length);
    pkt->tcp_flags = 0;

    const unsigned char *l4 = buffer + sizeof(struct eth_header) + ip_header_len;

    if (ip->protocol == PROTO_TCP) {
        struct tcp_header *tcp = (struct tcp_header *)l4;
        pkt->protocol = "TCP";
        pkt->src_port = ntohs(tcp->src_port);
        pkt->dst_port = ntohs(tcp->dst_port);
        pkt->tcp_flags = tcp->flags;
        int tcp_hdr_len = ((tcp->offset_reserved >> 4) & 0x0F) * 4;
        pkt->payload = l4 + tcp_hdr_len;
        pkt->payload_len = pkt->length - ip_header_len - tcp_hdr_len;
        if (pkt->payload_len < 0) pkt->payload_len = 0;
        return 0;
    }

    if (ip->protocol == PROTO_UDP) {
        struct udp_header *udp = (struct udp_header *)l4;
        pkt->protocol = "UDP";
        pkt->src_port = ntohs(udp->src_port);
        pkt->dst_port = ntohs(udp->dst_port);
        pkt->payload = l4 + sizeof(struct udp_header);
        pkt->payload_len = pkt->length - ip_header_len - sizeof(struct udp_header);
        if (pkt->payload_len < 0) pkt->payload_len = 0;
        return 0;
    }

    if (ip->protocol == PROTO_ICMP) {
        pkt->protocol = "ICMP";
        pkt->src_port = 0;
        pkt->dst_port = 0;
        pkt->payload = NULL;
        pkt->payload_len = 0;
        return 0;
    }

    return -1;
}
