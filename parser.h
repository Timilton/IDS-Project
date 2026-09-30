#ifndef PARSER_H
#define PARSER_H

#include <arpa/inet.h>
#include <stdint.h>
#include <sys/types.h>

/*
 * TCP flag bit masks. Kept in this header since anomaly.c also checks them.
 */
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_ACK 0x10

/*
 * A parsed packet. This is the interface between capture and detection.
 * parse_packet() fills one of these; downstream modules only see this struct,
 * never raw bytes.
 */
typedef struct {
    char           src_ip[INET_ADDRSTRLEN];
    char           dst_ip[INET_ADDRSTRLEN];
    uint32_t       src_ip_raw;              /* for hash map key */
    const char    *protocol;                /* "TCP", "UDP", "ICMP" */
    unsigned short src_port;
    unsigned short dst_port;
    unsigned short length;
    unsigned char  tcp_flags;               /* 0 for non-TCP */
    const unsigned char *payload;
    int            payload_len;
} parsed_packet_t;

/*
 * Parse raw capture bytes into a parsed_packet_t.
 * Returns 0 on success, -1 if not IPv4 or protocol not handled (skip the packet).
 */
int parse_packet(const unsigned char *buffer, ssize_t buffer_len, parsed_packet_t *pkt);

#endif
