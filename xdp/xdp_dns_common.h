#ifndef XDP_DNS_COMMON_H
#define XDP_DNS_COMMON_H

/*
 * Shared definitions between XDP kernel program and user-space loader.
 * This header is included by both xdp_dns_kern.c (BPF) and xdp_dns_user.c.
 */

#define DNS_MAX_NAME    128
#define DNS_PORT        53

/* DNS record types */
#define DNS_TYPE_A      1
#define DNS_TYPE_NS     2
#define DNS_TYPE_CNAME  5
#define DNS_TYPE_SOA    6
#define DNS_TYPE_PTR    12
#define DNS_TYPE_MX     15
#define DNS_TYPE_TXT    16
#define DNS_TYPE_AAAA   28

/*
 * BPF map key: query type + lowercase domain name (dotted notation).
 * Example: qtype=1, name="www.test.com"
 */
struct dns_key {
    __u16 qtype;
    char  name[DNS_MAX_NAME];
};

/*
 * BPF map value: IPv4/IPv6 address + TTL.
 * For A records: ip field is used (4 bytes).
 * For AAAA records: ip6 field is used (16 bytes).
 */
struct dns_val {
    __u32 ip;       /* IPv4 address in network byte order */
    __u32 ttl;      /* TTL in seconds, host byte order */
    __u8  ip6[16];  /* IPv6 address in network byte order */
};

/*
 * Answer section sizes (using name compression pointer 0xC00C).
 * A record:    2 (name ptr) + 2 (type) + 2 (class) + 4 (TTL) + 2 (RDLEN) + 4 (RDATA) = 16
 * AAAA record: 2 (name ptr) + 2 (type) + 2 (class) + 4 (TTL) + 2 (RDLEN) + 16 (RDATA) = 28
 */
#define DNS_ANSWER_A_SIZE    16
#define DNS_ANSWER_AAAA_SIZE 28

/* Statistics counters (PERCPU array indices) */
enum {
    STAT_TOTAL = 0,
    STAT_HIT   = 1,
    STAT_MISS  = 2,
    STAT_MAX   = 3,
};

#endif /* XDP_DNS_COMMON_H */
