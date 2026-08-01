/*
 * XDP DNS Fast Path - eBPF kernel program
 *
 * This program runs at the network driver level (XDP hook) and handles
 * DNS A/AAAA-record queries entirely in the kernel, bypassing the network
 * stack. Cache misses and complex queries are passed to user-space via
 * XDP_PASS.
 *
 * Key features:
 *   - Handles EDNS OPT queries (strips OPT before responding)
 *   - Supports both A and AAAA record types
 *   - LRU hash map for O(1) lookups with automatic eviction
 *   - Per-CPU statistics for lock-free counting
 *
 * Requirements: Linux kernel >= 5.8 (bpf_xdp_adjust_tail support)
 *
 * Build: clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -c xdp_dns_kern.c -o xdp_dns_kern.o
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "xdp_dns_common.h"

/* LRU hash map: (qtype + domain name) -> IP address + TTL */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 100000);
    __type(key, struct dns_key);
    __type(value, struct dns_val);
} dns_map SEC(".maps");

/* Per-CPU statistics counters */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, STAT_MAX);
    __type(key, __u32);
    __type(value, __u64);
} stats_map SEC(".maps");

static __always_inline void stat_inc(__u32 key)
{
    __u64 *val = bpf_map_lookup_elem(&stats_map, &key);
    if (val)
        __sync_fetch_and_add(val, 1);
}

/*
 * Parse a DNS question name from wire format to a lowercase dotted string.
 *
 * Wire format: 3www4test3com0 (length-prefixed labels, zero-terminated)
 * Output:      "www.test.com"
 *
 * Uses a single bounded loop (max 255 iterations) for verifier compatibility.
 * Returns total bytes consumed from dns start (header + question), or -1 on error.
 */
static __always_inline int parse_dns_question(const void *dns, const void *data_end,
                                               struct dns_key *key)
{
    int pos = 12;          /* skip 12-byte DNS header */
    int name_pos = 0;
    int remaining = 0;     /* bytes left in current label */

    for (int i = 0; i < 255; i++) {
        if ((const __u8 *)dns + pos + 1 > (const __u8 *)data_end)
            return -1;

        if (remaining == 0) {
            /* Read label length byte */
            __u8 label_len = *((const __u8 *)dns + pos);
            pos++;

            if (label_len == 0)
                break;          /* end of name */

            if (label_len > 63)
                return -1;      /* compression pointer or invalid */

            remaining = label_len;

            /* Insert dot separator between labels */
            if (name_pos > 0 && name_pos < DNS_MAX_NAME)
                key->name[name_pos++] = '.';
        } else {
            /* Copy one character, convert to lowercase */
            if (name_pos + 1 >= DNS_MAX_NAME)
                return -1;

            char c = *((const char *)dns + pos);
            if (c >= 'A' && c <= 'Z')
                c += 32;
            key->name[name_pos++] = c;
            pos++;
            remaining--;
        }
    }

    key->name[name_pos] = '\0';

    /* Read qtype (2 bytes) and qclass (2 bytes) */
    if ((const __u8 *)dns + pos + 4 > (const __u8 *)data_end)
        return -1;

    __u16 qtype_net = *((const __u16 *)((const __u8 *)dns + pos));
    key->qtype = bpf_ntohs(qtype_net);

    /* Return total bytes consumed from DNS message start */
    return pos + 4;
}

/*
 * Recompute IP header checksum (20-byte IPv4 header, 10 x 16-bit words).
 * Uses #pragma unroll for verifier compatibility.
 */
static __always_inline void recompute_ip_checksum(struct iphdr *iph)
{
    iph->check = 0;
    __u32 sum = 0;
    __u16 *words = (__u16 *)iph;

#pragma unroll
    for (int i = 0; i < 10; i++) {
        sum += words[i];
    }
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    iph->check = ~sum & 0xFFFF;
}

/*
 * Build a DNS response packet in-place using XDP_TX.
 *
 * Handles both A and AAAA records, and strips EDNS OPT records from the
 * additional section by adjusting the packet tail in a single call.
 *
 * Steps:
 *  1. Calculate net tail adjustment: answer_size - edns_size
 *  2. Adjust packet tail (single bpf_xdp_adjust_tail call)
 *  3. Swap Ethernet MAC addresses
 *  4. Swap IPv4 addresses, update total length, recompute checksum
 *  5. Swap UDP ports, update length, zero checksum
 *  6. Set DNS response flags, ANCOUNT=1, ARCOUNT=0
 *  7. Append answer section (name pointer + type + class + TTL + RDLENGTH + RDATA)
 */
static __always_inline int build_response(struct xdp_md *ctx,
                                           struct dns_val *val,
                                           int dns_payload_len,
                                           int edns_size,
                                           __u16 qtype)
{
    int answer_size = (qtype == DNS_TYPE_A) ? DNS_ANSWER_A_SIZE : DNS_ANSWER_AAAA_SIZE;

    /* Net tail adjustment: add answer space, remove EDNS OPT */
    int tail_delta = answer_size - edns_size;
    if (bpf_xdp_adjust_tail(ctx, tail_delta))
        return -1;

    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Re-parse headers after adjust_tail (pointers are invalidated) */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return -1;

    int ip_hdr_len = iph->ihl * 4;
    if (ip_hdr_len < 20)
        return -1;
    if ((void *)iph + ip_hdr_len > data_end)
        return -1;

    struct udphdr *udp = (void *)iph + ip_hdr_len;
    if ((void *)(udp + 1) > data_end)
        return -1;

    void *dns = (void *)(udp + 1);
    if ((void *)dns + 12 > data_end)
        return -1;

    /* 1. Swap Ethernet MAC addresses */
    __u8 tmp_mac[ETH_ALEN];
    __builtin_memcpy(tmp_mac, eth->h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, tmp_mac, ETH_ALEN);

    /* 2. Swap IPv4 addresses */
    __u32 tmp_ip = iph->saddr;
    iph->saddr = iph->daddr;
    iph->daddr = tmp_ip;

    /* 3. Update IP total length */
    __u16 old_tot_len = bpf_ntohs(iph->tot_len);
    iph->tot_len = bpf_htons(old_tot_len + tail_delta);

    /* 4. Recompute IP checksum */
    recompute_ip_checksum(iph);

    /* 5. Swap UDP source/destination ports */
    __u16 tmp_port = udp->source;
    udp->source = udp->dest;
    udp->dest = tmp_port;

    /* 6. Update UDP length */
    __u16 old_udp_len = bpf_ntohs(udp->len);
    udp->len = bpf_htons(old_udp_len + tail_delta);

    /* 7. Zero UDP checksum (valid for UDP over IPv4) */
    udp->check = 0;

    /* 8. Set DNS response flags: QR=1, AA=1, copy RD */
    __u16 *flags_ptr = (__u16 *)dns + 1;   /* offset 2 in DNS message */
    __u16 old_flags = bpf_ntohs(*flags_ptr);
    __u16 rd = (old_flags >> 8) & 1;       /* copy RD bit from request */
    *flags_ptr = bpf_htons(0x8400 | (rd << 8));  /* QR=1, AA=1, RD=copy */

    /* 9. Set ANCOUNT = 1 */
    __u16 *ancount_ptr = (__u16 *)dns + 3;  /* offset 6 in DNS message */
    *ancount_ptr = bpf_htons(1);

    /* 10. Set ARCOUNT = 0 (strip EDNS OPT) */
    __u16 *arcount_ptr = (__u16 *)dns + 5;  /* offset 10 in DNS message */
    *arcount_ptr = bpf_htons(0);

    /* 11. Append answer section at end of question section */
    __u8 *answer = (__u8 *)dns + dns_payload_len;
    if ((void *)(answer + answer_size) > data_end)
        return -1;

    /* Name compression pointer: 0xC00C -> offset 12 in DNS message */
    *(__u16 *)(answer + 0)  = bpf_htons(0xC00C);
    /* Type: A or AAAA */
    *(__u16 *)(answer + 2)  = bpf_htons(qtype);
    /* Class: IN (1) */
    *(__u16 *)(answer + 4)  = bpf_htons(1);
    /* TTL */
    *(__u32 *)(answer + 6)  = bpf_htonl(val->ttl);
    /* RDLENGTH */
    *(__u16 *)(answer + 10) = bpf_htons(qtype == DNS_TYPE_A ? 4 : 16);

    /* RDATA: IPv4 or IPv6 address */
    if (qtype == DNS_TYPE_A) {
        *(__u32 *)(answer + 12) = val->ip;
    } else {
        __builtin_memcpy(answer + 12, val->ip6, 16);
    }

    return 0;
}

/*
 * Main XDP program entry point.
 *
 * Returns:
 *   XDP_TX   - cache hit, response sent from NIC
 *   XDP_PASS - cache miss or unsupported query, pass to kernel network stack
 */
SEC("xdp")
int xdp_dns_prog(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    stat_inc(STAT_TOTAL);

    /* --- Layer 1: Ethernet --- */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    /* --- Layer 2: IPv4 --- */
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    if (iph->ihl < 5)
        return XDP_PASS;

    int ip_hdr_len = iph->ihl * 4;
    if ((void *)iph + ip_hdr_len > data_end)
        return XDP_PASS;

    if (iph->protocol != IPPROTO_UDP)
        return XDP_PASS;

    /* --- Layer 3: UDP --- */
    struct udphdr *udp = (void *)iph + ip_hdr_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    /* Only handle queries to port 53 */
    if (udp->dest != bpf_htons(DNS_PORT))
        return XDP_PASS;

    /* --- Layer 4: DNS header --- */
    void *dns = (void *)(udp + 1);
    if ((void *)dns + 12 > data_end)
        return XDP_PASS;

    __u16 *dns_words = (__u16 *)dns;
    __u16 flags   = bpf_ntohs(dns_words[1]);
    __u16 qdcount = bpf_ntohs(dns_words[2]);
    __u16 ancount = bpf_ntohs(dns_words[3]);
    __u16 nscount = bpf_ntohs(dns_words[4]);
    __u16 arcount = bpf_ntohs(dns_words[5]);

    /* Only handle standard queries (QR=0) with exactly 1 question */
    if ((flags & 0x8000) != 0)
        return XDP_PASS;   /* not a query */

    if (qdcount != 1 || ancount != 0 || nscount != 0)
        return XDP_PASS;

    /* Reject if too many additional records (complex EDNS options) */
    if (arcount > 1)
        return XDP_PASS;

    /* --- Layer 5: Parse DNS question --- */
    struct dns_key key;
    __builtin_memset(&key, 0, sizeof(key));

    int dns_payload_len = parse_dns_question(dns, data_end, &key);
    if (dns_payload_len < 0)
        return XDP_PASS;

    /* Only accelerate A and AAAA record queries */
    if (key.qtype != DNS_TYPE_A && key.qtype != DNS_TYPE_AAAA)
        return XDP_PASS;

    /* --- Calculate EDNS OPT size (if present) --- */
    int udp_payload_len = bpf_ntohs(udp->len) - 8;  /* subtract UDP header */
    if (udp_payload_len < dns_payload_len)
        return XDP_PASS;

    int edns_size = udp_payload_len - dns_payload_len;

    /* Sanity check: EDNS OPT record should be small (< 128 bytes) */
    if (edns_size > 128)
        return XDP_PASS;

    /* --- Layer 6: BPF map lookup --- */
    struct dns_val *val = bpf_map_lookup_elem(&dns_map, &key);
    if (!val) {
        stat_inc(STAT_MISS);
        return XDP_PASS;
    }

    /* --- Cache hit: build and send response --- */
    if (build_response(ctx, val, dns_payload_len, edns_size, key.qtype) < 0) {
        stat_inc(STAT_MISS);
        return XDP_PASS;
    }

    stat_inc(STAT_HIT);
    return XDP_TX;
}

char LICENSE[] SEC("license") = "GPL";
