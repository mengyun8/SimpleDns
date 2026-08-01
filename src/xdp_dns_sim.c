/*
 * XDP 内核逻辑模拟测试程序
 *
 * 在用户态模拟 XDP eBPF 程序的数据包处理流程，验证：
 *   - 以太网/IPv4/UDP/DNS 协议层解析
 *   - BPF Map 查找逻辑 (模拟)
 *   - 响应构建 (MAC/IP 交换, 校验和, 答案段)
 *   - EDNS OPT 大小计算和 tail 调整
 *   - 统计计数器
 *
 * 构建: gcc -O2 -Wall -o xdp_dns_sim xdp_dns_sim.c
 * 用法:   ./xdp_dns_sim
 */

#ifndef __linux__
typedef unsigned char  __u8;
typedef unsigned short __u16;
typedef unsigned int   __u32;
typedef unsigned long long __u64;
#else
#include <linux/types.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <string.h>

#include "xdp_dns_common.h"

/* 模拟常量 */
#define ETH_ALEN 6
#define ETH_P_IP 0x0800
#define IPPROTO_UDP 17
#define BUF_SIZE 1500

#define XDP_PASS 1
#define XDP_TX 3

/* 模拟统计 */
static __u64 sim_stats[STAT_MAX];

static void stat_inc(__u32 key) { if (key < STAT_MAX) sim_stats[key]++; }

/* --- 模拟数据结构 --- */

struct ethhdr_sim {
    __u8 h_dest[ETH_ALEN];
    __u8 h_source[ETH_ALEN];
    __u16 h_proto;
};

struct iphdr_sim {
    __u8  ihl:4, version:4;
    __u8  tos;
    __u16 tot_len;
    __u16 id;
    __u16 frag_off;
    __u8  ttl;
    __u8  protocol;
    __u16 check;
    __u32 saddr;
    __u32 daddr;
};

struct udphdr_sim {
    __u16 source;
    __u16 dest;
    __u16 len;
    __u16 check;
};

/* --- 模拟 BPF Map --- */

#define MAP_SIZE 256
static struct dns_key map_keys[MAP_SIZE];
static struct dns_val map_vals[MAP_SIZE];
static int map_count = 0;

static int map_update(struct dns_key *key, struct dns_val *val)
{
    for (int i = 0; i < map_count; i++) {
        if (map_keys[i].qtype == key->qtype &&
            strcmp(map_keys[i].name, key->name) == 0) {
            map_vals[i] = *val;
            return 0;
        }
    }
    if (map_count >= MAP_SIZE) return -1;
    map_keys[map_count] = *key;
    map_vals[map_count] = *val;
    map_count++;
    return 0;
}

static struct dns_val *map_lookup(struct dns_key *key)
{
    for (int i = 0; i < map_count; i++) {
        if (map_keys[i].qtype == key->qtype &&
            strcmp(map_keys[i].name, key->name) == 0)
            return &map_vals[i];
    }
    return NULL;
}

/* --- DNS 解析 (模拟内核 parse_dns_question) --- */

static int parse_dns_question(const __u8 *dns, int data_len, struct dns_key *key)
{
    int pos = 12;
    int name_pos = 0;
    int remaining = 0;

    for (int i = 0; i < 255; i++) {
        if (pos + 1 > data_len) return -1;

        if (remaining == 0) {
            __u8 label_len = dns[pos++];
            if (label_len == 0) break;
            if (label_len > 63) return -1;
            remaining = label_len;
            if (name_pos > 0 && name_pos < DNS_MAX_NAME)
                key->name[name_pos++] = '.';
        } else {
            if (name_pos + 1 >= DNS_MAX_NAME) return -1;
            char c = dns[pos++];
            if (c >= 'A' && c <= 'Z') c += 32;
            key->name[name_pos++] = c;
            remaining--;
        }
    }
    key->name[name_pos] = '\0';

    if (pos + 4 > data_len) return -1;
    key->qtype = ntohs(*(__u16 *)(dns + pos));
    return pos + 4;
}

/* --- IP 校验和计算 (模拟 recompute_ip_checksum) --- */

static __u16 recompute_ip_checksum(struct iphdr_sim *iph)
{
    iph->check = 0;
    __u32 sum = 0;
    __u16 *words = (__u16 *)iph;
    for (int i = 0; i < 10; i++)
        sum += words[i];
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    return ~sum & 0xFFFF;
}

/* --- 构建完整以太网帧 --- */

static int build_eth_frame(__u8 *buf, int max_len,
                           const char *src_mac, const char *dst_mac,
                           __u32 src_ip, __u32 dst_ip,
                           __u16 src_port, __u16 dst_port,
                           const __u8 *dns_payload, int dns_len)
{
    int total = 14 + 20 + 8 + dns_len; /* ETH + IP + UDP + DNS */
    if (total > max_len) return -1;

    int pos = 0;

    /* Ethernet */
    struct ethhdr_sim *eth = (struct ethhdr_sim *)buf;
    sscanf(dst_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &eth->h_dest[0], &eth->h_dest[1], &eth->h_dest[2],
           &eth->h_dest[3], &eth->h_dest[4], &eth->h_dest[5]);
    sscanf(src_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &eth->h_source[0], &eth->h_source[1], &eth->h_source[2],
           &eth->h_source[3], &eth->h_source[4], &eth->h_source[5]);
    eth->h_proto = htons(ETH_P_IP);
    pos = 14;

    /* IP */
    struct iphdr_sim *iph = (struct iphdr_sim *)(buf + pos);
    iph->version = 4;
    iph->ihl = 5;
    iph->tos = 0;
    iph->tot_len = htons(20 + 8 + dns_len);
    iph->id = htons(0x1234);
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_UDP;
    iph->saddr = src_ip;
    iph->daddr = dst_ip;
    iph->check = recompute_ip_checksum(iph);
    pos += 20;

    /* UDP */
    struct udphdr_sim *udp = (struct udphdr_sim *)(buf + pos);
    udp->source = htons(src_port);
    udp->dest = htons(dst_port);
    udp->len = htons(8 + dns_len);
    udp->check = 0;
    pos += 8;

    /* DNS */
    memcpy(buf + pos, dns_payload, dns_len);
    pos += dns_len;

    return pos;
}

/* --- DNS 查询构建 --- */

static int encode_wire_name(const char *name, __u8 *out, int out_max)
{
    int pos = 0;
    const char *p = name;
    while (*p) {
        const char *dot = strchr(p, '.');
        int label_len = dot ? (int)(dot - p) : (int)strlen(p);
        if (label_len == 0) break;
        if (pos + 1 + label_len + 1 > out_max) return -1;
        out[pos++] = (__u8)label_len;
        memcpy(out + pos, p, label_len);
        pos += label_len;
        if (!dot) break;
        p = dot + 1;
    }
    out[pos++] = 0;
    return pos;
}

static int build_dns_query(__u8 *buf, int max_len, const char *name,
                           __u16 qtype, __u16 id, int with_edns)
{
    *(__u16 *)(buf + 0) = htons(id);
    *(__u16 *)(buf + 2) = htons(0x0100);
    *(__u16 *)(buf + 4) = htons(1);
    *(__u16 *)(buf + 6) = htons(0);
    *(__u16 *)(buf + 8) = htons(0);
    *(__u16 *)(buf + 10) = htons(with_edns ? 1 : 0);
    int pos = 12;

    int name_len = encode_wire_name(name, buf + pos, max_len - pos - 4);
    if (name_len < 0) return -1;
    pos += name_len;
    *(__u16 *)(buf + pos) = htons(qtype); pos += 2;
    *(__u16 *)(buf + pos) = htons(1); pos += 2;

    if (with_edns) {
        buf[pos++] = 0;
        *(__u16 *)(buf + pos) = htons(41); pos += 2;
        *(__u16 *)(buf + pos) = htons(4096); pos += 2;
        *(__u32 *)(buf + pos) = 0; pos += 4;
        *(__u16 *)(buf + pos) = htons(0); pos += 2;
    }

    return pos;
}

/* --- 模拟 XDP 程序核心逻辑 --- */

static int sim_xdp_dns(__u8 *frame, int frame_len, int *out_action)
{
    stat_inc(STAT_TOTAL);

    __u8 *data = frame;
    __u8 *data_end = frame + frame_len;

    /* Layer 1: Ethernet */
    struct ethhdr_sim *eth = (struct ethhdr_sim *)data;
    if ((void *)(eth + 1) > (void *)data_end) { *out_action = XDP_PASS; return -1; }
    if (eth->h_proto != htons(ETH_P_IP)) { *out_action = XDP_PASS; return -1; }

    /* Layer 2: IPv4 */
    struct iphdr_sim *iph = (struct iphdr_sim *)(eth + 1);
    if ((void *)(iph + 1) > (void *)data_end) { *out_action = XDP_PASS; return -1; }
    if (iph->ihl < 5) { *out_action = XDP_PASS; return -1; }
    int ip_hdr_len = iph->ihl * 4;
    if ((void *)iph + ip_hdr_len > (void *)data_end) { *out_action = XDP_PASS; return -1; }
    if (iph->protocol != IPPROTO_UDP) { *out_action = XDP_PASS; return -1; }

    /* Layer 3: UDP */
    struct udphdr_sim *udp = (struct udphdr_sim *)((void *)iph + ip_hdr_len);
    if ((void *)(udp + 1) > (void *)data_end) { *out_action = XDP_PASS; return -1; }
    if (udp->dest != htons(DNS_PORT)) { *out_action = XDP_PASS; return -1; }

    /* Layer 4: DNS */
    void *dns = (void *)(udp + 1);
    if (dns + 12 > (void *)data_end) { *out_action = XDP_PASS; return -1; }

    __u16 *dns_words = (__u16 *)dns;
    __u16 flags   = ntohs(dns_words[1]);
    __u16 qdcount = ntohs(dns_words[2]);
    __u16 ancount = ntohs(dns_words[3]);
    __u16 nscount = ntohs(dns_words[4]);
    __u16 arcount = ntohs(dns_words[5]);

    if ((flags & 0x8000) != 0) { *out_action = XDP_PASS; return -1; }
    if (qdcount != 1 || ancount != 0 || nscount != 0) { *out_action = XDP_PASS; return -1; }
    if (arcount > 1) { *out_action = XDP_PASS; return -1; }

    /* Layer 5: Parse DNS question */
    struct dns_key key;
    memset(&key, 0, sizeof(key));
    int dns_payload_len = parse_dns_question(dns, (int)(data_end - (__u8 *)dns), &key);
    if (dns_payload_len < 0) { *out_action = XDP_PASS; return -1; }

    if (key.qtype != DNS_TYPE_A && key.qtype != DNS_TYPE_AAAA) {
        *out_action = XDP_PASS; return -1;
    }

    /* EDNS size calculation */
    int udp_payload_len = ntohs(udp->len) - 8;
    if (udp_payload_len < dns_payload_len) { *out_action = XDP_PASS; return -1; }
    int edns_size = udp_payload_len - dns_payload_len;
    if (edns_size > 128) { *out_action = XDP_PASS; return -1; }

    /* Layer 6: BPF map lookup */
    struct dns_val *val = map_lookup(&key);
    if (!val) {
        stat_inc(STAT_MISS);
        *out_action = XDP_PASS;
        return -1;
    }

    /* Cache hit - simulate response build */
    int answer_size = (key.qtype == DNS_TYPE_A) ? DNS_ANSWER_A_SIZE : DNS_ANSWER_AAAA_SIZE;
    int tail_delta = answer_size - edns_size;

    /* Simulate adjust_tail: grow/shrink buffer */
    int new_frame_len = frame_len + tail_delta;
    if (new_frame_len > BUF_SIZE) { stat_inc(STAT_MISS); *out_action = XDP_PASS; return -1; }

    /* Re-parse (simulating pointer invalidation) */
    eth = (struct ethhdr_sim *)data;
    iph = (struct iphdr_sim *)(eth + 1);
    ip_hdr_len = iph->ihl * 4;
    udp = (struct udphdr_sim *)((void *)iph + ip_hdr_len);
    dns = (void *)(udp + 1);
    data_end = data + new_frame_len;

    /* Swap MAC */
    __u8 tmp_mac[ETH_ALEN];
    memcpy(tmp_mac, eth->h_source, ETH_ALEN);
    memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
    memcpy(eth->h_dest, tmp_mac, ETH_ALEN);

    /* Swap IP */
    __u32 tmp_ip = iph->saddr;
    iph->saddr = iph->daddr;
    iph->daddr = tmp_ip;

    /* Update IP length + checksum */
    iph->tot_len = htons(ntohs(iph->tot_len) + tail_delta);
    iph->check = recompute_ip_checksum(iph);

    /* Swap ports + update UDP length */
    __u16 tmp_port = udp->source;
    udp->source = udp->dest;
    udp->dest = tmp_port;
    udp->len = htons(ntohs(udp->len) + tail_delta);
    udp->check = 0;

    /* DNS flags */
    dns_words[1] = htons(0x8400); /* QR=1, AA=1 */
    dns_words[3] = htons(1);      /* ANCOUNT=1 */
    dns_words[5] = htons(0);      /* ARCOUNT=0 */

    /* Answer section */
    __u8 *answer = (__u8 *)dns + dns_payload_len;
    if ((void *)(answer + answer_size) > (void *)data_end) {
        stat_inc(STAT_MISS); *out_action = XDP_PASS; return -1;
    }

    *(__u16 *)(answer + 0)  = htons(0xC00C);
    *(__u16 *)(answer + 2)  = htons(key.qtype);
    *(__u16 *)(answer + 4)  = htons(1);
    *(__u32 *)(answer + 6)  = htonl(val->ttl);
    *(__u16 *)(answer + 10) = htons(key.qtype == DNS_TYPE_A ? 4 : 16);

    if (key.qtype == DNS_TYPE_A) {
        *(__u32 *)(answer + 12) = val->ip;
    } else {
        memcpy(answer + 12, val->ip6, 16);
    }

    stat_inc(STAT_HIT);
    *out_action = XDP_TX;
    return new_frame_len;
}

/* --- 测试框架 --- */

static int tests_run = 0, tests_pass = 0, tests_fail = 0;

#define TEST_BEGIN(name) do { tests_run++; printf("  [TEST] %-50s ", name); } while(0)
#define TEST_PASS() do { tests_pass++; printf("PASS\n"); } while(0)
#define TEST_FAIL(fmt, ...) do { tests_fail++; printf("FAIL: " fmt "\n", ##__VA_ARGS__); } while(0)

/* --- 初始化 Map --- */

static void init_map(void)
{
    struct dns_key key;
    struct dns_val val;

    /* www.test.com -> 2.3.4.4 */
    memset(&key, 0, sizeof(key));
    key.qtype = DNS_TYPE_A;
    strcpy(key.name, "www.test.com");
    val.ip = inet_addr("2.3.4.4");
    val.ttl = 200;
    memset(val.ip6, 0, 16);
    map_update(&key, &val);

    /* www.test.com AAAA -> 2001:db8::2 */
    key.qtype = DNS_TYPE_AAAA;
    struct in6_addr addr6;
    inet_pton(AF_INET6, "2001:db8::2", &addr6);
    memcpy(val.ip6, &addr6, 16);
    val.ttl = 200;
    map_update(&key, &val);
}

/* --- 测试用例 --- */

static void test_a_record_hit(void)
{
    TEST_BEGIN("A 记录命中 (XDP_TX)");

    __u8 dns[BUF_SIZE];
    int dns_len = build_dns_query(dns, sizeof(dns), "www.test.com", DNS_TYPE_A, 0x1111, 0);

    __u8 frame[BUF_SIZE];
    int frame_len = build_eth_frame(frame, sizeof(frame),
                                     "aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02",
                                     inet_addr("10.0.0.1"), inet_addr("10.0.0.2"),
                                     12345, 53, dns, dns_len);

    int action;
    int ret = sim_xdp_dns(frame, frame_len, &action);

    if (action != XDP_TX) { TEST_FAIL("期望 XDP_TX, 得到 %d", action); return; }
    if (ret < 0) { TEST_FAIL("响应构建失败"); return; }

    /* 验证响应中的 DNS 答案 */
    struct ethhdr_sim *eth = (struct ethhdr_sim *)frame;
    struct iphdr_sim *iph = (struct iphdr_sim *)(eth + 1);
    struct udphdr_sim *udp = (struct udphdr_sim *)((void *)iph + 20);
    void *dns_resp = (void *)(udp + 1);

    __u16 *dw = (__u16 *)dns_resp;
    __u16 flags = ntohs(dw[1]);
    __u16 ancount = ntohs(dw[3]);
    __u16 arcount = ntohs(dw[5]);

    if (!(flags & 0x8000)) { TEST_FAIL("QR 位未设置"); return; }
    if (!(flags & 0x0400)) { TEST_FAIL("AA 位未设置"); return; }
    if (ancount != 1) { TEST_FAIL("ANCOUNT 期望 1, 得到 %u", ancount); return; }
    if (arcount != 0) { TEST_FAIL("ARCOUNT 期望 0 (EDNS 已剥离), 得到 %u", arcount); return; }

    /* 验证端口交换 */
    if (ntohs(udp->source) != 53) { TEST_FAIL("源端口未交换"); return; }
    if (ntohs(udp->dest) != 12345) { TEST_FAIL("目标端口未交换"); return; }

    /* 验证 IP 交换 */
    if (iph->saddr != inet_addr("10.0.0.2")) { TEST_FAIL("源 IP 未交换"); return; }
    if (iph->daddr != inet_addr("10.0.0.1")) { TEST_FAIL("目标 IP 未交换"); return; }

    TEST_PASS();
}

static void test_aaaa_record_hit(void)
{
    TEST_BEGIN("AAAA 记录命中 (XDP_TX)");

    __u8 dns[BUF_SIZE];
    int dns_len = build_dns_query(dns, sizeof(dns), "www.test.com", DNS_TYPE_AAAA, 0x2222, 0);

    __u8 frame[BUF_SIZE];
    int frame_len = build_eth_frame(frame, sizeof(frame),
                                     "aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02",
                                     inet_addr("10.0.0.1"), inet_addr("10.0.0.2"),
                                     12345, 53, dns, dns_len);

    int action;
    int ret = sim_xdp_dns(frame, frame_len, &action);

    if (action != XDP_TX) { TEST_FAIL("期望 XDP_TX, 得到 %d", action); return; }
    if (ret < 0) { TEST_FAIL("响应构建失败"); return; }

    /* 验证 AAAA 答案 (28 字节) */
    struct ethhdr_sim *eth = (struct ethhdr_sim *)frame;
    struct iphdr_sim *iph = (struct iphdr_sim *)(eth + 1);
    struct udphdr_sim *udp = (struct udphdr_sim *)((void *)iph + 20);
    void *dns_resp = (void *)(udp + 1);

    __u16 *dw = (__u16 *)dns_resp;
    __u16 ancount = ntohs(dw[3]);
    if (ancount != 1) { TEST_FAIL("ANCOUNT 期望 1"); return; }

    /* 验证 IP total length 正确增加了 28 */
    /* IP(20) + UDP(8) + DNS header(12) + name(14: 3www4test3com0) + qtype/qclass(4) + AAAA(28) = 86 */
    __u16 expected_tot_len = 20 + 8 + 12 + 14 + 4 + 28;
    if (ntohs(iph->tot_len) != expected_tot_len) {
        TEST_FAIL("IP tot_len 期望 %u, 得到 %u", expected_tot_len, ntohs(iph->tot_len));
        return;
    }

    TEST_PASS();
}

static void test_cache_miss(void)
{
    TEST_BEGIN("缓存未命中 (XDP_PASS)");

    __u8 dns[BUF_SIZE];
    int dns_len = build_dns_query(dns, sizeof(dns), "unknown.test.com", DNS_TYPE_A, 0x3333, 0);

    __u8 frame[BUF_SIZE];
    int frame_len = build_eth_frame(frame, sizeof(frame),
                                     "aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02",
                                     inet_addr("10.0.0.1"), inet_addr("10.0.0.2"),
                                     12345, 53, dns, dns_len);

    int action;
    sim_xdp_dns(frame, frame_len, &action);

    if (action == XDP_PASS)
        TEST_PASS();
    else
        TEST_FAIL("期望 XDP_PASS, 得到 %d", action);
}

static void test_edns_query_hit(void)
{
    TEST_BEGIN("EDNS 查询命中 (剥离 OPT, XDP_TX)");

    __u8 dns[BUF_SIZE];
    /* 构建带 EDNS 的查询 */
    int dns_len = build_dns_query(dns, sizeof(dns), "www.test.com", DNS_TYPE_A, 0x4444, 1);

    __u8 frame[BUF_SIZE];
    int frame_len = build_eth_frame(frame, sizeof(frame),
                                     "aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02",
                                     inet_addr("10.0.0.1"), inet_addr("10.0.0.2"),
                                     12345, 53, dns, dns_len);

    int action;
    int ret = sim_xdp_dns(frame, frame_len, &action);

    if (action != XDP_TX) { TEST_FAIL("期望 XDP_TX, 得到 %d", action); return; }
    if (ret < 0) { TEST_FAIL("响应构建失败"); return; }

    /* 验证 ARCOUNT=0 (EDNS 已剥离) */
    struct ethhdr_sim *eth = (struct ethhdr_sim *)frame;
    struct iphdr_sim *iph = (struct iphdr_sim *)(eth + 1);
    struct udphdr_sim *udp = (struct udphdr_sim *)((void *)iph + 20);
    void *dns_resp = (void *)(udp + 1);

    __u16 *dw = (__u16 *)dns_resp;
    __u16 arcount = ntohs(dw[5]);

    if (arcount != 0) { TEST_FAIL("ARCOUNT 期望 0, 得到 %u", arcount); return; }

    /* 验证响应大小 = 原始 - EDNS(11) + answer(16) = frame_len + 5 */
    int expected_len = frame_len - 11 + 16;
    if (ret != expected_len) {
        TEST_FAIL("响应长度期望 %d, 得到 %d", expected_len, ret);
        return;
    }

    TEST_PASS();
}

static void test_non_dns_port(void)
{
    TEST_BEGIN("非 53 端口 (XDP_PASS)");

    __u8 dns[BUF_SIZE];
    int dns_len = build_dns_query(dns, sizeof(dns), "www.test.com", DNS_TYPE_A, 0x5555, 0);

    __u8 frame[BUF_SIZE];
    int frame_len = build_eth_frame(frame, sizeof(frame),
                                     "aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02",
                                     inet_addr("10.0.0.1"), inet_addr("10.0.0.2"),
                                     12345, 8080, dns, dns_len); /* port 8080 */

    int action;
    sim_xdp_dns(frame, frame_len, &action);

    if (action == XDP_PASS)
        TEST_PASS();
    else
        TEST_FAIL("期望 XDP_PASS, 得到 %d", action);
}

static void test_non_udp_protocol(void)
{
    TEST_BEGIN("非 UDP 协议 (XDP_PASS)");

    __u8 dns[BUF_SIZE];
    int dns_len = build_dns_query(dns, sizeof(dns), "www.test.com", DNS_TYPE_A, 0x6666, 0);

    __u8 frame[BUF_SIZE];
    int frame_len = build_eth_frame(frame, sizeof(frame),
                                     "aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02",
                                     inet_addr("10.0.0.1"), inet_addr("10.0.0.2"),
                                     12345, 53, dns, dns_len);

    /* 篡改协议为 TCP */
    struct ethhdr_sim *eth = (struct ethhdr_sim *)frame;
    struct iphdr_sim *iph = (struct iphdr_sim *)(eth + 1);
    iph->protocol = 6; /* TCP */
    iph->check = recompute_ip_checksum(iph);

    int action;
    sim_xdp_dns(frame, frame_len, &action);

    if (action == XDP_PASS)
        TEST_PASS();
    else
        TEST_FAIL("期望 XDP_PASS, 得到 %d", action);
}

static void test_qr_response_packet(void)
{
    TEST_BEGIN("QR=1 响应包 (XDP_PASS)");

    __u8 dns[BUF_SIZE];
    int dns_len = build_dns_query(dns, sizeof(dns), "www.test.com", DNS_TYPE_A, 0x7777, 0);
    /* 设置 QR=1 */
    *(__u16 *)(dns + 2) = htons(0x8100);

    __u8 frame[BUF_SIZE];
    int frame_len = build_eth_frame(frame, sizeof(frame),
                                     "aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02",
                                     inet_addr("10.0.0.1"), inet_addr("10.0.0.2"),
                                     12345, 53, dns, dns_len);

    int action;
    sim_xdp_dns(frame, frame_len, &action);

    if (action == XDP_PASS)
        TEST_PASS();
    else
        TEST_FAIL("期望 XDP_PASS, 得到 %d", action);
}

static void test_ns_query_pass(void)
{
    TEST_BEGIN("NS 查询 (XDP_PASS, 非 A/AAAA)");

    __u8 dns[BUF_SIZE];
    int dns_len = build_dns_query(dns, sizeof(dns), "test.com", DNS_TYPE_NS, 0x8888, 0);

    __u8 frame[BUF_SIZE];
    int frame_len = build_eth_frame(frame, sizeof(frame),
                                     "aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02",
                                     inet_addr("10.0.0.1"), inet_addr("10.0.0.2"),
                                     12345, 53, dns, dns_len);

    int action;
    sim_xdp_dns(frame, frame_len, &action);

    if (action == XDP_PASS)
        TEST_PASS();
    else
        TEST_FAIL("期望 XDP_PASS, 得到 %d", action);
}

static void test_ip_checksum_valid(void)
{
    TEST_BEGIN("IP 校验和验证");

    __u8 dns[BUF_SIZE];
    int dns_len = build_dns_query(dns, sizeof(dns), "www.test.com", DNS_TYPE_A, 0x9999, 0);

    __u8 frame[BUF_SIZE];
    int frame_len = build_eth_frame(frame, sizeof(frame),
                                     "aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02",
                                     inet_addr("10.0.0.1"), inet_addr("10.0.0.2"),
                                     12345, 53, dns, dns_len);

    int action;
    int ret = sim_xdp_dns(frame, frame_len, &action);
    if (action != XDP_TX || ret < 0) { TEST_FAIL("XDP_TX 失败"); return; }

    /* 验证 IP 校验和正确 */
    struct ethhdr_sim *eth = (struct ethhdr_sim *)frame;
    struct iphdr_sim *iph = (struct iphdr_sim *)(eth + 1);

    __u16 saved_check = iph->check;
    iph->check = 0;
    __u16 calc_check = recompute_ip_checksum(iph);

    if (saved_check == calc_check)
        TEST_PASS();
    else
        TEST_FAIL("校验和不匹配: saved=0x%04X calc=0x%04X", saved_check, calc_check);
}

static void test_stats_counters(void)
{
    TEST_BEGIN("统计计数器验证");

    /* 重置统计 */
    memset(sim_stats, 0, sizeof(sim_stats));

    /* 发送 3 个命中 + 2 个未命中 */
    __u8 dns[BUF_SIZE], frame[BUF_SIZE];

    /* 命中 1: www.test.com A */
    int dl = build_dns_query(dns, sizeof(dns), "www.test.com", DNS_TYPE_A, 1, 0);
    int fl = build_eth_frame(frame, sizeof(frame), "aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02",
                              inet_addr("10.0.0.1"), inet_addr("10.0.0.2"), 12345, 53, dns, dl);
    int act; sim_xdp_dns(frame, fl, &act);

    /* 命中 2: www.test.com AAAA */
    dl = build_dns_query(dns, sizeof(dns), "www.test.com", DNS_TYPE_AAAA, 2, 0);
    fl = build_eth_frame(frame, sizeof(frame), "aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02",
                          inet_addr("10.0.0.1"), inet_addr("10.0.0.2"), 12345, 53, dns, dl);
    sim_xdp_dns(frame, fl, &act);

    /* 命中 3: www.test.com A (with EDNS) */
    dl = build_dns_query(dns, sizeof(dns), "www.test.com", DNS_TYPE_A, 3, 1);
    fl = build_eth_frame(frame, sizeof(frame), "aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02",
                          inet_addr("10.0.0.1"), inet_addr("10.0.0.2"), 12345, 53, dns, dl);
    sim_xdp_dns(frame, fl, &act);

    /* 未命中 1: unknown.test.com */
    dl = build_dns_query(dns, sizeof(dns), "unknown.test.com", DNS_TYPE_A, 4, 0);
    fl = build_eth_frame(frame, sizeof(frame), "aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02",
                          inet_addr("10.0.0.1"), inet_addr("10.0.0.2"), 12345, 53, dns, dl);
    sim_xdp_dns(frame, fl, &act);

    /* 未命中 2: NS 查询 (非 A/AAAA, 在 map 查找前过滤, 不计入 MISS) */
    dl = build_dns_query(dns, sizeof(dns), "test.com", DNS_TYPE_NS, 5, 0);
    fl = build_eth_frame(frame, sizeof(frame), "aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02",
                          inet_addr("10.0.0.1"), inet_addr("10.0.0.2"), 12345, 53, dns, dl);
    sim_xdp_dns(frame, fl, &act);

    /* 5 个包: 3 命中 + 1 未命中 + 1 过滤 (NS 非 A/AAAA, 不计入 MISS) */
    if (sim_stats[STAT_TOTAL] != 5) {
        TEST_FAIL("TOTAL 期望 5, 得到 %llu", sim_stats[STAT_TOTAL]);
        return;
    }
    if (sim_stats[STAT_HIT] != 3) {
        TEST_FAIL("HIT 期望 3, 得到 %llu", sim_stats[STAT_HIT]);
        return;
    }
    if (sim_stats[STAT_MISS] != 1) {
        TEST_FAIL("MISS 期望 1, 得到 %llu", sim_stats[STAT_MISS]);
        return;
    }

    TEST_PASS();
}

/* --- 主函数 --- */

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    printf("\n============================================\n");
    printf("  SimpleDns XDP - 内核逻辑模拟测试\n");
    printf("============================================\n\n");

    init_map();

    printf("--- 命中/未命中测试 ---\n");
    test_a_record_hit();
    test_aaaa_record_hit();
    test_cache_miss();
    test_edns_query_hit();

    printf("\n--- 过滤逻辑测试 ---\n");
    test_non_dns_port();
    test_non_udp_protocol();
    test_qr_response_packet();
    test_ns_query_pass();

    printf("\n--- 数据完整性测试 ---\n");
    test_ip_checksum_valid();
    test_stats_counters();

    printf("\n============================================\n");
    printf("  结果: %d 通过, %d 失败, 共 %d\n",
           tests_pass, tests_fail, tests_run);
    if (tests_fail == 0)
        printf("  全部通过\n");
    else
        printf("  存在失败用例\n");
    printf("============================================\n\n");

    return (tests_fail == 0) ? 0 : 1;
}
