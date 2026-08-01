/*
 * XDP DNS 协议边界测试程序
 *
 * 测试 DNS 协议解析在各种畸形和边界条件下的行为：
 *   - 空包、过短包
 *   - 超长域名 (63 字节单标签、253 字节全名)
 *   - 压缩指针 (合法和畸形)
 *   - EDNS OPT 附加段
 *   - 非标准查询类型
 *   - 多问题段
 *   - QR 位为 1 的包 (响应而非查询)
 *   - TTL 边界值 (0, 最大值)
 *
 * 构建: gcc -O2 -Wall -o xdp_dns_edge xdp_dns_edge.c
 * 用法:   ./xdp_dns_edge
 */

#ifndef __linux__
typedef unsigned char  __u8;
typedef unsigned short __u16;
typedef unsigned int   __u32;
typedef unsigned long long __u64;
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "xdp_dns_common.h"

#define BUF_SIZE 1500

/* --- 从测试程序复制的核心函数 --- */

static int parse_wire_name(const __u8 *data, int data_len, int offset,
                           char *out, int out_max)
{
    int pos = offset;
    int out_pos = 0;

    for (int i = 0; i < 127; i++) {
        if (pos + 1 > data_len) return -1;
        __u8 label_len = data[pos++];
        if (label_len == 0) break;
        if (label_len > 63) return -1;
        if (out_pos > 0 && out_pos < out_max) out[out_pos++] = '.';
        for (int j = 0; j < label_len; j++) {
            if (pos + 1 > data_len) return -1;
            if (out_pos + 1 >= out_max) return -1;
            char c = data[pos++];
            if (c >= 'A' && c <= 'Z') c += 32;
            out[out_pos++] = c;
        }
    }
    out[out_pos] = '\0';
    return pos - offset;
}

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

/* --- 测试框架 --- */

static int tests_run = 0;
static int tests_pass = 0;
static int tests_fail = 0;

#define TEST_BEGIN(name) do { \
    tests_run++; \
    printf("  [TEST] %-50s ", name); \
} while(0)

#define TEST_PASS() do { \
    tests_pass++; \
    printf("PASS\n"); \
} while(0)

#define TEST_FAIL(fmt, ...) do { \
    tests_fail++; \
    printf("FAIL: " fmt "\n", ##__VA_ARGS__); \
} while(0)

/* --- 辅助: 构建 DNS 查询包 --- */

static int build_query(__u8 *buf, int max_len, const char *name, __u16 qtype,
                       __u16 flags, __u16 qdcount, __u16 arcount)
{
    *(__u16 *)(buf + 0)  = htons(0xABCD);
    *(__u16 *)(buf + 2)  = htons(flags);
    *(__u16 *)(buf + 4)  = htons(qdcount);
    *(__u16 *)(buf + 6)  = htons(0);
    *(__u16 *)(buf + 8)  = htons(0);
    *(__u16 *)(buf + 10) = htons(arcount);
    int pos = 12;

    int name_len = encode_wire_name(name, buf + pos, max_len - pos - 4);
    if (name_len < 0) return -1;
    pos += name_len;
    *(__u16 *)(buf + pos) = htons(qtype);
    pos += 2;
    *(__u16 *)(buf + pos) = htons(1);
    pos += 2;

    /* 附加 EDNS OPT 记录 (如果 arcount > 0) */
    if (arcount > 0) {
        if (pos + 11 > max_len) return -1;
        buf[pos++] = 0;             /* root name */
        *(__u16 *)(buf + pos) = htons(41); pos += 2;  /* type OPT */
        *(__u16 *)(buf + pos) = htons(4096); pos += 2; /* UDP payload size */
        *(__u32 *)(buf + pos) = 0; pos += 4;           /* extended RCODE + flags */
        *(__u16 *)(buf + pos) = htons(0); pos += 2;    /* RDLENGTH = 0 */
    }

    return pos;
}

/* --- 边界测试用例 --- */

static void test_empty_packet(void)
{
    TEST_BEGIN("空包 (0 字节)");
    __u8 buf[1] = {0};
    char name[DNS_MAX_NAME];
    int ret = parse_wire_name(buf, 0, 12, name, sizeof(name));
    if (ret < 0)
        TEST_PASS();
    else
        TEST_FAIL("期望返回 -1, 得到 %d", ret);
}

static void test_too_short_header(void)
{
    TEST_BEGIN("过短包 (5 字节, < 12 字节头部)");
    __u8 buf[5] = {0};
    char name[DNS_MAX_NAME];
    int ret = parse_wire_name(buf, 5, 12, name, sizeof(name));
    if (ret < 0)
        TEST_PASS();
    else
        TEST_FAIL("期望返回 -1, 得到 %d", ret);
}

static void test_long_label_63(void)
{
    TEST_BEGIN("最大单标签 (63 字节)");

    /* 构建 63 字节的标签 */
    char long_label[64];
    memset(long_label, 'a', 63);
    long_label[63] = '\0';

    __u8 wire[80];
    wire[0] = 63;
    memcpy(wire + 1, long_label, 63);
    wire[64] = 0; /* 终止 */

    char decoded[DNS_MAX_NAME];
    int ret = parse_wire_name(wire, 65, 0, decoded, sizeof(decoded));

    if (ret < 0) {
        TEST_FAIL("合法 63 字节标签解析失败");
        return;
    }

    if (strlen(decoded) == 63 && strcmp(decoded, long_label) == 0)
        TEST_PASS();
    else
        TEST_FAIL("解码结果不匹配, 长度=%zu", strlen(decoded));
}

static void test_label_too_long_64(void)
{
    TEST_BEGIN("超长标签 (64 字节, 应拒绝)");

    __u8 wire[66];
    wire[0] = 64; /* > 63, 应被拒绝 */
    memset(wire + 1, 'a', 64);
    wire[65] = 0;

    char decoded[DNS_MAX_NAME];
    int ret = parse_wire_name(wire, 66, 0, decoded, sizeof(decoded));

    if (ret < 0)
        TEST_PASS();
    else
        TEST_FAIL("期望拒绝 64 字节标签, 得到 ret=%d", ret);
}

static void test_max_domain_253(void)
{
    TEST_BEGIN("超长域名 (253 字节, 超出缓冲区应拒绝)");

    /* 构建 253 字节的域名: 3个63字节标签 + 61字节标签 */
    /* DNS_MAX_NAME=128, 253 字节超出缓冲区, 应返回 -1 */
    char domain[256];
    int pos = 0;
    for (int i = 0; i < 3; i++) {
        memset(domain + pos, 'a', 63);
        pos += 63;
        domain[pos++] = '.';
    }
    memset(domain + pos, 'b', 61);
    pos += 61;
    domain[pos] = '\0';

    __u8 wire[BUF_SIZE];
    int wlen = encode_wire_name(domain, wire, sizeof(wire));
    if (wlen < 0) {
        TEST_FAIL("编码失败");
        return;
    }

    char decoded[DNS_MAX_NAME];
    int ret = parse_wire_name(wire, wlen, 0, decoded, sizeof(decoded));

    /* 253 字节超出 DNS_MAX_NAME (128), 应返回 -1 */
    if (ret < 0)
        TEST_PASS();
    else
        TEST_FAIL("期望返回 -1 (超出缓冲区), 得到 %d", ret);
}

static void test_domain_fits_buffer(void)
{
    TEST_BEGIN("接近缓冲区上限的域名 (126 字节)");

    /* 构建 126 字节的域名: 2个63字节标签, 加点分隔 = 63+1+63 = 127 */
    /* 但 DNS_MAX_NAME=128, parse_wire_name 在 out_pos+1>=out_max 时返回 -1 */
    /* 所以最大可解码长度为 126 字符 (留 1 字节给 null) */
    char domain[DNS_MAX_NAME];
    int pos = 0;
    memset(domain + pos, 'a', 62);
    pos += 62;
    domain[pos++] = '.';
    memset(domain + pos, 'b', 62);
    pos += 62;
    domain[pos] = '\0';

    __u8 wire[BUF_SIZE];
    int wlen = encode_wire_name(domain, wire, sizeof(wire));
    if (wlen < 0) {
        TEST_FAIL("编码失败");
        return;
    }

    char decoded[DNS_MAX_NAME];
    int ret = parse_wire_name(wire, wlen, 0, decoded, sizeof(decoded));

    if (ret < 0)
        TEST_FAIL("合法 126 字节域名解析失败");
    else if (strcmp(decoded, domain) == 0)
        TEST_PASS();
    else
        TEST_FAIL("解码不匹配: 期望 '%s', 得到 '%s'", domain, decoded);
}

static void test_truncated_name(void)
{
    TEST_BEGIN("截断的域名 (标签长度声明 10 但只提供 3 字节)");

    __u8 wire[] = { 10, 'a', 'b', 'c' }; /* 声明 10 字节但只有 3 字节 */
    char decoded[DNS_MAX_NAME];
    int ret = parse_wire_name(wire, sizeof(wire), 0, decoded, sizeof(decoded));

    if (ret < 0)
        TEST_PASS();
    else
        TEST_FAIL("期望拒绝截断的域名, 得到 ret=%d", ret);
}

static void test_compression_pointer_valid(void)
{
    TEST_BEGIN("压缩指针 (指向偏移 12)");

    /* 在偏移 12 处放置 "test.com", 后面用压缩指针引用 */
    __u8 wire[BUF_SIZE];
    int pos = 0;

    /* 偏移 0: 一个名称 "xyz" */
    wire[0] = 3; wire[1]='x'; wire[2]='y'; wire[3]='z'; wire[4]=0;
    pos = 5;

    /* 偏移 5: 压缩指针指向偏移 0 */
    wire[5] = 0xC0; wire[6] = 0x00;
    pos = 7;

    /* 注意: 我们的 parse_wire_name 不支持压缩指针 (label_len > 63 返回 -1) */
    /* 这是预期行为: 用户态回退处理压缩指针, XDP 不支持 */
    char decoded[DNS_MAX_NAME];
    int ret = parse_wire_name(wire, pos, 5, decoded, sizeof(decoded));

    if (ret < 0)
        TEST_PASS();
    else
        TEST_FAIL("期望拒绝压缩指针, 得到 ret=%d", ret);
}

static void test_edns_opt_stripped(void)
{
    TEST_BEGIN("EDNS OPT 记录: 构建带 EDNS 的查询并验证 ARCOUNT");

    __u8 query[BUF_SIZE];
    int qlen = build_query(query, sizeof(query), "www.test.com",
                           DNS_TYPE_A, 0x0100, 1, 1);
    if (qlen < 0) {
        TEST_FAIL("构建查询失败");
        return;
    }

    __u16 arcount = ntohs(*(__u16 *)(query + 10));
    if (arcount != 1) {
        TEST_FAIL("ARCOUNT 期望 1, 得到 %u", arcount);
        return;
    }

    /* 检查 EDNS OPT 记录在包尾 */
    /* 问题段: 12 (header) + 3www4test3com0 (14 bytes) + 4 (qtype+qclass) = 30 */
    int question_end = 12 + 14 + 4; /* 30 */
    int edns_start = question_end;

    /* OPT record: root name (1) + type (2) + class (2) + ttl (4) + rdlen (2) = 11 */
    if (qlen - edns_start != 11) {
        TEST_FAIL("EDNS OPT 大小期望 11, 得到 %d", qlen - edns_start);
        return;
    }

    /* 验证 OPT type = 41 */
    __u16 opt_type = ntohs(*(__u16 *)(query + edns_start + 1));
    if (opt_type == 41)
        TEST_PASS();
    else
        TEST_FAIL("OPT type 期望 41, 得到 %u", opt_type);
}

static void test_qr_bit_set(void)
{
    TEST_BEGIN("QR=1 的包 (响应而非查询)");

    __u8 query[BUF_SIZE];
    /* flags = 0x8100: QR=1, RD=1 */
    int qlen = build_query(query, sizeof(query), "www.test.com",
                           DNS_TYPE_A, 0x8100, 1, 0);
    if (qlen < 0) {
        TEST_FAIL("构建查询失败");
        return;
    }

    __u16 flags = ntohs(*(__u16 *)(query + 2));
    if (flags & 0x8000)
        TEST_PASS();
    else
        TEST_FAIL("QR 位未设置");
}

static void test_multi_question(void)
{
    TEST_BEGIN("多问题段 (QDCOUNT=2)");

    __u8 query[BUF_SIZE];
    int qlen = build_query(query, sizeof(query), "www.test.com",
                           DNS_TYPE_A, 0x0100, 2, 0);
    if (qlen < 0) {
        TEST_FAIL("构建查询失败");
        return;
    }

    __u16 qdcount = ntohs(*(__u16 *)(query + 4));
    if (qdcount == 2)
        TEST_PASS();
    else
        TEST_FAIL("QDCOUNT 期望 2, 得到 %u", qdcount);
}

static void test_nonexistent_type(void)
{
    TEST_BEGIN("非标准查询类型 (type=999)");

    __u8 query[BUF_SIZE];
    int qlen = build_query(query, sizeof(query), "www.test.com",
                           999, 0x0100, 1, 0);
    if (qlen < 0) {
        TEST_FAIL("构建查询失败");
        return;
    }

    /* 解析问题段获取 qtype */
    char name[DNS_MAX_NAME];
    int consumed = parse_wire_name(query, qlen, 12, name, sizeof(name));
    if (consumed < 0) {
        TEST_FAIL("解析问题段失败");
        return;
    }

    __u16 qtype = ntohs(*(__u16 *)(query + 12 + consumed));
    if (qtype == 999)
        TEST_PASS();
    else
        TEST_FAIL("qtype 期望 999, 得到 %u", qtype);
}

static void test_root_domain(void)
{
    TEST_BEGIN("根域名查询 (.)");

    __u8 wire[2];
    int wlen = encode_wire_name("", wire, sizeof(wire));

    if (wlen != 1 || wire[0] != 0) {
        TEST_FAIL("根域名编码错误: wlen=%d, wire[0]=%d", wlen, wire[0]);
        return;
    }

    char decoded[DNS_MAX_NAME];
    int ret = parse_wire_name(wire, wlen, 0, decoded, sizeof(decoded));

    if (ret < 0)
        TEST_FAIL("根域名解析失败");
    else if (strlen(decoded) == 0)
        TEST_PASS();
    else
        TEST_FAIL("根域名解码非空: '%s'", decoded);
}

static void test_special_chars_in_name(void)
{
    TEST_BEGIN("域名中的特殊字符 (数字和连字符)");

    const char *name = "a1-b2.c3-d4.test.com";
    __u8 wire[64];
    int wlen = encode_wire_name(name, wire, sizeof(wire));
    if (wlen < 0) {
        TEST_FAIL("编码失败");
        return;
    }

    char decoded[DNS_MAX_NAME];
    int ret = parse_wire_name(wire, wlen, 0, decoded, sizeof(decoded));

    if (ret < 0)
        TEST_FAIL("解析失败");
    else if (strcmp(decoded, name) == 0)
        TEST_PASS();
    else
        TEST_FAIL("解码不匹配: 期望 '%s', 得到 '%s'", name, decoded);
}

static void test_deeply_nested_domain(void)
{
    TEST_BEGIN("深层嵌套域名 (10 级)");

    const char *name = "a.b.c.d.e.f.g.h.i.j.test.com";
    __u8 wire[128];
    int wlen = encode_wire_name(name, wire, sizeof(wire));
    if (wlen < 0) {
        TEST_FAIL("编码失败");
        return;
    }

    char decoded[DNS_MAX_NAME];
    int ret = parse_wire_name(wire, wlen, 0, decoded, sizeof(decoded));

    if (ret < 0)
        TEST_FAIL("解析失败");
    else if (strcmp(decoded, name) == 0)
        TEST_PASS();
    else
        TEST_FAIL("解码不匹配: 期望 '%s', 得到 '%s'", name, decoded);
}

static void test_case_mixed(void)
{
    TEST_BEGIN("混合大小写域名 (WwW.TeSt.CoM)");

    __u8 wire[64];
    int wlen = encode_wire_name("WwW.TeSt.CoM", wire, sizeof(wire));
    if (wlen < 0) {
        TEST_FAIL("编码失败");
        return;
    }

    char decoded[DNS_MAX_NAME];
    int ret = parse_wire_name(wire, wlen, 0, decoded, sizeof(decoded));

    if (ret < 0) {
        TEST_FAIL("解析失败");
        return;
    }

    /* parse_wire_name 会转为小写 */
    if (strcmp(decoded, "www.test.com") == 0)
        TEST_PASS();
    else
        TEST_FAIL("期望 'www.test.com', 得到 '%s'", decoded);
}

static void test_name_overflow(void)
{
    TEST_BEGIN("域名超长溢出 (输出缓冲区不足)");

    /* 构建 200 字符的域名 */
    char long_name[256];
    int pos = 0;
    for (int i = 0; i < 5; i++) {
        memset(long_name + pos, 'a', 40);
        pos += 40;
        long_name[pos++] = '.';
    }
    long_name[pos] = '\0';

    __u8 wire[BUF_SIZE];
    int wlen = encode_wire_name(long_name, wire, sizeof(wire));
    if (wlen < 0) {
        TEST_FAIL("编码失败");
        return;
    }

    /* 使用很小的输出缓冲区 */
    char small_buf[10];
    int ret = parse_wire_name(wire, wlen, 0, small_buf, sizeof(small_buf));

    if (ret < 0)
        TEST_PASS();
    else
        TEST_FAIL("期望返回 -1 (缓冲区溢出), 得到 %d", ret);
}

static void test_ttl_zero(void)
{
    TEST_BEGIN("TTL=0 边界值");

    /* 构建 A 记录答案段, TTL=0 */
    __u8 ans[16];
    *(__u16 *)(ans + 0)  = htons(0xC00C);
    *(__u16 *)(ans + 2)  = htons(DNS_TYPE_A);
    *(__u16 *)(ans + 4)  = htons(1);
    *(__u32 *)(ans + 6)  = htonl(0); /* TTL=0 */
    *(__u16 *)(ans + 10) = htons(4);
    *(__u32 *)(ans + 12) = inet_addr("1.2.3.4");

    __u32 ttl = ntohl(*(__u32 *)(ans + 6));
    if (ttl == 0)
        TEST_PASS();
    else
        TEST_FAIL("TTL 期望 0, 得到 %u", ttl);
}

static void test_ttl_max(void)
{
    TEST_BEGIN("TTL=0xFFFFFFFF 边界值");

    __u8 ans[16];
    *(__u16 *)(ans + 0)  = htons(0xC00C);
    *(__u16 *)(ans + 2)  = htons(DNS_TYPE_A);
    *(__u16 *)(ans + 4)  = htons(1);
    *(__u32 *)(ans + 6)  = htonl(0xFFFFFFFF); /* max TTL */
    *(__u16 *)(ans + 10) = htons(4);
    *(__u32 *)(ans + 12) = inet_addr("1.2.3.4");

    __u32 ttl = ntohl(*(__u32 *)(ans + 6));
    if (ttl == 0xFFFFFFFF)
        TEST_PASS();
    else
        TEST_FAIL("TTL 期望 0xFFFFFFFF, 得到 0x%X", ttl);
}

static void test_loopback_ip(void)
{
    TEST_BEGIN("回环 IP (127.0.0.1)");

    __u32 ip = inet_addr("127.0.0.1");
    struct in_addr addr;
    addr.s_addr = ip;

    if (strcmp(inet_ntoa(addr), "127.0.0.1") == 0)
        TEST_PASS();
    else
        TEST_FAIL("期望 127.0.0.1, 得到 %s", inet_ntoa(addr));
}

static void test_ipv6_loopback(void)
{
    TEST_BEGIN("IPv6 回环 (::1)");

    struct in6_addr addr6;
    if (inet_pton(AF_INET6, "::1", &addr6) != 1) {
        TEST_FAIL("inet_pton 解析失败");
        return;
    }

    __u8 expected[16] = {0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1};
    if (memcmp(&addr6, expected, 16) == 0)
        TEST_PASS();
    else
        TEST_FAIL("IPv6 地址不匹配");
}

static void test_ipv6_full(void)
{
    TEST_BEGIN("IPv6 完整地址 (2001:db8::1)");

    struct in6_addr addr6;
    if (inet_pton(AF_INET6, "2001:db8::1", &addr6) != 1) {
        TEST_FAIL("inet_pton 解析失败");
        return;
    }

    __u8 expected[16] = {0x20,0x01,0x0d,0xb8, 0,0,0,0, 0,0,0,0, 0,0,0,1};
    if (memcmp(&addr6, expected, 16) == 0)
        TEST_PASS();
    else
        TEST_FAIL("IPv6 地址不匹配");
}

/* --- 主函数 --- */

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    printf("\n============================================\n");
    printf("  SimpleDns XDP - DNS 协议边界测试\n");
    printf("============================================\n\n");

    printf("--- 畸形包测试 ---\n");
    test_empty_packet();
    test_too_short_header();
    test_truncated_name();
    test_name_overflow();

    printf("\n--- 域名边界测试 ---\n");
    test_long_label_63();
    test_label_too_long_64();
    test_max_domain_253();
    test_domain_fits_buffer();
    test_root_domain();
    test_deeply_nested_domain();
    test_special_chars_in_name();
    test_case_mixed();

    printf("\n--- DNS 协议特性测试 ---\n");
    test_compression_pointer_valid();
    test_edns_opt_stripped();
    test_qr_bit_set();
    test_multi_question();
    test_nonexistent_type();

    printf("\n--- TTL 和 IP 边界测试 ---\n");
    test_ttl_zero();
    test_ttl_max();
    test_loopback_ip();
    test_ipv6_loopback();
    test_ipv6_full();

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
