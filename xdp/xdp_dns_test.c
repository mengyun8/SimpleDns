/*
 * XDP DNS Test Program - macOS Compatible
 *
 * This program validates the DNS protocol logic (name parsing, response
 * construction, CNAME chain resolution, AAAA records) without requiring
 * XDP/eBPF. It can also run as a standalone DNS server on port 15353
 * for functional testing with dig.
 *
 * Build (macOS):  gcc -O2 -Wall -o xdp_dns_test xdp_dns_test.c
 * Build (Linux):  gcc -O2 -Wall -o xdp_dns_test xdp_dns_test.c
 *
 * Usage:
 *   ./xdp_dns_test              Run unit tests
 *   ./xdp_dns_test -s zonefile  Start standalone DNS server on port 15353
 *
 * Test with dig:
 *   dig @127.0.0.1 -p 15353 www.test.com
 *   dig @127.0.0.1 -p 15353 www.test.com AAAA
 *   dig @127.0.0.1 -p 15353 cname.test.com
 */

/* Provide Linux types for non-Linux platforms */
#include <stdint.h>
#ifndef __linux__
typedef uint8_t  __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "xdp_dns_common.h"

#define BUF_SIZE    1500
#define MAX_RECORDS 1024
#define MAX_LINE    1024
#define TEST_PORT   15353

/* --- Record store --- */

struct dns_record {
    char    name[DNS_MAX_NAME];
    __u16   type;
    __u16   ttl;
    char    data[DNS_MAX_NAME];
};

static struct dns_record records[MAX_RECORDS];
static int record_count = 0;
static volatile int running = 1;

static void sig_handler(int sig)
{
    (void)sig;
    running = 0;
}

/* --- String helpers --- */

static void to_lower(char *s)
{
    for (; *s; s++)
        if (*s >= 'A' && *s <= 'Z') *s += 32;
}

static void trim(char *s)
{
    char *p = s;
    while (*p && isspace((unsigned char)*p)) p++;
    if (p != s) memmove(s, p, strlen(p) + 1);
    p = s + strlen(s) - 1;
    while (p >= s && isspace((unsigned char)*p)) *p-- = '\0';
}

static void make_fqdn(const char *label, const char *origin, char *out, int outlen)
{
    if (strcmp(label, "@") == 0) {
        strncpy(out, origin, outlen - 1);
        out[outlen - 1] = '\0';
    } else if (label[0] != '\0' && label[strlen(label) - 1] == '.') {
        int len = strlen(label);
        if (len > 0 && label[len - 1] == '.') len--;
        strncpy(out, label, outlen - 1);
        out[len] = '\0';
        out[outlen - 1] = '\0';
    } else {
        snprintf(out, outlen, "%s.%s", label, origin);
    }
    to_lower(out);
}

static unsigned int parse_type(const char *s)
{
    if (strcmp(s, "A") == 0)     return DNS_TYPE_A;
    if (strcmp(s, "NS") == 0)    return DNS_TYPE_NS;
    if (strcmp(s, "CNAME") == 0) return DNS_TYPE_CNAME;
    if (strcmp(s, "AAAA") == 0)  return DNS_TYPE_AAAA;
    if (strcmp(s, "SOA") == 0)   return DNS_TYPE_SOA;
    if (strcmp(s, "TXT") == 0)   return DNS_TYPE_TXT;
    if (strcmp(s, "MX") == 0)    return DNS_TYPE_MX;
    return 0;
}

/* --- Zone file loader --- */

static int load_zone_file(const char *filename, const char *origin)
{
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        fprintf(stderr, "Cannot open zone file %s: %s\n", filename, strerror(errno));
        return -1;
    }

    char line[MAX_LINE];
    int in_soa = 0;

    while (fgets(line, sizeof(line), fp)) {
        trim(line);
        if (line[0] == '\0' || line[0] == ';' || line[0] == '#' || line[0] == '$')
            continue;
        if (in_soa) {
            if (strchr(line, ')')) in_soa = 0;
            continue;
        }

        char *tokens[8];
        int ntok = 0;
        char *saveptr = NULL;
        char *tok = strtok_r(line, " \t", &saveptr);
        while (tok && ntok < 8) {
            tokens[ntok++] = tok;
            tok = strtok_r(NULL, " \t", &saveptr);
        }
        if (ntok < 4) continue;

        int idx = 0;
        char *name_tok = tokens[idx++];
        __u16 ttl = 300;
        unsigned int rtype = 0;
        char *rdata = NULL;

        if (idx < ntok && isdigit((unsigned char)tokens[idx][0]))
            ttl = atoi(tokens[idx++]);
        if (idx < ntok && strcasecmp(tokens[idx], "IN") == 0)
            idx++;
        if (idx >= ntok) continue;
        rtype = parse_type(tokens[idx++]);
        if (rtype == DNS_TYPE_SOA) {
            in_soa = (strchr(line, '(') != NULL);
            continue;
        }
        if (rtype == 0 || idx >= ntok) continue;
        rdata = tokens[idx];

        char fqdn[DNS_MAX_NAME];
        make_fqdn(name_tok, origin, fqdn, sizeof(fqdn));

        if (record_count >= MAX_RECORDS) continue;

        struct dns_record *rec = &records[record_count++];
        strncpy(rec->name, fqdn, DNS_MAX_NAME - 1);
        rec->name[DNS_MAX_NAME - 1] = '\0';
        rec->type = rtype;
        rec->ttl = ttl;

        if (rtype == DNS_TYPE_CNAME || rtype == DNS_TYPE_NS)
            make_fqdn(rdata, origin, rec->data, DNS_MAX_NAME);
        else {
            strncpy(rec->data, rdata, DNS_MAX_NAME - 1);
            rec->data[DNS_MAX_NAME - 1] = '\0';
        }

        printf("[ZONE] %-5s  %s  ->  %s  (ttl=%u)\n",
               tokens[idx - 1], fqdn, rec->data, ttl);
    }

    fclose(fp);
    printf("Loaded %d records\n\n", record_count);
    return record_count;
}

/* --- DNS wire format parsing/encoding --- */

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

/* --- DNS query handler --- */

static struct dns_record *find_record(const char *name, __u16 type)
{
    for (int i = 0; i < record_count; i++)
        if (records[i].type == type && strcmp(records[i].name, name) == 0)
            return &records[i];
    return NULL;
}

static int handle_dns_query(const __u8 *query, int query_len,
                            __u8 *response, int resp_max)
{
    if (query_len < 12) return -1;

    memcpy(response, query, query_len);
    int resp_len = 12;  /* header only; grows with question + answers */
    int question_end = 12;

    __u16 id      = ntohs(*(__u16 *)(query + 0));
    __u16 flags   = ntohs(*(__u16 *)(query + 2));
    __u16 qdcount = ntohs(*(__u16 *)(query + 4));

    __u16 resp_flags = 0x8000 | 0x0400;
    resp_flags |= (flags & 0x7800);  /* copy opcode */
    resp_flags |= (flags & 0x0100);  /* copy RD */

    __u16 rcode = 0;
    __u16 ancount = 0;

    if (qdcount > 0) {
        char qname[DNS_MAX_NAME];
        int consumed = parse_wire_name(query, query_len, 12, qname, sizeof(qname));
        if (consumed < 0) {
            rcode = 1;
        } else {
            int qtype_offset = 12 + consumed;
            if (qtype_offset + 4 > query_len) {
                rcode = 1;
            } else {
                __u16 qtype  = ntohs(*(__u16 *)(query + qtype_offset));
                __u16 qclass = ntohs(*(__u16 *)(query + qtype_offset + 2));

                /* Truncate to question section, dropping EDNS OPT records
                 * that dig appends in the additional section */
                question_end = qtype_offset + 4;
                resp_len = question_end;

                if (qclass != 1) {
                    rcode = 4;
                } else {
                    char cname[DNS_MAX_NAME];
                    strncpy(cname, qname, sizeof(cname) - 1);
                    cname[sizeof(cname) - 1] = '\0';

                    int max_chain = 10;
                    while (max_chain-- > 0) {
                        struct dns_record *rec = find_record(cname, qtype);
                        if (rec) {
                            if (qtype == DNS_TYPE_A) {
                                __u8 *ans = response + resp_len;
                                if (resp_len + 16 > resp_max) break;
                                *(__u16 *)(ans + 0)  = htons(0xC00C);
                                *(__u16 *)(ans + 2)  = htons(DNS_TYPE_A);
                                *(__u16 *)(ans + 4)  = htons(1);
                                *(__u32 *)(ans + 6)  = htonl(rec->ttl);
                                *(__u16 *)(ans + 10) = htons(4);
                                *(__u32 *)(ans + 12) = inet_addr(rec->data);
                                resp_len += 16;
                                ancount++;
                            } else if (qtype == DNS_TYPE_AAAA) {
                                __u8 *ans = response + resp_len;
                                if (resp_len + 28 > resp_max) break;
                                struct in6_addr addr6;
                                if (inet_pton(AF_INET6, rec->data, &addr6) != 1)
                                    break;
                                *(__u16 *)(ans + 0)  = htons(0xC00C);
                                *(__u16 *)(ans + 2)  = htons(DNS_TYPE_AAAA);
                                *(__u16 *)(ans + 4)  = htons(1);
                                *(__u32 *)(ans + 6)  = htonl(rec->ttl);
                                *(__u16 *)(ans + 10) = htons(16);
                                memcpy(ans + 12, &addr6, 16);
                                resp_len += 28;
                                ancount++;
                            }
                            break;
                        }

                        struct dns_record *cn = find_record(cname, DNS_TYPE_CNAME);
                        if (cn) {
                            int name_len = encode_wire_name(cn->data,
                                                            response + resp_len + 12,
                                                            resp_max - resp_len - 12);
                            if (name_len < 0) break;
                            if (resp_len + 12 + name_len > resp_max) break;

                            __u8 *ans = response + resp_len;
                            *(__u16 *)(ans + 0)  = htons(0xC00C);
                            *(__u16 *)(ans + 2)  = htons(DNS_TYPE_CNAME);
                            *(__u16 *)(ans + 4)  = htons(1);
                            *(__u32 *)(ans + 6)  = htonl(cn->ttl);
                            *(__u16 *)(ans + 10) = htons(name_len);
                            resp_len += 12 + name_len;
                            ancount++;

                            strncpy(cname, cn->data, sizeof(cname) - 1);
                            cname[sizeof(cname) - 1] = '\0';
                        } else {
                            rcode = 3;
                            break;
                        }
                    }
                }
            }
        }
    }

    *(__u16 *)(response + 0)  = htons(id);
    *(__u16 *)(response + 2)  = htons(resp_flags | rcode);
    *(__u16 *)(response + 4)  = htons(qdcount);
    *(__u16 *)(response + 6)  = htons(ancount);
    *(__u16 *)(response + 8)  = htons(0);
    *(__u16 *)(response + 10) = htons(0);

    return resp_len;
}

/* --- Build a DNS query packet for testing --- */

static int build_dns_query(__u8 *buf, int max_len, const char *name, __u16 qtype)
{
    int pos = 0;

    /* Header: ID=0x1234, flags=0x0100 (standard query, RD=1), QDCOUNT=1 */
    *(__u16 *)(buf + 0)  = htons(0x1234);
    *(__u16 *)(buf + 2)  = htons(0x0100);
    *(__u16 *)(buf + 4)  = htons(1);
    *(__u16 *)(buf + 6)  = htons(0);
    *(__u16 *)(buf + 8)  = htons(0);
    *(__u16 *)(buf + 10) = htons(0);
    pos = 12;

    /* Question: name + qtype + qclass */
    int name_len = encode_wire_name(name, buf + pos, max_len - pos - 4);
    if (name_len < 0) return -1;
    pos += name_len;
    *(__u16 *)(buf + pos) = htons(qtype);
    pos += 2;
    *(__u16 *)(buf + pos) = htons(1);  /* class IN */
    pos += 2;

    return pos;
}

/* --- Unit tests --- */

static int tests_run = 0;
static int tests_pass = 0;

#define TEST(name) do { tests_run++; printf("  [TEST] %s ... ", name); } while(0)
#define PASS() do { tests_pass++; printf("PASS\n"); } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); } while(0)

static void test_encode_decode_name(void)
{
    TEST("encode/decode round-trip: www.test.com");

    __u8 wire[64];
    int wlen = encode_wire_name("www.test.com", wire, sizeof(wire));
    if (wlen < 0) { FAIL("encode failed"); return; }

    /* Verify wire format: 3www4test3com0 */
    __u8 expected[] = {3,'w','w','w', 4,'t','e','s','t', 3,'c','o','m', 0};
    if (wlen != (int)sizeof(expected) || memcmp(wire, expected, wlen) != 0) {
        FAIL("wire format mismatch");
        printf("  got: ");
        for (int i = 0; i < wlen; i++) printf("%02x ", wire[i]);
        printf("\n");
        return;
    }

    /* Decode back */
    char decoded[DNS_MAX_NAME];
    int dlen = parse_wire_name(wire, wlen, 0, decoded, sizeof(decoded));
    if (dlen < 0) { FAIL("decode failed"); return; }

    if (strcmp(decoded, "www.test.com") != 0) {
        FAIL("decoded name mismatch");
        printf("  expected: www.test.com, got: %s\n", decoded);
        return;
    }

    PASS();
}

static void test_dns_a_query(void)
{
    TEST("A query for www.test.com -> 2.3.4.4");

    __u8 query[BUF_SIZE];
    __u8 response[BUF_SIZE];

    int qlen = build_dns_query(query, sizeof(query), "www.test.com", DNS_TYPE_A);
    if (qlen < 0) { FAIL("build query failed"); return; }

    int rlen = handle_dns_query(query, qlen, response, sizeof(response));
    if (rlen < 0) { FAIL("handle query failed"); return; }

    /* Verify response header */
    __u16 rflags = ntohs(*(__u16 *)(response + 2));
    __u16 rancount = ntohs(*(__u16 *)(response + 6));
    __u16 rrcode = rflags & 0x000F;

    if ((rflags & 0x8000) == 0) { FAIL("QR bit not set"); return; }
    if (rrcode != 0) { FAIL("RCODE not NOERROR"); return; }
    if (rancount != 1) { FAIL("ANCOUNT != 1"); return; }

    /* Find answer section: skip header(12) + question(name + 4) */
    __u8 qname_wire[64];
    int qname_len = 0;
    /* The question name starts at offset 12 */
    qname_len = parse_wire_name(response, rlen, 12, (char *)qname_wire, sizeof(qname_wire));
    int answer_offset = 12 + qname_len + 4;  /* name + qtype + qclass */

    if (answer_offset + 16 > rlen) { FAIL("answer section too short"); return; }

    /* Verify answer: compression pointer + type A + class IN + TTL + RDLENGTH + RDATA */
    __u16 name_ptr = ntohs(*(__u16 *)(response + answer_offset));
    __u16 type = ntohs(*(__u16 *)(response + answer_offset + 2));
    __u16 rdlength = ntohs(*(__u16 *)(response + answer_offset + 10));
    __u32 ip = *(__u32 *)(response + answer_offset + 12);

    if (name_ptr != 0xC00C) { FAIL("name compression pointer wrong"); return; }
    if (type != DNS_TYPE_A) { FAIL("answer type not A"); return; }
    if (rdlength != 4) { FAIL("RDLENGTH != 4"); return; }

    struct in_addr addr;
    addr.s_addr = ip;
    if (strcmp(inet_ntoa(addr), "2.3.4.4") != 0) {
        char msg[64];
        snprintf(msg, sizeof(msg), "expected 2.3.4.4, got %s", inet_ntoa(addr));
        FAIL(msg);
        return;
    }

    PASS();
}

static void test_nxdomain(void)
{
    TEST("NXDOMAIN for unknown.nonexistent.com");

    __u8 query[BUF_SIZE];
    __u8 response[BUF_SIZE];

    int qlen = build_dns_query(query, sizeof(query), "unknown.nonexistent.com", DNS_TYPE_A);
    if (qlen < 0) { FAIL("build query failed"); return; }

    int rlen = handle_dns_query(query, qlen, response, sizeof(response));
    if (rlen < 0) { FAIL("handle query failed"); return; }

    __u16 rflags = ntohs(*(__u16 *)(response + 2));
    __u16 rrcode = rflags & 0x000F;

    if (rrcode != 3) { FAIL("RCODE not NXDOMAIN"); return; }

    PASS();
}

static void test_case_insensitive(void)
{
    TEST("case-insensitive: WWW.TEST.COM == www.test.com");

    __u8 query[BUF_SIZE];
    __u8 response[BUF_SIZE];

    /* Build query with uppercase name */
    int qlen = build_dns_query(query, sizeof(query), "WWW.TEST.COM", DNS_TYPE_A);
    if (qlen < 0) { FAIL("build query failed"); return; }

    int rlen = handle_dns_query(query, qlen, response, sizeof(response));
    if (rlen < 0) { FAIL("handle query failed"); return; }

    __u16 rancount = ntohs(*(__u16 *)(response + 6));
    __u16 rrcode = ntohs(*(__u16 *)(response + 2)) & 0x000F;

    if (rrcode != 0) { FAIL("RCODE not NOERROR"); return; }
    if (rancount != 1) { FAIL("ANCOUNT != 1"); return; }

    PASS();
}

static void test_aaaa_query(void)
{
    TEST("AAAA query for www.test.com -> 2001:db8::2");

    __u8 query[BUF_SIZE];
    __u8 response[BUF_SIZE];

    int qlen = build_dns_query(query, sizeof(query), "www.test.com", DNS_TYPE_AAAA);
    if (qlen < 0) { FAIL("build query failed"); return; }

    int rlen = handle_dns_query(query, qlen, response, sizeof(response));
    if (rlen < 0) { FAIL("handle query failed"); return; }

    __u16 rflags = ntohs(*(__u16 *)(response + 2));
    __u16 rancount = ntohs(*(__u16 *)(response + 6));
    __u16 rrcode = rflags & 0x000F;

    if ((rflags & 0x8000) == 0) { FAIL("QR bit not set"); return; }
    if (rrcode != 0) { FAIL("RCODE not NOERROR"); return; }
    if (rancount != 1) { FAIL("ANCOUNT != 1"); return; }

    /* Find answer section */
    __u8 qname_wire[64];
    int qname_len = parse_wire_name(response, rlen, 12, (char *)qname_wire, sizeof(qname_wire));
    int answer_offset = 12 + qname_len + 4;

    if (answer_offset + 28 > rlen) { FAIL("AAAA answer section too short"); return; }

    __u16 type = ntohs(*(__u16 *)(response + answer_offset + 2));
    __u16 rdlength = ntohs(*(__u16 *)(response + answer_offset + 10));

    if (type != DNS_TYPE_AAAA) { FAIL("answer type not AAAA"); return; }
    if (rdlength != 16) { FAIL("RDLENGTH != 16"); return; }

    /* Verify IPv6 address: 2001:db8::2 */
    __u8 expected_ip6[16] = {0x20,0x01,0x0d,0xb8, 0,0,0,0, 0,0,0,0, 0,0,0,0x02};
    if (memcmp(response + answer_offset + 12, expected_ip6, 16) != 0) {
        FAIL("IPv6 address mismatch");
        return;
    }

    PASS();
}

static void test_cname_chain(void)
{
    TEST("CNAME chain: cname.test.com -> www.test.com -> 2.3.4.4");

    __u8 query[BUF_SIZE];
    __u8 response[BUF_SIZE];

    int qlen = build_dns_query(query, sizeof(query), "cname.test.com", DNS_TYPE_A);
    if (qlen < 0) { FAIL("build query failed"); return; }

    int rlen = handle_dns_query(query, qlen, response, sizeof(response));
    if (rlen < 0) { FAIL("handle query failed"); return; }

    __u16 rancount = ntohs(*(__u16 *)(response + 6));
    __u16 rrcode = ntohs(*(__u16 *)(response + 2)) & 0x000F;

    if (rrcode != 0) { FAIL("RCODE not NOERROR"); return; }
    /* Should have 2 answers: CNAME record + A record */
    if (rancount != 2) {
        char msg[64];
        snprintf(msg, sizeof(msg), "ANCOUNT != 2 (got %u)", rancount);
        FAIL(msg);
        return;
    }

    PASS();
}

static void test_empty_name(void)
{
    TEST("encode/decode empty root name");

    __u8 wire[16];
    int wlen = encode_wire_name("", wire, sizeof(wire));
    /* Root name is just a zero byte */
    if (wlen != 1 || wire[0] != 0) {
        FAIL("root name encoding wrong");
        printf("  got %d bytes: ", wlen);
        for (int i = 0; i < wlen; i++) printf("%02x ", wire[i]);
        printf("\n");
        return;
    }

    PASS();
}

static void run_unit_tests(void)
{
    printf("\n========== Unit Tests ==========\n\n");
    test_encode_decode_name();
    test_dns_a_query();
    test_aaaa_query();
    test_cname_chain();
    test_nxdomain();
    test_case_insensitive();
    test_empty_name();

    printf("\nResults: %d/%d passed\n", tests_pass, tests_run);
    if (tests_pass == tests_run)
        printf("All tests PASSED\n");
    else
        printf("Some tests FAILED\n");
    printf("================================\n");
}

/* --- Standalone DNS server --- */

static void run_server(const char *zonefile, const char *origin)
{
    printf("Starting standalone DNS server on port %d\n", TEST_PORT);
    printf("Zone: %s (%s)\n\n", zonefile, origin);

    if (load_zone_file(zonefile, origin) < 0)
        return;

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        fprintf(stderr, "socket: %s\n", strerror(errno));
        return;
    }

    int reuse = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    /* Set receive timeout so the server loop can check the running flag */
    struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = INADDR_ANY,
        .sin_port = htons(TEST_PORT),
    };

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr))) {
        fprintf(stderr, "bind port %d: %s\n", TEST_PORT, strerror(errno));
        close(sock);
        return;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("Server ready. Test with:\n");
    printf("  dig @127.0.0.1 -p %d www.%s\n\n", TEST_PORT, origin);

    __u8 query_buf[BUF_SIZE];
    __u8 response_buf[BUF_SIZE];
    int count = 0;

    while (running) {
        struct sockaddr_in client;
        socklen_t clen = sizeof(client);

        int n = recvfrom(sock, query_buf, sizeof(query_buf), 0,
                         (struct sockaddr *)&client, &clen);
        if (n < 12) continue;

        count++;

        char qname[DNS_MAX_NAME];
        parse_wire_name(query_buf, n, 12, qname, sizeof(qname));

        int resp_len = handle_dns_query(query_buf, n, response_buf, sizeof(response_buf));
        if (resp_len > 0) {
            sendto(sock, response_buf, resp_len, 0,
                   (struct sockaddr *)&client, clen);
            printf("#%d  query: %s  from %s\n", count, qname,
                   inet_ntoa(client.sin_addr));
        }
    }

    close(sock);
    printf("\nServer stopped. Served %d queries.\n", count);
}

/* --- Main --- */

int main(int argc, char *argv[])
{
    if (argc >= 2 && strcmp(argv[1], "-s") == 0) {
        /* Standalone server mode */
        const char *zonefile = argc > 2 ? argv[2] : "../test.com.zone";
        const char *origin   = argc > 3 ? argv[3] : "test.com";
        run_server(zonefile, origin);
    } else {
        /* Unit test mode: load zone file first */
        const char *zonefile = argc > 1 ? argv[1] : "../test.com.zone";
        const char *origin   = argc > 2 ? argv[2] : "test.com";

        printf("Loading zone file: %s (origin: %s)\n", zonefile, origin);
        load_zone_file(zonefile, origin);

        run_unit_tests();
    }

    return 0;
}
