/*
 * XDP DNS User-Space Loader + Fallback DNS Server
 *
 * Responsibilities:
 *   1. Load the XDP eBPF program onto a network interface
 *   2. Parse zone files and populate the BPF hash map (A + AAAA records)
 *   3. Run a fallback UDP DNS server for XDP_PASS packets (cache misses,
 *      non-A/AAAA queries, CNAME chains, etc.)
 *   4. Print periodic statistics
 *
 * Build: gcc -O2 -Wall -o xdp_dns_user xdp_dns_user.c -lbpf -lelf -lz
 *
 * Usage: sudo ./xdp_dns_user -i eth0 -z test.com.zone -o test.com
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "xdp_dns_common.h"

#define BUF_SIZE        1500
#define MAX_RECORDS     1024
#define MAX_LINE        1024

/* --- Local record store for fallback server --- */

struct dns_record {
    char    name[DNS_MAX_NAME];
    __u16   type;
    __u16   ttl;
    char    data[DNS_MAX_NAME];   /* IP string for A/AAAA, target for CNAME/NS */
};

static struct dns_record records[MAX_RECORDS];
static int record_count = 0;
static int ifindex = 0;
static volatile int running = 1;

/* --- Signal handler --- */

static void sig_handler(int sig)
{
    (void)sig;
    running = 0;
}

/* --- String helpers --- */

static void to_lower(char *s)
{
    for (; *s; s++)
        if (*s >= 'A' && *s <= 'Z')
            *s += 32;
}

static void trim(char *s)
{
    char *p = s;
    while (*p && isspace((unsigned char)*p)) p++;
    if (p != s) memmove(s, p, strlen(p) + 1);
    p = s + strlen(s) - 1;
    while (p >= s && isspace((unsigned char)*p)) *p-- = '\0';
}

/*
 * Build a fully-qualified domain name from a zone file label.
 * Handles '@' (zone origin), relative names (append origin),
 * and absolute names (trailing dot stripped).
 */
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

/* --- Zone file parser --- */

static unsigned int parse_type(const char *s)
{
    if (strcmp(s, "A") == 0)     return DNS_TYPE_A;
    if (strcmp(s, "NS") == 0)    return DNS_TYPE_NS;
    if (strcmp(s, "CNAME") == 0) return DNS_TYPE_CNAME;
    if (strcmp(s, "SOA") == 0)   return DNS_TYPE_SOA;
    if (strcmp(s, "AAAA") == 0)  return DNS_TYPE_AAAA;
    if (strcmp(s, "TXT") == 0)   return DNS_TYPE_TXT;
    if (strcmp(s, "MX") == 0)    return DNS_TYPE_MX;
    return 0;
}

/*
 * Parse a BIND-format zone file.
 * Extracts A, AAAA, NS, CNAME records. Skips $TTL, SOA multi-line, comments.
 *
 * Returns number of A+AAAA records found (for BPF map population).
 */
static int load_zone_file(const char *filename, const char *origin,
                          int map_fd)
{
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        fprintf(stderr, "Cannot open zone file %s: %s\n", filename, strerror(errno));
        return -1;
    }

    char line[MAX_LINE];
    int map_count = 0;
    int in_soa = 0;

    while (fgets(line, sizeof(line), fp)) {
        trim(line);

        /* Skip empty lines and comments */
        if (line[0] == '\0' || line[0] == ';' || line[0] == '#')
            continue;

        /* Handle SOA multi-line block */
        if (in_soa) {
            if (strchr(line, ')'))
                in_soa = 0;
            continue;
        }

        /* Skip $TTL and other directives */
        if (line[0] == '$')
            continue;

        /* Tokenize the line */
        char *tokens[8];
        int ntok = 0;
        char *saveptr = NULL;
        char *tok = strtok_r(line, " \t", &saveptr);
        while (tok && ntok < 8) {
            tokens[ntok++] = tok;
            tok = strtok_r(NULL, " \t", &saveptr);
        }

        if (ntok < 4)
            continue;

        /* Parse: [name] [ttl] [IN] <type> <data>
         * Or:    [name] [IN] <type> <data>
         */
        int idx = 0;
        char *name_tok = tokens[idx++];
        __u16 ttl = 300;
        unsigned int rtype = 0;
        char *rdata = NULL;

        /* Try to parse second token as TTL (numeric) or "IN" */
        if (idx < ntok && isdigit((unsigned char)tokens[idx][0])) {
            ttl = atoi(tokens[idx++]);
        }

        /* Skip "IN" class */
        if (idx < ntok && strcasecmp(tokens[idx], "IN") == 0)
            idx++;

        /* Next token is the record type */
        if (idx >= ntok)
            continue;
        rtype = parse_type(tokens[idx++]);

        /* Skip SOA multi-line */
        if (rtype == DNS_TYPE_SOA) {
            in_soa = (strchr(line, '(') != NULL);
            continue;
        }

        if (rtype == 0 || idx >= ntok)
            continue;

        rdata = tokens[idx];

        /* Build FQDN */
        char fqdn[DNS_MAX_NAME];
        make_fqdn(name_tok, origin, fqdn, sizeof(fqdn));

        if (record_count >= MAX_RECORDS) {
            fprintf(stderr, "Warning: max records reached, skipping %s\n", fqdn);
            continue;
        }

        struct dns_record *rec = &records[record_count++];
        strncpy(rec->name, fqdn, DNS_MAX_NAME - 1);
        rec->name[DNS_MAX_NAME - 1] = '\0';
        rec->type = rtype;
        rec->ttl = ttl;

        /* For CNAME/NS, make FQDN of the target too */
        if (rtype == DNS_TYPE_CNAME || rtype == DNS_TYPE_NS) {
            make_fqdn(rdata, origin, rec->data, DNS_MAX_NAME);
        } else {
            strncpy(rec->data, rdata, DNS_MAX_NAME - 1);
            rec->data[DNS_MAX_NAME - 1] = '\0';
        }

        /* Populate BPF map for A and AAAA records */
        if ((rtype == DNS_TYPE_A || rtype == DNS_TYPE_AAAA) && map_fd >= 0) {
            struct dns_key key;
            struct dns_val val;

            memset(&key, 0, sizeof(key));
            memset(&val, 0, sizeof(val));
            key.qtype = rtype;
            strncpy(key.name, fqdn, DNS_MAX_NAME - 1);
            val.ttl = ttl;

            if (rtype == DNS_TYPE_A) {
                val.ip = inet_addr(rdata);
            } else {
                /* Parse IPv6 address */
                struct in6_addr addr6;
                if (inet_pton(AF_INET6, rdata, &addr6) != 1) {
                    fprintf(stderr, "Invalid IPv6: %s\n", rdata);
                    continue;
                }
                memcpy(val.ip6, &addr6, 16);
            }

            if (bpf_map_update_elem(map_fd, &key, &val, BPF_ANY) == 0) {
                map_count++;
                printf("[MAP]  %-5s  %s  ->  %s  (ttl=%u)\n",
                       rtype == DNS_TYPE_A ? "A" : "AAAA", fqdn, rdata, ttl);
            } else {
                fprintf(stderr, "Failed to update BPF map for %s: %s\n",
                        fqdn, strerror(errno));
            }
        }

        printf("[ZONE] %-5s  %s  ->  %s  (ttl=%u)\n",
               tokens[idx - 1], fqdn, rec->data, ttl);
    }

    fclose(fp);
    printf("Loaded %d records (%d A/AAAA records into BPF map)\n", record_count, map_count);
    return map_count;
}

/* --- DNS query parsing (for fallback server) --- */

/*
 * Parse DNS wire-format name to dotted string.
 * Returns bytes consumed, or -1 on error.
 */
static int parse_wire_name(const __u8 *data, int data_len, int offset,
                           char *out, int out_max)
{
    int pos = offset;
    int out_pos = 0;

    for (int i = 0; i < 127; i++) {
        if (pos + 1 > data_len)
            return -1;

        __u8 label_len = data[pos++];

        if (label_len == 0)
            break;

        if (label_len > 63)
            return -1;

        if (out_pos > 0 && out_pos < out_max)
            out[out_pos++] = '.';

        for (int j = 0; j < label_len; j++) {
            if (pos + 1 > data_len)
                return -1;
            if (out_pos + 1 >= out_max)
                return -1;
            char c = data[pos++];
            if (c >= 'A' && c <= 'Z')
                c += 32;
            out[out_pos++] = c;
        }
    }

    out[out_pos] = '\0';
    return pos - offset;
}

/* Encode dotted name to DNS wire format */
static int encode_wire_name(const char *name, __u8 *out, int out_max)
{
    int pos = 0;
    const char *p = name;

    while (*p) {
        const char *dot = strchr(p, '.');
        int label_len = dot ? (int)(dot - p) : (int)strlen(p);

        if (label_len == 0)
            break;

        if (pos + 1 + label_len + 1 > out_max)
            return -1;

        out[pos++] = (__u8)label_len;
        memcpy(out + pos, p, label_len);
        pos += label_len;

        if (!dot)
            break;
        p = dot + 1;
    }

    out[pos++] = 0;  /* terminating zero */
    return pos;
}

/* --- Fallback DNS server --- */

static struct dns_record *find_record(const char *name, __u16 type)
{
    for (int i = 0; i < record_count; i++) {
        if (records[i].type == type && strcmp(records[i].name, name) == 0)
            return &records[i];
    }
    return NULL;
}

/*
 * Handle a DNS query and construct a response.
 * Supports A, AAAA, CNAME (with chain resolution), NS records.
 * Truncates EDNS OPT records from the additional section.
 * Returns NXDOMAIN for unknown names.
 */
static int handle_dns_query(const __u8 *query, int query_len,
                            __u8 *response, int resp_max)
{
    if (query_len < 12)
        return -1;

    /* Copy query to response (header + question will be kept) */
    memcpy(response, query, query_len);
    int resp_len = 12;  /* header only; grows with question + answers */
    int question_end = 12;

    /* Parse header */
    __u16 id      = ntohs(*(__u16 *)(query + 0));
    __u16 flags   = ntohs(*(__u16 *)(query + 2));
    __u16 qdcount = ntohs(*(__u16 *)(query + 4));

    /* Set response flags */
    __u16 resp_flags = 0x8000 | 0x0400;  /* QR=1, AA=1 */
    resp_flags |= (flags & 0x7800);       /* copy opcode */
    resp_flags |= (flags & 0x0100);       /* copy RD */

    __u16 rcode = 0;
    __u16 ancount = 0;

    if (qdcount > 0) {
        char qname[DNS_MAX_NAME];
        int consumed = parse_wire_name(query, query_len, 12, qname, sizeof(qname));
        if (consumed < 0) {
            rcode = 1;  /* FORMERR */
        } else {
            int qtype_offset = 12 + consumed;
            if (qtype_offset + 4 > query_len) {
                rcode = 1;
            } else {
                __u16 qtype  = ntohs(*(__u16 *)(query + qtype_offset));
                __u16 qclass = ntohs(*(__u16 *)(query + qtype_offset + 2));

                /* Truncate to question section, dropping EDNS OPT records */
                question_end = qtype_offset + 4;
                resp_len = question_end;

                if (qclass != 1) {
                    rcode = 4;  /* NOTIMP */
                } else {
                    /* CNAME chain resolution */
                    char cname[DNS_MAX_NAME];
                    strncpy(cname, qname, sizeof(cname) - 1);
                    cname[sizeof(cname) - 1] = '\0';

                    int max_chain = 10;
                    while (max_chain-- > 0) {
                        struct dns_record *rec = find_record(cname, qtype);
                        if (rec) {
                            /* Found the answer */
                            if (qtype == DNS_TYPE_A) {
                                __u8 *ans = response + resp_len;
                                if (resp_len + 16 > resp_max)
                                    break;
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
                                if (resp_len + 28 > resp_max)
                                    break;
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

                        /* Try CNAME */
                        struct dns_record *cn = find_record(cname, DNS_TYPE_CNAME);
                        if (cn) {
                            /* Append CNAME record */
                            int name_len = encode_wire_name(cn->data,
                                                            response + resp_len + 12,
                                                            resp_max - resp_len - 12);
                            if (name_len < 0)
                                break;
                            if (resp_len + 12 + name_len > resp_max)
                                break;

                            __u8 *ans = response + resp_len;
                            *(__u16 *)(ans + 0) = htons(0xC00C);
                            *(__u16 *)(ans + 2) = htons(DNS_TYPE_CNAME);
                            *(__u16 *)(ans + 4) = htons(1);
                            *(__u32 *)(ans + 6) = htonl(cn->ttl);
                            *(__u16 *)(ans + 10) = htons(name_len);
                            resp_len += 12 + name_len;
                            ancount++;

                            strncpy(cname, cn->data, sizeof(cname) - 1);
                            cname[sizeof(cname) - 1] = '\0';
                        } else {
                            rcode = 3;  /* NXDOMAIN */
                            break;
                        }
                    }
                }
            }
        }
    }

    /* Write response header */
    *(__u16 *)(response + 0)  = htons(id);
    *(__u16 *)(response + 2)  = htons(resp_flags | rcode);
    *(__u16 *)(response + 4)  = htons(qdcount);
    *(__u16 *)(response + 6)  = htons(ancount);
    *(__u16 *)(response + 8)  = htons(0);  /* NSCOUNT */
    *(__u16 *)(response + 10) = htons(0);  /* ARCOUNT */

    return resp_len;
}

/* --- Statistics printing --- */

static void print_stats(int map_fd)
{
    __u32 keys[STAT_MAX] = {STAT_TOTAL, STAT_HIT, STAT_MISS};
    __u64 vals[STAT_MAX];
    const char *names[] = {"total", "hit", "miss"};

    for (int i = 0; i < STAT_MAX; i++) {
        __u64 val = 0;
        if (bpf_map_lookup_elem(map_fd, &keys[i], &val) == 0)
            vals[i] = val;
        else
            vals[i] = 0;
    }

    double hit_rate = 0;
    if (vals[STAT_TOTAL] > 0)
        hit_rate = (double)vals[STAT_HIT] / vals[STAT_TOTAL] * 100.0;

    printf("\n=== XDP DNS Statistics ===\n");
    for (int i = 0; i < STAT_MAX; i++)
        printf("  %-6s: %llu\n", names[i], (unsigned long long)vals[i]);
    printf("  hit rate: %.2f%%\n", hit_rate);
    printf("==========================\n");
}

/* --- Main --- */

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s -i <ifname> -z <zonefile> -o <origin> [-c <conffile>] [-v]\n"
        "\n"
        "Options:\n"
        "  -i <ifname>    Network interface to attach XDP program\n"
        "  -z <zonefile>  Zone file path (BIND format)\n"
        "  -o <origin>    Zone origin domain (e.g. test.com)\n"
        "  -c <conffile>  Config file (optional, overrides -z/-o)\n"
        "  -v             Verbose output\n"
        "  -h             Show this help\n",
        prog);
}

int main(int argc, char *argv[])
{
    const char *ifname = NULL;
    const char *zonefile = NULL;
    const char *origin = NULL;
    const char *conffile = NULL;
    int verbose = 0;
    int opt;

    while ((opt = getopt(argc, argv, "i:z:o:c:vh")) != -1) {
        switch (opt) {
        case 'i': ifname = optarg; break;
        case 'z': zonefile = optarg; break;
        case 'o': origin = optarg; break;
        case 'c': conffile = optarg; break;
        case 'v': verbose = 1; break;
        case 'h': usage(argv[0]); return 0;
        default:  usage(argv[0]); return 1;
        }
    }

    if (!ifname) {
        fprintf(stderr, "Error: network interface required (-i)\n");
        usage(argv[0]);
        return 1;
    }

    if (!zonefile || !origin) {
        fprintf(stderr, "Error: zone file (-z) and origin (-o) required\n");
        usage(argv[0]);
        return 1;
    }

    /* Resolve interface index */
    ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        fprintf(stderr, "Error: interface %s not found: %s\n", ifname, strerror(errno));
        return 1;
    }

    printf("SimpleDns XDP - High-performance DNS server\n");
    printf("Interface: %s (index %d)\n", ifname, ifindex);
    printf("Zone: %s (%s)\n\n", zonefile, origin);

    /* --- Load BPF program --- */
    struct bpf_object *obj = bpf_object__open_file("xdp_dns_kern.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object: %s\n",
                strerror(-libbpf_get_error(obj)));
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load BPF program: %s\n", strerror(errno));
        bpf_object__close(obj);
        return 1;
    }

    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "xdp_dns_prog");
    if (!prog) {
        fprintf(stderr, "Failed to find XDP program in BPF object\n");
        bpf_object__close(obj);
        return 1;
    }

    int prog_fd = bpf_program__fd(prog);

    /* Find maps */
    struct bpf_map *a_map = bpf_object__find_map_by_name(obj, "dns_map");
    struct bpf_map *s_map = bpf_object__find_map_by_name(obj, "stats_map");
    if (!a_map || !s_map) {
        fprintf(stderr, "Failed to find BPF maps\n");
        bpf_object__close(obj);
        return 1;
    }

    int a_map_fd = bpf_map__fd(a_map);
    int s_map_fd = bpf_map__fd(s_map);

    /* --- Populate BPF map from zone file --- */
    printf("Loading zone file...\n");
    if (load_zone_file(zonefile, origin, a_map_fd) < 0) {
        fprintf(stderr, "Failed to load zone file\n");
        bpf_object__close(obj);
        return 1;
    }

    /* --- Attach XDP program --- */
    printf("\nAttaching XDP program to %s...\n", ifname);
    if (bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_DRV_MODE, NULL)) {
        fprintf(stderr, "DRV mode attach failed, trying SKB mode...\n");
        if (bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, NULL)) {
            fprintf(stderr, "Failed to attach XDP program: %s\n", strerror(errno));
            bpf_object__close(obj);
            return 1;
        }
        printf("Attached in SKB/generic mode\n");
    } else {
        printf("Attached in driver/native mode\n");
    }

    /* --- Setup fallback DNS server --- */
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        fprintf(stderr, "Failed to create socket: %s\n", strerror(errno));
        bpf_xdp_detach(ifindex, 0, NULL);
        bpf_object__close(obj);
        return 1;
    }

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = INADDR_ANY,
        .sin_port = htons(DNS_PORT),
    };

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr))) {
        fprintf(stderr, "Failed to bind UDP 53: %s\n", strerror(errno));
        close(sock);
        bpf_xdp_detach(ifindex, 0, NULL);
        bpf_object__close(obj);
        return 1;
    }

    /* --- Signal handling --- */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("\nServer running. Press Ctrl+C to stop.\n");
    printf("XDP fast path handles A/AAAA cache hits.\n");
    printf("Fallback server handles cache misses and complex queries.\n\n");

    /* --- Main loop: fallback server + periodic stats --- */
    __u8 query_buf[BUF_SIZE];
    __u8 response_buf[BUF_SIZE];
    struct sockaddr_in client;
    socklen_t client_len;
    int query_count = 0;

    while (running) {
        fd_set fds;
        struct timeval tv = {.tv_sec = 5, .tv_usec = 0};

        FD_ZERO(&fds);
        FD_SET(sock, &fds);

        int rc = select(sock + 1, &fds, NULL, NULL, &tv);
        if (rc < 0) {
            if (errno == EINTR)
                continue;
            break;
        }

        /* Print stats every 5 seconds */
        if (rc == 0) {
            if (verbose)
                print_stats(s_map_fd);
            continue;
        }

        /* Handle incoming DNS query (from XDP_PASS) */
        client_len = sizeof(client);
        int n = recvfrom(sock, query_buf, sizeof(query_buf), 0,
                         (struct sockaddr *)&client, &client_len);
        if (n < 12)
            continue;

        query_count++;

        if (verbose) {
            char qname[DNS_MAX_NAME];
            int consumed = parse_wire_name(query_buf, n, 12, qname, sizeof(qname));
            __u16 qtype = 0;
            if (consumed > 0 && 12 + consumed + 4 <= n)
                qtype = ntohs(*(__u16 *)(query_buf + 12 + consumed));
            printf("[FALLBACK] query #%d: %s type=%u from %s\n",
                   query_count, qname, qtype, inet_ntoa(client.sin_addr));
        }

        int resp_len = handle_dns_query(query_buf, n, response_buf, sizeof(response_buf));
        if (resp_len > 0) {
            sendto(sock, response_buf, resp_len, 0,
                   (struct sockaddr *)&client, client_len);
        }
    }

    /* --- Cleanup --- */
    printf("\nShutting down...\n");
    print_stats(s_map_fd);

    close(sock);
    bpf_xdp_detach(ifindex, 0, NULL);
    bpf_object__close(obj);

    printf("XDP program detached. Goodbye.\n");
    return 0;
}
