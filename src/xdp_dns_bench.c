/*
 * XDP DNS 性能基准测试程序 (QPS 压测)
 *
 * 通过向 DNS 服务器发送大量 UDP 查询来测量 QPS 和延迟分布。
 * 支持单线程和多线程模式，模拟 XDP 快路径的性能上限。
 *
 * 构建: gcc -O2 -Wall -lpthread -o xdp_dns_bench xdp_dns_bench.c
 *
 * 用法:
 *   ./xdp_dns_bench -p 15353 -t 4 -n 100000
 *     -p 端口 (默认 15353)
 *     -t 线程数 (默认 1)
 *     -n 每线程查询数 (默认 100000)
 *     -d 查询域名 (默认 www.test.com)
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
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h>

#define BUF_SIZE 1500
#define MAX_THREADS 64

/* --- DNS wire format helpers (inline copies from test program) --- */

static int encode_wire_name(const char *name, unsigned char *out, int out_max)
{
    int pos = 0;
    const char *p = name;
    while (*p) {
        const char *dot = strchr(p, '.');
        int label_len = dot ? (int)(dot - p) : (int)strlen(p);
        if (label_len == 0) break;
        if (pos + 1 + label_len + 1 > out_max) return -1;
        out[pos++] = (unsigned char)label_len;
        memcpy(out + pos, p, label_len);
        pos += label_len;
        if (!dot) break;
        p = dot + 1;
    }
    out[pos++] = 0;
    return pos;
}

static int build_dns_query(unsigned char *buf, int max_len,
                           const char *name, unsigned short qtype,
                           unsigned short id)
{
    *(__u16 *)(buf + 0)  = htons(id);
    *(__u16 *)(buf + 2)  = htons(0x0100); /* RD=1 */
    *(__u16 *)(buf + 4)  = htons(1);      /* QDCOUNT=1 */
    *(__u16 *)(buf + 6)  = htons(0);
    *(__u16 *)(buf + 8)  = htons(0);
    *(__u16 *)(buf + 10) = htons(0);
    int pos = 12;
    int name_len = encode_wire_name(name, buf + pos, max_len - pos - 4);
    if (name_len < 0) return -1;
    pos += name_len;
    *(__u16 *)(buf + pos) = htons(qtype);
    pos += 2;
    *(__u16 *)(buf + pos) = htons(1); /* class IN */
    pos += 2;
    return pos;
}

/* --- 计时器 --- */

static double now_sec(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

/* --- 线程参数 --- */

struct thread_arg {
    int thread_id;
    int sock;
    struct sockaddr_in server;
    int num_queries;
    const char *domain;
    unsigned short qtype;
    /* 结果 */
    __u64 sent;
    __u64 received;
    __u64 errors;
    double min_latency_us;
    double max_latency_us;
    double total_latency_us;
};

static void *bench_thread(void *arg)
{
    struct thread_arg *ta = (struct thread_arg *)arg;
    unsigned char query[BUF_SIZE];
    unsigned char response[BUF_SIZE];
    double lat_min = 1e18, lat_max = 0, lat_sum = 0;

    ta->sent = 0;
    ta->received = 0;
    ta->errors = 0;

    for (int i = 0; i < ta->num_queries; i++) {
        unsigned short id = (unsigned short)((ta->thread_id << 12) | (i & 0xFFF));
        int qlen = build_dns_query(query, sizeof(query), ta->domain, ta->qtype, id);
        if (qlen < 0) { ta->errors++; continue; }

        double t_start = now_sec();

        int n = sendto(ta->sock, query, qlen, 0,
                       (struct sockaddr *)&ta->server, sizeof(ta->server));
        if (n < 0) { ta->errors++; continue; }
        ta->sent++;

        n = recvfrom(ta->sock, response, sizeof(response), 0, NULL, NULL);
        if (n < 0) { ta->errors++; continue; }

        double latency_us = (now_sec() - t_start) * 1e6;
        ta->received++;

        if (latency_us < lat_min) lat_min = latency_us;
        if (latency_us > lat_max) lat_max = latency_us;
        lat_sum += latency_us;
    }

    ta->min_latency_us = (lat_min < 1e18) ? lat_min : 0;
    ta->max_latency_us = lat_max;
    ta->total_latency_us = lat_sum;

    return NULL;
}

/* --- 主函数 --- */

static void usage(const char *prog)
{
    fprintf(stderr,
        "用法: %s [-p 端口] [-t 线程数] [-n 每线程查询数] [-d 域名] [-q 类型]\n"
        "\n"
        "选项:\n"
        "  -p <端口>      目标端口 (默认 15353)\n"
        "  -t <线程数>    并发线程数 (默认 1, 最大 %d)\n"
        "  -n <查询数>    每线程发送的查询数 (默认 100000)\n"
        "  -d <域名>      查询域名 (默认 www.test.com)\n"
        "  -q <类型>      查询类型: 1=A, 28=AAAA (默认 1)\n",
        prog, MAX_THREADS);
}

int main(int argc, char *argv[])
{
    int port = 15353;
    int num_threads = 1;
    int num_queries = 100000;
    const char *domain = "www.test.com";
    unsigned short qtype = 1; /* A */

    int opt;
    while ((opt = getopt(argc, argv, "p:t:n:d:q:h")) != -1) {
        switch (opt) {
        case 'p': port = atoi(optarg); break;
        case 't': num_threads = atoi(optarg); break;
        case 'n': num_queries = atoi(optarg); break;
        case 'd': domain = optarg; break;
        case 'q': qtype = (unsigned short)atoi(optarg); break;
        case 'h': usage(argv[0]); return 0;
        default:  usage(argv[0]); return 1;
        }
    }

    if (num_threads < 1) num_threads = 1;
    if (num_threads > MAX_THREADS) num_threads = MAX_THREADS;
    if (num_queries < 1) num_queries = 1;

    printf("============================================\n");
    printf("  SimpleDns XDP - 性能基准测试\n");
    printf("============================================\n");
    printf("  目标: 127.0.0.1:%d\n", port);
    printf("  线程: %d\n", num_threads);
    printf("  每线程查询: %d\n", num_queries);
    printf("  总查询数: %lld\n", (long long)num_threads * num_queries);
    printf("  域名: %s (type=%u)\n\n", domain, qtype);

    /* 创建线程 */
    pthread_t threads[MAX_THREADS];
    struct thread_arg args[MAX_THREADS];

    for (int i = 0; i < num_threads; i++) {
        memset(&args[i], 0, sizeof(args[i]));
        args[i].thread_id = i;
        args[i].num_queries = num_queries;
        args[i].domain = domain;
        args[i].qtype = qtype;

        args[i].sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (args[i].sock < 0) {
            fprintf(stderr, "线程 %d 创建 socket 失败: %s\n", i, strerror(errno));
            return 1;
        }

        /* 设置 2 秒超时 */
        struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
        setsockopt(args[i].sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        args[i].server.sin_family = AF_INET;
        args[i].server.sin_addr.s_addr = inet_addr("127.0.0.1");
        args[i].server.sin_port = htons(port);
    }

    printf("  开始压测...\n\n");

    double t_start = now_sec();

    for (int i = 0; i < num_threads; i++) {
        if (pthread_create(&threads[i], NULL, bench_thread, &args[i])) {
            fprintf(stderr, "创建线程 %d 失败\n", i);
            return 1;
        }
    }

    for (int i = 0; i < num_threads; i++)
        pthread_join(threads[i], NULL);

    double elapsed = now_sec() - t_start;

    /* 汇总结果 */
    __u64 total_sent = 0, total_received = 0, total_errors = 0;
    double lat_min = 1e18, lat_max = 0, lat_sum = 0;

    for (int i = 0; i < num_threads; i++) {
        total_sent += args[i].sent;
        total_received += args[i].received;
        total_errors += args[i].errors;
        if (args[i].min_latency_us < lat_min) lat_min = args[i].min_latency_us;
        if (args[i].max_latency_us > lat_max) lat_max = args[i].max_latency_us;
        lat_sum += args[i].total_latency_us;
        close(args[i].sock);
    }

    double qps = (elapsed > 0) ? (double)total_received / elapsed : 0;
    double avg_lat = (total_received > 0) ? lat_sum / total_received : 0;
    double success_rate = (total_sent > 0) ? (double)total_received / total_sent * 100.0 : 0;

    printf("============================================\n");
    printf("  测试结果\n");
    printf("============================================\n");
    printf("  耗时:        %.3f 秒\n", elapsed);
    printf("  发送:        %llu\n", (unsigned long long)total_sent);
    printf("  收到响应:    %llu\n", (unsigned long long)total_received);
    printf("  错误/超时:   %llu\n", (unsigned long long)total_errors);
    printf("  成功率:      %.2f%%\n", success_rate);
    printf("  QPS:         %.0f\n", qps);
    printf("  平均延迟:    %.1f us\n", avg_lat);
    printf("  最小延迟:    %.1f us\n", (lat_min < 1e18) ? lat_min : 0);
    printf("  最大延迟:    %.1f us\n", lat_max);
    printf("============================================\n");

    /* 性能评级 */
    printf("\n  性能评级:\n");
    if (qps > 100000) {
        printf("    ★★★★★ 极佳 (>100K QPS, 接近 XDP 加速水平)\n");
    } else if (qps > 50000) {
        printf("    ★★★★  良好 (>50K QPS, 用户态回退水平)\n");
    } else if (qps > 10000) {
        printf("    ★★★   一般 (>10K QPS)\n");
    } else {
        printf("    ★★    需优化 (<10K QPS)\n");
    }

    return 0;
}
