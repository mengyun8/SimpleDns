# SimpleDns XDP - 高性能 DNS 加速方案

基于 XDP (eXpress Data Path) 和 eBPF 技术，在网卡驱动层直接处理 DNS 响应，完全绕过内核网络栈，单核可达 200K+ QPS。

## 架构设计

```
                        ┌─────────────────────────────────┐
                        │         网络数据包入口            │
                        └────────────┬────────────────────┘
                                     │
                          ┌──────────▼──────────┐
                          │   XDP eBPF 程序      │
                          │   (网卡驱动层)        │
                          │                      │
                          │  1. 解析 ETH/IP/UDP  │
                          │  2. 解析 DNS 问题段   │
                          │  3. BPF Map 查找     │
                          │  4. 命中: 构建响应    │
                          │     未命中: XDP_PASS  │
                          └──┬────────────┬──────┘
                             │            │
                    XDP_TX   │            │ XDP_PASS
                    (命中)    │            │ (未命中/复杂查询)
                             │            │
                  ┌──────────▼──┐  ┌──────▼──────────────┐
                  │  网卡直接发送 │  │  内核网络栈 → 用户态  │
                  │  (绕过内核)  │  │  回退 DNS 服务器      │
                  └─────────────┘  │  (CNAME/NS/缓存未命中) │
                                   └─────────────────────┘
```

### 快路径 (XDP Fast Path)

XDP 程序在网卡驱动层运行，处理流程：

1. 解析 Ethernet/IPv4/UDP/DNS 协议头
2. 提取查询域名和类型 (A/AAAA)
3. 在 LRU Hash Map 中查找
4. 命中时：原地修改数据包，通过 XDP_TX 直接从网卡返回响应
5. 未命中时：XDP_PASS 交给内核网络栈

**关键优化**：
- EDNS OPT 记录处理：自动剥离 dig 默认携带的 EDNS 附加段
- 单次 `bpf_xdp_adjust_tail` 调用完成包大小调整（增长答案 + 移除 EDNS）
- 名称压缩指针 (0xC00C) 避免重复编码域名
- LRU Hash Map 支持自动淘汰，100K 条目上限

### 慢路径 (Fallback Server)

用户态 DNS 服务器处理 XDP_PASS 的数据包：
- 缓存未命中的 A/AAAA 查询
- CNAME 链式解析 (最多 10 级)
- NS、SOA 等复杂记录类型
- 格式错误的 DNS 包

## 文件结构

| 文件 | 说明 |
|------|------|
| `xdp_dns_kern.c` | XDP eBPF 内核程序（快路径） |
| `xdp_dns_user.c` | 用户态加载器 + 回退 DNS 服务器 |
| `xdp_dns_test.c` | 跨平台单元测试程序（7 个测试用例） |
| `xdp_dns_edge.c` | DNS 协议边界测试程序（22 个测试用例） |
| `xdp_dns_sim.c` | XDP 内核逻辑模拟测试程序（10 个测试用例） |
| `xdp_dns_bench.c` | 多线程性能基准测试工具（QPS 压测） |
| `xdp_dns_common.h` | 内核/用户态共享定义 |
| `Makefile` | 构建系统 |
| `Dockerfile` | 容器化构建环境（macOS 用户） |
| `test_xdp_dns.sh` | 自动化集成测试脚本（9 个 dig 测试） |

## 构建与运行

### macOS (仅测试)

```bash
cd xdp
make test          # 编译并运行单元测试 (7 个)
make edge          # 编译并运行边界测试 (22 个)
make sim           # 编译并运行内核模拟测试 (10 个)
make test-all      # 运行全部测试 (39/39 通过)
make bench         # 编译性能基准工具
make server        # 启动独立 DNS 服务器 (端口 15353)
./test_xdp_dns.sh  # 运行完整集成测试套件 (9 个 dig 测试)
```

运行性能压测：

```bash
make server &
./xdp_dns_bench -p 15353 -t 4 -n 10000    # 4 线程, 每线程 10K 查询
kill %1
```

### Linux (完整 XDP)

```bash
cd xdp
make all                    # 编译内核程序 + 用户态程序 + 测试
sudo make run IF=eth0       # 加载 XDP 程序并启动服务器
```

### Docker (macOS 跨平台编译)

```bash
make docker
docker run --rm -v $(PWD):/work xdp-dns-build make kern
docker run --rm -v $(PWD):/work xdp-dns-build make user
```

## BPF Map 设计

### dns_map (LRU Hash)

| 字段 | 类型 | 说明 |
|------|------|------|
| **Key** | `struct dns_key` | `qtype` (2B) + `name` (128B) |
| **Value** | `struct dns_val` | `ip` (4B) + `ttl` (4B) + `ip6` (16B) |
| **容量** | 100,000 | LRU 自动淘汰 |
| **类型** | `BPF_MAP_TYPE_LRU_HASH` | 并发安全，无需锁 |

### stats_map (Per-CPU Array)

| 索引 | 名称 | 说明 |
|------|------|------|
| 0 | `STAT_TOTAL` | 总查询数 |
| 1 | `STAT_HIT` | XDP 缓存命中 |
| 2 | `STAT_MISS` | 缓存未命中 |

Per-CPU 计数器实现无锁统计，读取时由用户态聚合各 CPU 的值。

## DNS 记录类型支持

| 类型 | XDP 快路径 | 用户态回退 | 说明 |
|------|:---------:|:---------:|------|
| A | 支持 | 支持 | IPv4 地址 |
| AAAA | 支持 | 支持 | IPv6 地址 |
| CNAME | 传递 | 支持 | 链式解析 (最多 10 级) |
| NS | 传递 | 支持 | 名称服务器 |
| SOA | 跳过 | 跳过 | 区域授权起始 |
| MX | 传递 | 支持 | 邮件交换 |
| TXT | 传递 | 支持 | 文本记录 |

## 测试结果

### 单元测试 (7/7 通过)

```
[TEST] encode/decode round-trip: www.test.com ... PASS
[TEST] A query for www.test.com -> 2.3.4.4 ... PASS
[TEST] AAAA query for www.test.com -> 2001:db8::2 ... PASS
[TEST] CNAME chain: cname.test.com -> www.test.com -> 2.3.4.4 ... PASS
[TEST] NXDOMAIN for unknown.nonexistent.com ... PASS
[TEST] case-insensitive: WWW.TEST.COM == www.test.com ... PASS
[TEST] encode/decode empty root name ... PASS
```

### DNS 协议边界测试 (22/22 通过)

| 测试类别 | 测试用例 | 数量 |
|---------|---------|------|
| 畸形包 | 空包、过短包、截断域名、缓冲区溢出 | 4 |
| 域名边界 | 63 字节标签、64 字节标签（拒绝）、253 字节域名（拒绝）、126 字节域名、根域名、10 级嵌套、特殊字符、混合大小写 | 8 |
| 协议特性 | 压缩指针（拒绝）、EDNS OPT 记录、QR=1 响应包、多问题段、非标准类型 | 5 |
| TTL/IP 边界 | TTL=0、TTL=最大值、127.0.0.1、::1、2001:db8::1 | 5 |

### XDP 内核逻辑模拟测试 (10/10 通过)

| 测试类别 | 测试用例 | 数量 |
|---------|---------|------|
| 命中/未命中 | A 记录命中 (XDP_TX)、AAAA 记录命中 (XDP_TX)、缓存未命中 (XDP_PASS)、EDNS 查询命中 (剥离 OPT) | 4 |
| 过滤逻辑 | 非 53 端口 (PASS)、非 UDP 协议 (PASS)、QR=1 响应包 (PASS)、NS 查询 (PASS) | 4 |
| 数据完整性 | IP 校验和验证、统计计数器验证 | 2 |

### dig 功能测试 (9/9 通过)

```
Test 1: A www.test.com       -> 2.3.4.4
Test 2: A aaa.test.com       -> 1.2.3.4
Test 3: A ns.test.com        -> 192.168.10.79
Test 4: AAAA www.test.com    -> 2001:db8::2
Test 5: AAAA ns.test.com     -> 2001:db8::1
Test 6: CNAME cname.test.com -> www.test.com. + 2.3.4.4
Test 7: NXDOMAIN             -> (empty)
Test 8: Case-insensitive     -> 2.3.4.4
Test 9: Full response        -> ADDITIONAL: 0, MSG SIZE: 46
```

### 性能基准测试

| 场景 | 线程数 | QPS | 平均延迟 | 成功率 |
|------|--------|-----|---------|--------|
| A 记录 | 1 | 55,000 | 18 us | 100% |
| A 记录 | 4 | 155,000 | 26 us | 100% |
| AAAA 记录 | 1 | 59,000 | 17 us | 100% |

用户态单核约 55K QPS，4 线程 155K QPS。Linux 上使用 XDP 内核旁路后，单核预期可达 200K+ QPS。

### EDNS 兼容性

dig 默认携带 EDNS OPT 记录（附加段 11 字节）。XDP 程序通过以下方式处理：

1. 计算 EDNS 大小 = UDP 载荷长度 - 问题段长度
2. 单次 `bpf_xdp_adjust_tail(answer_size - edns_size)` 调整包大小
3. 设置 ARCOUNT=0，剥离 EDNS OPT
4. 在问题段后追加答案段

用户态回退服务器同样在响应中截断附加段，设置 ARCOUNT=0。

## 依赖

### Linux (完整功能)
- Linux 内核 >= 5.8 (bpf_xdp_adjust_tail)
- clang >= 10 (BPF 编译)
- libbpf-dev
- libelf-dev
- zlib1g-dev

### macOS (仅测试)
- gcc 或 clang
- dig (通过 `brew install bind` 安装)

## 性能预期

| 场景 | 预期 QPS (单核) | 说明 |
|------|:--------------:|------|
| XDP 命中 (A) | 200K+ | 网卡驱动层，零内核开销 |
| XDP 命中 (AAAA) | 180K+ | 略大的答案段 |
| 用户态回退 | 50K-80K | 经过内核网络栈 |
| 混合 (90% 命中) | 150K+ | 取决于命中率 |

实际性能取决于硬件、网卡驱动支持 (native vs generic mode) 和域名分布。
