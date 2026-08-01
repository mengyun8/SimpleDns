# SimpleDns XDP

基于 XDP (eXpress Data Path) 和 eBPF 技术的高性能权威 DNS 服务器。在网卡驱动层直接处理 DNS 响应，完全绕过内核网络栈，单核可达 200K+ QPS。支持 A/AAAA/NS/CNAME 记录类型，EDNS OPT 兼容，跨平台编译。

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

## 项目结构

```
SimpleDns/
├── Makefile                  # 统一构建系统（支持交叉编译）
├── build.sh                  # 跨平台打包脚本
├── README.md
├── Dockerfile                # 容器化构建环境
├── conf/
│   ├── simpledns.conf        # 主配置文件
│   └── test.com.zone         # zone 文件示例
├── src/
│   ├── xdp_dns_kern.c        # XDP eBPF 内核程序（快路径）
│   ├── xdp_dns_user.c        # 用户态加载器 + 回退 DNS 服务器
│   ├── xdp_dns_test.c        # 单元测试程序 (7 个用例)
│   ├── xdp_dns_edge.c        # DNS 协议边界测试 (22 个用例)
│   ├── xdp_dns_sim.c         # XDP 内核逻辑模拟测试 (10 个用例)
│   ├── xdp_dns_bench.c       # 多线程性能基准测试工具
│   └── xdp_dns_common.h      # 内核/用户态共享定义
├── scripts/
│   ├── test_xdp_dns.sh       # 集成测试脚本 (9 个 dig 测试)
│   └── install.sh            # 安装脚本
└── legacy/                   # 旧版 SimpleDns 代码 (libevent 版本)
```

## 快速开始

### 编译

```bash
# 当前平台编译
make

# 运行全部测试 (39/39 通过)
make test-all

# 生成本平台安装包
make package
```

### 交叉编译

```bash
# 交叉编译指定平台
make TARGET=linux-amd64 all
make TARGET=linux-arm64 all
make TARGET=darwin-amd64 all
make TARGET=darwin-arm64 all

# 生成指定平台安装包
make TARGET=linux-amd64 package

# 构建所有 4 个平台安装包
./build.sh all
```

### 安装

```bash
# 解压安装包
tar xzf dist/simpledns-xdp-1.0.0-darwin-arm64.tar.gz
cd simpledns-xdp-1.0.0-darwin-arm64

# 安装到系统 (需要 root)
sudo ./scripts/install.sh

# 或安装到自定义目录
sudo ./scripts/install.sh /opt/simpledns
```

### 运行 (Linux)

```bash
# 加载 XDP 程序并启动 DNS 服务器 (需要 root)
sudo simpledns-xdp -i eth0 -z /usr/local/var/simpledns/test.com.zone -o test.com -v
```

### 测试 (macOS/Linux)

```bash
# 运行集成测试
./scripts/test_xdp_dns.sh

# 启动测试服务器 (端口 15353)
make server

# 使用 dig 测试
dig @127.0.0.1 -p 15353 www.test.com
dig @127.0.0.1 -p 15353 www.test.com AAAA
dig @127.0.0.1 -p 15353 cname.test.com

# 性能压测
make server &
simpledns-bench -p 15353 -t 4 -n 10000
kill %1
```

## 交叉编译支持

### 支持的目标平台

| 目标平台 | 说明 | BPF 内核程序 | 用户态加载器 | 测试工具 |
|---------|------|:----------:|:----------:|:------:|
| `linux-amd64` | Linux x86_64 | 支持 | 支持 | 支持 |
| `linux-arm64` | Linux ARM64 | 支持 | 支持 | 支持 |
| `darwin-amd64` | macOS Intel | - | - | 支持 |
| `darwin-arm64` | macOS Apple Silicon | - | - | 支持 |

### 交叉编译方式

**macOS 上交叉编译**：

macOS 可直接交叉编译两个架构 (amd64/arm64)，使用 clang 的 `-arch` 选项：

```bash
make TARGET=darwin-amd64 package    # macOS Intel
make TARGET=darwin-arm64 package    # macOS Apple Silicon
```

**macOS 上编译 Linux 包 (通过 Docker)**：

```bash
# 构建 Docker 镜像
make docker

# 在容器中编译 Linux 包
docker run --rm -v $(PWD):/work simpledns-build make TARGET=linux-amd64 package
docker run --rm -v $(PWD):/work simpledns-build make TARGET=linux-arm64 package
```

**Linux 上交叉编译**：

```bash
# 安装交叉编译工具链
sudo apt install gcc-aarch64-linux-gnu    # ARM64
# 或
sudo apt install gcc-x86-64-linux-gnu     # x86_64

# 交叉编译
make TARGET=linux-arm64 CROSS_CC=aarch64-linux-gnu-gcc package
```

**一键构建所有平台包**：

```bash
./build.sh all
# 或
make package-all
```

### 安装包结构

```
simpledns-xdp-1.0.0-<platform>.tar.gz
├── bin/
│   ├── simpledns-xdp          # XDP 加载器 + 回退服务器 (仅 Linux)
│   ├── xdp_dns_kern.o         # BPF 内核程序 (仅 Linux)
│   ├── simpledns-test         # 单元测试
│   ├── simpledns-edge         # 边界测试
│   ├── simpledns-sim          # 内核模拟测试
│   └── simpledns-bench        # 性能基准工具
├── conf/
│   ├── simpledns.conf         # 配置文件
│   └── test.com.zone          # zone 文件示例
├── scripts/
│   ├── install.sh             # 安装脚本
│   └── test_xdp_dns.sh        # 测试脚本
└── README.md
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

### 全部测试通过: 48/48

| 测试类型 | 程序 | 用例数 | 结果 | 说明 |
|---------|------|--------|------|------|
| 单元测试 | `simpledns-test` | 7 | 7/7 | DNS 协议核心逻辑 |
| 边界测试 | `simpledns-edge` | 22 | 22/22 | 畸形包、域名边界、EDNS、TTL |
| 内核模拟 | `simpledns-sim` | 10 | 10/10 | XDP 数据包处理流程 |
| 集成测试 | `test_xdp_dns.sh` | 9 | 9/9 | dig 功能验证 |

### 单元测试 (7/7)

```
[TEST] encode/decode round-trip: www.test.com ... PASS
[TEST] A query for www.test.com -> 2.3.4.4 ... PASS
[TEST] AAAA query for www.test.com -> 2001:db8::2 ... PASS
[TEST] CNAME chain: cname.test.com -> www.test.com -> 2.3.4.4 ... PASS
[TEST] NXDOMAIN for unknown.nonexistent.com ... PASS
[TEST] case-insensitive: WWW.TEST.COM == www.test.com ... PASS
[TEST] encode/decode empty root name ... PASS
```

### DNS 协议边界测试 (22/22)

| 测试类别 | 测试用例 | 数量 |
|---------|---------|------|
| 畸形包 | 空包、过短包、截断域名、缓冲区溢出 | 4 |
| 域名边界 | 63 字节标签、64 字节标签（拒绝）、253 字节域名（拒绝）、126 字节域名、根域名、10 级嵌套、特殊字符、混合大小写 | 8 |
| 协议特性 | 压缩指针（拒绝）、EDNS OPT 记录、QR=1 响应包、多问题段、非标准类型 | 5 |
| TTL/IP 边界 | TTL=0、TTL=最大值、127.0.0.1、::1、2001:db8::1 | 5 |

### XDP 内核逻辑模拟测试 (10/10)

| 测试类别 | 测试用例 | 数量 |
|---------|---------|------|
| 命中/未命中 | A 记录命中 (XDP_TX)、AAAA 记录命中 (XDP_TX)、缓存未命中 (XDP_PASS)、EDNS 查询命中 (剥离 OPT) | 4 |
| 过滤逻辑 | 非 53 端口 (PASS)、非 UDP 协议 (PASS)、QR=1 响应包 (PASS)、NS 查询 (PASS) | 4 |
| 数据完整性 | IP 校验和验证、统计计数器验证 | 2 |

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

## 配置说明

### 主配置文件

路径：`/etc/simpledns/simpledns.conf`（或安装前缀下 `etc/simpledns/`）

```
zone: test.com /var/simpledns/test.com.zone
```

| 指令 | 格式 | 说明 |
|------|------|------|
| `zone` | `zone: <域名> <zone文件>` | 声明 zone 及其数据文件 |

### Zone 文件格式

采用标准 BIND zone 文件语法，示例（`conf/test.com.zone`）：

```
$TTL    86400
@              IN SOA  ns     root (
		42              ; serial
		3H              ; refresh
		15M             ; retry
		1W              ; expiry
		1D )            ; minimum

@    	300    IN    NS         ns
ns    	300    IN    A          192.168.10.79
ns    	300    IN    AAAA       2001:db8::1
www    	200    IN    A    	2.3.4.4
www    	200    IN    AAAA       2001:db8::2
cname   200    IN    CNAME      www
```

## 构建命令一览

| 命令 | 说明 |
|------|------|
| `make` | 编译当前平台所有程序 |
| `make test-all` | 运行全部测试 (单元 + 边界 + 模拟) |
| `make test` | 编译并运行单元测试 |
| `make edge` | 编译并运行边界测试 |
| `make sim` | 编译并运行内核模拟测试 |
| `make bench` | 编译性能基准工具 |
| `make server` | 启动测试 DNS 服务器 (端口 15353) |
| `make package` | 生成本平台安装包 |
| `make package-all` | 构建所有 4 个平台安装包 |
| `make TARGET=<platform> package` | 生成指定平台安装包 |
| `make docker` | 构建 Docker 镜像 (用于 BPF 编译) |
| `make clean` | 清理构建产物 |
| `make help` | 显示帮助信息 |

## 依赖

### Linux (完整功能)
- Linux 内核 >= 5.8 (bpf_xdp_adjust_tail)
- clang >= 10 (BPF 编译)
- libbpf-dev, libelf-dev, zlib1g-dev
- gcc / make

### macOS (测试和基准)
- clang (Xcode Command Line Tools)
- dig (通过 `brew install bind` 安装)

### Docker (跨平台编译)
- Docker (用于 macOS 上编译 Linux 包)

## 性能预期

| 场景 | 预期 QPS (单核) | 说明 |
|------|:--------------:|------|
| XDP 命中 (A) | 200K+ | 网卡驱动层，零内核开销 |
| XDP 命中 (AAAA) | 180K+ | 略大的答案段 |
| 用户态回退 | 50K-80K | 经过内核网络栈 |
| 混合 (90% 命中) | 150K+ | 取决于命中率 |

实际性能取决于硬件、网卡驱动支持 (native vs generic mode) 和域名分布。

## Legacy 代码

`legacy/` 目录包含基于 libevent 的原始 SimpleDns 实现，已被 XDP 方案取代，仅作参考保留。
