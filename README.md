# SimpleDns

一个基于 C 语言和 libevent 的轻量级权威 DNS 服务器。启动时从配置文件加载 zone 数据，通过 UDP 53 端口响应 DNS 查询，支持 A、AAAA、NS、CNAME、SOA 等常见记录类型，并实现了 EDNS Client Subnet（ECS）解析。

## 功能特性

- 基于 libevent 的事件驱动 I/O 模型，单线程非阻塞处理 UDP 查询
- 从标准 BIND 格式 zone 文件加载域名记录
- 支持记录类型：A、AAAA、NS、CNAME、SOA
- 支持 CNAME 链式追踪与 NS 委托追加
- 解析 EDNS0 OPT 记录，提取客户端子网信息（RFC 7871）
- 使用 Linux 内核风格双向链表管理 zone 与 domain 数据
- 可配置日志文件路径，日志带时间戳与源码定位

## 项目结构

| 文件 | 职责 |
|------|------|
| `SimpleDns.c` | 程序入口，创建 UDP socket、启动 libevent 事件循环 |
| `Dns.c` / `Dns.h` | DNS 协议核心：报文编解码、资源记录管理、查询解析 |
| `Dnsdb.c` / `Dnsdb.h` | DNS 数据库：zone 文件解析、域名查找、记录匹配 |
| `conf.c` / `conf.h` | 配置解析工具：行分词器、token 链表管理 |
| `env.c` / `env.h` | 环境初始化：读取主配置文件、加载 zone、初始化日志 |
| `log.c` / `log.h` | 日志系统：分级日志、时间戳格式化输出 |
| `list.h` | Linux 内核风格双向链表实现 |
| `Makefile` | 构建脚本 |
| `SimpleDns.conf` | 主配置文件示例 |
| `test.com.zone` | zone 文件示例 |

## 架构概览

```
                   UDP 53 端口
                       |
                 libevent 事件循环
                       |
                  do_accept 回调
                       |
         +-------------+-------------+
         |             |             |
    recvfrom()    解包 & 解析     sendto()
         |             |             |
         |    Message_unpackage      |
         |    Message_resolve        |
         |    Message_package        |
         |             |             |
         +-------------+-------------+
                       |
                   Dnsdb 查找
                       |
              Zone 文件数据 (内存)
```

### 请求处理流程

1. **接收数据包** — libevent 监听 UDP socket 的 `EV_READ` 事件，触发 `do_accept` 回调，通过 `recvfrom` 读取客户端请求
2. **解包报文** — `Message_unpackage` 解析 DNS 报文头、Question 段，并尝试解析 EDNS0 OPT 记录以提取客户端真实 IP
3. **解析查询** — `Message_resolve` 遍历每个 Question，调用 `Dnsdb_lookup` 在内存数据库中查找匹配记录；若命中 CNAME 则自动追踪下一跳，命中 NS 则将记录追加到 Additional 段
4. **编码响应** — `Message_package` 将响应头、Question 段、Answer/Authority/Additional 段按 DNS 报文格式编码到缓冲区
5. **发送响应** — `sendto` 将编码后的报文发回客户端地址
6. **释放资源** — `Message_free` 释放本次查询动态分配的 Question 与 ResourceRecord 链表

## 模块详解

### DNS 协议层（Dns.c / Dns.h）

定义了 DNS 报文的核心数据结构：

- `struct Message` — 完整 DNS 报文，包含头字段（id、flags、各段计数）和 Question、Answer、Authority、Additional 四段链表
- `struct Question` — 查询问题段（qName、qType、qClass）
- `struct ResourceRecord` — 资源记录（name、type、class、ttl、rd_length、rd_data）
- `union ResourceData` — 资源数据联合体，覆盖 A、AAAA、NS、CNAME、SOA、PTR、MX、TXT、SRV 等类型

关键函数：

| 函数 | 作用 |
|------|------|
| `Message_unpackage` | 解析入站 DNS 报文，解码头部与 Question 段，解析 EDNS0 Client Subnet |
| `Message_resolve` | 对每个 Question 执行数据库查找，处理 CNAME 链追踪与 NS 委托 |
| `Message_package` | 将响应 Message 编码为 DNS 线格式报文 |
| `Message_encode` | 编码头部、Question 段及全部资源记录段 |
| `decode_domain_name` | 将 DNS 线格式域名（3www4test3com0）解码为点分字符串 |
| `encode_domain_name` | 将点分字符串编码为 DNS 线格式域名 |
| `ResourceRecord_Create` | 根据类型、TTL、rdata 创建资源记录 |
| `ResourceRecord_Add` | 按记录类型分发到 Answer 段（A/AAAA/NS/CNAME）或 Authority 段（SOA） |

网络字节序处理通过 `get8bits`/`get16bits`/`get32bits`（读取时 `ntohs`/`ntohl`）和 `put8bits`/`put16bits`/`put32bits`（写入时 `htons`/`htonl`）完成。

### DNS 数据库层（Dnsdb.c / Dnsdb.h）

使用三层嵌套链表组织 zone 数据：

```
Dnsdb_t
  └── Domain_t (域名，如 test.com)
        └── Zone_t (记录条目，如 www.test.com → A 2.3.4.4)
```

关键函数：

| 函数 | 作用 |
|------|------|
| `Dnsdb_load` | 加载一个域名的 zone 文件，创建 Domain 并加入数据库 |
| `Dnsdb_domain_load` | 逐行读取 zone 文件，跳过注释行，解析每条记录 |
| `Zone_load` | 解析单行 zone 记录，处理相对名（追加 origin）、`@` 符号（zone 根）、TTL、记录类型与 rdata |
| `Dnsdb_lookup` | 主查找入口：先匹配 origin 域名，再在对应 Domain 内查找具体记录 |
| `Dnsdb_lookup_origin` | 遍历所有 Domain，找到与查询名最匹配的 zone origin |
| `Domain_findzone` | 在 Domain 的 Zone 链表中查找匹配记录，同时收集 `@` 对应的 NS 记录 |
| `Record_check` | 将字符串记录类型（"A"、"NS" 等）映射为 RR 类型枚举 |

zone 文件解析支持的记录类型：A、NS、CNAME、AAAA、SOA、TXT、MX。对于 CNAME/NS/MX 类型的 rdata，若未以 `.` 结尾则自动追加 origin 域名。

### 配置与环境层（env.c / conf.c）

主配置文件路径硬编码为 `/etc/SimpleDns.conf`，支持两种指令：

- `logfile: <路径>` — 指定日志文件，默认 `/var/log/SimpleDns.log`
- `zone: <域名> <zone文件路径>` — 声明一个 zone 及其数据文件

`conf.c` 提供通用的行分词器 `buffer_get_key`，按空格/Tab 切分配置行，结果存入 `val_t` 链表供上层使用。`Zone_load` 和 `env_parse_line` 均依赖此分词器。

### 日志系统（log.c / log.h）

通过 `log_init` 打开日志文件，提供 `log_info` 和 `log_error` 两个函数，输出格式为 `YYYY/M/D H:M:S [I|E] [函数名:行号] 消息`。`log` 宏根据日志级别自动分发，并注入 `__func__` 和 `__LINE__` 信息。

日志级别枚举：

| 枚举值 | 含义 |
|--------|------|
| `LOG_INFO` | 信息级，走 `log_info` |
| `LOG_WARN` | 警告级，走 `log_error` |
| `LOG_ERR` | 错误级，走 `log_error` |

### 链表工具（list.h）

移植自 Linux 内核的通用双向链表实现，提供 `list_add`、`list_del`、`list_for_each`、`list_for_each_safe`、`list_entry`（基于 `container_of`）等标准操作。Dnsdb 模块使用此链表管理 Domain 和 Zone 节点。

## 编译与安装

### 依赖

- GCC
- libevent（开发库）
- pthread

### 编译

```bash
make
```

编译参数：`-g -m64 -O3 -D_GNU_SOURCE -Wall`，链接 `-levent -lpthread`。

### 安装

```bash
sudo make install
```

将配置文件复制到 `/etc/SimpleDns.conf`，zone 文件复制到 `/var/SimpleDns/`。

### 清理

```bash
make clean
```

## 配置说明

### 主配置文件

路径：`/etc/SimpleDns.conf`

```
logfile: /var/log/SimpleDns.log
zone: test.com /var/SimpleDns/test.com.zone
```

| 指令 | 格式 | 说明 |
|------|------|------|
| `logfile` | `logfile: <路径>` | 日志文件路径，可选，默认 `/var/log/SimpleDns.log` |
| `zone` | `zone: <域名> <zone文件>` | 声明 zone 及其数据文件，可出现多行 |

以 `#` 或 `;` 开头的行被视为注释。

### Zone 文件格式

采用标准 BIND zone 文件语法，示例（`test.com.zone`）：

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
aaa    	200    IN    A    	1.2.3.4
www    	200    IN    A    	2.3.4.4
```

| 字段 | 说明 |
|------|------|
| `$TTL` | 默认生存时间 |
| `@` | 代表 zone origin（即域名本身） |
| 名称 | 记录名，相对名会自动追加 origin；以 `.` 结尾为绝对名 |
| TTL | 生存时间（秒），可省略使用 `$TTL` |
| `IN` | 类别，固定为 Internet |
| 类型 | A、NS、CNAME、AAAA、SOA、TXT、MX |
| 数据 | 对应记录的值，如 IP 地址或目标域名 |

## 运行与测试

### 启动服务

```bash
sudo ./SimpleDns
```

需要 root 权限绑定 53 端口。启动后输出 `Server start .......` 并进入事件循环。

### 测试查询

使用 dig 测试：

```bash
dig @127.0.0.1 www.test.com
```

示例输出：

```
; <<>> DiG 9.11.0-P3 <<>> @127.0.0.1 www.test.com
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 12498
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;www.test.com.			IN	A

;; ANSWER SECTION:
www.test.com.		200	IN	A	2.3.4.4

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1)
```

查询 CNAME 记录时会自动追踪链式解析：

```bash
dig @127.0.0.1 xxx.test.com
```

```
;; ANSWER SECTION:
xxx.test.com.		600	IN	CNAME	aaa.test.com.
aaa.test.com.		200	IN	A	1.2.3.4
```

## EDNS Client Subnet 支持

`Message_unpackage` 在解析完 Question 段后，继续检查 Additional 段是否存在 EDNS0 OPT 记录（type 41）。若检测到 Client Subnet 选项（option code 8），则从中提取客户端真实 IP 地址并存入 `msg->cliaddr`，供后续基于来源 IP 的解析逻辑使用。

## 多线程说明

源码中保留了多线程实现的注释代码（`#if 0` 块），原设计为按线程数创建多个 `event_base`，并使用 `SCHED_FIFO` 实时调度策略与 CPU 亲和性绑定。当前版本为单线程运行，多线程代码未启用。

## XDP 高性能加速方案

`xdp/` 目录包含基于 XDP (eXpress Data Path) 和 eBPF 技术的高性能 DNS 加速方案，在网卡驱动层直接处理 DNS 响应，完全绕过内核网络栈，单核可达 200K+ QPS。

### 架构概览

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

### 核心文件

| 文件 | 职责 |
|------|------|
| `xdp/xdp_dns_kern.c` | XDP eBPF 内核程序（快路径，处理 A/AAAA 查询） |
| `xdp/xdp_dns_user.c` | 用户态加载器 + 回退 DNS 服务器 |
| `xdp/xdp_dns_common.h` | 内核/用户态共享定义（BPF Map 结构、常量） |
| `xdp/xdp_dns_test.c` | 跨平台单元测试程序（7 个测试用例） |
| `xdp/xdp_dns_edge.c` | DNS 协议边界测试程序（22 个测试用例） |
| `xdp/xdp_dns_sim.c` | XDP 内核逻辑模拟测试程序（10 个测试用例） |
| `xdp/xdp_dns_bench.c` | 多线程性能基准测试工具（QPS 压测） |
| `xdp/test_xdp_dns.sh` | 自动化集成测试脚本（9 个 dig 测试） |

### 测试命令

根目录 Makefile 提供以下代理目标，可直接在项目根目录执行：

```bash
make test-all    # 运行全部测试（单元 + 边界 + 内核模拟，共 39/39 通过）
make test        # 仅运行单元测试
make edge        # 仅运行 DNS 协议边界测试
make sim         # 仅运行 XDP 内核逻辑模拟测试
make bench       # 编译性能基准工具
```

运行性能压测：

```bash
cd xdp
./xdp_dns_test -s ../test.com.zone test.com &     # 启动 DNS 服务器
./xdp_dns_bench -p 15353 -t 4 -n 10000             # 4 线程压测
kill %1                                             # 停止服务器
```

### 性能基准测试结果

| 场景 | QPS | 平均延迟 | 成功率 |
|------|-----|---------|--------|
| 单线程 A 记录 | 55,000 | 18 us | 100% |
| 4 线程 A 记录 | 155,000 | 26 us | 100% |
| 单线程 AAAA 记录 | 59,000 | 17 us | 100% |

用户态单核约 55K QPS，4 线程 155K QPS。Linux 上使用 XDP 内核旁路后，单核预期可达 200K+ QPS。

### Linux 上加载 XDP 程序

```bash
cd xdp
make all                    # 编译内核程序 + 用户态程序 + 测试
sudo make run IF=eth0       # 加载 XDP 程序并启动服务器
```

详细文档见 `xdp/README.md`。
