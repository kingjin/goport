# GoPort

**GoPort** 是一个面向 Windows 的高速 TCP/UDP 端口扫描器：通过 Npcap 的 `wpcap.dll` 注入无状态 TCP SYN 报文并读取 SYN-ACK / RST 应答，扫描思路参考 Goby 的引擎，但提供命令行与内置 Web 两种使用方式。

整个项目只依赖 Go 标准库，不依赖 cgo、C 编译器或任何第三方 Go 包，最终产物是一个自包含的 `goport.exe`。

[![Go](https://img.shields.io/badge/Go-1.25-00ADD8?logo=go&logoColor=white)](https://go.dev/)
[![Platform](https://img.shields.io/badge/platform-Windows-0078D6?logo=windows&logoColor=white)](#环境要求)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

```
goport -t 192.168.1.0/24 -p minimal
```

---

## 目录

- [特性](#特性)
- [工作原理](#工作原理)
- [环境要求](#环境要求)
- [安装与构建](#安装与构建)
- [快速开始](#快速开始)
- [命令行参考](#命令行参考)
- [目标与端口的写法](#目标与端口的写法)
- [端口预设](#端口预设)
- [输出格式](#输出格式)
- [Web 界面](#web-界面)
- [端口状态判定规则](#端口状态判定规则)
- [项目结构](#项目结构)
- [内部设计要点](#内部设计要点)
- [测试](#测试)
- [故障排查](#故障排查)
- [已知限制](#已知限制)
- [合规声明](#合规声明)
- [许可证](#许可证)

---

## 特性

- **TCP SYN 半开扫描**：纯 Go 直接调用 `wpcap.dll` 构造以太网 / IPv4 / TCP 帧并注入，自己维护探针表匹配应答；不建立完整连接，速度快、对目标影响小。
- **自动降级**：`-m auto`（默认）优先 SYN；当前进程没有管理员权限时自动改用 `connect()` 扫描，结果语义一致。
- **connect 扫描**：普通 socket，无需管理员权限，也无需 Npcap。
- **UDP 探测**：为 DNS、NTP、SNMP、NetBIOS、SSDP、mDNS、SIP、IPMI 等端口发送协议相关的有效请求，而不是空数据报。
- **主机发现与下一跳解析**：基于 ARP 解析目标 MAC、跨网段时解析网关 MAC，并复用系统 ARP 缓存减少等待。
- **服务识别**：对 open 的 TCP 端口做协议感知的 banner 抓取，识别 TLS 证书、HTTP 状态 / Server 头 / 页面标题、SSH、MySQL、Redis、VNC、FTP、SMTP、POP3、IMAP 等。
- **Goby 端口预设**：内置 `minimal`、`enterprise`、`cafe`、`database`、`general`、`scada`、`iot`、`backdoor`、`all`，也可直接读取 Goby 的 `config/config.json`。
- **多种输出**：table / JSON / NDJSON / CSV；CSV 可输出 GBK 编码，中文 Windows 的 Excel 双击即可正常显示。
- **内置 Web 界面**：单文件页面，无外部资源；地址数量不受 Web 请求规模限制（内部上限 1677 万，按 512 个地址一批推进），可实时看进度、停止扫描、导出 CSV。
- **辅助工具**：`-list-if` 列出网卡、`-doctor` 环境自检、`-dry-run` 只构造报文校验校验和、`-no-banner` 加速。
- **纯 Go、零第三方依赖**：`go.mod` 没有 `require`，`CGO_ENABLED=0` 即可构建。

---

## 工作原理

### SYN 模式

1. 通过 `iphlpapi.dll`（`GetAdaptersAddresses` / 路由表 / ARP 表）枚举网卡、确定源 IP、源 MAC、默认路由和目标网段；由网卡 GUID 推导出 Npcap 设备名 `\Device\NPF_{GUID}`。
2. 用 Npcap 打开一收一发两个抓包句柄，接收句柄设置 BPF 过滤器 `ip` 并把缓冲区扩大到 4 MiB。
3. 通过 ARP 解析每个目标的下一跳 MAC（同网段直接解析目标，跨网段解析网关），无应答的目标被标记为“无响应”并跳过。
4. 发送循环按目标速率注入 SYN/UDP 帧，探针按 (目标 IP, 目标端口, 源端口) 哈希到 64 个分片表；源端口从 20000–65535 轮转，随机初始序列号。
5. 抓包循环分类应答：
   - TCP `SYN+ACK` → `open`（并校验 `ack == seq+1`，防止无关流量伪造结果）
   - TCP `RST` → `closed`
   - UDP 应答 → `open`
   - ICMP type 3 code 3/4 → `closed`；code 0/1/2/13 → `filtered`
   - 超过重传次数仍无应答 → TCP `filtered`，UDP `open|filtered`
6. open 的 TCP 结果进入 banner 工作池补充服务信息，再统一交给输出层。

### connect 模式

普通 `net.Dialer` 并发连接（默认 500 并发），根据 `connection refused`、超时等错误映射端口状态；UDP 则 `Dial` + 写探测载荷 + 等回复。该模式不经过 Npcap，也无需管理员权限。

### 自动模式

`auto` 先尝试 SYN。Npcap 驱动默认只允许管理员访问（`HKLM\SYSTEM\CurrentControlSet\Services\npcap\Parameters\AdminOnly=1`），程序会先读该策略：若当前未提权且策略开启，则直接跳过注定失败的驱动打开，改用 connect 模式，并在 stderr 提示。

```
                 ┌──────────────────────────────┐
  目标/端口解析 → │ cmd/goport  (CLI / Web)        │
                 └──────────────┬───────────────┘
                                │ scan.Config
                 ┌──────────────▼───────────────┐
                 │ internal/scan                 │
                 │  目标枚举 · 端口解析 · 预设     │
                 │  SYN 引擎 / connect 引擎       │
                 │  ARP 发现 · 限速/重传 · banner │
                 └───────┬──────────────┬───────┘
                         │              │
              ┌──────────▼───┐   ┌──────▼─────────┐
              │ internal/npcap│   │ internal/packet │
              │ wpcap.dll     │   │ 帧构造 / 解析    │
              └──────────┬───┘   └────────────────┘
                         │
              ┌──────────▼────────┐
              │ internal/netinfo   │
              │ iphlpapi.dll       │
              └────────────────────┘
```

---

## 环境要求

| 项目 | 要求 |
| --- | --- |
| 操作系统 | Windows 10 / 11（依赖 `wpcap.dll`、`iphlpapi.dll` 等 Windows API，其他平台无法编译运行） |
| Npcap | 需要安装 [Npcap](https://npcap.com/#download)；SYN 模式依赖它，connect 模式不需要；安装时建议勾选 **WinPcap API-compatible Mode** |
| 权限 | SYN 模式需要**管理员权限**；connect 模式普通用户即可 |
| Go（仅构建时） | Go 1.25 或更新（`go.mod` 声明 `go 1.25`） |
| cgo / C 编译器 | 不需要，`CGO_ENABLED=0` |

> 提示：Npcap 驱动默认策略 `AdminOnly=1`。若希望普通用户也能使用 SYN 模式，可在安装 Npcap 时取消“Restrict Npcap driver's access to Administrators only”，或在注册表 `HKLM\SYSTEM\CurrentControlSet\Services\npcap\Parameters` 下把 `AdminOnly` 设为 `0`（这会降低主机抓包安全性，请自行评估）。

---

## 安装与构建

### 获取源码

```bat
git clone https://github.com/kingjin/goport.git
cd goport
```

### 方式一：使用构建脚本

在项目根目录双击或执行：

```bat
build.bat
```

产物为 `bin\goport.exe`。脚本会设置 `CGO_ENABLED=0`、`-trimpath`、`-ldflags "-s -w"`（去符号、减小体积），并检查 `go` 是否在 `PATH` 中。

### 方式二：手动构建

```bat
set CGO_ENABLED=0
go build -trimpath -ldflags "-s -w" -o bin\goport.exe .\cmd\goport
```

### 方式三：直接运行

```bat
go run .\cmd\goport -doctor
```

### 安装 Npcap

1. 从 <https://npcap.com/#download> 下载安装包。
2. 安装时勾选 **Install Npcap in WinPcap API-compatible Mode**（GoPort 只使用 WinPcap 兼容导出）。
3. 安装完成后执行自检：

```bat
bin\goport.exe -doctor
```

自检会依次检查 `wpcap.dll`、网卡枚举、默认路由、系统 ARP 表、管理员权限、实际打开网卡与链路层类型、`minimal` 预设解析，最后给出结论。

---

## 快速开始

```bat
:: 1. 环境自检（建议先跑一次）
bin\goport.exe -doctor

:: 2. 查看网卡，记下编号 / 名称
bin\goport.exe -list-if

:: 3. 扫描一个 C 段，使用最小端口集
bin\goport.exe -t 192.168.1.0/24 -p minimal

:: 4. 全端口扫描并写入文件
bin\goport.exe -t 10.0.0.5 -p all -rate 5000 -f csv -csv-enc gbk -o result.csv

:: 5. 没有管理员权限时用 connect 模式
bin\goport.exe -t 10.0.0.0/24 -p 22,80,443,3389 -m connect

:: 6. JSON 输出给其他工具消费
bin\goport.exe -t 10.0.0.5 -p 1-10000 -f json -o result.json

:: 7. 跨网段扫描，手动指定网关 MAC
bin\goport.exe -t 172.16.8.10 -p 80,443 -i 5 -gw-mac aa-bb-cc-dd-ee-ff

:: 8. 只校验报文构造（不需要 Npcap 权限）
bin\goport.exe -dry-run -t 10.0.0.5 -p 443

:: 9. 启动 Web 界面（自动打开浏览器）
bin\goport.exe -ui
```

> `bin\goport.exe` 不带任何参数双击启动时，会直接进入桌面模式：在 `127.0.0.1:8080` 起 Web 服务并自动打开浏览器。

---

## 命令行参考

Go 的 `flag` 解析规则：参数可写作 `-flag value`、`-flag=value`，也接受 `--flag`；布尔开关请用 `-banner=false` 这种形式，不要写成 `-banner false`（否则 `false` 会被当成位置参数目标）。

目标可以用 `-t` 重复给出，也可以直接作为位置参数追加，两者会合并：

```bat
goport -t 10.0.0.1 -t 10.0.0.2 -p 80
goport -p 80 10.0.0.1 10.0.0.2
```

### 目标

| 参数 | 说明 |
| --- | --- |
| `-t`, `-target` | 目标，可重复。支持单地址、CIDR、范围、域名、目标文件 |

### 端口

| 参数 | 说明 |
| --- | --- |
| `-p`, `-ports` | 端口列表，如 `80,443,8000-8100,U:161`、`all`；也可以直接写预设名 |
| `-preset`, `-presets` | 使用内置预设，如 `minimal`、`enterprise` |
| `-goby-config` | 读取 Goby 的 `config/config.json` 中的端口预设；与 `-preset` 配合使用 |

### 扫描控制

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `-m`, `-mode` | `auto` | `auto` / `syn` / `connect`（别名：`a`、`s`、`half`、`half-open`、`c`、`full`、`tcp`） |
| `-i`, `-iface`, `-interface` | 自动 | 网卡编号或名称子串，先 `-list-if` 查看；默认走默认路由网卡 |
| `-rate` | `2000` | SYN 模式每秒探测数（pps） |
| `-timeout` | `400` | 单次探测超时（毫秒） |
| `-retries` | `2` | 无应答重传次数 |
| `-shuffle` | 关闭 | 随机化探测顺序（用互质步长遍历全组合，内存 O(1)） |
| `-batch` | 关闭 | 使用 `pcap_sendqueue` 批量注入，更快；部分驱动会丢应答 |
| `-no-batch` | — | 显式关闭批量发送（覆盖 `-batch`） |
| `-ttl` | `64` | 探测报文 TTL |
| `-arp-timeout` | `3000` | 同网段 ARP 解析窗口（毫秒） |
| `-c`, `-concurrency` | `500` | connect 模式并发数 |
| `-src-ip` | 自动 | 覆盖源 IP（调试 / 多网卡场景） |
| `-src-mac` | 自动 | 覆盖源 MAC，如 `aa:bb:cc:dd:ee:ff` |
| `-gw-mac` | 自动 | 指定网关 MAC（跨网段且 ARP 解析失败时使用） |

### 结果与输出

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `-banner` | 开启 | 服务识别（对 open 的 TCP 端口抓 banner） |
| `-no-banner` | — | 关闭服务识别，速度更快 |
| `-banner-timeout` | `1200` | 单次 banner 抓取超时（毫秒） |
| `-show-closed` | 关闭 | 输出 closed 端口 |
| `-show-filtered` | 关闭 | 输出 filtered / open\|filtered 端口 |
| `-f`, `-format` | `table` | `table`（别名 `txt`/`text`）、`json`、`ndjson`（别名 `jsonl`）、`csv` |
| `-csv-enc` | `utf8` | CSV 编码：`utf8` 或 `gbk`（也接受 `gb2312`、`gb-2312`、`cp936`、`936`、`ansi`） |
| `-o`, `-out` | 无 | 结果写入文件（文件内容使用 `-format` 指定格式） |
| `-no-color` | 关闭 | 关闭 ANSI 颜色；同时尊重 `NO_COLOR` 环境变量 |
| `-no-progress` | 关闭 | 不打印进度行 |

### 其他

| 参数 | 说明 |
| --- | --- |
| `-list-if` | 列出网卡、Npcap 设备名、网段，并标记默认路由网卡 |
| `-doctor` | 环境自检（Npcap / 权限 / 路由 / 抓包 / 预设） |
| `-web <地址>` | 启动 Web 界面，如 `-web 127.0.0.1:8080`；端口被占用时自动向后尝试最多 10 个端口 |
| `-ui` | 等价于 `-web 127.0.0.1:8080` |
| `-open` | 与 `-web` / `-ui` 一起使用时，启动后自动打开浏览器（桌面模式默认就会尝试；`GOPORT_NO_BROWSER=1` 可禁用） |
| `-dry-run` | 只构造 TCP SYN / UDP / ARP 报文并校验校验和，不发送，也不需要 Npcap 权限 |
| `-v`, `-verbose` | 详细日志（网卡、源地址、存活目标、批处理回退等） |
| `-V`, `-version` | 打印版本 |
| `-h`, `-help` | 打印用法 |

### 退出码

| 退出码 | 含义 |
| --- | --- |
| `0` | 扫描正常完成（含扫描结束后结果为空的情况） |
| `1` | 运行期错误（Npcap 打不开、输出文件创建失败、扫描出错等） |
| `2` | 参数错误（目标 / 端口 / 模式 / 格式解析失败，或缺少目标） |
| `130` | 被 Ctrl+C / SIGTERM 中断，已输出部分结果 |

---

## 目标与端口的写法

### 目标

| 写法 | 含义 |
| --- | --- |
| `10.0.0.1` | 单个 IPv4 地址 |
| `10.0.0.0/24` | CIDR 网段（前缀长度 ≤ /30 时去掉网络地址与广播地址；/31、/32 保留全部） |
| `10.0.0.1-254` | 最后一段范围，等价于 `10.0.0.1-10.0.0.254` |
| `10.0.0.1-10.0.0.9` | 任意地址范围（起止可反写，会自动交换） |
| `example.com` | 域名，解析全部 A 记录（5 秒超时） |
| `hosts.txt` | 目标文件，每行一个表达式；`#` 或 `;` 之后为注释 |
| `@hosts.txt` | 同上，显式标记为文件 |

细节：

- 多个目标可用逗号、空格、制表符、换行或分号分隔，`-t` 可重复。
- 地址会去重（表达式很多时自动关闭去重以节省内存），并保持输入顺序。
- 单次扫描地址上限 **16,777,216**（`0.0.0.0/0` 这类误输入会直接被拒绝）。
- 目前只支持 IPv4；IPv6 会明确报错。
- 目标文件写域名、CIDR、范围都可以。

### 端口

| 写法 | 含义 |
| --- | --- |
| `80` | 单个 TCP 端口 |
| `80,443,8080` | 多个端口 |
| `8000-8100` | 端口区间（起止可反写） |
| `U:161` / `udp:161` | UDP 端口 |
| `T:80` / `tcp:80` | 显式标记 TCP（默认即 TCP） |
| `U:53,123` | 注意：`U:` 只作用于紧跟其后的一个 token，`123` 仍是 TCP |
| `all` | `0-65535` |
| `minimal` | 预设名，可与具体端口混写（如 `minimal,8080`） |

分隔符支持逗号、空格、制表符、换行和分号。端口会去重并排序。

---

## 端口预设

内置预设与 Goby 的端口列表保持一致，`U:` 前缀同样表示 UDP：

| 预设 | 说明 | 常用别名 |
| --- | --- | --- |
| `minimal` | 最小集合：常见远程管理 / Web / 数据库 / UDP 发现端口 | `min`、`default` |
| `enterprise` | 企业内网常见服务，覆盖面较广 | `ent` |
| `cafe` | 咖啡厅 / 酒店 / 机场等公共网络常见端口 | `coffee`、`hotel`、`airport` |
| `database` | 各类数据库及其管理端口 | `db` |
| `general` | 通用大列表（含大量区间） | — |
| `scada` | 工控 / SCADA 协议端口 | `ics`、`ot` |
| `iot` | IoT 与嵌入式设备端口 | — |
| `backdoor` | 少量后门 / 远控常用端口 | `backdoors`、`backdoor check` |
| `all` | `0-65535` | `full`、`0-65535` |

预设名大小写不敏感。使用 Goby 自定义配置：

```bat
goport -t 10.0.0.0/24 -goby-config ".\Goby\config\config.json" -preset enterprise
```

`-goby-config` 会读取 JSON 中的 `ports[].title` / `ports[].value`；标题会转小写、去掉空格、把 `/` 换成 `-`、去掉 `scanconfig.` 前缀。若同时给了 `-p`，以 `-p` 为准。

---

## 输出格式

### table（默认）

适合终端查看，列宽按字符（含中文）对齐：

```
HOST             PORT   PROTO  STATE         SERVICE        RTT       INFO
10.0.0.5         22     tcp    open          ssh            1.2ms     SSH-2.0-OpenSSH_9.6
10.0.0.5         80     tcp    open          http           0.8ms     HTTP/1.1 200 OK | Server: nginx | title=...
```

- 只有 stdout 是终端、且未写文件、未设置 `NO_COLOR`、未加 `-no-color` 时才输出颜色。
- 进度行与统计摘要写到 **stderr**，因此 `-f json > out.json` 不会把进度混进结果。

### json

边扫边写的 JSON 数组，结束时补上 `]`：

```json
[
  {"host":"10.0.0.5","port":22,"proto":"tcp","state":"open","service":"ssh","banner":"SSH-2.0-OpenSSH_9.6","rtt_ms":1.2,"at":"2026-01-01T12:00:00Z"}
]
```

### ndjson

每行一个 JSON 对象，适合流式管道处理。

### csv

表头固定为：

```
host,port,proto,state,service,rtt_ms,banner,at
```

`-csv-enc gbk` 时每个完整 CSV 记录会通过 Windows 代码页 936 转换后再写出（GBK 无法表示的字符变成 `?`），中文 Windows 的 Excel 可直接打开。字段中的逗号、引号、换行由 `encoding/csv` 负责转义。

### 结果字段

| 字段 | 说明 |
| --- | --- |
| `host` | 目标 IPv4 地址 |
| `port` | 端口号 |
| `proto` | `tcp` / `udp` |
| `state` | `open` / `closed` / `filtered` / `open\|filtered` |
| `service` | 端口对应的服务名（内置表），banner 识别可覆盖 |
| `banner` | 服务识别得到的一行摘要（HTTP、SSH、TLS 证书、MySQL 版本等） |
| `rtt_ms` | 从发出探针到收到应答的毫秒数；无应答为 0 |
| `at` | 结果产生时间（RFC3339） |

扫描结束后 stderr 会输出摘要，例如：

```
扫描完成，用时 3.214s
  目标 254 个（无响应 0），端口 14 个，共 3556 个探测
  发送 3556 个探测（重传 12，平均 1106 pps），收到 2100 个应答
  结果：open 12，closed 2088，filtered 1456，已输出 12 行
```

---

## Web 界面

### 启动

```bat
bin\goport.exe -ui
:: 或指定监听地址
bin\goport.exe -web 127.0.0.1:9000
```

终端会打印实际地址（例如 `http://127.0.0.1:8080`）。若端口已被占用，会在 8080–8090 范围内自动向后寻找可用端口。关闭窗口或 Ctrl+C 即停止服务。

不带参数双击 `goport.exe` 也会进入同样的桌面模式，并自动用默认浏览器打开页面。

### 使用

- **IP / 网段**：支持多行，也支持逗号 / 空格分隔；支持 CIDR、范围、域名。
- **端口**：支持多行、区间、`U:` 前缀，以及预设名与具体端口混写（如 `minimal,8080`）。
- 提交前会实时预览：地址数 × 端口数 = 探测数，以及分几批执行。
- 可切换 `auto` / `syn` / `connect`、是否做服务识别、是否显示 closed / filtered。
- 扫描中显示进度条、已用时间、预计剩余、模式、open / closed / filtered 计数；可点“停止”。
- 完成后展示结果表格，并可导出两种 CSV：GB2312/GBK（Excel 友好）与 UTF-8。

### Web 模式的行为与限制

| 项目 | 值 |
| --- | --- |
| 每批地址数 | 512（批次之间释放探针表 / 句柄） |
| 单批时间预算 | `max(120s, 探测数 × (1+重试) / 速率 × 3)` |
| 内存中结果上限 | 200,000 条（超出只计数，导出时附注“仅导出前 N 条”） |
| 保留历史作业 | 8 个（用于导出 / 回看） |
| 并发作业 | 同时只允许 1 个；重复提交返回 409，需等待或先停止 |
| 默认端口 | 输入框留空时使用 `1-1000` |
| 文件目标 | 不支持，页面会提示直接粘贴地址 |
| 扫描参数 | 速率 2000 pps、超时 600 ms、重试 1 次、banner 并发 32 / 超时 1000 ms、connect 并发 300 |

> 作业与结果只保存在内存里，进程退出后丢失；需要留存请及时导出 CSV。
>
> Web 界面**没有身份认证**。默认只监听 `127.0.0.1` 是安全的；如果改成 `0.0.0.0` 或局域网地址，同一网络内任何人都能用运行 GoPort 的主机发起扫描，请谨慎。

### HTTP API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` | `/` | 内置页面（单文件，无外部依赖） |
| `POST` | `/api/preview` | 只解析目标与端口，返回数量，不扫描 |
| `POST` | `/api/scan` | 创建扫描作业并立即返回作业 id，后台按批执行 |
| `GET` | `/api/status?id=<id>` | 查询进度、统计、模式、批次（`id` 省略时取最近一次作业） |
| `GET` | `/api/results?id=<id>` | 取回已收集的结果（扫描中也会返回部分结果） |
| `POST` | `/api/cancel?id=<id>` | 请求停止作业 |
| `GET` | `/api/export?id=<id>&enc=gbk` | 导出 CSV（`enc=utf8` 为 UTF-8，其他值为 GBK） |

请求体字段（`preview` / `scan`）：

```json
{
  "target": "10.0.0.0/24\n10.0.0.5",
  "ports": "22,80,443\nU:161",
  "mode": "auto",
  "banner": true,
  "all": false
}
```

`preview` 响应：

```json
{"ok":true,"targets":254,"ports":14,"tcp_ports":12,"udp_ports":2,"pairs":3556,"batches":1}
```

`scan` 响应：

```json
{"ok":true,"id":"b3f1c2a9d4e7","targets":254,"ports":14,"pairs":3556,"batches":1}
```

CSV 导出的列：`时间,主机,端口,协议,状态,服务,耗时(ms),信息`，使用 CRLF 换行。

---

## 端口状态判定规则

| 模式 | 应答 | 判定 |
| --- | --- | --- |
| TCP SYN | `SYN+ACK`（且 ack 匹配序列号） | `open` |
| TCP SYN | `RST` | `closed` |
| TCP SYN | ICMP type 3 code 3 / 4 | `closed` |
| TCP SYN | ICMP type 3 code 0 / 1 / 2 / 13 | `filtered` |
| TCP SYN | 重传耗尽仍无应答 | `filtered` |
| TCP connect | 连接成功 | `open` |
| TCP connect | `connection refused` | `closed` |
| TCP connect | 超时 / 取消 / 其他错误 | `filtered` |
| UDP（SYN 引擎） | 收到 UDP 应答 | `open` |
| UDP（SYN 引擎） | 无应答且无 ICMP | `open\|filtered` |
| UDP（connect） | 收到应答 | `open` |
| UDP（connect） | 收到 ICMP 端口不可达 | `closed` |
| UDP（connect） | 无应答 | `open\|filtered` |

说明：

- `filtered` 表示“没有任何应答”，可能是防火墙丢包、主机不在线，或探测报文本身未能送达。
- `open|filtered` 是 UDP 的经典语义：没有应答既可能是服务开着但不回包，也可能是被过滤。
- 默认只输出 `open`；需要看 closed / filtered 时加 `-show-closed` / `-show-filtered`，Web 里对应“结果范围”。

---

## 项目结构

```
goport/
├─ go.mod                        module goport（go 1.25，无第三方依赖）
├─ build.bat                     一键构建 bin\goport.exe
├─ README.md                     项目说明
├─ LICENSE                       MIT 许可证
├─ .gitignore                    构建产物与扫描结果
├─ cmd/goport/
│  ├─ main.go                    入口、扫描编排、参数校验、摘要输出、用法文本
│  ├─ cli.go                     命令行定义、环境自检（-doctor）、-dry-run
│  ├─ web.go                     内嵌 Web 服务、作业管理、CSV 导出、页面 HTML
│  └─ console_windows.go         ANSI 控制台、ShellExecuteW 打开浏览器、错误停窗
└─ internal/
   ├─ scan/
   │  ├─ engine.go               模式选择、配置校验、环境解析、网卡选择、auto 降级
   │  ├─ syn.go                  SYN/UDP 引擎：探针表、生成器、限速、重传、应答分类
   │  ├─ connect.go              connect() 引擎
   │  ├─ discovery.go            ARP 解析下一跳 MAC
   │  ├─ udp.go                  DNS/NTP/SNMP/NBNS/SSDP/mDNS/SIP/IPMI 探测载荷
   │  ├─ banner.go               TLS / HTTP / 明文协议 banner 抓取与描述
   │  ├─ services.go             端口 → 服务名表
   │  ├─ presets.go              Goby 端口预设与别名、读取 Goby 配置
   │  ├─ ports.go                端口表达式解析
   │  ├─ targets.go              目标表达式解析（地址/CIDR/范围/域名/文件）
   │  ├─ output.go               table/JSON/NDJSON/CSV 输出与 GBK 编码
   │  └─ stats.go                Result / State / Stats 与并发计数器
   ├─ npcap/
   │  ├─ pcap.go                 wpcap.dll 绑定：加载、设备枚举、OpenLive
   │  ├─ handle.go               过滤器、注入、抓包、缓冲区、批量发送、提权/错误文本
   │  └─ driver.go               读取 AdminOnly 策略、CanInject 快速判断
   ├─ netinfo/netinfo.go         iphlpapi：网卡、IPv4 表、路由、ARP 缓存、设备名匹配
   ├─ packet/packet.go           以太网/IPv4/TCP/UDP/ARP/ICMP 构造与解析、校验和
   └─ enc/gbk.go                 UTF-8 ↔ GBK（调用 Windows 代码页 936）
```

---

## 内部设计要点

### 探针表与应答匹配

- 键为 `dst<<32 | dport<<16 | sport`，64 个分片各自加锁，降低高 pps 下的锁竞争。
- 抓包线程用 `take()` 原子地“认领”探针，应答与超时只会有一方生效。
- 只接受目的地址等于扫描端源 IP、目的端口落在 20000–65535 的帧，避免把无关流量当结果。
- TCP `SYN+ACK` 校验 `ack == seq+1`；`RST` 校验 ACK 或序列号，降低结果被伪造的概率。

### 顺序与随机化

- 默认按“端口优先”枚举：所有主机先扫 0 号端口，再扫下一个端口，避免对单台主机瞬间打出几万个 SYN。
- 每个主机的端口顺序带一个基于主机地址的旋转量，避免同一时刻所有主机被同一端口命中。
- `-shuffle` 用与总数互质的步长遍历整个组合空间，做到 O(1) 内存的随机顺序。

### 限速与重传

- 令牌桶限速，桶容量为 20 ms 的突发量，避免严格的逐包 sleep。
- 重传间隔按 `base × 2^retry` 指数退避，最长 `4 × base`；`base` 即 `-timeout`。

### 批量注入

`-batch` 使用 WinPcap/Npcap 的 `pcap_sendqueue_*` 扩展：一次驱动调用发送一批帧（队列上限 1 MiB，单次最多 128 帧，`sync=1` 等待真正上线）。若 DLL 不导出这些函数或驱动拒绝，会自动退回逐包 `pcap_sendpacket`。

### 抓包缓冲

接收句柄会把内核缓冲扩到 4 MiB（`pcap_setbuff`），这是高速扫描下不丢 SYN-ACK / RST 的关键；同时设置 BPF `ip`，把非 IP 流量挡在内核里。

### 主机发现

- 同网段目标：逐个 ARP 请求，最多 3 轮，窗口由 `-arp-timeout` 控制；先用系统 ARP 缓存做种子，命中就不再发请求。
- 跨网段目标：解析默认网关 MAC，所有跨网段目标共用该下一跳。
- 回环目标：使用 Npcap Loopback 设备（`\Device\NPF_Loopback`），链路层为 `DLT_NULL`，没有 MAC 层。
- 只接受单播、非零、非广播的 ARP 应答；没有应答的主机计入“无响应”并跳过。
- connect 模式不做 ARP 发现，直接走系统协议栈，因此也能扫描路由可达但不同网段的主机。

### 服务识别

- 只处理 `state=open` 且 `proto=tcp` 的结果；CLI 默认 64 个 worker（Web 32 个），队列 8192。
- 端口分类：TLS 端口先做 TLS 握手；HTTP 端口先发 `GET / HTTP/1.0`；其他端口按“服务器先说话”读取首包，必要时发送协议小探针（如 Redis `PING`、Memcached `version`、SMTP `EHLO`、FTP `SYST` 等）。
- TLS 使用 `InsecureSkipVerify`（扫描器不能因为证书无效而放弃），输出协议版本、CN、签发者、到期日；若对端其实是 HTTP，再补一条 HTTP 摘要。
- 所有 banner 文本会做可打印字符过滤、空白折叠和长度截断，避免把二进制垃圾写进表格或 CSV。

### Web 作业模型

- `POST /api/scan` 只创建作业并立刻返回，实际扫描在 goroutine 中按 512 个地址一批执行。
- 每批新建 `scan.Config` 与 `context.WithTimeout`，批次结束后释放探针表和句柄，因此上万地址也不会一次性压满内存。
- `auto` 模式只在第一批尝试 SYN，之后沿用已经确定的实际模式，避免每批都重复探测权限。
- 页面用 700 ms 轮询 `/api/status`，完成后拉 `/api/results`；网络抖动时 1.5 s 后重试。

### 纯 Go 绑定

`internal/npcap` 通过 `syscall.NewLazyDLL("wpcap.dll")` + `NewProc` 调用 C 函数，结构体布局用 `unsafe` 手工对齐（`pcap_if`、`pcap_pkthdr`、`pcap_send_queue` 等），因此不需要 cgo、不需要 `pcap.h`，也不需要 C 编译器。`internal/netinfo` 用同样方式访问 `iphlpapi.dll`，并且能在非管理员权限下枚举网卡（`pcap_findalldevs` 在 Npcap 默认策略下反而会因权限失败）。

---

## 测试

```bat
go test ./...
go test -v .\internal\scan
go test -run TestParseTargets .\internal\scan
```

测试覆盖（约 100 个用例）：

- `internal/packet`：SYN / UDP / ARP 构造、IPv4 与传输层校验和、TCP/UDP/ICMP/ARP 解析、截断帧与过小缓冲区。
- `internal/scan`：目标与端口解析、预设与 Goby 配置、SYN 应答分类（SYN-ACK / RST / UDP / ICMP）、探针表并发安全、生成器覆盖性、限速器、重传退避、banner 描述、connect 扫描、输出格式与 GBK CSV。
- `internal/netinfo`：掩码转换、地址转换、网卡匹配、回环适配器、主机网卡/路由/ARP 表读取。
- `internal/enc`：GBK 已知字节、往返转换、CSV 表头编码。

说明：测试面向 Windows；其中涉及网卡、路由和 ARP 的用例会读取运行主机的真实系统信息。`internal/npcap` 需要真实驱动与权限，因此没有单元测试，改用它上层的 `-dry-run` / `-doctor` 做集成验证。

---

## 故障排查

| 现象 | 原因与处理 |
| --- | --- |
| `无法加载 wpcap.dll` | 未安装 Npcap，或安装时未启用 WinPcap API 兼容模式。重装 Npcap 并勾选该选项 |
| `无法打开 Npcap 驱动：当前进程不是管理员权限` | 右键“以管理员身份运行”终端后重试；或改用 `-m connect` |
| `Npcap 服务未运行` | 执行 `sc start npcap`（管理员） |
| `找不到可用的网卡` / 网卡选错 | 先 `-list-if`，再用 `-i <编号或名称子串>` 指定 |
| `没有默认路由` | 跨网段扫描需要 `-i` 指定网卡，并用 `-gw-mac` 指定网关 MAC |
| `跨网段扫描需要网关 MAC，但解析失败` | ARP 被防火墙 / VLAN 隔离拦截；手动传 `-gw-mac aa:bb:cc:dd:ee:ff` |
| `N 个目标都没有响应 ARP` | 目标不在同一广播域、已下线，或被防火墙拦截。确认网段 / 网卡；对路由可达但 ARP 不通的目标改用 `-m connect`；也可调大 `-arp-timeout` |
| 明明开放却显示 `filtered` | 速率过高导致驱动丢应答：降低 `-rate`、关掉 `-batch`、调大 `-timeout`，或确认没有被扫描端防火墙拦截 |
| 扫描很慢 | 提高 `-rate`（SYN）、增大 `-c`（connect）、加 `-no-banner`、避免对超大网段使用 `general` / `all` |
| 结果顺序看起来是“按端口”的 | 默认按端口优先枚举；需要随机顺序加 `-shuffle` |
| CSV 在 Excel 里中文乱码 | 加 `-csv-enc gbk`；Web 导出选 GBK 版本 |
| `未知预设 "xxx"` | 预设名或别名拼写错误；`-h` 会列出全部内置预设 |
| 双击 exe 窗口一闪而过 | 从终端运行以查看错误；程序在桌面模式启动失败时会停住等待回车 |
| Web 打不开 | 看终端打印的实际端口（被占用会自动 +1）；确认没有代理拦截 `127.0.0.1` |

---

## 已知限制

- **仅 Windows**：依赖 `wpcap.dll`、`iphlpapi.dll`、`kernel32.dll` 等，跨平台无法编译。
- **仅 IPv4**：IPv6 目标会明确报错，没有 IPv6 探测实现。
- **SYN 需要管理员**：除非 Npcap 的 `AdminOnly` 被关闭；否则请用 `connect` 模式。
- **SYN 模式依赖 ARP 发现**：同网段目标必须能回应 ARP，否则不会被扫描；跨网段目标依赖网关 MAC。
- **UDP 判定天然模糊**：无应答只能给 `open|filtered`，且只有内置载荷覆盖的端口才会主动“问话”，其余端口发送空数据报。
- **服务识别是尽力而为**：只对 open 的 TCP 端口做，非标准端口可能识别不出；TLS 证书不做信任校验。
- **Web 结果在内存中**：最多保留 20 万条、8 个历史作业，进程退出即丢失；同时只允许一个扫描。
- **Web 无认证**：不要绑定到公网或不可信网络。
- **没有配置文件**：所有参数通过命令行 / Web 表单传入。
- **不做 OS 识别、漏洞检测、口令爆破**：只做端口状态与服务 banner 探测。

---

## 合规声明

GoPort 会主动向目标发送网络探测报文，仅适用于**你拥有或已获得明确书面授权**的系统与网络。未经授权的端口扫描可能违反法律、云服务商条款或组织安全策略。使用者应自行承担全部责任。

---

## 许可证

本项目采用 [MIT License](LICENSE) 发布。

Copyright (c) 2026 kingjin
