# fucloudflare

自托管的 Cloudflare 式边缘平台，单一二进制 `fucf`（Rust）。

| 模块 | 功能 |
|------|------|
| DNS | 权威 DNS（UDP/TCP），代理记录解析到边缘 IP；按访客国家 / 大洲 / 运营商（ECS 感知）调度到节点，带健康检查与故障切换，可按地区屏蔽解析 |
| 面板 | 内嵌的网页控制面板：DNS 记录、机群与节点（含分档限流）、调度规则、区域设置、规则、电子邮件路由、Workers；完全托管与 CNAME 接入两种模式 |
| 多节点 | 主节点保存配置，其余节点作为只读副本数秒内自动同步（含缓存清除、证书、邮件规则）；副本把流量统计和安全事件上报给主节点 |
| CDN | HTTP/1.1、HTTP/2、HTTP/3 (QUIC) 反向代理，WebSocket，gRPC，SNI 证书，边缘缓存与清除（Range、源站故障时回退到过期副本），brotli/gzip 压缩，源站故障转移 |
| 节点限流 | 每个节点可设周期流量配额（摘除 DNS / 开始限速 / 硬限流三档）和限速；超限节点自动退出 DNS 应答，硬限流后只返回提示页 |
| 证书 | 内置 ACME 客户端：向 Let's Encrypt 等 CA 自动签发并续期证书（DNS-01 / TLS-ALPN-01 / HTTP-01），也可上传自有证书 |
| 规则 | 重定向规则、请求/响应改写规则、缓存规则 |
| 电子邮件 | SMTP 收信与转发路由（不落盘）：按地址 / `+tag` / `*` 兜底转发或丢弃，SRS 发件人改写与退信回溯，支持外发中继（submission 587/465） |
| 分析 | 全机群的时间序列（分钟级 1 天、小时级 30 天）：请求数、流量、状态码、缓存命中、拦截数、协议版本，按节点、国家、主机名、路径拆分；重启不丢 |
| WAF | 自定义规则、限速、托管规则集、JS 质询、Under Attack 模式、安全事件日志（全机群汇总） |
| 回源规则 | 按表达式改写回源地址 / 端口 / 协议 / Host 头 / SNI |
| Spectrum | 任意 TCP / UDP 端口转发，可选 PROXY protocol v1 |
| Workers | 在边缘节点运行 JavaScript（Fetch API 子集） |

## 运行

```powershell
cargo run --release -- --ns ns1.yourdomain.com,ns2.yourdomain.com --edge-ip 203.0.113.10
```

| 参数 | 默认 | 说明 |
|------|------|------|
| `--dns-listen` | `0.0.0.0:53` | 权威 DNS |
| `--http-listen` / `--https-listen` | `0.0.0.0:80` / `0.0.0.0:443` | 边缘监听，`off` 关闭 |
| `--http3-listen` | 同 HTTPS 地址 | HTTP/3 的 UDP 监听地址，可与 HTTPS 不同端口（`Alt-Svc` 会通告它）；`off` 关闭 |
| `--h3-front-listen` | 无 | HTTP/3 前置入口：本机另一个占着 UDP 443 的 QUIC 服务（如带 `proxy` 伪装的 Hysteria 2）把普通 HTTP/3 访客用明文 HTTP 转到这个地址，见"HTTP/3 前置"。只应监听回环地址 |
| `--h3-front-cert` / `--h3-front-port` | 无 / `443` | 前置服务向访客出示的证书（PEM）和它的 UDP 端口；只对该证书覆盖的主机名通告 HTTP/3 |
| `--edge-ttl` | `300` | `--cname-base` 下各名字的应答 TTL（秒）。节点故障或流量超限后，最长这么久之后访客才被调度走 |
| `--release-key` | 无 | 发布公钥（见"滚动更新与自动回滚"）。配置后本节点接受机群滚动发布的新版本，新版本不能用时自动退回；不配置则只能手动替换二进制 |
| `--proxy-protocol` | 关 | 边缘 TCP 连接必须以 PROXY protocol v1 头开始（仅用于只经可信四层代理可达的监听） |
| `--api-listen` | `127.0.0.1:8787` | 管理 API 与面板 |
| `--geoip-db` / `--geoip-asn-db` | 无 | MaxMind GeoLite2 Country / ASN 库；启用按大洲、国家、运营商调度和 `ip.geoip.*` 规则字段 |
| `--geoip-cn-db` | `--geoip-db` 同目录下的 `ip2region_v4.xdb`、`ip2region_v6.xdb`（如果有） | [ip2region](https://github.com/lionsoul2014/ip2region) 库（Apache-2.0 / MIT）：中国大陆地址的省份。GeoLite2 只知道约六分之一大陆地址的省份，按省份调度要靠它 |
| `--cname-base` | 无 | 该域名下的所有子名都解析到边缘（如 `cdn.example.com`，需委托给本服务）；CNAME 接入模式的区域把主机名 CNAME 到它 |
| `--panel-host` | 无 | 在边缘上以该主机名对外发布面板和管理 API（HTTPS，仍需令牌） |
| `--panel-origin` | 无 | 多节点承载面板：本节点把面板主机名的请求转给运行面板的节点（`ip[:port]`，HTTPS，按面板主机名校验证书），访客地址随 `X-Forwarded-For` 带过去；以面板主机名配置的同步对端也直连这里。这样面板的 DNS 记录可以开代理、解析到任意节点 |
| `--primary` | 无 | 作为只读副本运行：主节点的面板主机名（走 HTTPS），或它的管理 API 地址 `http://host:port` |
| `--node-name` | 自动 | 本节点在机群里的名字；默认取 `--edge-ip` 所属的已登记节点 |
| `--acme-directory` | Let's Encrypt | 签发托管证书的 CA 的 ACME 目录地址；`off` 关闭。使用即表示同意该 CA 的服务条款 |
| `--acme-email` | 无 | 留给 CA 的联系邮箱（到期提醒） |
| `--edge-ip` | 无 | 边缘节点公网 IP；代理记录和 Spectrum 域名解析到它 |
| `--spectrum-bind` | `0.0.0.0` | Spectrum 监听绑定的本机 IP |
| `--smtp-listen` | 无（关闭） | SMTP 收信监听地址（如 `0.0.0.0:25`）；配置后本节点启用电子邮件路由 |
| `--mail-host` | 无 | 本节点在 SMTP 问候语与 MX 建议里使用的主机名（可逗号分隔多个，第一个用于 banner） |
| `--mail-relay` | 无 | 外发邮件中继（`smtp://[user:pass@]host[:587]` 强制 STARTTLS，或 `smtps://[user:pass@]host[:465]` 隐式 TLS）；出方向 25 端口受限的云主机必须配置 |
| `--cache-mb` | `512` | 边缘缓存上限 |
| `--data-dir` | `data` | 配置 `state.json`、`api_token`、分析数据 `analytics.json`、安全事件 `events.json`、ACME 账户 `acme_account.json`、本节点流量计数 `usage.json` |

所有参数都有 `FUCF_*` 环境变量，见 `fucf --help`。

## 管理 API

基址 `http://127.0.0.1:8787/client/v4`，认证头 `Authorization: Bearer <token>`，响应信封与 Cloudflare v4 一致。
用户自己的 API 令牌和 Global API Key 见下面的“开放 API”。完整的接口文档：[docs/api.md](docs/api.md)。
zones 与 dns_records 的路径和字段与 Cloudflare 兼容；其余资源是简化的自有结构。

```
/system                                  GET              角色（primary / replica）、节点名、配置版本、NS、CNAME 基础域名；主节点上还有各副本的同步状态
/analytics                               GET              所有区域的流量合计，?since= 同下
/warp/purge_cache                        POST             清除预留端点 /cdn-cgi/fucf-warp 的缓存：{"purge_everything":true} | {"files":[键...]} | {"prefixes":[键前缀...]}
/nodes[/{id}]                            CRUD             {"name", "ipv4", "ipv6", "continents": ["AS","OC"], "enabled", "traffic_dns_gb", "traffic_throttle_gb", "traffic_limit_gb", "traffic_period", "traffic_reset_day", "rate_limit_mbps"}；
                                                          返回值带 healthy、副本状态（配置版本、是否同步、最后上报时间）和 traffic（本周期已用字节数、状态）
/steering[/{id}]                         CRUD             {"name", "priority", "countries", "regions", "continents", "asns", "as_orgs", "action": "route|block", "nodes": [...]}
/steering/test?ip=                       GET              这个地址被定位到哪里（国家、省份、大洲、ASN）、命中哪条规则
/email/status                            GET              本节点 SMTP 监听地址、主机名、中继配置与最近转发活动
/zones                                   GET POST         {"name", "type": "full|partial"}
/zones/{id}                              GET PATCH DELETE
/zones/{id}/dns_records[/{id}]           GET POST PUT PATCH DELETE   与 Cloudflare 相同的字段，另有 "origin"：已代理记录的高级回源选项（见下）
/releases[/{sha256}]                     GET PUT DELETE   滚动发布，见"滚动更新与自动回滚"
/zones/{id}/settings[/{name}]            GET PATCH        {"value": ...}
/zones/{id}/purge_cache                  POST             {"purge_everything":true} | {"files":[...]} | {"prefixes":[...]}
/zones/{id}/custom_certificates[/{id}]   CRUD             {"certificate": PEM, "private_key": PEM, "hosts": [...]}；返回值带 expires_on
/zones/{id}/ssl/certificate_packs[/{id}] GET POST PATCH DELETE   {"hosts": [...], "validation_method": "auto|dns|tls-alpn|http"}；PATCH 立即重试
/zones/{id}/firewall/rules[/{id}]        CRUD             {"expression", "action", "priority", "enabled", "description"}
/zones/{id}/rate_limits[/{id}]           CRUD             {"expression", "threshold", "period", "mitigation_timeout", "action"}
/zones/{id}/security/events              GET
/zones/{id}/origin_rules[/{id}]          CRUD             {"expression", "origin_host", "origin_port", "origin_scheme", "host_header", "sni", "priority"}
/zones/{id}/redirect_rules[/{id}]        CRUD             {"expression", "target_url", "status_code", "preserve_query_string", "priority"}
/zones/{id}/transform_rules[/{id}]       CRUD             {"expression", "rewrite_path", "set_request_headers", "remove_request_headers", "set_response_headers", "remove_response_headers"}
/zones/{id}/cache_rules[/{id}]           CRUD             {"expression", "cache": true|false, "edge_ttl", "priority"}
/zones/{id}/email                        GET              区域邮件路由开关、规则、当前 MX/SPF 及缺失的建议 DNS 记录
/zones/{id}/email/rules[/{id}]           CRUD             {"address", "action": "forward|drop", "destinations": [...], "enabled", "description"}
/zones/{id}/analytics                    GET              ?since=-1440（分钟）| 90m | 24h | 7d（默认 24h，最长 30d），?step= 分钟
/zones/{id}/spectrum/apps[/{id}]         CRUD             {"protocol":"tcp/2222", "dns":{"name":"ssh"}, "origin_direct":["tcp://192.0.2.1:22"], "proxy_protocol":"off|v1"}
/zones/{id}/workers/routes[/{id}]        CRUD             {"pattern":"example.com/api/*", "script":"name"}
/workers/scripts[/{name}]                GET PUT DELETE   PUT 的请求体即 JS 源码
/workers/scripts/{name}/settings         GET PATCH        {"vars": {"KEY":"value"}}
```

### 高级回源（记录上的 `origin`）

已代理的 A / AAAA / CNAME 记录可以带一组回源选项，说明"连到这条记录的内容之后，怎么跟它说话"：

```json
{ "type": "A", "name": "app", "content": "203.0.113.5", "proxied": true,
  "origin": { "sni": "edge.cdn.example", "host_header": "app.origin.example", "port": 443, "scheme": "https" } }
```

| 字段 | 默认 | 说明 |
|------|------|------|
| `sni` | 同回源 Host | TLS 握手时报给源站的域名。填了就用 HTTPS 回源（除非 `scheme` 另有指定；与 `scheme: "http"` 同时出现会被拒绝） |
| `host_header` | 访客访问的域名 | 发给源站的 `Host` 请求头 |
| `port` | HTTPS 443 / HTTP 80 | 源站端口 |
| `scheme` | 跟随区域的 `ssl` 模式 | `http` 或 `https` |

典型用途：源站自己也在别的 CDN 后面（例如用了 Cloudflare 自定义主机名，再配一个优选地址）——记录内容填要连的地址，
`sni` 填握手用的域名，`host_header` 填真正要访问的域名，两者可以不同。证书是否校验仍由区域的 `ssl` 模式决定
（`strict` 时按 `sni` 校验）。

- 四项都可省略；全部留空等于没有选项。`PATCH` 时不带 `origin` 表示不动，带空对象 `{}` 表示清除。
- 匹配到的回源规则（`origin_rules`）逐字段优先于记录上的选项；回源规则用 `origin_host` 把请求改送别处时，
  记录上的选项不再适用（它们描述的是记录内容那个源站）。
- 同名的多条地址记录各带各的选项；故障转移只在选项相同的地址之间进行。CNAME 记录的选项对它最终解析到的地址生效。
- 不影响 DNS 应答，也不影响缓存键（仍按访客访问的域名）。

### 区域设置

| 名称 | 取值 | 说明 |
|------|------|------|
| `ssl` | `flexible`(默认) / `full` / `strict` | 回源用 HTTP / HTTPS 不验证书 / HTTPS 验证书 |
| `always_use_https` | bool | HTTP 301 到 HTTPS |
| `waf` | `block`(默认) / `log` / `off` | 托管规则集模式 |
| `development_mode` | bool | 绕过缓存 |
| `http2` | bool（默认开） | 向访客提供 HTTP/2；关闭后 TCP 上只有 HTTP/1.1 |
| `http3` | bool（默认开） | 提供 HTTP/3 (QUIC)，通过 `Alt-Svc` 头和 HTTPS DNS 记录通告；关闭后两者都不再通告 |
| `edge_nodes` | 节点名数组（默认空） | 只由这些节点服务该区域；空表示所有节点，按访客位置调度 |
| `security_level` | `medium`(默认) / `under_attack` | Under Attack 模式：所有访客先过 JS 质询（防火墙的 `skip` 规则可豁免，如回调接口） |
| `browser_cache_ttl` | 秒（默认 0） | 边缘会缓存的内容，浏览器缓存时间不足该值时提到该值；0 表示不改源站的 `Cache-Control` |
| `hsts_max_age` / `hsts_include_subdomains` | 秒（默认 0）/ bool | HTTPS 响应带 `Strict-Transport-Security`；0 表示不发 |
| `grpc` | bool（默认开） | 代理 gRPC：经 HTTP/2 或 HTTP/3 到达、`Content-Type` 为 `application/grpc` 的请求以 HTTP/2 回源 |
| `origin_check_path` / `origin_check_interval` | 路径（默认空）/ 秒（默认 30） | 源站主动健康检查：每个节点定期请求每个源站地址的这个路径，连续两次失败（无应答或状态码不是 2xx/3xx）的地址排到最后；`GET /zones/{id}/origins/health` 查看本节点的检查结果 |
| `session_affinity` | bool（默认关） | 会话保持：同一访客 IP 始终回到同一个源站地址（记录的 `origin.weight`，1–100，决定各地址分到的请求比例） |
| `email_routing` | bool（默认关） | 启用该区域的电子邮件路由（需配合开启 `--smtp-listen` 的节点与 MX 记录） |

### 规则表达式

防火墙规则、限速、回源规则共用，语法是 Cloudflare 表达式的子集：

```
(http.request.uri.path contains "/admin" and not ip.src in {10.0.0.0/8 192.0.2.1})
  or lower(http.user_agent) matches "curl|wget"
```

- 字段：`http.host` `http.request.uri` `http.request.uri.path` `http.request.uri.query` `http.request.full_uri`
  `http.request.method` `http.user_agent` `http.referer` `http.cookie` `http.x_forwarded_for`
  `http.request.headers["name"]` `ip.src` `ssl`
  `ip.geoip.country` `ip.geoip.continent` `ip.geoip.asnum` `ip.geoip.as_org`（需要 GeoIP 库）
- 运算符：`eq ne contains matches in lt le gt ge`（及 `== != ~ < <= > >=`），`and or not`（及 `&& || !`）
- 函数：`lower() upper() url_decode() len() starts_with(x,"p") ends_with(x,"s")`
- 空表达式匹配所有请求。

防火墙动作：`block`、`js_challenge`、`log`、`skip`（放行并跳过限速与托管规则）。按 `priority` 升序执行。

## 面板、节点与调度

面板在管理 API 的根路径（`http://127.0.0.1:8787/`），设置了 `--panel-host` 时也可经边缘的 HTTPS 访问；用 API 令牌登录。

**接入模式**（区域的 `type`，可在面板里切换）

- `full` 完全托管：把域名的 NS 指向本服务，所有记录在这里管理，代理记录直接解析到边缘节点。
- `partial` CNAME 接入：域名留在原 DNS 服务商，把主机名 CNAME 到 `<名字>.<cname-base>`，由本服务解析到边缘节点。

**节点分配**：每个节点登记 IPv4/IPv6 和它负责的大洲。解析代理记录时按访客位置（优先用 EDNS Client Subnet）选节点：

1. 调度规则按 `priority` 升序匹配访客的国家、大洲、ASN 或运营商名；`route` 规则回答 `nodes` 列表里第一个健康的节点（列表顺序即故障切换顺序）。
2. 没有规则命中时，回答负责访客所在大洲的节点。
3. 位置未知或对应节点都不可用时，回答所有健康节点。

各节点每 10 秒探测一次所有节点的 443 端口：设置了 `--cname-base` 时以它为 SNI 完成一次 TLS 握手（能穿过按 SNI 分流的四层代理，
确认到达的是 fucf 本身），否则只做 TCP 连接。连续 3 次失败的节点不会出现在应答里，连续 2 次成功后恢复；`enabled: false` 的节点同样被排除。

**屏蔽**

- DNS 屏蔽：调度规则的 `action` 设为 `block`，命中的访客查询返回 `REFUSED`（对整个边缘生效）。
- CDN 屏蔽：区域的防火墙规则使用 `ip.geoip.*` 字段，例如
  `ip.geoip.country eq "CN" and ip.geoip.asnum in {4134 4809}`，动作 `block` 返回 403。

**协议选择**：区域设置 `http2` / `http3` 控制向访客提供哪些协议。HTTP/3 开启时，代理主机名的 HTTPS 记录（type 65）
先通告 `h3`（及其端口），再通告 `h2`，支持的客户端首次连接就能直接走 QUIC。

### DNS：更多记录类型、辅助名称服务器、查询统计

- 记录类型增加 `HTTPS`、`SVCB`（内容如 `1 . alpn=h2,h3 port=443 ipv4hint=192.0.2.1`）、`TLSA`、`SSHFP`、`DS`（委派出去的子域的 DS）、`NAPTR`、`URI`。
- 区域设置 `dns_transfer_to`：允许做区域传送（AXFR，仅 TCP）的辅助名称服务器地址或网段；区域变更时向其中的单个地址发 NOTIFY。
  传给辅助服务器的内容同样隐藏源站：代理的名字给出全部边缘节点的地址（辅助服务器上没有按访客调度）。开启了 DNSSEC 的区域不传送（签名是按查询在线做的）。
  把辅助服务器放在别的服务商，整个机群不在时域名仍可解析。
- `GET /zones/{id}/dns_analytics`：本节点自启动以来为该区域应答的查询数，按类型和应答码拆分。

### DNS 响应限速与内核层封禁

- `--dns-rrl`（`FUCF_DNS_RRL`，默认 100，0 为关闭）：UDP 上对同一网络（/24、/56）同一名字每秒最多应答这么多次；超出的部分一半以截断（TC）应答，
  真正的解析器会改用 TCP 重试，其余丢弃。UDP 的来源地址可以伪造，不限速的权威服务器会被用来放大攻击别人。本机回环不限。
- `--ban-export 文件`（`FUCF_BAN_EXPORT`）：把自动防火墙当前封禁的地址（只含动作为拦截的规则）写成 nftables 脚本，每 30 秒检查、有变化才重写。
  fucf 自己没有改内核表的权限，也不替你决定封禁覆盖哪些端口：由宿主机用 `nft -f 文件` 加载（例如配一个 systemd path 单元），并自己加丢弃规则，如
  `nft add chain inet fucf input '{ type filter hook input priority -10; }'` 和 `nft add rule inet fucf input tcp dport { 80, 443 } ip saddr @banned4 drop`。
  注意同一台机器上的其他服务是否也该被这条规则覆盖。

### 限速的计数方式

- `characteristics`：区分客户端的依据，默认只按 `ip`；可选 `asn`、`country`、`host`、`path`、`header:名称`、`cookie:名称`，最多 4 个，组合成一个计数键（例如 `["header:x-api-key"]` 按 API 密钥限速）。
- `status_codes`：只统计以这些状态码应答的请求（如 `[401, 403]` 用来挡撞库）。这类规则在应答之后计数，超限的客户端从下一个请求起被拦。
- 一个客户端在某个节点上被限速（封禁 10 秒以上）后，其他节点随上报得知，也照样拦它；计数本身仍是各节点各算各的。

### 实测调度与故障切换

- 调度规则的动作除了 `route`（按顺序取第一个可用节点）和 `block`，还有 `fastest`：解析到访客所在网络**实测最快**的节点。
  每个节点记录访客 TLS 1.3 / QUIC 握手的一次往返时间，按网络（国家、省或州、运营商 AS 号，如 `CN-JS/4134`、`CN/4134`、`CN-JS`、`CN`）
  取滑动平均，随上报传给其他节点；DNS 用最精确且至少两个候选节点都有足够样本（5 次握手、一天以内）的那一级来比较。
  `nodes` 是候选节点，留空为全部。数据不足时在候选里轮流分配，另有 5% 的应答随机分给其他候选，以便持续测量。
  `GET /steering/measured` 返回全部实测数据；面板的"定位"会显示某个地址所在网络的实测排名。
  （TLS 1.2 的握手是两次往返，不计入；经 HTTP/3 前置进来的连接量不到访客的往返时间。）
- 指向边缘的应答的 TTL 由 `--edge-ttl`（`FUCF_EDGE_TTL`，默认 300 秒）决定，代理记录最多 300 秒：调小后节点故障或超量时访客更快换走，代价是解析次数更多。
- TLS 会话票据的密钥由机群令牌和时间（每 12 小时一换）导出，所有节点相同：访客被 DNS 换到另一个节点、或节点重启后，
  仍可恢复会话而不必完整握手。

## 边缘自身的端点 `/cdn-cgi/`

`/cdn-cgi/` 下的路径由请求到达的那台节点自己应答，对任何主机名都一样：不回源，不经过区域的 WAF、规则和缓存，也不计入区域的分析数据
（但计入节点流量）。没有定义的路径一律 404。

| 路径 | 作用 |
|------|------|
| `/cdn-cgi/fucf-trace` | 调试信息，格式同 Cloudflare 的 `/cdn-cgi/trace`（每行 `key=value`） |
| `/cdn-cgi/fucf-warp`（及其下所有路径） | **预留**：由节点接管，目前一律返回 501。实现位置在 `src/edge/warp.rs`，处理函数拿到完整的请求（方法、子路径、头、流式请求体，HTTP/1.1 下可升级连接）和访客信息。它在边缘缓存里有自己的一块（`warp::cached` / `warp::store`，与各区域的缓存互不影响，共用节点的缓存上限），用 `POST /warp/purge_cache` 在所有节点上清除 |
| `/cdn-cgi/limit/page.css`、`mark.svg` | 节点限流提示页的资源（见下一节） |

`fucf-trace` 的字段：前面是 Cloudflare 的键，含义相同——`fl`（`fucf-<节点名>`）、`h`（主机名）、`ip`、`ts`、`visit_scheme`、`uag`、
`colo`（节点名大写）、`http`（`http/1.1` / `http/2` / `http/3`）、`loc`（国家，未知为 `XX`）、`tls`（`TLSv1.3` / `TLSv1.2` / `off`）、
`sni`（`plaintext` / `off`）、`warp`（恒为 `off`）、`kex`；后面是自有的——`ray`、`asn`、`zone`（该主机名所属且已代理的区域，否则 `-`）、
`limit`（本节点的限流状态）。

```bash
curl https://<任意接入的主机名>/cdn-cgi/fucf-trace      # 看请求落在哪个节点、节点看到的 IP / 协议 / 地区
```

注意：源站自己如果也用到 `/cdn-cgi/` 路径（例如源站在 Cloudflare 后面时的邮箱保护、质询脚本、RUM 上报），经本边缘访问时这些路径是 404。

## 节点限流与限速

给某个节点的 CDN 流量设上限（例如这台机器的流量还要留给别的服务）。配置写在节点上（`/nodes/{id}`，`null` 表示不限）：

| 字段 | 说明 |
|------|------|
| `traffic_dns_gb` | **DNS 限流**：本周期用量超过它之后，该节点不再出现在 DNS 应答里（调度规则顺延到下一个节点），但仍然正常服务还连着它的访客 |
| `traffic_throttle_gb` | **限速起点**：超过它之后 `rate_limit_mbps` 才开始生效（必须同时设置 `rate_limit_mbps`） |
| `traffic_limit_gb` | **硬限流**：超过它之后，该节点对所有请求只返回 509 提示页，不再回源、不再读缓存 |
| `traffic_period` / `traffic_reset_day` | 周期：`month`（默认，每月 `traffic_reset_day` 日清零，1–28）或 `day`；按 UTC 计 |
| `rate_limit_mbps` | **限速**：该节点发送响应的总速率上限（Mbit/s），平滑整形，不报错。没设 `traffic_throttle_gb` 时始终生效 |

三个阈值必须递增（`dns` ≤ `throttle` ≤ `limit`），可以只设其中几个。例：1 TB 退出 DNS、1.25 TB 起限速到 10 Mbit/s、1.4 TB 停止服务、每月 1 日清零：

```json
{"traffic_dns_gb": 1000, "traffic_throttle_gb": 1250, "traffic_limit_gb": 1400, "rate_limit_mbps": 10, "traffic_period": "month", "traffic_reset_day": 1}
```

- 计量的是本节点发给访客的响应体字节数（1 GB = 10^9 字节），计数每 30 秒落盘一次，重启不丢。
- 每个节点自己计数、自己执行硬限流和限速，不依赖主节点。DNS 避让需要节点互相知道状态：副本把用量上报主节点，
  主节点把"哪些节点已超限"写进配置同步给所有节点（十几秒内生效）；节点对自己的状态立即生效。
  所有节点都超限时仍然要有人应答：优先回答只是 DNS 限流的节点，其次是已限速的，全部硬限流时回答全部。
- **提示页的资源来自别的节点**：页面本身只有几百字节，样式和图片从 `limit.<cname-base>` 加载，这个名字只会解析到还有额度的节点
  （需要给它配一张证书，例如用 `tls-alpn` 方式签一张托管证书；没配 `--cname-base` 时提示页是纯文字版）。
- **防止拿提示页刷流量**：在已硬限流的节点上请求这些资源（`/cdn-cgi/limit/*`），只返回一行纯文本，提示检查 DNS。
- gRPC 客户端收到的是 `RESOURCE_EXHAUSTED`；面板 / 管理 API 所在的主机名和 ACME 验证不受限流影响。
- `GET /nodes` 的 `traffic` 字段显示各节点本周期的用量和状态（`ok` / `dns_limited` / `throttled` / `limited`）。调高或去掉上限立即解除限制。

## 证书

- **上传**：`custom_certificates`，优先级最高。
- **托管（自动签发）**：`POST /zones/{id}/ssl/certificate_packs`，不带参数即为区域的根域名加通配符。主节点向 CA 下单、完成验证、
  把证书写进配置（随配置同步到所有节点），剩余有效期不足三分之一时自动续期；失败按 10 分钟起、逐次翻倍（最长一天）重试，
  原因写在 `error` 里，`PATCH` 可立即重试。续期失败期间继续使用原证书。
- 两者都没有时，为托管域名即时生成自签名证书。

验证方式（`validation_method`，默认 `auto`）：

| 方式 | 何时使用 | 前提 |
|------|----------|------|
| `dns`（DNS-01） | 通配符必须用它；`auto` 对完全托管（full）的区域也用它 | 域名的 NS 指向本服务。域名在别处托管时，在原 DNS 加一条 `_acme-challenge.<名字>` CNAME 到 `_acme-challenge.<名字>.<cname-base>`（接口返回值的 `dns_delegation` 列出了要加的记录），之后签发和续期都不用再动它 |
| `tls-alpn`（TLS-ALPN-01） | `auto` 对 CNAME 接入（partial）区域的普通主机名用它 | 该主机名的 443 最终到达本服务的 HTTPS 监听（按 SNI 透传的四层代理不影响） |
| `http`（HTTP-01） | 手动指定 | 该主机名的 80 到达本服务的 HTTP 监听 |

质询应答随配置同步到所有节点（CA 的多个验证点可能落在任何一个节点上），主节点等在线的副本都确认拿到之后才通知 CA 验证。
ACME 账户密钥只保存在主节点的数据目录里。测试时可把 `--acme-directory` 指向 Let's Encrypt 的 staging 目录
`https://acme-staging-v02.api.letsencrypt.org/directory`，避免触发正式环境的频率限制。

## 请求处理顺序

`/cdn-cgi/`（节点自己应答，到此为止）→ 节点硬限流（超限则到此为止）→ Host 匹配代理记录 → `always_use_https` → 防火墙规则 → Under Attack 质询 → 限速 → 托管规则 → 重定向规则 → 改写规则（请求侧）→ Worker 路由 → 缓存（缓存规则）→ 回源规则 → 源站 → 区域设置的响应头（HSTS、浏览器缓存时间）→ 改写规则（响应侧）→ 压缩。

- HTTP/3：与 HTTPS 同端口号的 UDP 上提供，HTTPS 响应带 `Alt-Svc` 头引导客户端升级；三种协议共用同一条处理链路。
- 压缩：客户端支持时对 1 KiB–8 MiB 的文本类响应做 brotli 或 gzip（源站已压缩的不动）。
- 重验证：缓存过期且带 `ETag`/`Last-Modified` 时向源站发条件请求，304 则续期（`REVALIDATED`）；客户端的 `If-None-Match`/`If-Modified-Since` 可直接由缓存回 304。
- Range：缓存里有完整对象时，单段 Range 请求直接切片返回 206（`If-Range` 不匹配或多段时返回整个对象）；缓存里没有时原样转给源站，其应答不入缓存。
- 源站故障：源站连不上、超时或返回 500/502/503/504 时，过期不超过 24 小时的缓存副本照常返回（`STALE`）。
- 没有 `Content-Length` 的响应（如源站边压缩边发送）在 8 MiB 以内时读完后入缓存，更大的照常流式透传。
- 回源请求带 `CF-IPCountry`（访客国家，需要 GeoIP 库；客户端自带的同名头会被去掉）。
- gRPC：区域设置 `grpc` 开启时（默认），gRPC 请求以 HTTP/2 回源（源站用 TLS 时须支持 ALPN `h2`，明文时须支持 h2c），
  请求和响应都按消息流式透传（含双向流），响应 trailers（`grpc-status`）原样送达；一次调用没有时长上限，连接靠 HTTP/2 ping 保活。
  边缘自己拒绝或失败的请求（WAF、限流、源站不可达）以 gRPC 状态码返回而不是错误页。gRPC-Web 是普通 HTTP，不走这条路径。
- 故障转移：一个主机名有多条代理 A/AAAA 记录时轮询；连接被拒的地址 10 秒内排到最后，请求体已缓冲（≤1 MiB）时自动换下一个地址重发。
- 缓存规则：`cache: true` 让任意内容类型可缓存，`edge_ttl` 覆盖源站的 `Cache-Control`；`cache: false` 强制不缓存；`ignore_query: true` 让缓存键只含路径（不同查询串共用一份）。首条匹配生效。
- 清除缓存除 `purge_everything`、`files`、`prefixes` 外还可以给 `hosts`：清掉这些主机名下的全部对象。

- 缓存：默认只缓存静态扩展名（js/css/图片/字体等），或源站显式返回 `Cache-Control: public` / `s-maxage`；
  遵守 `no-store/private/no-cache`、`Set-Cookie`、`Vary`。响应头 `CF-Cache-Status`: `HIT / MISS / EXPIRED / REVALIDATED / STALE / BYPASS / DYNAMIC`。
- HTTPS：优先使用上传的证书，其次是自动签发的托管证书，都没有则为托管域名即时生成自签名证书（见"证书"一节）。
- DNS：根域名可以建 CNAME（CNAME 拉平）：应答时不返回 CNAME，而是目标的 A/AAAA；目标在本服务托管的区域内时直接查，
  否则由后台每分钟用系统解析器解析一次。根域名的 CNAME 可以和 MX/TXT 等记录并存，但不能和 A/AAAA 并存。
- 回源失败返回 Cloudflare 风格状态码：521（连接被拒）、522（超时）、525（TLS 失败）、530（无可用源站）。

## Workers

```js
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname === "/hello") return Response.json({ hello: env.NAME });
    const res = await fetch(request);            // 走缓存 + 回源
    const out = new Response(res.body, res);
    out.headers.set("x-edge", "fucf");
    return out;
  }
}
```

支持 `export default { fetch }` 和 `addEventListener("fetch", ...)` 两种写法；提供 `Request` `Response` `Headers`
`URL` `URLSearchParams` `fetch` `console`。`fetch` 访问本边缘托管的域名时走缓存和回源规则，其余地址直接外连。

## 电子邮件路由

为托管域名提供类似 Cloudflare Email Routing 的收信转发功能：节点通过 SMTP 接收发往域名的邮件，**不落盘、不存信**，在发件服务器等待 `DATA` 应答期间同步转交给目标邮箱——只有所有目标都收下才回复 `250`，临时失败回复 `451`（由发件方重试，5 天内对已送达的目标自动去重），永久拒收回复 `550`。

- **规则匹配**：支持本地名（如 `postmaster`，等价于 `postmaster@域名`）、完整地址（含子域）、`name+tag@` 自动归并到 `name@`（若有带 tag 的专属规则则优先）、以及 `*` 兜底规则。动作支持 `forward`（1–10 个外部邮箱，禁止转发回本域或本平台其他开启邮件路由的域）和 `drop`（收下后静默丢弃）。
- **SRS 发件人改写**：转发时用机群共享的 API 令牌对信封发件人做 HMAC-SHA256 签名，改写为 `srs0=<hash>=<stamp>=<原域>=<原本地名>@<本域>`（约 21 天有效），保证目标邮箱的 SPF 校验通过；退信（仅限空信封发件人 `MAIL FROM:<>`）落到任意节点都能验签还原并回投给原始发件人。
- **DNS 记录与迁移**：面板的"电子邮件"页和 `GET /zones/{id}/email` 会检查该域名的 `MX` 与 `SPF` 记录，列出缺失项并支持一键添加；建议同时配置 `DMARC`（`v=DMARC1; p=quarantine; ...`）并在使用外部中继发信时配置对应中继商的 `SPF` / `DKIM`。邮件相关的 `MX` / `TXT` 记录都是普通的 `dns_records`，`email_rules` 存放在配置 `state.json` 中随副本同步自动复制，域名迁移或导入导出时会一并带走。
- **网络要求（云主机 25 端口）**：许多云厂商（包括 AWS EC2）默认封堵**出方向 TCP 25**，无法直连 Gmail / QQ 等目标的 MX:25。生产环境请配置 `--mail-relay` 走中继服务的 submission 端口（`587` STARTTLS 或 `465` 隐式 TLS，均强制校验证书）；若要接收公网邮件，需在收信节点开启 `--smtp-listen 0.0.0.0:25` 并确认防火墙 / 安全组放行入方向 TCP 25。

## 面板账户、两步验证与通行密钥

面板用账户登录。账户只存在提供面板的那个节点上（数据目录的 `accounts.json`，权限 0600），不属于配置，不会同步给副本。
API 令牌照旧可用（运维脚本、副本同步、应急），拥有全部权限，不走两步验证。

- **初始化**：还没有任何账户时，面板要求填写邮箱、密码和本节点的 API 令牌，创建第一个管理员（`POST /auth/setup`）。
  也可以用令牌直接建：`POST /users {"email": "...", "role": "admin"}`，不带密码时系统随机生成一个并只返回这一次，对方首次登录必须改掉。
- **角色**：`admin` 全部；`editor` 改配置（域名、记录、规则、Workers 等），不能管用户、发布和节点操作；`viewer` 只读。最后一个管理员不能被降级、停用或删除。
- **密码**：至少 8 位，PBKDF2-HMAC-SHA256（60 万轮）加盐存储。连续输错 5 次起账户暂时锁定（1 分钟起，逐次翻倍，最长 15 分钟）。改密码后其他会话全部失效。
- **两步验证（TOTP）**：在"账户与安全"里用验证器 App 扫码，输入一次验证码后生效。之后登录先密码、再 6 位验证码（前后各容忍一个 30 秒窗口，同一个码只能用一次）。
- **备用验证码**：只是两步验证的替补，没开两步验证就没有。开启时发 10 个，用一个失效一个；可随时重新生成（要密码），旧的全部作废。只存摘要，只显示一次。
- **通行密钥（WebAuthn）**：可添加多个。两种用法：登录页"用通行密钥登录"（不输密码，要求密钥自己验证用户：指纹 / 面容 / PIN）；或输完密码后代替验证码。
  支持 ES256、RS256、EdDSA，校验来源、挑战、签名和计数器。只能在面板自己的 HTTPS 域名（`--panel-host`）或 `localhost` 下使用。
- **会话**：30 天，令牌只存摘要；"账户与安全"里能看到每个会话的设备、IP、登录方式，并逐个下线。
- **审计**：登录成败、改密码、两步验证和通行密钥的增删、用户管理、节点操作都有记录（最近 300 条，管理员可见）。
- 管理员可以给别人重置密码、清除两步验证（对方丢了手机时）。

接口：`/auth/status` `/auth/setup` `/auth/login` `/auth/second_step` `/auth/passkey/begin|finish`（无需登录）；
`/account` 及其下的 `password` `totp/begin` `totp/enable` `two_factor/disable` `backup_codes` `passkeys` `sessions` `logout`；`/users[/{id}]`；`/audit`。

## 机群与节点

面板的"机群与节点"页（`GET /fleet`）把机群运维与边缘节点调度配置合为一页，逐台列出节点的详情：角色、IPv4/IPv6、负责大洲、分档限流配置与本周期用量/状态、程序版本和二进制摘要、是否支持滚动发布 / 是否在试运行、配置版本与同步状态、运行时长、最近报到时间、进程内存、主机内存、负载、边缘缓存占用、HTTP/3 前置及其证书到期时间、主机名 / 内核 / PID、监听地址。
副本大约每分钟把自身状态随上报带给主节点。

管理员可以在同一页添加 / 删除节点、编辑节点的调度大洲与三档流量限制（摘除 DNS / 开始限速 / 停服及周期与重置日），对节点下指令（`POST /fleet/{节点}/actions {"action": "restart" | "purge_cache"}`：本机立即执行，副本在 5 秒内取走执行），以及发布新版本、撤回并回退或仅忘掉当前发布，见下节。

## 更新时不断连

进程换成另一个二进制（滚动发布、面板的"重启"、或替换 `/usr/local/bin/fucf` 后发 `SIGUSR2`）时，监听的套接字（边缘、HTTP/3、DNS、API、SMTP）
原样交给下一个进程（环境变量 `FUCF_LISTEN_FDS`）：这期间到达的连接在内核队列里等几百毫秒，而不是被拒绝。
换之前先等手上的请求答完（最多 2 秒），期间已有连接上的新请求得到"边缘节点正在更新"页面（503，`Retry-After: 30`，30 秒后自动刷新）。
手动换二进制：

```bash
install -m 755 fucf /usr/local/bin/fucf && systemctl kill -s USR2 --kill-whom=main fucf   # 或在 unit 里写 ExecReload=/bin/kill -USR2 $MAINPID，用 systemctl reload fucf
```

`systemctl restart` 仍会有几百毫秒没有进程监听；停止时同样先给手上的请求最多 3 秒，期间来的访客看到更新页面。

## 开放 API：API 令牌与 Global API Key（兼容 Cloudflare）

除了面板登录和机群自己的 API token，还可以用 **Cloudflare 格式的 API 令牌**（面板：账户与安全 → API 令牌）。
`Authorization: Bearer <令牌>`，基址 `https://<面板域名>/client/v4`。certbot-dns-cloudflare、acme.sh `dns_cf`、lego、
Terraform、各种 DDNS 脚本只要把 API 地址换掉就能用。

```
/user                                     GET              凭据属于谁
/user/tokens[/{id}]                       GET POST PUT DELETE   {"name", "policies": [...], "condition": {"request.ip": {"in": [...], "not_in": [...]}}, "not_before", "expires_on", "status": "active|disabled"}
                                                           POST 的返回值里有 value（只给这一次）；PUT 整体替换（值不变）
/user/tokens/{id}/value                   PUT              轮换：返回新值，旧值立即失效
/user/tokens/verify                       GET              当前令牌是否有效
/user/tokens/permission_groups            GET              权限组（与 Cloudflare 同名：Zone Read、DNS Write、Cache Purge、Workers KV Storage Write……）
/accounts[/{id}]                          GET              唯一的账户（Cloudflare 工具需要它的 id）
/accounts/{id}/workers/scripts/...        同 /workers/scripts/...；/accounts/{id}/storage/kv/namespaces/... 同 /kv/namespaces/...；
/accounts/{id}/d1/database/...            同 /d1/database/...；/accounts/{id}/tokens/... 同 /user/tokens/...
/account/api_key                          POST             {"password", "remove": false}：生成（或删除）自己的 Global API Key
```

policy 与 Cloudflare 相同：`{"effect": "allow|deny", "resources": {...}, "permission_groups": [{"id"} 或 {"name"}]}`，资源写法
`com.cloudflare.api.account.zone.<zone id>` / `com.cloudflare.api.account.zone.*` / `com.cloudflare.api.account.<account id>`（可内含 zone 资源）
/ `com.cloudflare.api.user.<user id>`；deny 优先；写权限包含读；对某个域名有任何权限就能看到这个域名（`GET /zones` 只列出令牌涉及的域名）。
令牌能做的不超过所有者的角色；登录、改密码、两步验证、用户管理、复制同步永远不能用令牌。令牌在机群里像会话一样同步。

Global API Key：请求头 `X-Auth-Email` + `X-Auth-Key`，拥有所有者的全部权限（`/account/*` 除外）。

DNS 记录的 Cloudflare 兼容补充：
- 过滤：`type`、`proxied`、`search`、`match=any|all`，name / content / comment 的 `x`、`x.exact`、`x.contains`、`x.startswith`、`x.endswith`（comment 另有 `.present`/`.absent`）；排序 `order=type|name|content|ttl|proxied` + `direction=asc|desc`
- SRV、CAA 可以用 `data`（`{"priority","weight","port","target"}` / `{"flags","tag","value"}`）代替 `content`
- `POST /zones/{id}/dns_records/batch`：`{"deletes":[{"id"}], "patches":[{"id",...}], "puts":[{"id",...}], "posts":[{...}]}`，按这个顺序执行；先整体检查，
  之后若某一步失败，它之前的修改保留（错误信息说明停在哪）——这一点和 Cloudflare 的原子批量不同
- `GET /zones/{id}/dns_records/export`：BIND 文件（已代理的带 `cf_tags=cf-proxied:true`）；`POST /zones/{id}/dns_records/import`：multipart 字段 `file`（或直接把文件当请求体），`proxied=true` 把能代理的都代理
- 代理（`proxied`）和自定义回源（`origin`：端口、SNI、Host、协议、节点内回源）照常可用，见上面的“高级回源”

## 自动防火墙

区域设置 `auto_firewall`（面板：域名 → 安全 → 自动防火墙，默认关）：每 30 秒看一次最近的安全事件——托管规则命中（拦截或记录）、防火墙拦截、限速——
在 `auto_firewall_window` 秒（默认 600）内攻击达到 `auto_firewall_threshold` 次（默认 10）的地址，被加进这个域名的一条自动规则
（`managed_by: auto_firewall`，表达式 `ip.src in {...}`，优先级 1000，动作 `auto_firewall_action`：block 或 managed_challenge），
封 `auto_firewall_ban` 秒（默认 86400）；期间继续攻击会续期，到期自动移出，空了规则就删掉。IPv6 按 /64 封；机群节点自己的地址和内网地址从不封；
最多 1000 个地址（保留最晚到期的）。在主节点上运行（它有全机群的安全事件），规则随配置同步到所有节点。

另外两条自动维护的规则：
- 按网络：同一个 ASN 里有 `auto_firewall_network_ips`（默认 10）个机房 / VPN / 黑名单地址在攻击时，整个 ASN 的访客先点一下人机验证
  （`managed_by: auto_firewall_networks`；家庭宽带不会被整网处理；机群节点自己的地址除外）。`auto_firewall_networks=false` 关闭。
- 攻击潮：窗口内攻击地址数达到 `auto_firewall_surge`（默认 50，0 关闭）时自动进入受攻击模式，攻击停止一小时后恢复原来的级别。

## 安全级别、IP 纯净度与页面内人机验证

- `security_level`：`off` / `low`（简易：威胁分 ≥ 80 要验证）/ `medium`（中等：≥ 50）/ `high`（严格：≥ 25，含机房 IP）/ `under_attack`（受攻击模式：所有人）。
  级别越高，验证要做的计算越多（17 / 18 / 19 位），对可疑环境越不宽容。`/.well-known/acme-challenge/` 和 `/cdn-cgi/` 永远不验证。
- 威胁分（0–100，规则里写 `cf.threat_score` 或 `fcf.threat_score`）：每个节点每 12 小时拉一次 FireHOL level1/level2、Tor 出口、VPN 与机房网段
  （存在 `<数据目录>/reputation`，`FUCF_IP_REPUTATION=false` 关闭），加上按 AS 名称识别的云厂商、本机群自动封禁过的地址；内网、机群自己的地址、
  来自自家网络的搜索引擎爬虫为 0。面板“调度 → 定位测试”能看到某个 IP 的威胁分和原因。
- 人机验证检测：webdriver 与各类自动化框架痕迹、调试协议、被改写的原生函数、UA 与 Client Hints / iframe / Worker 里的 UA 是否一致、
  JS 引擎特征（报错措辞、`eval` 的打印长度）与 UA 声称的是否一致、`navigator.platform`、触摸、Canvas 噪声（反检测浏览器）、软件 WebGL、
  媒体设备、窗口工具栏、Fetch Metadata 请求头、语言、鼠标轨迹是否像尺子画的、计算是否在页面外完成。
- `challenge_script`（默认开，只在域名可能要求验证时生效）：在 HTML 页面里插入 `/cdn-cgi/challenge-platform/fcf.js`。空闲时后台悄悄通过验证；
  页面里的 `fetch` 被要求验证时就地弹出验证框，通过后自动重发（XHR 无法重发，通过后下一次请求即可）。
- 被要求验证的非页面请求（`Sec-Fetch-Mode` 不是 `navigate`，或 `Accept` 不含 `text/html`）得到 JSON，响应头 `fcf-mitigated: challenge`。
- 响应头一律用 `fcf-` 前缀（`fcf-cache-status`、`fcf-mitigated`、`fcf-ray`），不发任何 `cf-` 开头的头；源站在 Cloudflare 后面时它发的 `cf-*` 会被去掉。
  回源请求带 `fcf-connecting-ip` / `fcf-ipcountry`（以及给为 Cloudflare 写的程序用的 `cf-connecting-ip` / `cf-ipcountry`）。

## 备份与恢复

复制的数据（配置、账户、Workers KV、D1）在每个 `peer` 节点上都有完整一份；`accelerate` 节点只在内存里有。为了 AWS 账号整体出事也不丢：

- 每个节点（包括 accelerate 节点）每 6 小时把手里的副本写成一份备份到 `<数据目录>/backups`，保留最近 28 份
  （`FUCF_BACKUP_DIR`、`FUCF_BACKUP_EVERY_HOURS`、`FUCF_BACKUP_KEEP`）。不在同一家云的节点上的备份就是异地备份。
- `GET /client/v4/backup`：现拿一份（管理员，或只有 “Backup Read” 权限的令牌）。
- `.github/workflows/backup.yml`：每天从面板拉一份，用 age 公钥加密后存为 workflow artifact（90 天）。仓库是公开的，所以只存加密后的；
  需要 secret `FUCF_BACKUP_URL`、`FUCF_BACKUP_TOKEN` 和变量 `FUCF_BACKUP_AGE_RECIPIENT`，私钥自己离线保管。
- 恢复：拿任意一份备份（`age -d -i key.txt x.json.gz.age > x.json.gz`），在一台新机器（或幸存的节点上改成 `FUCF_ROLE=peer`）
  用 `FUCF_RESTORE_FROM=/path/x.json.gz` 启动一次，再把注册商那里的 NS 记录指向还活着的节点。

## 伪装子域

区域设置 `decoy_subdomains`（面板：域名 → 安全 → 伪装子域）：开启后该域名下任何没有记录的名字都能解析——指向没有流量限制、其次流量配额最大的健康节点
（不用仅加速节点），每个地址族一个地址——但都无法访问：HTTPS 握手失败，HTTP 直接断开。靠解析枚举子域就没有意义了。
已有记录、通配记录、空非终端、子域委派和 Spectrum 应用不受影响。

## 滚动更新与自动回滚

机群可以自己换二进制：把一个签过名的新版本交给主节点，它让副本**一台一台**地换，全部换完并稳定后自己最后换。
任何一步不成，**整个机群退回到原来运行的版本**。

```bash
fucf release-keygen                       # 生成发布密钥：private= 留在构建机，public= 配给每个节点（--release-key）
fucf release-sign KEY_FILE BINARY         # 输出 sha256= 和 signature=
# 交给主节点，开始滚动：
curl -X PUT -T BINARY -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:8787/client/v4/releases/$SHA256?signature=$SIGNATURE"
```

| 接口 | 作用 |
|------|------|
| `PUT /releases/{sha256}?signature=…` | 上传并开始滚动（请求体是二进制，上限 256 MiB）。签名不对、摘要不符、机群里有不支持发布的旧版节点时拒绝 |
| `GET /releases` | 进度：`rollout.phase` 为 `rolling`（哪台在 `updating` / `settling`）、`updating_primary`、`done`、`rolling_back`、`reverting_primary`、`failed`（带原因）；`nodes` 列出每台运行的二进制摘要、是否在试运行、是否拒绝过该版本 |
| `DELETE /releases/{sha256}` | 撤回：正在运行该版本的节点逐台退回原版本，主节点最后退 |
| `DELETE /releases/{sha256}?forget=true` | 只是忘掉这次发布：各节点保持现状，不再继续滚动 |

**在节点上**：systemd 启动的那个二进制（`/usr/local/bin/fucf`）始终不动，充当启动器——启动时看
`<data-dir>/releases`，如果那里有一个签名正确的当前版本，就 `exec` 成它（PID 不变，不依赖服务管理器）。
新版本先**试运行**（默认 45 秒，`FUCF_RELEASE_TRIAL` 可调），以下任一情况退回到它之前的版本（更早的发布版，或启动器自身）：

- 试运行期内退出，连续两次（第一次崩溃后服务管理器把它拉起来再试一次）；
- 撑过了试运行，但期末**自检**不过：DNS 的每个监听地址有应答、边缘监听可连接、管理 API 应答 200、副本自启动后至少成功联系过一次主节点；
- 卡死到连自检都跑不到（独立的看门狗线程，试运行结束 60 秒后动手）。

退回过的版本记入本节点的黑名单，不会再被启动；同一个二进制重新提交一次算新的一次尝试，黑名单对它清零。

**在主节点上**：副本每 5 秒轮询时带上自己运行的二进制摘要和状态，主节点据此发"许可"，一次只给一台；
拿到许可的副本从主节点下载、验签、切换。某台副本回来了（在线、配置已同步、运行新版本、试运行已通过）再稳定
三分之一个试运行期，才轮到下一台。下面的情况判定为失败并开始回退：有节点报告退回了该版本；拿到许可的节点
5 分钟内没以新版本回来；主节点自己换不上去。回退也是一台一台来（每台等它以旧版本回来并同步了配置，最多等 1 分钟），
主节点在结果里记下原因，重启后也还记得。

**手动安装优先**：`/usr/local/bin/fucf` 被替换成另一个二进制后（`fleet.sh deploy`），该节点上此前滚动上来的版本一律作废，
运行的就是新装的这个；`fleet.sh deploy` 也会先让主节点忘掉当前的发布，免得它再把节点换回去。

仅限 Unix（需要 `exec`）；Windows 上发布相关的接口存在，但节点换不了自己。

## HTTP/3 前置

UDP 443 被别的 QUIC 服务占用时（三台节点上是 Hysteria 2），fucf 自己的 QUIC 监听只能放在别的端口，而浏览器
不会跟随指向非特权端口的 `Alt-Svc`，等于没有 HTTP/3。前置入口让占着 443 的那个服务把"不是它自己客户端"的普通
HTTP/3 请求转给 fucf：它终结 QUIC 和 TLS，再用明文 HTTP/1.1 把请求发到 `--h3-front-listen`。Hysteria 2 的配置：

```yaml
masquerade:
  type: proxy
  proxy:
    url: http://127.0.0.1:18480
    rewriteHost: false      # 保留访客请求的主机名
    xForwarded: true        # 把访客地址写进 X-Forwarded-For
```

从这个入口进来的请求按访客的真实情况处理：HTTPS、HTTP/3（`/cdn-cgi/fucf-trace` 里 `http=http/3`，分析里计为 HTTP/3），
访客地址取 `X-Forwarded-For` 的**最后一项**（前置服务加的那一项；它前面的是访客自己带的，原样保留），WAF、限速、
回源头都用这个地址。谁能连上这个入口谁说的地址就被采信，所以它只该监听回环地址。

访客看到的证书是前置服务的，不是 fucf 的。因此只有 `--h3-front-cert` 那张证书覆盖（且在有效期内）的主机名才通告
HTTP/3：响应里的 `Alt-Svc: h3=":443"` 和 HTTPS 记录。证书文件每分钟检查一次，续期后自动跟上。证书不覆盖的主机名：
有自己的 QUIC 监听就通告那个，否则不通告。

`fucf h3-get URL [--connect 地址] [--insecure]` 用真正的 HTTP/3 发一个请求并打印应答，用来确认某个地址的 UDP 443
背后到底是谁在应答。

## 三节点部署（scripts/deploy）

三台 AWS 节点（us / eu / au）上，`fucf` 以 systemd 服务运行在现有 haproxy 的 SNI 分流之后，不占用公网 443：

- TCP 443 仍归 haproxy：SNI 以 `.example.com` 结尾的连接带 PROXY protocol 转给 `127.0.0.1:18443`（fucf），其余照旧给代理服务。
- UDP 443 归 Hysteria 2（`hysteria-server`）。fucf 不再另开 QUIC 端口（原先的 UDP 4433 浏览器不会用）；
  `fleet.sh h3front` 给 Hysteria 加上伪装回落，把普通 HTTP/3 访客转给 fucf 的前置入口 `127.0.0.1:18480`（见"HTTP/3 前置"）。
  Hysteria 出示的是节点 **IP 证书**，不含任何站点域名，所以目前**没有主机名会被通告 HTTP/3**；
  要让站点真正用上 HTTP/3，得让 Hysteria 的证书同时覆盖站点域名（并把它的 `sniGuard` 设为 `disable`，否则按 IP 连接的
  Hysteria 客户端会被拒）。
- 公网 53 由 fucf 自己应答（绑定节点的公网地址，`systemd-resolved` 的 127.0.0.53 不受影响）：`cdn.example.com` 委托给
  ns1（us）/ ns2（eu）/ ns3（au），其下所有名字按调度规则解析到节点。原来的 `fucloudflare-geodns` 已停用，保留作回滚。
  境内递归到这几台机器的 **IPv4 UDP 回程不通**（查询能到、应答回不去），IPv6 是通的：所以每个 NS 都有 AAAA，
  新增的 ns3 **只有 AAAA**；ns1 / ns2 的 A 记录要留着，没有 IPv6 出口的递归只能靠它们（纯 IPv6 的 NS 组实测最差）。
  委托记录在 Cloudflare，`fleet.sh ns` 对照、`fleet.sh ns apply` 补齐（只新增，不改不删）。
  `cdn.example.com` 下的应答 TTL 是 300 秒（`FUCF_EDGE_TTL`）：每次缓存未命中对境内访客都是一次慢查询，TTL 太短等于多挨几次。
- 主节点是 au：面板在 <https://panel.example.com>（令牌在 WSL 的 `~/.config/fucf-fleet-token`）。us / eu 是只读副本，
  每 5 秒向主节点拉取一次配置，不需要手动同步；副本上的管理 API 拒绝写操作。副本每 15 秒把流量统计和安全事件上报给主节点，
  面板和 API 在主节点上看到的是全机群的数据。
- 升级顺序：**先副本（us、eu），最后主节点（au）**。新版副本能跟旧版主节点工作（只是暂时无法上报）；反过来旧版副本会把
  新版主节点的配置每 5 秒重新套用一遍，直到它自己也升级。
- 管理 API 在各节点上只监听 `127.0.0.1:8787`，对外只有主节点经面板域名发布。

全部在 WSL 里执行（密钥在 `~/.ssh/<node>.pem`）：

```bash
scripts/deploy/build-linux.sh                 # 构建静态 Linux 二进制到 dist/
scripts/deploy/fleet.sh deploy [us|eu|au]     # 手动安装 / 升级（建议逐台进行，中间跑一次 verify.sh）；
                                              # 新版本起不来或不健康（服务、API、DNS 连续 10 秒正常）时自动换回原二进制和配置
scripts/deploy/fleet.sh release               # 滚动发布 dist/ 里的二进制：签名、上传到主节点、盯到完成；失败则全机群自动回退
scripts/deploy/fleet.sh release status        # 滚动进度
scripts/deploy/fleet.sh release withdraw      # 撤回当前版本，全机群退回
scripts/deploy/fleet.sh h3front [us|eu|au]    # 让 Hysteria 把普通 HTTP/3 访客转给 fucf（会重启 hysteria-server；不通则自动恢复原配置）
scripts/deploy/fleet.sh hy2sni 域名[:disable] [节点]   # Hysteria 改用 *.example.com 证书；默认严格校验客户端 SNI，加 :disable 则不校验
scripts/deploy/fleet.sh ns [apply]            # cdn.example.com 在 Cloudflare 的委托：对照 / 补齐
scripts/deploy/fleet.sh status
scripts/deploy/fleet.sh api GET /zones        # 调用主节点的管理 API
scripts/deploy/fleet.sh tune [us|eu|au]       # 内核传输调优 + 安装 GeoIP 库
scripts/deploy/steering.sh                    # 写入节点与调度规则（可重复执行）
scripts/deploy/verify.sh                      # 节点互相探测 HTTPS / QUIC / DNS
```

### 调度策略

`steering.sh` 的规则来自 2026-11 的三网延迟实测（三台都是 AWS 普通 BGP 线路）：

| 访客 | 首选 → 备用 | 依据 |
|------|-------------|------|
| 中国联通 | eu → au | 经欧亚陆缆直达斯德哥尔摩，170–220 ms，大面积 0% 丢包 |
| 中国移动 | au → eu | 亚太海缆到悉尼 140–185 ms |
| 中国电信 | au → eu | 悉尼整体最优（部分省份绕美，见下） |
| 中国其他网络 | au → eu | 多数经移动 / 联通出口 |
| 中东 | eu → au | GeoIP 归在亚洲，但离斯德哥尔摩近得多 |
| 其余 | 按大洲：亚洲 / 大洋洲 → au，欧洲 / 非洲 → eu，美洲 → us | |

中国大陆的流量在 au 与 eu 之间互为备用，只有两者都不可用时才会落到 us。
按省份调度（规则的 `regions`，ISO 3166-2 代码如 `JS` `ZJ` `SH` `SD` `AH`）用 ip2region 判断大陆地址的省份：GeoLite2 City 只覆盖约六分之一的大陆地址，江苏电信的 DNS 就查不到省份，规则多半不命中。
DNS 调度看到的是递归 DNS 的地址（带 ECS 时是访客网段）；面板「调度与 DNS 屏蔽」页可以输入 IP 测试定位和命中的规则。

`tune-node.sh` 针对 150–260 ms、5–15% 丢包的长肥管道：BBR + fq、TCP Fast Open、32 MiB 的 TCP 窗口上限、
加大 UDP 默认缓冲（QUIC）、关闭空闲后慢启动、开启 MTU 探测；并安装每周更新的 GeoLite2 库。

### 接入站点

接入一个站点（Cloudflare 灰云 CNAME + fucf 代理记录，一条命令）：

```bash
scripts/deploy/add-site.sh app <源站IP>       # https://app.example.com
scripts/deploy/verify-tls.sh app.example.com
```

证书：`fleet.sh cert` 在每台节点上用 certbot + Cloudflare DNS 验证签发 `example.com` 和 `*.example.com`，
并通过部署钩子 `/usr/local/bin/fucf-cert-hook` 装进本机 fucf；之后由各节点的 `certbot.timer` 自动续期并重新装入。
Cloudflare 令牌（Zone DNS 编辑权限）放在 WSL 的 `~/.config/fucf-cf-token` 和各节点的 `/etc/letsencrypt/cloudflare.ini`。
`*.cdn.example.com` 这一层不在证书范围内（该子域委托给了节点自己的 DNS，无法经 Cloudflare 做 DNS 验证），对外域名请用 `xxx.example.com`。

回滚单个节点的步骤写在 `install-node.sh` 开头的注释里。

发布密钥在 WSL 的 `~/.config/fucf-release-key`（第一次 `fleet.sh deploy` / `release` 时生成），公钥随 `deploy` 写进各节点的
`/etc/fucf/fucf.env`。所以**第一次**带上这套机制的版本只能用 `fleet.sh deploy` 手动装，之后才能用 `fleet.sh release`。

## 扩展能力（Workers 存储与定时、对等同步、原生反向代理与 OIDC）

### Workers KV / D1 / Cron Triggers / WebCrypto

- **Workers KV**：内置键值存储，可通过 `/client/v4/kv/namespaces` 管理命名空间与键值，并在 Worker 设置的 `kv_bindings` 中绑定到脚本的 `env`。
- **Workers D1（SQLite）**：基于内嵌 SQLite 的关系型数据库，可通过 `/client/v4/d1/database` 创建与查询，并通过 `d1_bindings` 绑定到 `env`。
- **Cron Triggers**：支持在 Worker 设置中配置 5 段式 UTC `crons` 表达式，按计划触发 `scheduled(controller, env, ctx)`，也可通过 `POST /client/v4/workers/scripts/{name}/scheduled` 手动触发。
- **WebCrypto**：Worker 运行时内置 `crypto.getRandomValues` 与 `crypto.subtle`（摘要、HMAC、AES、RSA/ECDSA 签名与验签、PBKDF2/HKDF 等）。

### 无主对等同步与纯加速节点

- **无主对等同步（`--role peer`）**：通过 `--role peer --peers <host1,host2,...>` 组成多活控制面机群，节点间双向同步配置、面板账户与遥测数据，支持持久化状态。
- **纯加速节点（`--role accelerate`）**：作为只读内存态数据面运行，不在磁盘落盘控制面状态，并自动抑制公共 NS 应答；可在节点配置中设置 `accel_hosts`（按子域名白名单），限制该节点仅对指定主机名提供加速与代理服务。

### 原生反向代理、Hysteria 2 回落、`/cdn-cgi/*` 与节点内回源

- **原生反向代理**：通过 `--proxy-listen`（HTTP/1.1 + h2c）、`--proxy-tls-listen`（TLS + HTTP/2 + HTTP/1.1）与 `--proxy-h3-listen`（QUIC / HTTP/3）直接承担反代；支持 HTTP/2 WebSocket（RFC 8441 Extended CONNECT）与 HTTP/3 WebSocket（RFC 9220）。
- **Hysteria 2 回落与 QUIC SNI 分流**：支持与 Hysteria 2 共存——既可通过 `--quic-fallback` 与 `--quic-fallback-sni` 在同一 UDP 443 端口解密 QUIC Initial SNI 并分流非托管流量，也可通过 `/client/v4/proxy/rules` 配置 `is_fallback: true` 兜底规则为 Hysteria 2 masquerade（`--h3-front-listen`）或未匹配的反代主机提供回落响应。
- **`/cdn-cgi/*` 可定制路由**：内置 `/cdn-cgi/fucf-trace`、`/cdn-cgi/limit/*` 与 `/cdn-cgi/fucf-warp`（配置 `--warp-upstream` 时可同时路由 `/cdn-cgi/warp` 至本地流式后端）；此外，`/client/v4/proxy/rules` 优先于内置 `/cdn-cgi/*` 处理器匹配，可按主机与路径前缀自定义任意 `/cdn-cgi/*` 路由。
- **CDN 节点内回源（`origin_node`）**：回源规则（`origin_rules`）及 DNS 记录回源选项支持指定 `origin_node`，将匹配流量经由机群内部指定节点回源。

### OAuth 2.0 / OIDC Worker 与 Kumo 主题界面

- **OAuth 2.0 / OIDC Worker（`workers/auth/`）**：随仓提供自托管认证 Worker，基于 KV、D1 与 WebCrypto 实现完整的 OIDC Discovery / JWKS / Authorization Code + PKCE 流程，支持 Passkeys（WebAuthn）、Linux.do Connect / GitHub / Google 等第三方登录，以及与管理面板集成的 SSO（`/client/v4/oauth/config`、`/client/v4/auth/oauth/login`）。
- **Cloudflare Kumo 风格界面**：管理面板采用 Cloudflare Kumo 视觉风格，支持亮色 / 暗色主题切换。

## 测试

```powershell
cargo test                # 单元 + 集成测试（真实源站、真实监听器）
cargo build; python scripts\e2e.py   # 针对真实二进制的端到端检查（滚动更新 / 回滚那一段只在 Linux 上跑，约多 2 分钟）
python scripts\dnsq.py 127.0.0.1 53 www.example.com A   # 手动查询 DNS
```

## 已知限制

- 多节点：配置单向同步（主节点 → 副本轮询）；缓存和限速计数是各节点各自的内存状态。分析数据和安全事件每 2 分钟及退出时落盘，
  进程被强杀会丢最后这一段；副本联系不上主节点期间攒着待上报的数据，重启则丢失。
  主节点不可用时副本继续按最后一次拿到的配置服务，但无法修改配置，证书也不会续期。
- 调度：健康检查只到 TLS 握手为止，不发 HTTP 请求；GeoIP 精度到国家、ASN 和（中国大陆，需 ip2region 库）省份，没有城市级调度。
- 证书：ACME 客户端只支持 ECDSA P-256 账户和证书密钥，不支持 External Account Binding（需要它的 CA 如 ZeroSSL 用不了）；
  对真实 CA 只实测过 Let's Encrypt（staging 和正式）的 TLS-ALPN-01；DNS-01 和 HTTP-01 目前只有模拟 CA 的自动化测试；HTTP/3 (QUIC) 监听不应答 TLS-ALPN-01（CA 只走 TCP，不影响签发）。
- 滚动更新：自检只查本机（监听、API、DNS 有应答，副本联系得上主节点），查不出"能应答但答错了"的版本；主节点换自己时
  面板和 API 中断几秒，期间副本按已有配置继续服务；被判定卡住的节点（收到回退许可 1 分钟没动静）不再等它，要人工处理；
  发布的二进制在主节点内存里过一遍（上传和下载各一份），小内存机器上注意 `MemoryMax`。
- HTTP/3 前置：经前置入口进来的 gRPC 不按 gRPC 处理（中间那一跳是 HTTP/1.1，带不了 trailers）；WebSocket 不经过它
  （HTTP/3 没有升级）；请求和响应都多一次本机转发。
- DNS：没有 DNSSEC、AXFR；CNAME 拉平的外部目标靠系统解析器，拿不到 TTL，固定每分钟刷新、以 60 秒 TTL 应答，刚建好的记录要等第一次解析完成才有应答。
- 缓存：单个对象上限 32 MiB（未声明长度的 8 MiB）；Range 请求只在缓存里已有完整对象时由缓存应答，不会为它去源站拉完整对象；多段 Range 返回整个对象。
- HTTP/3：不支持 0-RTT。回源除 gRPC 用 HTTP/2 外主要为 HTTP/1.1。
- gRPC：经 Worker 路由的请求不走 gRPC 路径；请求侧的 trailers 不转发；WAF 不检查 gRPC 请求体。
- 节点限流：只计响应体字节（不含请求体、响应头、TLS 开销），WebSocket 升级后的数据和 Spectrum 不计量也不限速；
  没有手动清零用量的接口（调高上限即可解除）；改 `traffic_reset_day` 使周期起点后移时用量清零；
  DNS 避让受解析缓存 TTL 影响（代理记录 300 秒），不是立刻生效；主节点不可用时，副本的超限状态传不到其他节点的 DNS。
- 压缩：未知长度（流式）的响应不压缩。
- 源站故障转移是被动的（没有对源站的主动健康检查），超时不会重发请求。
- 分析：按国家 / 主机名 / 路径的拆分只保留 7 天，每小时每个维度只留排名靠前的若干项（其余并入"(other)"）；没有 DNS 查询量统计。
- WAF：托管规则是一组正则，不是完整的 OWASP CRS；请求体只检查不超过 1 MiB 的。
- Workers：每个请求新建 JS 上下文（无全局状态复用）；只支持单文件脚本；请求体/响应体只能以文本读取
  （未读取的二进制体可原样透传）；不支持流式 API；单请求最多 50 个子请求，体积上限 16 MiB。
  CPU 限制靠循环次数上限，墙钟超时 30 秒后向客户端返回 500，但脚本线程要到自身结束才释放。
- Spectrum：所有应用共用边缘 IP，同一协议端口只能被一个应用占用；UDP 会话空闲 60 秒回收。

## 致谢

感谢 [LINUX DO 社区](https://linux.do) 对本项目的启发、交流与支持。
