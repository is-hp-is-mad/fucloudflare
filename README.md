# fucloudflare

自托管的 Cloudflare 式边缘平台，单一二进制 `fucf`（Rust）。

| 模块 | 功能 |
|------|------|
| DNS | 权威 DNS（UDP/TCP），代理记录解析到边缘 IP；按访客国家 / 大洲 / 运营商（ECS 感知）调度到节点，带健康检查与故障切换，可按地区屏蔽解析 |
| 面板 | 内嵌的网页控制面板：DNS 记录、机群与节点（含分档限流）、调度规则、区域设置、规则、电子邮件路由、Workers；完全托管与 CNAME 接入两种模式 |
| 多节点 | 无主对等同步（`--role peer --peers ...`）：每个对等节点都可读写，配置、面板账户、Workers KV / D1 和各节点的上报（流量统计、安全事件）在节点之间双向同步，冲突按混合逻辑时钟后写者胜；`--role accelerate` 节点只拉取配置、内存运行、拒绝写入 |
| CDN | HTTP/1.1、HTTP/2、HTTP/3 (QUIC) 反向代理，WebSocket，gRPC，SNI 证书，边缘缓存与清除（Range、源站故障时回退到过期副本），brotli/zstd/gzip 压缩，图片缩放，源站故障转移 |
| 节点限流 | 每个节点可设周期流量配额（摘除 DNS / 开始限速 / 硬限流三档）和限速；超限节点自动退出 DNS 应答，硬限流后只返回提示页 |
| 证书 | 内置 ACME 客户端：向 Let's Encrypt 等 CA 自动签发并续期证书（DNS-01 / TLS-ALPN-01 / HTTP-01），也可上传自有证书 |
| 规则 | 重定向规则、请求/响应改写规则、缓存规则 |
| 电子邮件 | SMTP 收信与转发路由（不落盘）：按地址 / `+tag` / `*` 兜底转发或丢弃，SRS 发件人改写与退信回溯，转发的信加本域名的 DKIM 签名，支持外发中继（submission 587/465） |
| 分析 | 全机群的时间序列（分钟级 1 天、小时级 30 天）：请求数、流量、状态码、缓存命中、拦截数、协议版本，按节点、国家、主机名、路径拆分；重启不丢 |
| WAF | 自定义规则、限速、托管规则集、人机验证（`js_challenge` / `managed_challenge`）、按 IP 威胁分的安全级别与 Under Attack 模式、自动防火墙、安全事件日志（全机群汇总）、规则共用的 IP 列表（`ip.src in $名字`） |
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
| `--edge-ttl` | `300` | 指向边缘的 DNS 应答的 TTL（秒）：`--cname-base` 下的名字用它，代理记录用它但最多 300（记录自己的 TTL 不管用）。节点故障或流量超限后，最长这么久之后访客才被调度走 |
| `--dns-rrl` | `100` | 权威 DNS 的 UDP 响应限速（每个网络每个名字每秒的应答数），`0` 关闭，见"DNS 响应限速与内核层封禁" |
| `--ban-export` | 无 | 把自动防火墙封禁的地址写成 nftables 脚本的文件路径，见"DNS 响应限速与内核层封禁" |
| `--origin-client-cert` / `--origin-client-key` | 无 | 回源时出示的客户端证书和私钥（PEM），两个要一起给，见"回源时出示客户端证书" |
| `--mtls-ca` | 无 | 签发访客客户端证书的 CA（PEM，可多张）。配置后 HTTPS 和 HTTP/3 监听向访客要客户端证书（不强制），见"访客客户端证书（mTLS）" |
| `--release-key` | 无 | 发布公钥（见"滚动更新与自动回滚"）。配置后本节点接受机群滚动发布的新版本，新版本不能用时自动退回；不配置则只能手动替换二进制 |
| `--proxy-protocol` | 关 | 边缘 TCP 连接必须以 PROXY protocol v1 头开始（仅用于只经可信四层代理可达的监听） |
| `--api-listen` | `127.0.0.1:8787` | 管理 API 与面板 |
| `--geoip-db` / `--geoip-asn-db` | 无 | MaxMind GeoLite2 Country / ASN 库；启用按大洲、国家、运营商调度和 `ip.geoip.*` 规则字段 |
| `--geoip-cn-db` | `--geoip-db` 同目录下的 `ip2region_v4.xdb`、`ip2region_v6.xdb`（如果有） | [ip2region](https://github.com/lionsoul2014/ip2region) 库（Apache-2.0 / MIT）：中国大陆地址的省份。GeoLite2 只知道约六分之一大陆地址的省份，按省份调度要靠它 |
| `--cname-base` | 无 | 该域名下的所有子名都解析到边缘（如 `cdn.example.com`，需委托给本服务）；CNAME 接入模式的区域把主机名 CNAME 到它 |
| `--panel-host` | 无 | 在边缘上以该主机名对外发布面板和管理 API（HTTPS，仍需令牌） |
| `--panel-origin` | 无 | 多节点承载面板：本节点把面板主机名的请求转给运行面板的节点（`ip[:port]`，HTTPS，按面板主机名校验证书），访客地址随 `X-Forwarded-For` 带过去；以面板主机名配置的同步对端也直连这里。这样面板的 DNS 记录可以开代理、解析到任意节点 |
| `--role` | `peer` | `peer`：可读写的控制面，与 `--peers` 双向同步；`accelerate`：只读的纯加速节点（见"无主对等同步与纯加速节点"） |
| `--peers` | 无 | 逗号分隔的同步对端：面板主机名或节点主机名（走 HTTPS），或 `http(s)://host:port`。旧的 `--primary` 仍被接受（并入 `--peers`），已不推荐 |
| `--node-name` | 自动 | 本节点在机群里的名字；默认取 `--edge-ip` 所属的已登记节点 |
| `--acme-directory` | Let's Encrypt | 签发托管证书的 CA 的 ACME 目录地址；`off` 关闭。使用即表示同意该 CA 的服务条款 |
| `--acme-email` | 无 | 留给 CA 的联系邮箱（到期提醒） |
| `--edge-ip` | 无 | 边缘节点公网 IP；代理记录和 Spectrum 域名解析到它 |
| `--spectrum-bind` | `0.0.0.0` | Spectrum 监听绑定的本机 IP |
| `--smtp-listen` | 无（关闭） | SMTP 收信监听地址（如 `0.0.0.0:25`）；配置后本节点启用电子邮件路由 |
| `--mail-host` | 无 | 本节点在 SMTP 问候语与 MX 建议里使用的主机名（可逗号分隔多个，第一个用于 banner） |
| `--mail-relay` | 无 | 外发邮件中继（`smtp://[user:pass@]host[:587]` 强制 STARTTLS，或 `smtps://[user:pass@]host[:465]` 隐式 TLS）；出方向 25 端口受限的云主机必须配置 |
| `--cache-mb` | `512` | 边缘缓存上限 |
| `--cache-disk-mb` / `--cache-disk-dir` | `150` / `<数据目录>/cache` | 边缘缓存的磁盘层大小（MiB，`0` 为只用内存）和目录：放内存里放不下的、以及重启前缓存的对象 |
| `--data-dir` | `data` | 配置 `state.json`、`api_token`、分析数据 `analytics.json`、安全事件 `events.json`、ACME 账户 `acme_account.json`、本节点流量计数 `usage.json` |
| `--api-token` | 自动生成 | 机群自己的 API 令牌（节点之间、运维脚本用，拥有全部权限）；不给时生成一个存进 `<数据目录>/api_token` |
| `--ns` | `ns1.fucf.local,ns2.fucf.local` | 本部署的名称服务器主机名，分配给新建的区域 |
| `--ip-reputation` | `true` | 按公开黑名单给访客地址打威胁分（每 12 小时拉取），供安全级别和 `fcf.threat_score` 使用；`false` 关闭 |
| `--tls-cert-dir` | 无 | 别的工具签发、续期的证书所在目录（acme.sh、certbot、Caddy 的存储，或手写的 `名字.crt` + `名字.key`），可逗号分隔多个；配置里没有证书的名字用它们，每分钟重新看一次 |
| `--tls-default-sni` | 无 | TLS 客户端不带 SNI（按 IP 连接）时当作的服务器名，例如本节点的公网地址 |
| `--acme-webroot` | 无 | 外部 ACME HTTP-01 质询的 webroot 目录（`<目录>/.well-known/acme-challenge/<令牌>`），让 fucf 自己占 80 端口而不用 Caddy / nginx |
| `--export-domains` | 无 | 域名列表变化时把全部托管域名（加面板主机名和 CNAME 基础域名）每行一个写进这个文件（给 HAProxy 的 `-m dom -f` 用） |
| `--quic-fallback` / `--quic-fallback-sni` | 无 | 与另一个 QUIC 服务（如 Hysteria 2）共用 UDP 443：按 QUIC Initial 里的 SNI 分流，不属于托管区域（或在 `--quic-fallback-sni` 里列出）的转到这个本地地址，见"原生反向代理、Hysteria 2 回落、`/cdn-cgi/*` 与节点内回源" |
| `--warp-upstream` | 无 | `/cdn-cgi/fucf-warp` 的本地流式后端（如 `h2c://127.0.0.1:10002/ray`） |
| `--proxy-listen` / `--proxy-tls-listen` / `--proxy-h3-listen` | 无 | 原生反向代理的监听（HTTP/1.1 + h2c，`ip:port[=标签]`；TLS + HTTP/2；QUIC / HTTP/3），可逗号分隔多个，规则见 `/proxy/rules` |
| `--file-root-allow` | 无 | 带 `file_root` 的反代规则可以提供文件的目录（含其下所有内容），可逗号分隔多个；不配置时一个文件都不提供 |
| `--backup-dir` / `--backup-every-hours` / `--backup-keep` | `<数据目录>/backups` / `6` / `28` | 本节点备份的位置、间隔（小时，`0` 为不备份）和保留份数，见"备份与恢复" |
| `--restore-from` | 无 | 启动时并入这份备份（这里更新的保留），用于从备份恢复机群 |

所有参数都有 `FUCF_*` 环境变量，见 `fucf --help`。

## 管理 API

基址 `http://127.0.0.1:8787/client/v4`，认证头 `Authorization: Bearer <token>`，响应信封与 Cloudflare v4 一致。
用户自己的 API 令牌和 Global API Key 见下面的“开放 API”。完整的接口文档：[docs/api.md](docs/api.md)。
zones 与 dns_records 的路径和字段与 Cloudflare 兼容；其余资源是简化的自有结构。

```
/system                                  GET              角色（peer / accelerate）、节点名、配置版本、NS、CNAME 基础域名，以及各对端的同步状态
/analytics                               GET              所有区域的流量合计，?since= 同下
/warp/purge_cache                        POST             清除预留端点 /cdn-cgi/fucf-warp 的缓存：{"purge_everything":true} | {"files":[键...]} | {"prefixes":[键前缀...]}
/nodes[/{id}]                            CRUD             {"name", "ipv4", "ipv6", "continents": ["AS","OC"], "enabled", "traffic_dns_gb", "traffic_throttle_gb", "traffic_limit_gb", "traffic_period", "traffic_reset_day", "rate_limit_mbps"}；
                                                          返回值带 healthy、副本状态（配置版本、是否同步、最后上报时间）和 traffic（本周期已用字节数、状态）
/steering[/{id}]                         CRUD             {"name", "priority", "countries", "regions", "continents", "asns", "as_orgs", "action": "route|fastest|block", "nodes": [...]}
/steering/test?ip=                       GET              这个地址被定位到哪里（国家、省份、大洲、ASN）、命中哪条规则、所在网络的实测排名
/steering/measured                       GET              各节点实测的访客握手往返时间：{网络: {节点: {"ms", "samples", "age"}}}，见"实测调度与故障切换"
/email/status                            GET              本节点 SMTP 监听地址、主机名、中继配置与最近转发活动
/zones                                   GET POST         {"name", "type": "full|partial"}
/zones/{id}                              GET PATCH DELETE
/zones/{id}/dns_records[/{id}]           GET POST PUT PATCH DELETE   与 Cloudflare 相同的字段，另有 "origin"：已代理记录的高级回源选项（见下）
/releases[/{sha256}]                     GET PUT DELETE   滚动发布，见"滚动更新与自动回滚"
/zones/{id}/settings[/{name}]            GET PATCH        {"value": ...}
/zones/{id}/purge_cache                  POST             {"purge_everything":true} | {"files":[...]} | {"prefixes":[...]} | {"hosts":[...]} | {"tags":[...]}
/zones/{id}/custom_certificates[/{id}]   CRUD             {"certificate": PEM, "private_key": PEM, "hosts": [...]}；返回值带 expires_on
/zones/{id}/origin_ca                    GET POST DELETE  区域自己的源站 CA：创建（已有则 409）、查看 CA 证书（从不返回 CA 私钥）、删除，见"源站 CA"
/zones/{id}/origin_ca/sign               POST             {"hostnames": [...], "days": 365}：为源站签发证书，返回证书和只显示这一次的私钥
/zones/{id}/ssl/certificate_packs[/{id}] GET POST PATCH DELETE   {"hosts": [...], "validation_method": "auto|dns|tls-alpn|http"}；PATCH 立即重试
/zones/{id}/firewall/rules[/{id}]        CRUD             {"expression", "action", "priority", "enabled", "description"}
/zones/{id}/rate_limits[/{id}]           CRUD             {"expression", "threshold", "period", "mitigation_timeout", "action", "characteristics", "status_codes"}，见"限速的计数方式"
/zones/{id}/security/events              GET
/zones/{id}/origin_rules[/{id}]          CRUD             {"expression", "origin_host", "origin_port", "origin_scheme", "host_header", "sni", "priority"}
/zones/{id}/redirect_rules[/{id}]        CRUD             {"expression", "target_url", "status_code", "preserve_query_string", "priority"}
/zones/{id}/transform_rules[/{id}]       CRUD             {"expression", "rewrite_path", "set_request_headers", "remove_request_headers", "set_response_headers", "remove_response_headers"}
/zones/{id}/cache_rules[/{id}]           CRUD             {"expression", "cache": true|false, "edge_ttl", "ignore_query", "cache_key_headers", "cache_key_cookies", "priority"}
/zones/{id}/dnssec                       GET PATCH        {"status": "active|disabled"}；GET 返回给注册商的 DS 记录
/zones/{id}/custom_hostnames[/{id}]      GET POST PATCH DELETE   {"hostname", "custom_origin_server"}，没有 PUT，见"自定义主机名（SSL for SaaS）"
/zones/{id}/origins/health               GET              本节点对这个区域各源站地址的健康检查结果（区域设置 origin_check_path）
/zones/{id}/dns_analytics                GET              本节点自启动以来为这个区域应答的 DNS 查询数：{"total", "by_type", "by_rcode"}
/zones/{id}/email                        GET PATCH        区域邮件路由开关、规则、当前 MX/SPF/DKIM 及缺失的建议 DNS 记录；PATCH {"dkim_selector", "dkim_private_key"}
/zones/{id}/email/rules[/{id}]           CRUD             {"address", "action": "forward|drop", "destinations": [...], "enabled", "description"}
/zones/{id}/analytics                    GET              ?since=-1440（分钟）| 90m | 24h | 7d（默认 24h，最长 30d），?step= 分钟
/zones/{id}/logs/requests                GET              应答节点上这个区域最近的请求：?since=游标 &limit= &status=404|5xx &host= &path=前缀 &ip=，见“请求日志”
/zones/{id}/logpush/jobs[/{id}]          CRUD             {"name", "destination": "https://...", "enabled", "status_min", "batch_seconds"}
/zones/{id}/waiting_rooms[/{id}]         CRUD             {"name", "host", "path_prefix":"/shop", "total_active_users", "new_users_per_minute", "session_minutes", "enabled"}，见“等候室”
/zones/{id}/spectrum/apps[/{id}]         CRUD             {"protocol":"tcp/2222", "dns":{"name":"ssh"}, "origin_direct":["tcp://192.0.2.1:22"], "proxy_protocol":"off|v1"}
/zones/{id}/workers/routes[/{id}]        CRUD             {"pattern":"example.com/api/*", "script":"name"}
/workers/scripts[/{name}]                GET PUT DELETE   PUT 的请求体即 JS 源码，或只含一个模块的 wrangler 式 multipart 上传，见“Workers”
/workers/scripts/{name}/settings         GET PATCH        {"vars": {"KEY":"value"}, "kv_bindings": {"名字": 命名空间 id}, "d1_bindings": {"名字": 数据库 id}, "crons": ["*/5 * * * *"]}
/workers/scripts/{name}/scheduled        POST             {"cron": "*/5 * * * *"}：立即运行一次 scheduled()
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
| `weight` | 1 | 1–100：同名的多个地址按权重轮流分请求（如 3 和 1：每 4 个请求里前一个地址拿 3 个），见区域设置 `session_affinity` |

典型用途：源站自己也在别的 CDN 后面（例如用了 Cloudflare 自定义主机名，再配一个优选地址）——记录内容填要连的地址，
`sni` 填握手用的域名，`host_header` 填真正要访问的域名，两者可以不同。证书是否校验仍由区域的 `ssl` 模式决定
（`strict` 时按 `sni` 校验）。

- 每一项都可省略；全部留空等于没有选项。`PATCH` 时不带 `origin` 表示不动，带空对象 `{}` 表示清除。
- 匹配到的回源规则（`origin_rules`）逐字段优先于记录上的选项；回源规则用 `origin_host` 把请求改送别处时，
  记录上的选项不再适用（它们描述的是记录内容那个源站）。
- 同名的多条地址记录各带各的选项；故障转移只在选项相同（`weight` 不算）的地址之间进行。CNAME 记录的选项对它最终解析到的地址生效（这些地址的权重都按 1）。
- 不影响 DNS 应答，也不影响缓存键（仍按访客访问的域名）。

### 区域设置

| 名称 | 取值 | 说明 |
|------|------|------|
| `ssl` | `flexible`(默认) / `full` / `strict` | 回源用 HTTP / HTTPS 不验证书 / HTTPS 验证书 |
| `mtls` | `off`(默认) / `on` | 只接受出示了有效客户端证书的访客，其余一律 403，见"访客客户端证书（mTLS）" |
| `always_use_https` | bool（默认关） | HTTP 301 到 HTTPS |
| `waf` | `block`(默认) / `log` / `off` | 托管规则集模式 |
| `development_mode` | bool（默认关） | 绕过缓存 |
| `http2` | bool（默认开） | 向访客提供 HTTP/2；关闭后 TCP 上只有 HTTP/1.1 |
| `http3` | bool（默认开） | 提供 HTTP/3 (QUIC)，通过 `Alt-Svc` 头和 HTTPS DNS 记录通告；关闭后两者都不再通告 |
| `edge_nodes` | 节点名数组（默认空） | 只由这些节点服务该区域；空表示所有节点，按访客位置调度 |
| `security_level` | `off` / `essentially_off` / `low` / `medium`(默认) / `high` / `under_attack` | 按访客 IP 的威胁分决定谁要先过人机验证（见"安全级别、IP 纯净度与页面内人机验证"）；`under_attack` 时所有访客都要过（防火墙的 `skip` 规则可豁免，如回调接口） |
| `challenge_script` | bool（默认开） | 把 fucf 的验证脚本注入站点的 HTML 页面：后台静默完成验证，并就地处理被要求验证的 `fetch` 请求 |
| `browser_cache_ttl` | 秒（默认 0） | 边缘会缓存的内容，浏览器缓存时间不足该值时提到该值；0 表示不改源站的 `Cache-Control` |
| `hsts_max_age` / `hsts_include_subdomains` | 秒（默认 0）/ bool | HTTPS 响应带 `Strict-Transport-Security`；0 表示不发 |
| `grpc` | bool（默认开） | 代理 gRPC：经 HTTP/2 或 HTTP/3 到达、`Content-Type` 为 `application/grpc` 的请求以 HTTP/2 回源 |
| `origin_check_path` / `origin_check_interval` | 路径（默认空，最长 256 字节）/ 秒（默认 30，10–3600） | 源站主动健康检查：每个节点按这个间隔向区域里已代理的 A/AAAA 记录的每个地址发 GET 请求这个路径（按访客访问该名字的方式连过去，5 秒超时，User-Agent `fucf-health/<版本>`；回源规则改送别处的地址、通配符名字和暂停的区域不查）。2xx/3xx 算通过，连续两次失败（无应答或别的状态码）的地址排到最后，通过一次就恢复；`GET /zones/{id}/origins/health` 查看本节点的检查结果（`name`、`address`、`healthy`、`failures`、`checked_at`、`detail`；面板：域名 → SSL/TLS → 源站健康） |
| `cache_tier_node` | 节点名（默认空） | 分层缓存：其他节点的 GET/HEAD 请求经这个节点回源（HTTPS，按访客的方式请求它），它的缓存供全机群共用，源站只被它请求；该节点刚失败过时改为直接回源。建议选离源站近的节点。保存时不检查节点是否存在：写的不是机群里的节点、在它自己身上、或请求已被回源规则或记录的 `origin.node` 送去别处时，不分层（面板：域名 → 缓存 → 分层缓存） |
| `cache_chunking` | 字节（默认 0） | 大文件分片缓存：不小于这个大小的对象按 512 KiB 一片存进边缘缓存，Range 请求只读涉及的片；0 为关闭，否则 524288 到 33554432（见"缓存"里的"大文件分片"；面板：域名 → 缓存 → 大文件分片） |
| `early_hints_links` | 字符串数组（默认空，最多 16 条） | 预加载提示：给这个域名的 HTML 页面（200 应答）加上 `Link` 头，见"预加载提示（代替 Early Hints）"（面板：域名 → 缓存 → 预加载提示） |
| `image_resizing` | bool（默认关） | 图片缩放：`/cdn-cgi/image/<参数>/<路径>` 返回本站图片缩放、转换格式后的结果，见"图片缩放"（面板：域名 → 缓存 → 图片缩放） |
| `session_affinity` | bool（默认关） | 会话保持：同一个访客地址总是从同一个源站地址开始（同名的地址不变时）；该地址检查失败或刚拒绝过连接时照常换下一个。各地址分到的比例由记录的 `origin.weight` 决定（见"高级回源"） |
| `dns_transfer_to` | 地址或网段数组（默认空，最多 16 个） | 允许做区域传送（AXFR）的辅助名称服务器，如 `["192.0.2.53", "2001:db8:53::/48"]`，见"DNS：更多记录类型、辅助名称服务器、查询统计"（面板：域名 → DNS 记录 → 区域传送） |
| `email_routing` | bool（默认关） | 启用该区域的电子邮件路由（需配合开启 `--smtp-listen` 的节点与 MX 记录） |
| `decoy_subdomains` | bool（默认关） | 伪装子域：没有记录的名字也能解析，但边缘不应答（见"伪装子域"） |
| `auto_firewall` 及 `auto_firewall_*` | 见"自动防火墙" | 按近期安全事件自动封禁地址、网络，或切到受攻击模式 |
| `auto_level_restore` / `auto_level_until` | 字符串（默认空）/ unix 秒（默认 0） | 自动防火墙把区域切到受攻击模式期间自己记下的：恢复成哪个级别、到什么时候；不用手动设置 |
| `error_pages` | 对象（默认 `{}`） | 自定义错误页：键为 `5xx` / `block` / `ratelimit` / `1xxx`，值为 HTML（见"自定义错误页"） |

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
  `cf.threat_score`（或 `fcf.threat_score`，见"安全级别、IP 纯净度与页面内人机验证"）`fcf.ja4`（或 `cf.bot_management.ja4`，见"TLS 指纹（JA4）"）
  `cf.tls_client_auth.cert_verified`（或 `fcf.client_cert_verified`，访客出示了经节点验证的客户端证书，见"访客客户端证书（mTLS）"）
- 运算符：`eq ne contains matches in lt le gt ge`（及 `== != ~ < <= > >=`），`and or not`（及 `&& || !`）
- 函数：`lower() upper() url_decode() len() starts_with(x,"p") ends_with(x,"s")`
- IP 列表：`ip.src in $office`（见下面的"IP 列表"）。
- 空表达式匹配所有请求。

防火墙动作：`block`、`js_challenge`（人机验证，浏览器看起来可疑时才要点击）、`managed_challenge`（总是要点击一次）、`log`、`skip`（放行并跳过限速与托管规则）。按 `priority` 升序执行。

## 面板、节点与调度

面板在管理 API 的根路径（`http://127.0.0.1:8787/`），设置了 `--panel-host` 时也可经边缘的 HTTPS 访问；用 API 令牌登录。

**接入模式**（区域的 `type`，可在面板里切换）

- `full` 完全托管：把域名的 NS 指向本服务，所有记录在这里管理，代理记录直接解析到边缘节点。
- `partial` CNAME 接入：域名留在原 DNS 服务商，把主机名 CNAME 到 `<名字>.<cname-base>`，由本服务解析到边缘节点。

**节点分配**：每个节点登记 IPv4/IPv6 和它负责的大洲。解析代理记录时按访客位置（优先用 EDNS Client Subnet）选节点：

1. 调度规则按 `priority` 升序匹配访客的国家、大洲、ASN 或运营商名；`route` 规则回答 `nodes` 列表里第一个健康的节点（列表顺序即故障切换顺序），`fastest` 规则回答实测最快的节点（见"实测调度与故障切换"）。
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

- 记录类型增加 `HTTPS`、`SVCB`、`TLSA`、`SSHFP`、`DS`、`NAPTR`、`URI`，内容按区域文件的写法填在 `content` 里（带空格的部分加双引号，存的是原样）：

  | 类型 | `content` |
  |------|-----------|
  | `HTTPS` / `SVCB` | `优先级 目标 [键=值 ...]`，如 `1 . alpn=h2,h3 port=443 ipv4hint=192.0.2.1`（`.` 表示记录自己的名字）；键有 `alpn`、`no-default-alpn`、`port`、`ipv4hint`、`ipv6hint`、`ech`（base64），每个最多一次；优先级 0（别名形式）不能带键 |
  | `TLSA` | `用途 选择器 匹配类型 数据`，数据为十六进制 |
  | `SSHFP` | `算法 类型 指纹`，指纹为十六进制 |
  | `DS` | `密钥标签 算法 摘要类型 摘要`，摘要为十六进制：委派出去（有 NS 记录）的子域的 DS，在该名字上应答 |
  | `NAPTR` | `顺序 优先 "标志" "服务" "正则" 替换`（替换为 `.` 表示没有） |
  | `URI` | `优先级 权重 "目标"` |

  `data` 写法仍只用于 SRV 和 CAA。已代理的名字上，HTTPS 查询由边缘回答自己的记录（通告 HTTP/3、HTTP/2），区域里填的 HTTPS 记录不会出现。
- 区域设置 `dns_transfer_to`：允许做区域传送的辅助名称服务器地址或网段（`地址/前缀`），最多 16 个；面板：域名 → DNS 记录 → 区域传送（逗号分隔，留空为不允许）。
  - 只有 TCP 上的 AXFR（每个节点的 `--dns-listen`），没有 IXFR，也没有 TSIG：地址是唯一的凭据，所以尽量写辅助服务器的具体地址，别写大网段。
    不在列表里的地址、开启了 DNSSEC 的区域（签名是按查询在线做的，没有现成的签名可传）一律回答 `REFUSED`。
  - 传给辅助服务器的内容同样隐藏源站：代理的名字（区域没暂停时）不给它的 A/AAAA/CNAME，而是给出全部非加速节点的地址（TTL 300），因为辅助服务器上没有按访客调度。
  - 区域的序列号变了约 2 秒后，每个非加速节点都向列表里的单个地址（网段不发）的 UDP 53 端口发一次 NOTIFY，不重发、不等回复，辅助服务器收到就立即来取。
    NOTIFY 总是开着，没有开关参数。
  - 把辅助服务器放在别的服务商，整个机群不在时域名仍可解析。例：`PATCH /zones/{id}/settings/dns_transfer_to {"value": ["192.0.2.53"]}`，
    再在 192.0.2.53 上用 `dig @ns1.example.net example.com AXFR` 试一次。
- `GET /zones/{id}/dns_analytics`：本节点自启动以来为该区域应答的查询数，如 `{"total": 1520, "by_type": {"A": 900, "AAAA": 400}, "by_rcode": {"NOERROR": 1500, "NXDOMAIN": 20}}`。
  UDP 和 TCP 的标准查询（IN 类）都算，按查询的类型（不认识的写成 `TYPE<n>`）和应答码（`NOERROR` / `NXDOMAIN` / `REFUSED`，其他为 `RCODE<n>`）拆分；
  不存在的名字即使在 DNSSEC 下以最小 NSEC 回答也记为 `NXDOMAIN`；区域传送不算。只在本节点内存里，重启清零，各节点各有一份。面板：域名 → DNS 记录 → 查询统计。

### 回源时出示客户端证书

`--origin-client-cert` / `--origin-client-key`（`FUCF_ORIGIN_CLIENT_CERT` / `FUCF_ORIGIN_CLIENT_KEY`，PEM）：回源的 TLS 握手里出示这张证书。
源站要求并校验客户端证书后，就只接受本机群的回源请求，别人即使知道源站地址也连不上。各节点用同一张证书。

### 访客客户端证书（mTLS）

节点用 `--mtls-ca <文件>`（`FUCF_MTLS_CA`，一张或多张 PEM 格式的 CA 证书）启动后，HTTPS 和 HTTP/3 监听在握手时向访客要这些 CA 签发的客户端证书，但不强制：
不出示证书的访客照常访问。出示了却验证不过（别的 CA 签的、过期了、不是客户端认证用的）的，握手直接失败，对这个节点上的所有主机名都一样。不配置时不要证书，TLS 和原来完全一样。
服务这类区域的节点应配同一个 CA 文件。

区域设置 `mtls` 为 `on` 时，没有经验证的客户端证书的请求一律 403，在区域的 `/cdn-cgi/`、各种规则和回源之前就拒绝。明文 HTTP、HTTP/3 前置以及其他看不到证书的入口都按没有证书算，
所以没配 `--mtls-ca` 的节点上这种区域拒绝所有人。面板自己的主机名和机群 ACME HTTP-01 质询的应答不受影响。
不管这个设置开没开，规则里都能用 `cf.tls_client_auth.cert_verified`（或 `fcf.client_cert_verified`）判断；`/cdn-cgi/fucf-trace` 的 `client_cert=` 显示 `verified` 或 `none`。
CA 是节点级的，不是区域级的：它签发的证书能通过所有开了 `mtls` 的区域。面板：域名 → SSL/TLS → 访客客户端证书。

### 源站 CA

每个区域可以有一个自己的私有 CA，为源站签发证书，源站不用公共 CA 也能提供 HTTPS（类似 Cloudflare 的 Origin CA）。`POST /zones/{id}/origin_ca` 创建，已有时 409；
换 CA 要先 `DELETE` 再 `POST`，旧 CA 签的证书随之失效。`GET` 返回 CA 证书、名称、创建时间和到期时间，任何接口都不返回 CA 私钥（它随区域配置保存，和 DKIM 私钥一样，所以每个节点都能签）。
CA 有效期 20 年，名称约束在本区域，只签服务器证书（扩展用途只有 `serverAuth`），所以它签的证书不能当访客客户端证书用。

`POST /zones/{id}/origin_ca/sign` 签发：`hostnames`（或 `names`）1–50 个名字，必须是区域本身或其下的名字，通配符只能写在最前面（`*.example.com`），不能是 IP；
`days`（或 `requested_validity`，必填）1–5475 天，到期时间超过 CA 的不签。返回 `certificate`、`private_key`（为这张证书新生成，平台不保存，只显示这一次）、`ca_certificate`、
`hostnames`、`requested_validity` 和 `expires_on`。源站装上后，回源用 `ssl` = `full`；`strict` 只认公共 CA。API 令牌需要 SSL and Certificates 读/写权限。
面板：域名 → SSL/TLS → 源站 CA。

### TLS 指纹（JA4）

每条 TLS 连接的 ClientHello 会算出 JA4 指纹（协议版本、加密套件、扩展、签名算法的组合）：浏览器、命令行工具和攻击工具的指纹各不相同，与它们自称的 User-Agent 无关。
规则表达式里用 `fcf.ja4`（或 `cf.bot_management.ja4`）匹配，例如 `fcf.ja4 eq "t13d1516h2_8daaf6152771_02713d6af862"`；`/cdn-cgi/fucf-trace` 的 `ja4=` 显示当前连接的指纹。
明文 HTTP、经 HTTP/3 或 HTTP/3 前置进来的连接没有指纹（为空）。

### 预加载提示（代替 Early Hints）

不发 103 Early Hints：hyper 1.x 的服务端发不出 1xx 中间应答（HTTP/1 编码器会把它换成 500，一个请求也只能回一个应答）。
替代办法是区域设置 `early_hints_links`：每条是一个 `Link` 头的写法，边缘把它们合成一个 `Link` 头，加在这个域名内容类型为 HTML 的 200 应答上（源站自己的 `Link` 头保留，资源、重定向、错误页、边缘自己的页面都不加）。
提示和页面的响应头一起到，在页面主体还在路上时起作用，源站还没出页面时帮不上忙。

```json
["</app.css>; rel=preload; as=style", "</fonts/a.woff2>; rel=preload; as=font; crossorigin", "<https://cdn.example.com>; rel=preconnect"]
```

只接受两种写法：`<URL>; rel=preload; as=类型` 和 `<URL>; rel=preconnect`，都可再加 `crossorigin`（或 `crossorigin=anonymous` / `use-credentials`）；参数不加引号，顺序、大小写随意，保存后按统一写法发出。
`URL` 是站内路径（`/app.css`，不能以 `//` 开头）或 `https://` 地址，只能是可见 ASCII，不能含空格、引号、逗号、分号、尖括号、反斜杠；`as` 取 `audio`、`document`、`embed`、`fetch`、`font`、`image`、`object`、`script`、`style`、`track`、`video`、`worker`。
最多 16 条，每条不超过 512 字节，合起来的头不超过 4096 字节，不合格的整个设置 400 并指出第几条。

### 图片缩放

区域设置 `image_resizing` 开启后，`https://<主机名>/cdn-cgi/image/<参数>/<路径>` 返回本站 `<路径>`（带上请求的查询串）的图片，缩放、重新编码后给访客；关闭时（默认）这种路径照常回源。

```sh
curl -sI https://example.com/cdn-cgi/image/width=400,format=webp/photos/a.jpg
```

原图按访客直接 GET `<路径>` 的方式取：防火墙、限速、等候室、各种规则、Worker、缓存看到的都是原图路径，不是 `/cdn-cgi/image/…`，所以拦了 `/photos/` 的规则也拦它的缩放图。
`<路径>` 只能是站内路径，或本主机名的 `http(s)://` 地址；别的主机名、`//…`、带用户名的地址、空路径和边缘自己的 `/cdn-cgi/` 路径返回 400，不能拿来代取别的网站。GET、HEAD 以外的方法返回 405。
参数用逗号分隔，不认识的参数和用不了的值忽略：`width` / `w`、`height` / `h`（像素，超过 4096 按 4096）；`fit` 取 `scale-down`（默认，放进框里，不放大）、`contain`（放进框里，可放大）、`cover`（铺满框，切掉多出的部分，可放大）、`crop`（同 `cover`，但比框小的原图只切不放大）、`pad`（同 `contain`，再居中放到框大小的画布上，JPEG 补白色，其他补透明）；`quality` / `q`（1 到 100，只对 JPEG，默认 85）；`format` / `f` 取 `jpeg`（或 `jpg`）、`png`、`webp`，`auto` 和其他值保持原图格式。
只给一边时另一边按原图比例。WebP 输出是无损的（纯 Rust 编码器没有有损模式）。按 EXIF 方向转正，保留 ICC 色彩配置，其余元数据去掉。

只处理 200 应答的 JPEG、PNG、WebP，原图不超过 16 MiB、5000 万像素（解码前从图片头读出，防解压炸弹），输出每边最多 4096 像素；每个节点同时只做两个，在阻塞线程上解码和缩放，排队超过 10 秒的直接给原图。
其他情况原样返回原图，带 `fcf-resized: original; <原因>`：`animated`（APNG、动图 WebP）、`unsupported`（别的类型）、`unchanged`（既没要尺寸，也没要换格式或 JPEG 质量）、`too-large`、`undecodable`、`busy`。原图路径上的错误、重定向和其他状态码原样传过去，不加这个头。
缩放结果带 `fcf-resized: <宽>x<高>`、自己的 `Content-Type`、`Content-Length` 和 `ETag`（`If-None-Match` 返回 304），以及 `fcf-cache-status: MISS` 或 `HIT`。
结果按原图内容和参数缓存，缓存时间跟原图能缓存的时间一样；原图不进缓存（`DYNAMIC`、`BYPASS`）时每次都重新处理。原图每次照样走一遍管道，边缘拿到新的原图（过期或被清除后）时，结果也跟着重新生成。

### 后量子密钥交换

TLS 用 aws-lc-rs 做密码学实现（HTTPS / HTTP/3 监听、回源、ACME、出站探测全部同一个），除 `X25519`、`secp256r1`、`secp384r1` 外还支持后量子混合密钥交换 `X25519MLKEM768`，不用配置。
TLS 1.3 下按访客客户端的偏好选：支持它的浏览器就用它，TLS 1.2 和不支持它的客户端照旧用 `X25519`；回源时优先报它，同时带一份普通 `X25519` 的密钥，源站不支持也不多一次往返。
`/cdn-cgi/fucf-trace` 的 `kex=` 显示本连接用的是哪个（明文 HTTP 和 HTTP/3 为空）。
编静态（musl）二进制时 aws-lc-rs 要编一份 C 代码，`musl-tools` 里的 `musl-gcc` 就够（`scripts/deploy/build-linux.sh` 和 CI 已经这样设置，不需要 cmake）；没有 C 编译器的机器编不出来。

### Bot 分

每个请求都有一个 1–99 的 Bot 分，方向和 Cloudflare 一样：1 几乎肯定是程序，99 几乎肯定是真人。规则里写 `fcf.bot_score`（或 `cf.bot_management.score`），
例如 `fcf.bot_score lt 30` 配人机验证或拦截；`/cdn-cgi/fucf-trace` 的 `bot=` 显示当前请求的分数。
分数由几项特征加减而来（评分表在 `src/edge/botscore.rs` 开头）：走了 TCP 上的 TLS 却拿不到 JA4 指纹、指纹是不是 TLS 1.3 + SNI + ALPN 的现代客户端、
威胁分、HTTP 版本、`User-Agent` / `Accept` / `Accept-Language` / `Accept-Encoding` / `Sec-Fetch-Mode` 在不在、UA 是不是 curl、python 之类的工具或爬虫。
分数里没有随机成分：威胁分相同，同一个请求在哪个节点都得同一个分。来自自家网络的搜索引擎爬虫固定 50 分（是程序，但别把它挡在外面）；只在 UA 里自称爬虫的按普通脚本算。
这只是经验规则，没有 Cloudflare 那样的机器学习，也没有 `verified_bot` 字段：拿不准时用人机验证，别直接拦截。

### DNS 响应限速与内核层封禁

- `--dns-rrl`（`FUCF_DNS_RRL`，默认 100，0 为关闭）：UDP 上对同一网络（/24、/56）同一名字每秒最多应答这么多次；超出的部分一半以截断（TC）应答，
  真正的解析器会改用 TCP 重试，其余丢弃。UDP 的来源地址可以伪造，不限速的权威服务器会被用来放大攻击别人。本机回环不限。
- `--ban-export 文件`（`FUCF_BAN_EXPORT`）：把自动防火墙当前封禁的地址（只含动作为拦截的规则）写成 nftables 脚本，每 30 秒检查、有变化才重写。
  fucf 自己没有改内核表的权限，也不替你决定封禁覆盖哪些端口：由宿主机用 `nft -f 文件` 加载（例如配一个 systemd path 单元），并自己加丢弃规则，如
  `nft add chain inet fucf input '{ type filter hook input priority -10; }'` 和 `nft add rule inet fucf input tcp dport { 80, 443 } ip saddr @banned4 drop`。
  注意同一台机器上的其他服务是否也该被这条规则覆盖。脚本里是 `inet fucf` 表的 `banned4`、`banned6` 两个集合，每个地址带着封禁剩下的时间（`timeout`）。
  目前只有 IPv4：自动防火墙对 IPv6 按 /64 封禁，这些网段还没有写进文件，`banned6` 总是空的。

### 限速的计数方式

- `characteristics`：区分客户端的依据，默认只按 `ip`；可选 `asn`、`country`、`host`、`path`、`header:名称`、`cookie:名称`，最多 4 个，组合成一个计数键（例如 `["header:x-api-key"]` 按 API 密钥限速）。
  大小写不限，存成小写（Cookie 名保留原样）；头名和 Cookie 名只能是字母、数字、`-`、`_`，最长 64。
  没带这个头或 Cookie 的请求按空值计，也就是这些客户端共用一个计数，并不会退回按 IP 算；要分开就把 `ip` 也写进去（如 `["ip", "header:x-api-key"]`）。`asn`、`country` 要有 GeoIP 库。
- `status_codes`：只统计以这些状态码应答的请求（如 `[401, 403]` 用来挡撞库；最多 20 个，100–599，写数字或字符串都行）。这类规则在应答之后计数，超限的客户端从下一个请求起被拦。
- 经 Rulesets API 时这两项是 `http_ratelimit` 阶段的 `characteristics` 和 `counting_expression`，对应关系见"Rulesets API（兼容 Cloudflare）"。
- 一个客户端在某个节点上被限速（封禁 10 秒以上）后，其他节点随上报得知，也照样拦它。
- 全机群计数是近似的，不保证精确：各节点随本来就有的上报（15–60 秒一次）把本节点最热的计数告诉其他节点——当前窗口里超过规则 `threshold` 一半的客户端，最多 64 个，附带计数所在窗口的结束时间。
  裁决时按"本节点计数 + 其他节点同一规则同一客户端计数之和 × 0.5"算，所以平均分散到 N 个节点上的客户端大约在限额的 N/2 倍时被拦（两个节点时是 4/3 倍），而不是 N 倍（不算上报延迟）。
  别的节点的计数到它的窗口结束就不再算；同一节点同一窗口再报一次是替换不是累加；自己的上报经别的节点绕回来不会再算一遍。
  每个节点都没超过一半的客户端不会被上报，上报也有延迟，所以仍可能放过超过限额的请求；各节点窗口不对齐，偶尔也会早一点拦。要硬性上限，就让这类客户端只走一个节点。
  内存有上限：本节点最多留 1024 个热计数，远端视图最多 4096 个客户端；计数键超过 512 字节的只在本节点计。
- 上报的计数键就是规则区分客户端用的值（访客地址、请求头和 Cookie 的值），只在机群自己经过认证的上报通道里传（`reports` 同步域里报告的 `rate` 字段），不写日志。旧版本节点不认识这个字段、直接忽略，滚动升级期间未升级的节点照旧只按自己的计数。

### 实测调度与故障切换

- 调度规则的动作除了 `route`（按顺序取第一个可用节点，`nodes` 必填）和 `block`，还有 `fastest`：解析到访客所在网络**实测最快**的节点。
  每个节点记录访客 TLS 1.3 / QUIC 握手的一次往返时间（要有 GeoIP 库），按网络（国家、省或州、运营商 AS 号，如 `CN-JS/4134`、`CN/4134`、`CN-JS`、`CN`）
  取滑动平均（新的一次占五分之一），随上报传给其他节点；DNS 用最精确且至少两个候选节点都有足够样本（5 次握手、一天以内）的那一级来比较，IPv4、IPv6 各选各的。
  `nodes` 是候选节点，留空为全部。数据不足时在候选里随机挑一个，有数据时也有 5% 的应答随机分给候选之一，以便持续测量。
  （TLS 1.2 的握手是两次往返，不计入；机群自己的节点不计；经 HTTP/3 前置进来的连接量不到访客的往返时间。）
- `GET /steering/measured` 返回全部实测数据，按网络、再按节点：`{"CN": {"hkg1": {"ms": 41.3, "samples": 87, "age": 12}}}`，
  `ms` 是滑动平均，`samples` 是计入的握手次数，`age` 是距最近一次的秒数；超过一天的不列出，什么都没测到时是 `{}`。每个节点最多记 4000 个网络。
  `GET /steering/test?ip=` 的 `measured` 是这个地址所在网络的排名（`{"network", "nodes": [{"name", "ms"}]}`，没有时为 `null`），面板的"定位"显示的就是它；"调度与 DNS 屏蔽"页下方的"实测延迟"表按节点列出全部实测数据。
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
| `/cdn-cgi/challenge-platform/widget.js`、`widget/ticket`、`widget/verify`、`siteverify` | 人机验证组件的脚本、出题、答题和后端校验（见“人机验证组件”） |

`fucf-trace` 的字段：前面是 Cloudflare 的键，含义相同——`fl`（`<dc>f<进程号>`）、`h`（主机名）、`ip`、`ts`、`visit_scheme`、`uag`、
`colo`（节点的 `colo`，没设时取节点名去掉末尾数字后大写）、`dc`（节点的 `dc`，没设时取节点名末尾的数字，默认 1）、`http`（`http/1.0` / `http/1.1` / `http/2` / `http/3`）、
`loc`（国家，未知为 `XX`）、`tls`（`TLSv1.3` / `TLSv1.2` / `off`）、`sni`（`plaintext` / `off`）、
`warp`（访客地址是本机群的节点时为 `fucf`，是 Cloudflare 的地址时为 `cloudflare`，否则 `off`）、`kex`（本连接的密钥交换组，如 `X25519MLKEM768`，见"后量子密钥交换"）；
后面是自有的——`ja4`（本连接的 JA4 指纹，见"TLS 指纹（JA4）"）、`ray`、`asn`、`zone`（该主机名所属且已代理的区域，否则 `-`）、
`limit`（本节点的限流状态）、`threat`（访客地址的威胁分）、`bot`（Bot 分，见"Bot 分"）、`client_cert`（`verified` / `none`，见"访客客户端证书（mTLS）"）、`region`（省或州，未知为空）。

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
- **托管（自动签发）**：`POST /zones/{id}/ssl/certificate_packs`，不带参数即为区域的根域名加通配符。持有 ACME 租约的那台节点（在线节点中名字最小的优先，租约 2 分钟，过期 30 秒后由别的节点接手）向 CA 下单、完成验证、
  把证书写进配置（随配置同步到所有节点），剩余有效期不足三分之一时自动续期；失败按 10 分钟起、逐次翻倍（最长一天）重试，
  原因写在 `error` 里，`PATCH` 可立即重试。续期失败期间继续使用原证书。
- 两者都没有时，为托管域名即时生成自签名证书。

验证方式（`validation_method`，默认 `auto`）：

| 方式 | 何时使用 | 前提 |
|------|----------|------|
| `dns`（DNS-01） | 通配符必须用它；`auto` 对完全托管（full）的区域也用它 | 域名的 NS 指向本服务。域名在别处托管时，在原 DNS 加一条 `_acme-challenge.<名字>` CNAME 到 `_acme-challenge.<名字>.<cname-base>`（接口返回值的 `dns_delegation` 列出了要加的记录），之后签发和续期都不用再动它 |
| `tls-alpn`（TLS-ALPN-01） | `auto` 对 CNAME 接入（partial）区域的普通主机名用它 | 该主机名的 443 最终到达本服务的 HTTPS 监听（按 SNI 透传的四层代理不影响） |
| `http`（HTTP-01） | 手动指定 | 该主机名的 80 到达本服务的 HTTP 监听 |

质询应答随配置同步到所有节点（CA 的多个验证点可能落在任何一个节点上），下单的节点等在线的其他节点都确认拿到之后才通知 CA 验证。
ACME 账户密钥只保存在下单节点自己的数据目录里，不同步。测试时可把 `--acme-directory` 指向 Let's Encrypt 的 staging 目录
`https://acme-staging-v02.api.letsencrypt.org/directory`，避免触发正式环境的频率限制。

### 自定义主机名（SSL for SaaS）

把别人的域名（例如 SaaS 客户的 `shop.example.net`）当作本平台的某个区域来服务，并为它自动签发证书。接口是 `/zones/{id}/custom_hostnames`
（`GET` 列表、`POST` 添加、`GET`/`PATCH`/`DELETE` 单条，没有 `PUT`），令牌权限是 SSL and Certificates 读/写；面板：域名 → SSL/TLS → 自定义主机名。

- **服务**：生效的自定义主机名走所属区域的整套处理：防火墙、规则、缓存和区域设置都生效，`http.host` 是自定义主机名本身，缓存按主机名分开；
  回源按 `custom_origin_server`（本区域下一个开启了代理的主机名，留空为区域根域名）的记录，`Host` 仍是自定义主机名。`PATCH` 只能改这一项。
- **名字的限制**：转成小写、去掉末尾的点，最长 253 个字符；不能是 IP、通配符、非 ASCII（国际化域名写 `xn--` 形式）或 CA 不会签的名字（`.test`、`.local`、单个标签等），这些返回 400。
  不能是本平台任何区域（不论属于谁）、区域之下或之上的名字，不能已是任何区域的自定义主机名（全机群唯一），也不能是平台自留的名字，这些返回 409。名字不能改，要换就删掉重建。
  每个区域最多 100 个；仅证书区域不能添加；DNS 在别处托管的区域只有配了 `--cname-base` 才能添加。
- **所有权验证**：平台不做对外 DNS 查询，也看不到别人的 DNS，所以由名字的所有者在自己的 DNS 加两条记录：名字本身 CNAME 到 `cname_target`，
  以及返回值里的 `dcv_delegation`：`_acme-challenge.<主机名>` CNAME 到 `_acme-challenge.<verify_txt>.<区域>`（DNS 在别处托管的区域再加 `.<cname-base>`）。
  `verify_txt` 是添加时随机生成的。签发只用 DNS-01，应答只发布在这一条自定义主机名的委派目标上，CA 顺着所有者的 CNAME 去查，
  所以只有所有者把委派指向本条目时才能验证通过。HTTP-01 和 TLS-ALPN-01 不用于自定义主机名：它们只能说明这个名字指到了机群的某个节点，指向别人的区域时也一样成立。
  CA 记得的旧验证会被撤销并让本次失败，一个区域验证过的名字不会把证书给到另一个区域。
- **状态**：`pending`（已添加）→ 有访客访问（纯加速节点以外的任一节点收到该 SNI 的 TLS 握手，或该 Host 的 HTTP 请求）之后才下单；
  签发成功 → `active`，开始服务；失败 → `failed`，原因写在 `error`，10 分钟起逐次翻倍（最长一天）重试，`failed` 不服务。
  `active` 在证书剩余三分之一有效期时自动续期，不需要访客；续期失败继续使用原证书。不是已添加的自定义主机名的 SNI 永远不会触发签发，也不写任何东西。
- **频率限制**：每个区域每小时最多 10 次、全机群每小时最多 30 次下单（含续期），每轮（每分钟一次，配置变化时也会）最多 3 个、逐个进行，由持有 ACME 租约的节点执行。
- 两个节点同时为两个区域接受了同一个名字时，较早创建的那个在所有节点上生效，另一个不服务也不签发。之后有人在该名字或其上级建了区域，区域优先：
  自定义主机名不再服务也不再续期。删除自定义主机名或其区域会一并删除证书。

## 请求处理顺序

区域设置 `mtls`（没有经验证的客户端证书则 403，到此为止）→ `/cdn-cgi/`（节点自己应答，到此为止）→ 节点硬限流（超限则到此为止）→ Host 匹配代理记录 → `always_use_https` → 防火墙规则 → Under Attack 质询 → 限速 → 托管规则 → 重定向规则 → 等候室 → 改写规则（请求侧）→ Worker 路由 → 缓存（缓存规则）→ 回源规则 → 源站 → 区域设置的响应头（HSTS、浏览器缓存时间）→ 改写规则（响应侧）→ 压缩。

- HTTP/3：与 HTTPS 同端口号的 UDP 上提供，HTTPS 响应带 `Alt-Svc` 头引导客户端升级；三种协议共用同一条处理链路。
- 压缩：客户端支持时对 1 KiB–8 MiB 的文本类响应做 brotli、zstd 或 gzip（源站已压缩的不动）。固定按 brotli → zstd → gzip 的顺序选，`q=0` 的不用；同时支持 br 和 zstd 的浏览器照旧拿 brotli，只支持 zstd 不支持 br 的才拿 zstd（级别 3）。zstd 用的是 C 库（zstd-sys），编译要有 C 编译器，静态（musl）构建照 aws-lc-rs 的设置用 `musl-gcc` 就够。
- 压缩副本入缓存：源站自己压缩的应答按访客接受的编码（br、gzip、zstd 三者，按 q 值算）分开存放，只发给接受同样编码的访客，不接受 zstd 的访客永远拿不到 zstd 副本；源站用访客没要的编码（例如给不支持 zstd 的访客发 zstd、发 deflate、没带 `Accept-Encoding` 也压缩）时照样转发，但不入缓存。
- 重验证：缓存过期且带 `ETag`/`Last-Modified` 时向源站发条件请求，304 则续期（`REVALIDATED`）；客户端的 `If-None-Match`/`If-Modified-Since` 可直接由缓存回 304。
- Range：缓存里有完整对象时，单段 Range 请求直接切片返回 206（`If-Range` 不匹配或多段时返回整个对象）；缓存里没有时原样转给源站，其应答不入缓存。
- 源站故障：源站连不上、超时或返回 500/502/503/504 时，过期不超过 24 小时的缓存副本照常返回（`STALE`）。
- 没有 `Content-Length` 的响应（如源站边压缩边发送）在 8 MiB 以内时读完后入缓存，更大的照常流式透传。
- 回源请求带 `fcf-ipcountry` 和 `cf-ipcountry`（访客国家，需要 GeoIP 库；客户端自带的同名头会被去掉）。
- gRPC：区域设置 `grpc` 开启时（默认），gRPC 请求以 HTTP/2 回源（源站用 TLS 时须支持 ALPN `h2`，明文时须支持 h2c），
  请求和响应都按消息流式透传（含双向流），响应 trailers（`grpc-status`）原样送达；一次调用没有时长上限，连接靠 HTTP/2 ping 保活。
  边缘自己拒绝或失败的请求（WAF、限流、源站不可达）以 gRPC 状态码返回而不是错误页。gRPC-Web 是普通 HTTP，不走这条路径。
- 故障转移：一个主机名有多条代理 A/AAAA 记录时按记录的 `origin.weight` 轮流（区域设置 `session_affinity` 开启时同一访客从同一个地址开始）；
  健康检查失败的地址（区域设置 `origin_check_path`）和 10 秒内拒绝过连接的地址排到最后，请求体已缓冲（≤1 MiB）时自动换下一个地址重发。
- 缓存规则：`cache: true` 让任意内容类型可缓存，`edge_ttl` 覆盖源站的 `Cache-Control`；`cache: false` 强制不缓存；`ignore_query: true` 让缓存键只含路径（不同查询串共用一份，回源时仍带着那次请求的查询串）。首条匹配生效。
  `ignore_query` 在 Rulesets API 里不显示，经它修改规则时保持原样。
- 自定义缓存键：缓存规则的 `cache_key_headers`（请求头名）和 `cache_key_cookies`（Cookie 名）让这些值也进缓存键，每个取值各存一份，
  适合按语言、设备或 Cookie 里的实验分组返回不同内容的源站。各最多 8 个名字；请求头名不区分大小写（存成小写），Cookie 名区分大小写；
  请求里没有的按空值算，同名 Cookie 取第一个，值里的控制字符会被去掉。加了这些值后键超过 2048 字节的请求不查也不存缓存（`BYPASS`），
  防止超长头把缓存撑爆；没配这两个字段的规则缓存键和以前完全一样。源站的 `Vary` 可以指向这些请求头（其他 `Vary` 照旧不缓存）。
  按 URL 或前缀清除时，同一 URL 的各个取值一起清掉。
- 清除缓存除 `purge_everything`、`files`、`prefixes` 外还可以给 `hosts`：清掉这些主机名下的全部对象（同区域的其他主机名不动）；或给 `tags`：清掉源站用 `Cache-Tag` 响应头（逗号分隔）标记过的对象，
  标签区分大小写、整个比较，该响应头随副本保存但不会发给访客。几种可以写在同一个请求里，命中任何一种的都清掉；`files` 和 `prefixes` 不看协议，HTTP 和 HTTPS 的副本一起清。
  返回 `{"id": 区域 id, "purged": 本节点清掉的对象数}`，其他节点随配置同步清除。
- `stale-while-revalidate`：源站的 `Cache-Control` 带 `stale-while-revalidate=N` 时，过期不超过 N 秒（最多一天）的副本先直接返回（`UPDATING`），同时在后台向源站取新副本（同一个对象同时只取一次）；
  Range 请求和后台队列已满时照常回源。
- 分层缓存：区域设置 `cache_tier_node`（见"区域设置"），其他节点的 GET/HEAD 都经那个节点回源。
- 大文件分片：区域设置 `cache_chunking` 设为 N 字节时，要入缓存的、声明了 `Content-Length` 且不小于 N、没有 `Content-Encoding` 的 200 应答
  按 512 KiB 一片存放（一条元数据存响应头、总长、新鲜度和标签，每片一条），访客拿到的应答与整份存放时完全一样（整个对象、单段 Range、`If-Range`、304、HEAD、416），
  Range 请求只读它涉及的片。内存层和磁盘层按片淘汰，大对象不必整份放得下（磁盘层不收超过其容量八分之一的单个对象）；节点状态里的对象数把片也算上。
  副本新鲜时缺了片，只向源站要缺的那几片：一个带 `Range`、`If-Range`（副本的强 `ETag`，没有就用 `Last-Modified`）和 `Accept-Encoding: identity` 的请求，
  只有正好是这段字节、总长和 `ETag`/`Last-Modified` 都对得上的 206 才用（`MISS`）；源站回 200（不支持 Range 或对象已变）就用这份完整应答、这一次整份存放；
  其他应答丢掉这份副本，请求照不分片的方式回源。没有校验值（或只有弱 `ETag`）的副本缺片时整份重取。每次填充都有自己的标记，片只和它所属的那次填充一起用，
  不会把两个版本拼在一起。过期副本只在请求要的片都还在时才按 `stale-while-revalidate`（`UPDATING`）或源站故障（`STALE`）返回，不做条件请求续期，而是整份重取。
  按 URL、前缀、主机名、标签或全部清除时片一起清掉，`purged` 里一个对象只算一次。关闭这个设置后，分片存放的副本按未命中处理，被整份的新副本替换。
  没变的：单个对象仍以 32 MiB 为上限；源站应答仍是整份读完才开始发给访客（边读边切片，切好的片直接用来应答）；没有 `Content-Length` 的应答整份存放；
  缓存里没有的对象收到 Range 请求时照旧原样回源、应答不入缓存。

- 缓存：默认只缓存静态扩展名（js/css/图片/字体等），或源站显式返回 `Cache-Control: public` / `s-maxage`；
  遵守 `no-store/private/no-cache`、`Set-Cookie`、`Vary`。响应头 `fcf-cache-status`: `HIT / MISS / EXPIRED / REVALIDATED / STALE / UPDATING / BYPASS / DYNAMIC`（边缘自己应答的为 `NONE`）。
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

- **隔离**：每个请求（以及每封邮件、每次定时触发）都新建一个 JS 上下文，上一个请求留下的全局变量、模块顶层变量、改过的原型、没结束的 Promise 到下一个请求都不在，两个脚本之间也什么都不共享。这是有意的：Boa 0.22 解析出的脚本绑在创建它的上下文（realm 和字符串表）上，不能跨上下文复用；只重置 realm 的话，新 realm 照样要建全部内置对象，前置脚本和用户脚本照样要重新编译，还会把上一个请求没跑完的任务带进下一个请求。要跨请求保存的东西放 KV 或 D1。
- **字节请求体**：`request.arrayBuffer()` / `request.bytes()` 原样拿到请求体的每个字节（`text()` / `json()` 照旧按 UTF-8 解码，坏的字节换成替换符）；`new Response(...)` 除了字符串还接受 `ArrayBuffer`、`Uint8Array`、`DataView` 等，构造时复制一份，二进制体不自动加 `Content-Type`。单个体不超过 16 MiB，一次执行交给边缘的字节体合计不超过 64 MiB。
- **上传与打包**：脚本只能是一个文件（`export default {...}`、esbuild 生成的末尾 `export { x as default };` 或 `addEventListener`），没有模块加载器，其他 `import` / `export` 上传时就被拒。`PUT` 也接受 wrangler 那样的 `multipart/form-data`：`metadata` 部分（JSON，`main_module` 或 `body_part` 指明脚本）加上恰好一个同名的 JavaScript 部分，存下的就是这个模块本身。多个模块、wasm / 文本 / 数据模块、source map、非空的 `bindings`、`assets` 一律 400，什么都不改；变量和 KV / D1 绑定用 `PATCH /workers/scripts/{name}/settings` 设置。所以先打成一个文件：`wrangler deploy --dry-run --outdir dist` 用 esbuild 打包、不调用任何接口，再用 curl 上传 `dist/` 里的文件（例子见 `docs/api.md`）。`wrangler deploy` 本身目前还走不完：上传前它要读 `/accounts/{id}/workers/services/{name}`，fucf 还没有这个接口。

## 电子邮件路由

为托管域名提供类似 Cloudflare Email Routing 的收信转发功能：节点通过 SMTP 接收发往域名的邮件，**不落盘、不存信**，在发件服务器等待 `DATA` 应答期间同步转交给目标邮箱——只有所有目标都收下才回复 `250`，临时失败回复 `451`（由发件方重试，5 天内对已送达的目标自动去重），永久拒收回复 `550`。

- **规则匹配**：支持本地名（如 `postmaster`，等价于 `postmaster@域名`）、完整地址（含子域）、`name+tag@` 自动归并到 `name@`（若有带 tag 的专属规则则优先）、以及 `*` 兜底规则。动作支持 `forward`（1–10 个外部邮箱，禁止转发回本域或本平台其他开启邮件路由的域）和 `drop`（收下后静默丢弃）。
- **SRS 发件人改写**：转发时用机群共享的 API 令牌对信封发件人做 HMAC-SHA256 签名，改写为 `srs0=<hash>=<stamp>=<原域>=<原本地名>@<本域>`（约 21 天有效），保证目标邮箱的 SPF 校验通过；退信（仅限空信封发件人 `MAIL FROM:<>`）落到任意节点都能验签还原并回投给原始发件人。
- **DKIM 签名**：在"电子邮件"页（或 `PATCH /zones/{id}/email`）填上选择器（`dkim_selector`，如 `fucf`）和私钥（`dkim_private_key`，未加密的 RSA 私钥，PKCS#8 PEM，2048 到 4096 位，可用 `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048` 生成）后，转发出去的信在交给目标之前加上本域名的 `DKIM-Signature`（`d=` 本域名，rsa-sha256，relaxed/relaxed，签 From、To、Cc、Subject、Date、Message-ID 等存在的头，From 多签一次防止被追加第二个 From）。面板和接口给出要添加的 TXT 记录：名称 `<选择器>._domainkey.<域名>`，内容 `v=DKIM1; k=rsa; p=<公钥>`，没有时会列进缺失记录里一键添加。私钥保存后不再显示，接口只回答 `has_dkim_private_key`；PATCH 里不带私钥（或为空）就保留原来的，`dkim_selector` 为 `null` 或空字符串则移除。没配置时信原样转发；没有 From 或有多个 From、签不了名的信照样转发，只是不带签名（记一条警告）。退回给原发件人的退信不签。ARC 封装还没有做。
- **DNS 记录与迁移**：面板的"电子邮件"页和 `GET /zones/{id}/email` 会检查该域名的 `MX`、`SPF` 与 DKIM 公钥记录，列出缺失项并支持一键添加；建议同时配置 `DMARC`（`v=DMARC1; p=quarantine; ...`）并在使用外部中继发信时配置对应中继商的 `SPF` / `DKIM`。邮件相关的 `MX` / `TXT` 记录都是普通的 `dns_records`，`email_rules` 存放在配置 `state.json` 中随副本同步自动复制，域名迁移或导入导出时会一并带走。
- **网络要求（云主机 25 端口）**：许多云厂商（包括 AWS EC2）默认封堵**出方向 TCP 25**，无法直连 Gmail / QQ 等目标的 MX:25。生产环境请配置 `--mail-relay` 走中继服务的 submission 端口（`587` STARTTLS 或 `465` 隐式 TLS，均强制校验证书）；若要接收公网邮件，需在收信节点开启 `--smtp-listen 0.0.0.0:25` 并确认防火墙 / 安全组放行入方向 TCP 25。

## 面板账户、两步验证与通行密钥

面板用账户登录。账户保存在数据目录的 `accounts.json`（权限 0600），不属于配置，但作为单独的一份在对等节点之间同步（纯加速节点不保存）。
API 令牌照旧可用（运维脚本、节点间同步、应急），拥有全部权限，不走两步验证。

- **初始化**：还没有任何账户时，面板要求填写邮箱、密码和本节点的 API 令牌，创建第一个管理员（`POST /auth/setup`）。
  也可以用令牌直接建：`POST /users {"email": "...", "role": "admin"}`，不带密码时系统随机生成一个并只返回这一次，对方首次登录必须改掉。
- **角色**：`admin` 全部；`editor` 改自己域名的配置（记录、规则等），不能改账户级的对象，也不能管用户、发布和节点操作；`viewer` 只读。最后一个管理员不能被降级、停用或删除。
- **密码**：至少 8 位，PBKDF2-HMAC-SHA256（60 万轮）加盐存储。连续输错 5 次起账户暂时锁定（1 分钟起，逐次翻倍，最长 15 分钟）。改密码后其他会话全部失效。
- **两步验证（TOTP）**：在"账户与安全"里用验证器 App 扫码，输入一次验证码后生效。之后登录先密码、再 6 位验证码（前后各容忍一个 30 秒窗口，同一个码只能用一次）。
- **备用验证码**：只是两步验证的替补，没开两步验证就没有。开启时发 10 个，用一个失效一个；可随时重新生成（要密码），旧的全部作废。只存摘要，只显示一次。
- **通行密钥（WebAuthn）**：可添加多个。两种用法：登录页"用通行密钥登录"（不输密码，要求密钥自己验证用户：指纹 / 面容 / PIN）；或输完密码后代替验证码。
  支持 ES256、RS256、EdDSA，校验来源、挑战、签名和计数器。只能在面板自己的 HTTPS 域名（`--panel-host`）或 `localhost` 下使用。
- **会话**：30 天，令牌只存摘要；"账户与安全"里能看到每个会话的设备、IP、登录方式，并逐个下线。
- **审计**：登录成败、改密码、两步验证和通行密钥的增删、用户管理、节点操作都有记录（最近 300 条，管理员可见）。
- 管理员可以给别人重置密码、清除两步验证（对方丢了手机时）。
- **域名归属（多租户）**：域名属于创建它的用户。不是管理员的用户（editor 和 viewer）只能看到、修改自己的域名，别人的域名在所有 `/zones/{id}/…` 接口上都按"域名不存在"返回 404，域名列表和总览统计也只算自己的。
  没有归属的域名（加这个功能之前就有的、用节点 API 令牌建的）只有管理员能看到；管理员能看到全部，并能在面板"管理"页或 `PATCH /zones/{id} {"owner": "<用户 id>"}` 里改归属（`null` 表示收回给管理员）。
  普通用户不能建和别人的域名重叠的域名（同名、子域或父域都不行）；账户级的对象（Workers、KV、D1、IP 列表、调度、节点等）只能看，只有管理员能改。用户的 API 令牌和 Global API Key 不会超出用户本人的范围。

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
/accounts/{id}/audit_logs                同 /audit；/accounts/{id}/rules/lists/... 和 /accounts/{id}/challenges/widgets/... 同名映射；其他路径 404（code 7000），别的账户 id 404（code 7003）
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

## Rulesets API（兼容 Cloudflare）

已有的规则也能按 Cloudflare 的 Rulesets API 读写，Terraform 的 `cloudflare_ruleset`、cf-terraforming 和照 Cloudflare 写的脚本可以直接用。
不另存一份：每个阶段的入口规则集就是下面这张表里那种规则的另一种写法；规则集 id 由域名和阶段算出来（各节点一样、永远不变），
规则 id 就是原来那条规则的 id。

| 阶段 | 对应 |
|---|---|
| `http_request_firewall_custom` | 防火墙规则 |
| `http_ratelimit` | 限速 |
| `http_request_dynamic_redirect` | 重定向规则 |
| `http_request_transform` / `http_request_late_transform` / `http_response_headers_transform` | 改写规则的路径 / 请求头 / 响应头 |
| `http_request_cache_settings` | 缓存规则 |
| `http_request_origin` | 回源规则 |

```
/zones/{id}/rulesets                                  GET 有规则的阶段；POST 新建（该阶段还没有规则时）
/zones/{id}/rulesets/phases/{phase}/entrypoint        GET；PUT {"rules": [...]} 整体替换，顺序即优先级
/zones/{id}/rulesets/{ruleset_id}                     GET PUT DELETE（DELETE 清空该阶段）
/zones/{id}/rulesets/{ruleset_id}/rules[/{rule_id}]   POST 加一条（可带 position）；PATCH 只改给出的字段；DELETE
```

- 这里做不到的字段或动作一律 400，并说明是哪个字段（如 `rules[2].action_parameters.uri.query`），不会悄悄丢掉；一次 PUT 要么全部生效，要么都不生效。
- `skip` 在这里会跳过其余自定义规则、安全级别、限速和托管规则，所以 `action_parameters` 至少要写 `ruleset: current`、
  `phases: [http_ratelimit, http_request_firewall_managed]`、`products: [securityLevel]`（或者不写）；只跳过一部分的 skip 会被拒绝，不会被放宽。
- 一条同时改路径、请求头、响应头的改写规则会出现在三个阶段里；经某个阶段修改只动那一部分，但表达式、描述和开关是共用的，
  它还在别的阶段时经单个阶段改这几项会被拒绝（请用 `/transform_rules`）。
- 限速的 `characteristics` 必须带 `cf.colo.id`（每个节点各自计数），另外可以加 `ip.src`（默认）、`ip.src.asnum`、`ip.geoip.country`、`http.host`、
  `http.request.uri.path`、`http.request.headers["名字"]`、`http.request.cookies["名字"]`；`counting_expression` 只能是规则自己的表达式加响应码，
  写成 `<表达式> and http.response.code in {401 403}`（表达式里有 `or` 时加括号），存为限速的 `status_codes`。
- 限速没有优先级，按创建顺序执行：可以在最后追加，不能重排。自动防火墙的规则不显示、不会被替换；回源规则的 `origin_node`、`origin_scheme`
  在 Cloudflare 里没有对应写法，不显示，修改时保持原样。
- 令牌：带阶段的路径（阶段名或规则集 id）要该阶段对应的权限；列表和 `POST /rulesets` 要 Firewall Services，POST 另外还要该阶段的权限。

## IP 列表（兼容 Cloudflare）

一组有名字的地址和网段，整个账户共用，任何域名的规则都可以写 `ip.src in $office`。接口照 Cloudflare 的账户列表
（`/accounts/{account id}/rules/lists…` 也能用），面板在账户导航的"IP 列表"里。

```
/rules/lists                         GET 全部；POST {"name", "description", "kind": "ip"}
/rules/lists/{id}                    GET；PUT / PATCH 改名字或说明；DELETE
/rules/lists/{id}/items              GET（?search=）；POST [{"ip", "comment"}] 追加；PUT [...] 整体替换；DELETE {"items": [{"id"}]}
/rules/lists/bulk_operations/{id}    条目改动返回的 operation_id，这里查到的总是 completed（改动在返回前已经完成）
```

- 名字只能是小写字母、数字和下划线，1 到 50 个字符，不能重名。只有 IP 列表：主机名、ASN、重定向列表一律拒绝。
- 条目是单个 IPv4 / IPv6 地址或 CIDR 网段。网段的主机位必须为零（`192.0.2.1/24` 会被拒绝，并提示应写 `192.0.2.0/24`）；
  `/32`、`/128` 存成不带前缀的地址；IPv4 映射的 IPv6 地址（`::ffff:192.0.2.1`）请直接写 IPv4。同一请求里重复的地址会被拒绝；
  追加已有的地址不会多出一条，给了备注就更新备注。
- 上限：100 个列表，每个列表 10000 条；说明和备注最多 500 个字符。
- 规则按名字引用列表，所以被规则用着的列表（无论规则是否启用、在哪个域名下）既不能删也不能改名，返回 409 并列出是哪些规则；
  规则里写不存在的列表名会被拒绝。万一名字暂时找不到列表（比如对等节点还没同步到），`ip.src in $名字` 不匹配任何地址，
  `not ip.src in $名字` 则匹配所有地址。
- 列表一改，用它的规则立即跟着变：快照重建时规则会用新的地址重新编译。
- 令牌：账户级的 Account Filter Lists Read / Write；只有域名权限的令牌碰不到列表。

## 请求日志

每个节点在内存里保留自己最近的 **5000 条**请求（所有域名合计，重启即清空，不写盘、不在节点之间同步）。
**日志含访客 IP**，另有时间、Ray ID、节点、主机、方法、路径（不含查询串，最长 512 字节）、状态码、缓存状态、字节数、耗时、
国家、ASN、User-Agent（最长 256 字节）、协议版本和被安全规则处理的动作（拦截 / 质询 / 限速）。

- 面板：域名 → 实时日志，每 2 秒用游标拉一次，可按状态码（`404` 或 `5xx`）和路径前缀过滤，离开页面就停。
- 接口 `GET /zones/{id}/logs/requests` **只回答应答这次请求的那个节点上的日志**；经面板域名访问时就是面板所在的节点，别的节点收到的请求看不到。
  带上一次返回的 `cursor` 作为 `since` 继续拉；游标比最旧的一条还旧时从最旧的开始（`gap: true` 表示中间有请求没来得及读就被挤掉了），
  比最新的还新（比如节点重启过）时什么都不返回，并给出当前最新的游标。参数写错或不认识一律 400。
- 推送：域名 → 实时日志 → 日志推送（`/zones/{id}/logpush/jobs`）。每个节点每 `batch_seconds` 秒（10–3600，默认 60）
  把自己收到的这个域名、状态码不低于 `status_min` 的请求以 NDJSON POST 到 `destination`。目标只能是 https，不能带用户名密码，
  不能是内网、本机地址（解析到这些地址的域名在连接时拒绝）；任务从它到达节点之后的请求开始推。
  10 秒内没有 2xx 应答就丢掉这一批，记一条警告，不重试。只有管理员能添加和修改推送任务。
- 令牌权限是 `Logs Read` / `Logs Write`；`Analytics Read` 看不到日志（日志里有访客 IP）。

## 等候室

源站扛不住时让访客排队（面板：域名 → 网络与协议 → 等候室，接口 `/zones/{id}/waiting_rooms`）。一个等候室管一个主机名下的一个路径前缀：
`/shop` 管 `/shop` 和 `/shop/` 下的路径，不管 `/shopping`；同一主机上前缀最长的生效，同一主机同一前缀只能有一个启用的，每个域名最多 20 个。

- 名额：同时在线 `total_active_users`（1–100000）个会话，任意 60 秒内最多放进 `new_users_per_minute` 个新访客（不能超过同时在线人数）。
  **名额按节点各自计算**：每个节点只数自己放进来和见过的访客，多个节点服务同一个域名时，源站看到的可能是名额的节点数倍。
- 放进来的访客拿到签名 Cookie `fucf_waiting_room`（全机群同一密钥，绑定等候室、随机访客号和到期时间；HttpOnly、SameSite=Lax，HTTPS 下带 Secure，Path 为路径前缀），
  在 `session_minutes`（1–30，默认 5）内直接通过；会话过半后再打开页面会续期，所以会话在最后一次打开页面后 `session_minutes` 分钟结束。伪造、过期、别的等候室的 Cookie 一律当作没有。
- 名额满或进入速率超限时返回排队页：状态码 200（与 Cloudflare 一致）、`Cache-Control: no-store`、`Retry-After: 20`，每 20 秒自动刷新，显示前面大约还有多少人。
  排队的访客拿到带到达时间的排队票 Cookie `fucf_waiting_ticket`，刷新时位置不变，先到的先放行；120 秒没刷新就算离开队伍，用过的票不能再用。
- 只有页面请求会排队；图片、脚本、接口请求和表单提交照常通过，`/cdn-cgi/` 和被防火墙 `skip` 规则放行的请求也不排队。
- 状态只在内存里，有上限，过期的会话和不再刷新的排队票会被清掉；重启后会话计数和队伍清空（Cookie 和排队票的到达时间仍然有效）。
- 令牌权限是 `Waiting Rooms Read` / `Waiting Rooms Write`。

## 自动防火墙

区域设置 `auto_firewall`（面板：域名 → 安全 → 自动防火墙，默认关）：每 30 秒看一次最近的安全事件——托管规则命中（拦截或记录）、防火墙拦截、限速——
在 `auto_firewall_window` 秒（默认 600）内攻击达到 `auto_firewall_threshold` 次（默认 10）的地址，被加进这个域名的一条自动规则
（`managed_by: auto_firewall`，表达式 `ip.src in {...}`，优先级 1000，动作 `auto_firewall_action`：block、managed_challenge 或 js_challenge），
封 `auto_firewall_ban` 秒（默认 86400）；期间继续攻击会续期，到期自动移出，空了规则就删掉。IPv6 按 /64 封；机群节点自己的地址和内网地址从不封；
最多 1000 个地址（保留最晚到期的）。只在面板所在的节点（没有 `--panel-origin` 的对等节点，每个对等节点都有全机群的安全事件）上运行，保证规则只有一个写入者，规则随配置同步到所有节点。
取值范围：`auto_firewall_threshold` 1–100000，`auto_firewall_window` 60–86400 秒，`auto_firewall_ban` 60–2592000 秒，`auto_firewall_network_ips` 2–100000，`auto_firewall_surge` 0 或 5–1000000。

另外两条自动维护的规则：
- 按网络：同一个 ASN 里有 `auto_firewall_network_ips`（默认 10）个机房 / VPN / 黑名单地址在攻击时，整个 ASN 的访客先点一下人机验证
  （`managed_by: auto_firewall_networks`；家庭宽带不会被整网处理；机群节点自己的地址除外）。`auto_firewall_networks=false` 关闭。
- 攻击潮：窗口内攻击地址数达到 `auto_firewall_surge`（默认 50，0 关闭）时自动进入受攻击模式，攻击停止一小时后恢复原来的级别。

## 告警

出事时主动通知（面板：告警）。通道有两种：Webhook（POST 一段 JSON）和 Telegram 机器人（机器人令牌加 chat id）。
只在面板所在的节点（没有 `--panel-origin` 的那台）上每 30 秒检查一次，触发和恢复各通知一次，持续触发时每 6 小时再提醒一次；
状态只放内存，重启后还在触发的会重新通知一次。

| 事件 | 什么时候触发 |
|---|---|
| `node_offline` | 启用的节点连续 3 次检查不在线；进程启动后 2 分钟内不算，之后重新数 |
| `sync_lagging` | 节点在线，但已经 5 分钟没有用上最新的配置版本 |
| `certificate_failing` | 证书包签发失败（一张证书都没有），或者在用的证书 14 天内到期 |
| `traffic_limit` | 节点流量到档（`dns_limited` / `throttled` / `limited`），换档会再通知 |
| `under_attack` | 域名被自动防火墙切到受攻击模式（手动开的不算） |
| `origin_errors` | 某域名 5 分钟内有 3 次回源错误事件；之后整整 5 分钟没有回源错误才算恢复 |

```
/alerts/channels[/{id}]       GET POST PUT PATCH DELETE   {"name", "kind": "webhook|telegram", "enabled", "events": [...], "url", "bot_token", "chat_id"}
/alerts/channels/{id}/test    POST                        发一条测试消息（停用的通道也能测）
/alerts/active                GET                         当前触发中的告警（不做检查的节点上 evaluating 为 false）
```

- Webhook 只接受 `https://`，不能指向内网、回环或保留地址，也不能带用户名密码；域名解析到内网地址时同样不发，不跟随跳转。
- `events` 至少选一个；未知的事件名会被拒绝。最多 20 个通道。改通道要管理员；API 令牌要 Notifications Read / Write（Fleet 权限不包括它）。
- 接口返回里令牌显示为 `***`、Webhook 地址只显示到域名（`https://host/***`）；原样送回打码后的值（或留空）会保留原来的，
  所以面板里改别的字段不会弄丢密钥。通道随配置同步、也在备份里，密钥一起。

## 人机验证组件（兼容 Turnstile 的用法）

把边缘的人机验证（检测和计算与区域的验证是同一套）放进网站自己的表单，网站后端再来问令牌是不是真的（面板：人机验证）。
组件属于整个账户，id 就是公开的 sitekey；密钥只在创建和轮换时显示一次，存下来的只是它的 SHA-256。

```
/challenges/widgets[/{sitekey}]          GET POST PUT PATCH DELETE   {"name", "domains": [...], "mode": "managed"}
/challenges/widgets/{sitekey}/rotate_secret   POST                    换新密钥，旧的立即失效（不支持宽限期）
/cdn-cgi/challenge-platform/siteverify   POST                         后端校验：secret、response、remoteip（可选）
```

```html
<script src="/cdn-cgi/challenge-platform/widget.js" async defer></script>
<div data-sitekey="0123456789abcdef0123456789abcdef"></div>
```

- `domains` 写完整的主机名（如 `shop.example.com`），1 到 10 个，不支持通配符；只有其中开了代理的主机名才发题，答题也必须回到同一个主机名，
  不开放跨域。通过后令牌写进容器里隐藏的 `fcf-challenge-response` 字段，随表单一起提交。
- 令牌 5 分钟内有效，绑定 sitekey、主机名和访客 IP，同一节点只认一次（换节点校验同一个令牌可能再认一次，所以每个令牌只校验一次）；
  给了 `remoteip` 就必须和拿令牌时的地址一致，比 Turnstile 严。错误码同 Turnstile：`missing-input-secret`、`invalid-input-secret`、
  `missing-input-response`、`invalid-input-response`、`timeout-or-duplicate`、`bad-request`、`internal-error`。
- siteverify 只走 HTTPS（本机回环除外），开了代理的主机名和面板域名上都能用；密钥不对时什么也不说，连 sitekey 存不存在都不说。
- 令牌不能当区域验证的通行 Cookie 用，反过来也不行。改组件要管理员；API 令牌要 Turnstile Sites Read / Write。

## 安全级别、IP 纯净度与页面内人机验证

- `security_level`：`off`（`essentially_off` 在这里与它相同）/ `low`（简易：威胁分 ≥ 80 要验证）/ `medium`（中等：≥ 50）/ `high`（严格：≥ 25，含机房 IP）/ `under_attack`（受攻击模式：所有人）。
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
- 响应头一律用 `fcf-` 前缀（`fcf-cache-status`、`fcf-mitigated`，以及 `fucf-ray`），不发任何 `cf-` 开头的头；源站在 Cloudflare 后面时它发的 `cf-*` 会被去掉。
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

## 自定义错误页

区域设置 `error_pages`（面板：域名 → 安全 → 自定义错误页）：用自己的 HTML 替换边缘自己写的错误页。值是一个对象，键只能是下面四个，
每个 HTML 最多 64 KiB（65536 字节，按 UTF-8 字节数算）；写成空字符串等于没设，用默认页。整个对象一次替换，`{}` 清空全部。

| 键 | 替换哪种页面 |
|----|------|
| `5xx` | 边缘回源失败时自己写的错误页：502、521、522、525、530（源站发来的 5xx 原样转发，不替换） |
| `block` | 防火墙拦截页（403：托管规则和动作为 `block` 的防火墙规则） |
| `ratelimit` | 限速页（429） |
| `1xxx` | 节点为这个域名的请求写的其他提示：请求无效或读不出（400）、请求体过大（413）、没开 HTTP/3（421）、Worker 出错或繁忙（500、503）等 |

模板里可以用这些占位符，每个都只替换一遍（值里即使带着占位符的样子也不会再展开），除 `::ERROR_BOX::` 外的值都做 HTML 转义
（`& < > " '`），放在文本里或引号属性里都安全：

| 占位符 | 值 |
|--------|----|
| `::RAY_ID::` | 这次请求的 Ray ID（与响应头 `fucf-ray` 相同） |
| `::STATUS::` | 状态码 |
| `::CLIENT_IP::` | 访客 IP |
| `::HOST::` | 访客请求的主机名 |
| `::NODE::` | 节点所在地（默认页上"节点"那一栏，如 `SIN`） |
| `::ERROR_BOX::` | 默认页的主体：默认页的样式表加 `<body>` 里的全部内容（双语说明、请求路径、Ray ID），原样插入；里面来自请求的值在生成默认页时已转义 |

只替换给浏览器看的页面：gRPC 请求、`fetch` / XHR / API 请求（`Sec-Fetch-Mode` 不是 `navigate`，或 `Accept` 里没有 `text/html`）、
人机验证页都保持原样；还没认出是哪个域名的请求就写出的页面（未知主机名、`/cdn-cgi/`、循环、节点流量用尽、"节点正在更新"）也不替换。响应的状态码和响应头不变
（`Retry-After`、`Cache-Control: no-store` 等照旧），只换响应体，`Content-Type` 为 `text/html; charset=utf-8`。

```sh
curl -s -X PATCH "http://127.0.0.1:8787/client/v4/zones/$ZONE/settings/error_pages" -H "Authorization: Bearer $TOKEN" \
  -d '{"value": {"5xx": "<h1>稍后再试</h1><p>状态 ::STATUS::，Ray ID ::RAY_ID::</p>"}}'
```

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

### 兼容性验证（草稿）

`.github/workflows/compat.yml` 用照 Cloudflare 写的真实工具检验 API 的兼容性。它只能在 Actions 页面手动启动（`workflow_dispatch`），
不随推送或 PR 运行，也不用任何仓库密钥。先编译一次 fucf，之后每个工具一个互不依赖的作业：各自在本机启动一个临时 fucf，
通过 API 建管理员和只带所需权限的 API 令牌，让工具指向 `http://127.0.0.1:8787/client/v4`，最后用 curl + jq 经 API 核对结果。

| 作业 | 工具 | 做什么、核对什么 |
|---|---|---|
| `terraform` | Terraform + cloudflare provider v5 | 建域名、两条记录、两个阶段的规则集（Rulesets API）；核对对象、边缘确实拦截；再 `plan` 必须没有差异；`destroy` 后域名不在 |
| `wrangler` | wrangler | `wrangler deploy` 一个 Worker；核对存下的是脚本本身，加路由后边缘返回它的输出 |
| `dns01` | lego（cloudflare DNS 插件）+ 本地 pebble | 走完整的 DNS-01：TXT 经 API 写入、由 fucf 的 DNS 应答、pebble 验证、lego 删除；核对证书已签发、记录已删 |
| `ddns` | ddclient（cloudflare 协议） | 经边缘的 HTTPS 面板主机（自签证书）更新一条 A 记录；核对 API 和 DNS 里都是新地址 |

工具版本都钉死（Terraform 和 ddclient 校验 SHA-256，Go 模块经校验和数据库，npm 包经 registry 的完整性哈希），
示例数据只用 `example.com` / `example.net` / `*.test` 和文档地址段。这份工作流是在没有运行过的情况下写的，
第一次实际运行后还要按日志调整（各作业的日志作为 artifact 上传）。已知会失败的两处：wrangler 上传前要读 `/accounts/{id}/workers/services/{name}`，fucf 还没有这个接口；ddclient 请求的 `/zones/?name=…` 带结尾斜杠，fucf 不认，两处都返回 404。

## 已知限制

- 多节点：对等节点之间双向同步，冲突按混合逻辑时钟后写者胜（同一对象几乎同时在两处修改时，只留下一处的修改）；缓存是各节点各自的内存状态，限速计数各节点各算、只近似地合计其他节点的计数（见"限速的计数方式"）。
  分析数据和安全事件每 2 分钟及退出时落盘，进程被强杀会丢最后这一段；对端保留各节点上报的时间有限（6 小时、16 MiB），离线更久的节点回来后拿不全。
  纯加速节点不落盘、不能修改配置，所有对等节点都联系不上时按最后一次拿到的配置服务。
  ACME 签发和续期由在线对等节点里选出的一个负责（租约），没有在线的对等节点时不会续期。
- 调度：健康检查只到 TLS 握手为止，不发 HTTP 请求；GeoIP 精度到国家、ASN 和（中国大陆，需 ip2region 库）省份，没有城市级调度。
- 证书：ACME 客户端只支持 ECDSA P-256 账户和证书密钥，不支持 External Account Binding（需要它的 CA 如 ZeroSSL 用不了）；
  对真实 CA 只实测过 Let's Encrypt（staging 和正式）的 TLS-ALPN-01；DNS-01 和 HTTP-01 目前只有模拟 CA 的自动化测试；HTTP/3 (QUIC) 监听不应答 TLS-ALPN-01（CA 只走 TCP，不影响签发）。
- 滚动更新：自检只查本机（监听、API、DNS 有应答，副本联系得上主节点），查不出"能应答但答错了"的版本；主节点换自己时
  面板和 API 中断几秒，期间副本按已有配置继续服务；被判定卡住的节点（收到回退许可 1 分钟没动静）不再等它，要人工处理；
  发布的二进制在主节点内存里过一遍（上传和下载各一份），小内存机器上注意 `MemoryMax`。
- HTTP/3 前置：经前置入口进来的 gRPC 不按 gRPC 处理（中间那一跳是 HTTP/1.1，带不了 trailers）；WebSocket 不经过它
  （HTTP/3 没有升级）；请求和响应都多一次本机转发。
- DNS：区域传送只有 TCP 上的 AXFR（没有 IXFR、TSIG，按来源地址放行），开启 DNSSEC 的区域不能传送；查询统计只在各节点内存里，重启清零；DNSSEC 只支持在线签名（ECDSA P-256，算法 13，NSEC 用最小否定应答）；CNAME 拉平的外部目标靠系统解析器，拿不到 TTL，固定每分钟刷新、以 60 秒 TTL 应答，刚建好的记录要等第一次解析完成才有应答。
- 缓存：单个对象上限 32 MiB（未声明长度的 8 MiB），分片存放（`cache_chunking`）也一样；Range 请求只在缓存里已有这个对象时由缓存应答，不会为它去源站拉完整对象；多段 Range 返回整个对象；
  要入缓存的应答整份读完才开始发给访客，分片存放也还不是边收边发。
- 0-RTT（TLS 1.3 early data）：HTTPS 和 HTTP/3 都不支持，也没有开关。会话票据是全机群通用的无状态票据，rustls 只在有状态的会话恢复下才接受 early data（防重放）；
  而 TCP 上的 TLS 库（tokio-rustls）总是握手全部完成后才把数据交给 HTTP 层，从不读出 early data，硬开的话被接受的 early data 会被丢掉、请求挂住，即使改成握手后再读也省不下任何往返。要做得自己驱动握手，留待以后。
- 回源除 gRPC 用 HTTP/2 外主要为 HTTP/1.1。
- gRPC：经 Worker 路由的请求不走 gRPC 路径；请求侧的 trailers 不转发；WAF 不检查 gRPC 请求体。
- 节点限流：只计响应体字节（不含请求体、响应头、TLS 开销），WebSocket 升级后的数据和 Spectrum 不计量也不限速；
  没有手动清零用量的接口（调高上限即可解除）；改 `traffic_reset_day` 使周期起点后移时用量清零；
  DNS 避让受解析缓存 TTL 影响（`--edge-ttl`，默认 300 秒），不是立刻生效；主节点不可用时，副本的超限状态传不到其他节点的 DNS。
- 压缩：未知长度（流式）的响应不压缩。
- 源站：主动健康检查要给区域设了 `origin_check_path` 才有，各节点各查各的，只查已代理的 A/AAAA 地址（CNAME 指向的地址不查）；超时不会重发请求。
- 分析：按国家 / 主机名 / 路径的拆分只保留 7 天，每小时每个维度只留排名靠前的若干项（其余并入"(other)"）；DNS 查询数（`dns_analytics`）不进时间序列，也不在节点之间汇总。
- 封禁导出（`--ban-export`）：只写 IPv4 的封禁，按 /64 封的 IPv6 还没有写进文件。
- WAF：托管规则是一组正则，不是完整的 OWASP CRS；请求体只检查不超过 1 MiB 的。
- Workers：每个请求新建 JS 上下文（无全局状态复用，每次都要重新编译前置脚本和用户脚本）；只支持单文件脚本，
  `wrangler deploy` 还走不完（缺 `/workers/services/{name}`），要先打包再用 curl 上传；不支持流式 API；
  单请求最多 50 个子请求，体积上限 16 MiB。
  CPU 限制靠循环次数上限，墙钟超时 30 秒后向客户端返回 500，但脚本线程要到自身结束才释放。
- Spectrum：所有应用共用边缘 IP，同一协议端口只能被一个应用占用；UDP 会话空闲 60 秒回收。

## 致谢

感谢 [LINUX DO 社区](https://linux.do) 对本项目的启发、交流与支持。
