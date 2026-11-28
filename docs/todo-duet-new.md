# todo-duet-new.md：追加任务单（第二批）

**先读 `docs/todo-duet.md` 的第 1、2 节**：那里的大部分规则适用于本文件——只在 `duet` 分支提交、不碰 `master`/`next`、公开仓库只用示例地址、没有编译器时的写法约束、交接记录格式。**两处规则有变，以本文件为准**：

1. **依赖**：原来禁止新增依赖。现在 N7–N10 明确点名需要的依赖可以加（只加点名说明的），版本钉死、不用 `*`/`latest`，优先选发布超过一周的版本。`Cargo.toml`/`Cargo.lock` 只在加依赖的任务里改。
2. **核心文件**：原来不许碰 `src/edge/`、`src/tls` 等核心文件，是因为另一方在并行改。现在核心工作**全部转交给你**，不再有人并行写核心代码，核心文件可以改，但仍要坚持小步提交、开始前 `git pull --rebase origin duet`、每步在交接记录里写清楚。

**顺序**：先把原任务单的 T2–T10、T12、T13 做完（T11 已取消），再做本文件 N1–N5，最后做 N6–N13。N6–N13 是核心大手术，盲写风险高，每一个都要格外照抄现有写法、多写单元测试。

## 0. 现状（避免做重）

`next` 分支上已经写完并推送的功能（只编译过，测试最后统一跑）。**不要重复实现**，但 N3/N4/N5 要为它们写界面、文档和 e2e：

| 功能 | 对外接口 / 位置 |
|---|---|
| 实测调度：节点记录访客握手往返时间 | `GET /steering/measured`（`{"records": [{"net","node","ms","at"}], "now"}`）；调度规则动作新增 `fastest`（面板已有） |
| TLS 会话票据全机群通用；`--edge-ttl` 对代理记录也生效 | 无新接口 |
| 源站主动健康检查、权重、会话保持 | 域名设置 `origin_check_path`、`session_affinity`（面板已有）；`GET /zones/{id}/origins/health` |
| 限速增强 | 限速规则新增 `characteristics`（`["IP","Header:x-x","Cookie:x","ASN","Country"]`）和 `status_codes`（`[404]`）字段；面板表单已有 |
| DNS 扩充 | 记录类型新增 HTTPS/SVCB/TLSA/SSHFP/DS/NAPTR/URI；域名设置 `dns_transfer_to`（允许 AXFR 的地址）；`GET /zones/{id}/dns_analytics` |
| 权威 DNS 响应限速；封禁导出 | 仅命令行：`--dns-rrl`、`--ban-export` |
| 缓存扩充 | 清除接口 body 新增 `hosts`、`tags`；缓存规则新增 `ignore_query`、`swr`；域名设置 `cache_tier_node` |
| TLS 指纹 JA4 | 表达式字段 `fcf.ja4`；`/cdn-cgi/fucf-trace` 的 `ja4=` |
| 回源客户端证书 | 仅命令行：`--origin-client-cert` / `--origin-client-key` |
| 遥测全网同步 | 无对外接口（面板数据天然变全） |

**明确不做、不要捡起来的**：Tunnel、Access（T11）、anycast/BGP、DNS 一次应答两个节点（评估后放弃：多 A 记录会均分流量，违背调度目的）。

## 1. 追加任务（第一批，风险低）

### [x] N1 Bot 综合评分（`fcf.bot_score`）

- 新文件 `src/edge/botscore.rs`：一个纯函数，把请求特征合成 1–99 的分数（1 = 几乎确定是机器人，99 = 几乎确定是人；和 Cloudflare 方向一致），附评分因素表（代码注释）。输入至少考虑：走了 TLS 却拿不出 JA4（指纹缺失可疑）、`info.threat` 纯净度分、HTTP 版本、常见浏览器头是否存在（`User-Agent`/`Accept`/`Accept-Language`）、是否已知爬虫（`reputation` 的爬虫判定；已知爬虫得稳定的中等分而非随机低分）。每个因素一个小函数，便于以后加 JA3、HTTP/2 指纹。
- 接线：`src/edge/mod.rs` 搜 `info.threat = rep.assess`，同处算出 bot 分存进 `ReqInfo` 新字段 `bot_score`；`src/edge/cgi.rs` 的 trace 加 `bot=`；`src/expr.rs` 加 `Val::BotScore`（照抄 `Val::Threat` 的全部出现处：枚举、`parse`、`eval`、`ty()`），`fcf.bot_score` 和 `cf.bot_management.score` 都识别。
- 单元测试：分数在 1–99 内；缺指纹的裸 TLS 客户端比完整浏览器低；已知爬虫分数稳定。
- 可选延伸（主体完成后）：JA3 摘要（MD5 可手写 16 字节 hex 格式化，不引 md5 crate）放在 JA4 旁边。HTTP/2 指纹不要碰（要拆帧）。

### [x] N2 自定义缓存键（请求头 / Cookie 参与键）

- 缓存规则（`src/items.rs` 搜 `pub struct CacheRule`）新增可选字段 `cache_key_headers`、`cache_key_cookies`（字符串数组，serde default）。
- 求值：`src/edge/mod.rs` 搜 `cache::cache_key(` 调用处，键里追加指定头/Cookie 的值（不存在按空串）；键总长设上限（如 2 KB），超长跳过缓存写入，避免键爆炸；头名小写统一、值里控制字符剔除。
- 校验与面板照抄 `ignore_query` 的全部接线处；表单加两个逗号分隔输入框。
- 单元测试：不同头值进不同条目；未配置时行为不变。

### [x] N3 新功能的面板界面

`src/panel.html` 很大（187 KB），只许按锚点搜片段、不许整读。锚点：`function card(`、`steerTest`、`setRow`、`async function api(`。

- 网络页：加"实测延迟"小表，数据来自 `GET /steering/measured`（注意 `result` 是 `{records, now}`，不是裸数组）；按节点分组显示毫秒数与时间。
- 域名页：加"源站健康"小表，数据来自 `GET /zones/{id}/origins/health`（数组：`origin/ok/last/error`）。
- DNS 页：加"查询统计"小表，数据来自 `GET /zones/{id}/dns_analytics`（`{queries, by_type}`）。
- 域名设置照抄 `origin_check_path` 的输入框写法：`cache_tier_node`（文本）、`dns_transfer_to`（逗号分隔 IP 列表，放 DNS 页）。空字符串=未设置。
- 每处做空态处理（接口可能返回空数组/空对象，面板不能报错）。

### [x] N4 新接口与行为的文档补齐

- `docs/api.md` 补上第 0 节表格里所有接口/字段：`GET /steering/measured`、`GET /zones/{id}/origins/health`、`GET /zones/{id}/dns_analytics`、purge body 的 `hosts`/`tags`、缓存规则全部新字段、限速规则 `characteristics`/`status_codes`、域名设置 `cache_tier_node`/`dns_transfer_to`/`origin_check_path`/`session_affinity`、新 DNS 记录类型与 AXFR 用法（`@dns_transfer` ACL 标签、`--dns-notify`）。
- 核对 README 已有小节与代码一致，过期就修。
- 例子只用保留地址与示例域名。

### [ ] N5 e2e 脚本覆盖新功能（只写静态能确定的）

- `scripts/e2e.py` baseline 段照抄现有检查风格，新增小而稳的检查：按 `tags`/`hosts` 清除的 API 形状、`dns_analytics` 在发过查询后出现记录、`/steering/measured` 形状、`characteristics` 限速在缺该头时按 IP 计数。
- 只写不依赖真源站行为的；拿不准语义的宁可不写，在交接里注明"留待验证"。

## 2. 追加任务（第二批，核心大手术，最后做）

### [ ] N6 大文件分片缓存

- 现状：`src/edge/cache.rs` 已有 `pub enum Range` 和 `pub fn parse_range(value: &str, len: u64) -> Range`；`Entry` 在 33 行。大响应目前整体进内存/磁盘层，内存预算吃不消。
- 设计：超过阈值（先定 512 KB 固定chunk、总大小阈值可配在域名设置 `cache_chunking`）的响应按固定大小分片存储：元数据条（响应头+总长）存原键，第 n 片存 `原键 + "|chunk:" + n`；`Cache-Control`/`tags`/SWR 语义挂在元数据条上。
- 取：命中元数据后按需拼片；访客带 `Range` 头时只取涉及的片；缺片用带 `Range` 头的回源子请求补（源站不支持 Range 则整取一次并降级为不分片）。
- 写：流式回源时按片增量落盘，避免整文件先进内存。
- 单元测试：分片/合并的纯逻辑（片边界、尾部不足一片、Range 解析映射到片号）；不要试图盲写并信 streaming 的正确性，集成验证留给最后。
- 谨慎：这是全任务单里风险最高的一项，放在第二批第一个做，做完交接里写清哪些路径没把握。

### [ ] N7 访客客户端证书 mTLS + 源站私有 CA

- rcgen 已在依赖里（`Cargo.toml` 36 行），不引新依赖。
- TLS 层（`src/edge/tls.rs` 搜 `fn base_server_config`）：新增全局开关 `--mtls-ca <pem 文件>`（env `FUCF_MTLS_CA`）。设置后用 rustls 0.23 的 `rustls::server::AllowAnyAnonymousOrAuthenticatedClient::new(roots)` 包进 `builder.with_client_cert_verifier(...)`（`roots` 用 `RootCertStore::empty()` + 逐张 `add(CertificateDer)`，PEM 解析照抄本文件 `parse_cert` 的 `pem_slice_iter` 用法）。不带证书的连接照常接受，验证结果在 HTTP 层裁决——因为 rustls 的 SNI 证书解析不支持按主机名决定是否要求客户端证书。
- 取结果：接受连接处搜 `peer_certificates`（如没有就在 TLS accept 后用 `get_ref().1.peer_certificates()`），有且通过验证则 `ReqInfo` 新字段 `client_cert_verified = true`。
- 裁决：域名设置 `mtls`（`"on"` 时无有效证书的访客 403）；`src/expr.rs` 加 `Val::CertVerified`（`cf.tls_client_auth.cert_verified`）；trace 加字段。
- 私有 CA（给源站签证书，配合已完成的回源客户端证书）：`POST /zones/{id}/origin_ca` 生成 CA（存进 store 条目），`POST /zones/{id}/origin_ca/sign` 按给的名称/天数签发证书并返回 PEM（不存私钥之外的额外状态）。rcgen 用法**照抄仓库现有代码**：搜 `rcgen::`（`src/edge/tls.rs` 162 行附近的备用证书就是现成例子）。API 形状拿不准就以简单为优，文档写清楚即可。
- 单元测试：CA 生成、签发、链式校验的纯逻辑。

### [ ] N8 后量子密钥交换（aws-lc-rs）

- 目标：TLS 握手支持 `X25519MLKEM768`。rustls 只有 aws-lc-rs 提供者带它，ring 没有。
- 改法：`Cargo.toml` 里 `rustls` 的 features 把 `ring` 换成 `aws-lc-rs`；`tokio-rustls` 同样换 feature；`quinn` 把 `rustls-ring` 换成对应的 aws-lc-rs feature（到 docs.rs 查 quinn 0.11 的 feature 名，查不到就按 `aws-lc-rs` 试）；`rcgen` 的 `ring` feature 换 `aws_lc_rs`。`src/edge/tls.rs` 搜 `fn crypto()` 和 `ring::default_provider`，换成 `rustls::crypto::aws_lc_rs::default_provider()`。`ring` 这个直接依赖若别处还用（搜 `ring::`）就保留。
- trace 的 `kex=` 字段已经存在，成了之后应能打出 `X25519MLKEM768`。
- **已知风险**：aws-lc-rs 编 musl 静态包需要 C 工具链，可能让 musl 构建挂掉——在交接里标注，集成阶段若失败可能整体回退本任务。
- 这一步改动小但牵连构建，单独一个提交，不和其他任务混。

### [ ] N9 协议三小件：zstd、0-RTT、Early Hints、图片缩放

四个子项各自独立提交，做不了的子项写明原因跳过，不要硬写：

1. **zstd**：可加依赖 `zstd`（钉版本）。搜 `accept_encoding_bucket`（`src/edge/cache.rs`）和响应压缩的选取逻辑，`zstd` 加进协商与 `Content-Encoding`；缓存键的编码桶同步加。
2. **0-RTT / Early Data**：rustls 0.23 服务端是 `ServerConfig` 的公开字段 `max_early_data_size`（0=关）。做成显式开关 `--early-data`（默认关），开时设为 16384；trace 加 `early_data=`；README 写清重放风险由运营者自担。QUIC 的 0-RTT 若 quinn API 不明就跳过并在交接里注明。
3. **Early Hints (103)**：hyper 高层 API 大概率发不出 1xx 中间响应。先查 hyper 1.x 是否有支持；没有就**不实现**，改而在文档说明，并支持在响应里按配置注入 `Link: rel=preload` 头作为替代。
4. **图片缩放 `/cdn-cgi/image/`**：可加依赖 `image`（纯 Rust，musl 安全）。`/cdn-cgi/image/<options>/<原始路径>` 端点：内部回源取图，按 options 子集（`width`/`height`/`fit`/`quality`/`format`）缩放/转码后输出；结果进缓存（键含 options）。入口参照 `src/edge/cgi.rs` 里现有 `/cdn-cgi/` 路由的写法。不支持的效果忽略而不是报错。

### [ ] N10 自定义主机名（SSL for SaaS）

- 场景：别人的域名 CNAME 到本机群用户的域名，我们自动给它签证书。
- 数据：新 item 类型照抄 `src/items.rs` 现有任一类型：`custom_hostname`，字段 `hostname`、`status`（`pending`/`active`/`failed`）、`verify_txt`（给用户拿去验证所有权的 TXT 值）。
- 签发：惰性——TLS 握手见到未配置的 SNI 时查 custom_hostname 表，命中且验证通过就走 ACME 签发。ACME 现成管线在 `src/site_acme.rs`（搜 `tls_alpn`、`eligible`、`wanted`），尽量复用而不是另起炉灶。验证所有权的最小可行方式：该主机名的 CNAME 指向本机群任一已配置域名即视为通过（用首次握手时带的 SNI 与配置比对；不要做外部 DNS 查询，权威服务器是我们自己，查外网域名解析不可靠）。
- API：items 系统天然给出 CRUD；状态流转写在文档。
- 单元测试：验证逻辑与 item 校验。
- 这项复杂度高，拿不准的简化并在交接里写明，不要堵住后面的任务。

### [ ] N11 全机群近似限速计数

- 现状：限速计数各节点各算；`src/reports.rs` 已有报告去重与转发通道（搜 `pub struct Report`、`pub struct Reports`）。
- 设计：新增报告种类 `rate`：每 30 秒各节点把本节点最热的若干计数键（键+计数+窗口）编成报告；其他节点收到后合入一张"远端视图"，按窗口半衰衰减。裁决时有效计数 = 本地计数 + 远端视图求和（可乘系数 0.5 防爆）。只在规则计数超过某阈值（如限速的一半）后才上报，控制报告量。
- 单元测试：合并、衰减、去重纯逻辑。近似即可，文档写清"近似、不保证精确"。

### [ ] N12 Workers 运行时加固（不换引擎）

- 背景：引擎选型（Boa/QuickJS/V8）所有者尚未拍板，**本任务不换引擎**，只做不锁死未来替换的结构性改进。代码在 `src/workers/`（`mod.rs`、`kv.rs`、`db.rs`、`crypto.rs`、`cron.rs`、`prelude.js`）。
- 子项：a) 上下文复用：按脚本内容版本缓存/复用 Boa context，不再每请求新建（注意隔离：全局状态每请求重置或文档声明不保证）；b) 请求体按字节暴露（`Uint8Array`/`ArrayBuffer`），不再只按文本；c) 多文件：支持简单打包格式（ wrangler 的 esbuild 产出本就是单文件——核实 wrangler 实际产出格式，若是单文件 bundle 则文档写清"先用 wrangler build 再上传"即可，不另造模块系统）。
- 单元测试：上下文复用不串状态、字节体读取。
- HTMLRewriter、Cache API、WebSocket、密钥绑定**不做**，等引擎选型后统一弄。

### [ ] N13 收尾自查

- 全部任务完成后：通读 `docs/todo-duet.md` 与本文档，逐项核对交接记录；把 `docs/api.md`、README 与代码最终对齐一遍；交接里列出"集成阶段最可能编译失败的 5 个地方"供另一方优先修。

## 3. 交接记录（每个任务做完在此追加一段，格式同原任务单第 3 节）

### N1
- 新文件 `src/edge/botscore.rs`：纯函数 `score(&Signals)` 把请求特征合成 1–99 的 Bot 分（1=机器人，99=真人，同 Cloudflare 方向），每个因素一个小函数，评分表写在模块注释里；从 50 起加减：TCP 上的 TLS 却无 JA4 -25、JA4 头形状（t13d+ALPN +10，其余 -10）、威胁分、HTTP 版本、UA 是否工具/爬虫、Accept/Accept-Language/Accept-Encoding 缺失、Sec-Fetch-Mode 存在 +10。
- 接线：`src/edge/mod.rs` 在 `rep.assess` 处一次取得威胁分和"已验证爬虫"（`reputation.rs` 新增 `Assessment::verified_crawler()`），算出 `ReqInfo.bot_score`；trace 加 `bot=`；`src/expr.rs` 的 `Val::BotScore` 识别 `fcf.bot_score` / `cf.bot_management.score`。已验证爬虫固定 50 分，自称爬虫但不在自家网络的按脚本算；边缘自己发的请求（Worker 子请求、健康检查）为 0。
- JA3 没做：要手写 MD5 和第二套 ClientHello 解析，而且 Chrome 打乱扩展顺序后 JA3 不稳定，JA4 已经够用。面板只在防火墙页的示例说明里加了一行（面板没有字段列表）。
- 留待能跑真实流量的人核对：权重是经验值；`ja4::peek` 对分片到达的大 ClientHello 只等约 30 ms，慢链路上的真浏览器可能拿不到指纹、被扣 25 分（仍在 50 以上）。

### N2
- 新文件 `src/edge/cachekey.rs`：缓存规则的 `cache_key_headers` / `cache_key_cookies` 把这些请求头 / Cookie 的值加进缓存键（每对以控制字符 0x1f 开头，值去掉控制字符、`%` 和非 ASCII 字节转成 %XX，所以不同取值不会撞键）；`cache::cache_key` 多了 `custom` 参数，插在 `|ae=` 之前，未压缩副本照样共用；没配这两个字段时键和以前逐字节相同。清除按 `Entry.url` 匹配，同一 URL 的各取值一起清掉（有测试）。
- 校验：各最多 8 个、名字 1–64 字符、不能重复；头名限字母数字 `-` `_` 并存成小写，Cookie 名用 RFC 6265 token 字符、保留大小写。缺失按空值；同名 Cookie 取第一个。加了这些值后键超过 2048 字节的请求不查也不存（`BYPASS`），上限只对加了这些字段的规则生效。额外放宽：源站 `Vary` 指向键里已有的头时照常缓存。
- Rulesets：映射到 `action_parameters.cache_key.custom_key.header.include` / `cookie.include`，`check_presence` 只接受空，`exclude_origin` 等其他字段一律 400；`ignore_query` 仍不映射、经 Rulesets 修改时保留。
- 没把握：滚动升级期间旧节点不认识新字段，会不区分取值地缓存（按 Cookie 区分个人内容时可能串给别人，升级完之前不要这样用）；头名存成小写，Terraform 写大写可能一直显示差异；Terraform provider 若总是带 `exclude_origin: false`，PUT 会失败。

### N3
- 面板（`src/panel.html`）：调度页下方加"实测延迟"表（`/steering/measured`，网络 → 节点 → `ms/samples/age`，按节点分组，同一网络多个节点时标出最快）；域名 SSL/TLS 页加"源站健康"表（`/origins/health`，`name/address/healthy/failures/checked_at/detail`）；DNS 记录页加"区域传送（AXFR）"输入框和"查询统计"（`/dns_analytics`，`total/by_type/by_rcode`）；缓存页加"分层缓存"上层节点输入框（附节点名候选）。
- 接口形状以代码为准，和任务单写的不同；三个表都只反映应答面板的那个节点，卡片里写明了。
- `dns_transfer_to` 用新的 `data-list` 标记，change 处理里按逗号或空白拆成数组发送，留空发 `[]`；只读角色看到的两个输入框是禁用的，表格谁都能看。
- 每个表都有空态，接口失败、字段缺失、类型不对都不报错（用 node 跑过各种异常输入）。没在浏览器里实际看过；调度页原有的"添加规则"对非管理员仍可见（服务端会拒），未改。

### N4
- 只改了 `docs/api.md` 和 `README.md`，内容按代码写，不按任务单：`/steering/measured` 是 `{网络: {节点: {ms, samples, age}}}`，`/origins/health` 是 `[{name, address, healthy, failures, checked_at, detail}]`，`/dns_analytics` 是 `{total, by_type, by_rcode}`；缓存规则没有 `swr`（只认源站的 `stale-while-revalidate`），也没有 `@dns_transfer` 标签和 `--dns-notify`（ACL 就是 `dns_transfer_to`，NOTIFY 总是发）。
- api.md 新增"Zone transfers (AXFR)""DNS query counts""Origins: health checks, weights and session affinity""Steering by measured round trips"四节；限速的 `characteristics` / `status_codes` 写在 Rules 里，Rulesets 的对应关系只链接、不重复。
- README 修了过期的地方：`--edge-ttl` 说明、`fucf-trace` 字段、已知限制里"没有 AXFR / 没有主动健康检查 / 没有 DNS 查询统计"，并补上 `--dns-rrl`、`--ban-export`、`--origin-client-*` 三个参数。
- 留给能运行的人：`--ban-export` 写不出 IPv6 封禁（autofw 存的是 /64，banset 只认单个地址），`banned6` 总是空的；`characteristics` 缺头时所有这类请求共用一个计数；`cache_tier_node` 保存时不检查节点是否存在。
