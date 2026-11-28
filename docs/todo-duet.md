# todo-duet.md：Duet 的规则与任务

先读完第 1、2 节再动手。任务在第 3 节，按顺序做；每做完一个，在本文件里勾选、在第 4 节写交接记录、然后提交。

## 0. 背景

fucf 是自托管的 Cloudflare 式边缘平台（Rust，单一二进制，见 `README.md`）。当前目标是继续对标 Cloudflare。
本文件里的任务归你；调度、DNS、TLS、缓存、同步、Tunnel、Workers 引擎由别人同时在 `next` 分支上做。

你只能操作这个 GitHub 仓库，没有编译器，也不能运行测试。所以要求是：**代码写到第一次就能编译**，测试照常写好，
编译、运行测试和合并由别人最后统一做。不要为了"验证"去触发或等待 CI。

## 1. 规则

### 1.1 分支与提交

- 只在 `duet` 分支上工作（不存在就从 `next` 创建）。**不要推送到 `master` 和 `next`**，不要强推，不要改写历史。
- 一个任务一个提交（大任务可以两三个）。提交信息用英文，格式照 `git log`：`feat: 一句完整的小写英文句子`，正文用 `- ` 列要点。
- 提交身份必须是仓库所有者的 GitHub noreply 身份
  `is-hp-is-mad <127638251+is-hp-is-mad@users.noreply.github.com>`。提交里不得出现机器主机名或私人邮箱。

### 1.2 这是公开仓库

- 代码、测试、文档里只用示例数据：域名用 `example.com` / `example.net` / `*.test`，
  地址用 `192.0.2.0/24`、`198.51.100.0/24`、`203.0.113.0/24`、`2001:db8::/32`。不写任何真实 IP、真实域名、真实邮箱。
- 不写任何密钥或令牌。测试夹具必须一眼看得出是假的（如 `test-token`）；CI 对全部历史做 gitleaks 扫描，
  提交进去就永远留在历史里。

### 1.3 没有编译器时怎么写 Rust

- **不新增依赖**：不要改 `Cargo.toml` 和 `Cargo.lock`（CI 用 `--locked`，锁文件对不上就整个编译失败）。
  现有的够用：tokio、axum 0.8、serde / serde_json、uuid、chrono、regex、ring、rustls、hyper 1、bytes、base64、flate2、brotli、rusqlite 等。
- **签名照抄，不凭记忆**：调用任何已有函数、类型、字段之前，先在仓库里搜到它的定义，按定义写。每个 `use` 路径都要搜得到。
- **`await` 与借用**（之前最常见的编译失败）：`.await` 之前把要用的值克隆成自有值；`std::sync::Mutex` 的锁不得跨 `.await`；
  处理函数的 future 必须是 `Send`。新的处理函数照抄同文件里最相近的那个的写法。
- **零警告**：`cargo check --tests` 在 Windows 和 Linux 上都必须没有警告。不留未使用的 import、变量、函数；
  不用 `#[allow(dead_code)]` 掩盖。只在 Unix 上能做的事放在 `#[cfg(unix)]` 后面，并给其他平台一个对应实现。
- **axum 0.8**：路径参数写 `{zone_id}`；处理函数的请求体参数（`Bytes`）放最后；返回 `ApiResult`。
- **风格**：照所在文件的现有风格。每个新的类型和函数写英文文档注释，说明"为什么"；测试名用整句
  （如 `a_report_counts_once_whichever_ways_it_comes`）。不写 emoji。
- **读大文件用搜索**：`src/panel.html`、`src/api.rs`、`src/edge/mod.rs`、`src/store.rs`、`src/auth.rs` 都在 100 KB 以上，
  按下面给的锚点字符串搜索后读片段，不要整文件读。
- 拿不准的地方不要猜着写一大片：写最小可行的实现，把疑问记进交接记录。

### 1.4 不要碰的文件

`Cargo.toml`、`Cargo.lock`、`.gitignore`、`.github/workflows/ci.yml`、`scripts/deploy/`、
`src/dns/`、`src/sync/`、`src/reports.rs`、`src/fleet.rs`、`src/release.rs`、`src/limits.rs`、`src/handoff*.rs`、
`src/edge/{cache,tls,upstream,proxy,h3,quic_mux,front}.rs`、`src/workers/`。
这些有人在同时修改。任务需要它们配合时，只调用其现有的公开接口；需要它们改动的，写进交接记录。

### 1.5 每个任务的固定产出

1. 功能本体尽量放**新文件**；对热点文件（`api.rs`、`main.rs`、`store.rs`、`items.rs`、`edge/mod.rs`、`panel.html`）只做最小的接线改动。
2. 同文件内的单元测试（`#[cfg(test)] mod tests`），不依赖网络。
3. `docs/api.md`（英文，示例域名）补上新接口；`README.md`（中文）补一小节。
4. 面板里能配置它（照相邻功能的写法，用现有的 `btn(...)`、`openForm(...)`、`api(...)`）。
5. 本文件：勾选任务，第 4 节写 3 到 5 行交接记录。

## 2. 代码地图（接线位置，都用搜索定位）

| 要做的事 | 位置与锚点 |
|---|---|
| 加一个模块 | `src/main.rs` 顶部的 `mod` 列表；边缘相关的放 `src/edge/`，在 `src/edge/mod.rs` 顶部 `pub mod` 列表登记 |
| 加 API 路由 | `src/api.rs`，在 `.route("/zones/{zone_id}/analytics", get(analytics))` 之前。通用增删改查用 `crud::<T>("/zones/{zone_id}/…")` |
| API 辅助 | `src/api.rs`：`St`、`Params`、`Who`、`Caller`、`ApiResult`、`ok(...)`、`bad(...)`、`body(&bytes)`、`paginated(...)`、`ApiError` |
| 令牌权限 | `src/tokens.rs` 的 `pub fn need(path: &str) -> Need`：**没登记的路径一律拒绝令牌访问**。新路径要在这里映射到 `Area`；新 `Area` 要在 `groups!` 表里加读、写两个权限组（id 任取 32 位十六进制，不与已有重复） |
| Cloudflare 的账户级路径 | `src/api.rs` 的 `fn account_path`：把 `/accounts/{id}/…` 映射到内部路径 |
| 域名下的配置对象 | `src/items.rs`：实现 `Item`（照 `CacheRule`，含 `item_boilerplate!`）。`src/store.rs` 里搜 `cache_rules`，它出现的每一处都要给新字段照做一份 |
| 全局配置对象 | 照 `steering`：`src/items.rs` 的 `SteerRule`；`src/store.rs` 里搜 `steering`，每一处照做；API 照 `list_steering` / `create_steering` / `update_steering` / `delete_steering` |
| 区域设置项 | `src/items.rs` 的 `Settings`（搜 `browser_cache_ttl`，定义、默认值、校验各一处），README 的"区域设置"表 |
| 规则表达式 | `src/expr.rs`：`Expr::parse`、`ReqInfo`、`matches(&info)` |
| 请求处理链 | `src/edge/mod.rs` 的 `async fn process(`：`/cdn-cgi/` → 面板 → 节点限流 → 主机匹配 → `ReqInfo {` → `self.waf.check(` → 重定向 → 改写 → Worker → 缓存与回源 |
| 响应出口 | `src/edge/mod.rs` 的 `pub async fn respond(`：错误页（`fn page(`、`fn page_with(`、`PageCtx`、`EdgeError`）、统计（`edge.stats.record(`） |
| 人机验证 | `src/edge/challenge.rs`（`VERIFY_PATH`、`config`、`assess_at`、`verify`），脚本在 `src/edge/challenge-*.js`；签名用 `Waf::mac` / `mac_ok`（全机群同一密钥） |
| 只在面板所在节点跑的后台任务 | `src/main.rs` 里搜 `edge::autofw::spawn(`，新任务挂在同一个条件下 |
| 机群状态 | `st.fleet.status(node, version)`（含 `online`、`in_sync`）、`st.fleet.usage(node)`、`st.health.is_up(node)`、`st.store.list_nodes()` |
| 向外发 HTTP 请求 | 照 `src/edge/reputation.rs` 里 `async fn fetch(` 的做法（`Target::from_url` 加 `edge.upstream.send`） |
| API 测试 | `src/api.rs` 测试模块的 `make_test_state` 和 `call` |
| 边缘测试 | `src/edge/tests.rs` 的 `setup()`、`get(&env, host, uri)`、`send(&env, method, host, uri, extra_headers, body)` |

## 3. 任务

### [x] T1 文档与现状对齐（不改代码）

- `README.md` 的"已知限制"和开头的模块表已经过时。逐条对照代码核实后改正，不确定的不要改。已知过时的例子：
  写着没有 DNSSEC（实际有，`src/dns/dnssec.rs`）；写着配置单向同步（实际是对等同步，`src/sync/`）；
  响应头写的是 `CF-Cache-Status`（实际是 `fcf-cache-status`）；防火墙动作缺 `managed_challenge`；`security_level` 的取值不全。
- `docs/api.md` 只覆盖了一部分接口。对照 `src/api.rs` 里全部 `.route(` 和 `crud::<`，补成完整的接口参考（方法、路径、请求体字段、示例）。

### [x] T2 e2e 分层测试的静态对齐

- `scripts/e2e_tiers/`（T1 到 T4）里的接口路径和代码不一致，例如 `harness.py` 的
  `KV_NAMESPACES_PATH = "/workers/kv/namespaces"`（实际是 `/kv/namespaces`）、D1 的路径（实际是 `/d1/database`）。
- 只做能静态确定的修正：对照 `src/api.rs` 改路径常量；响应头名 `cf-*` 改成 `fcf-*`（`cf-connecting-ip` 除外，它仍然发给源站）。
- 不要动 `scripts/e2e.py` 里的 baseline 部分。其余失败原因留给能运行的人，在交接记录里列出你看到的疑点。

### [x] T3 Rulesets API（Terraform / cf-terraforming 兼容）

- 目标：在现有规则类型上加一层 Cloudflare Rulesets API 的映射，不引入新的存储。新文件 `src/rulesets.rs`。
- 阶段与现有类型的对应（字段以 `src/items.rs` 里的结构体为准）：

  | phase | 现有类型 | Cloudflare 规则里的字段 |
  |---|---|---|
  | `http_request_firewall_custom` | `FirewallRule` | `action`：block / js_challenge / managed_challenge / log / skip |
  | `http_ratelimit` | `RateLimit` | `ratelimit.requests_per_period`、`period`、`mitigation_timeout` |
  | `http_request_dynamic_redirect` | `RedirectRule` | `action_parameters.from_value.{target_url.value, status_code, preserve_query_string}` |
  | `http_request_transform` | `TransformRule` 的路径改写 | `action_parameters.uri.path.value` |
  | `http_request_late_transform` | `TransformRule` 的请求头 | `action_parameters.headers.{name}.{operation, value}` |
  | `http_response_headers_transform` | `TransformRule` 的响应头 | 同上 |
  | `http_request_cache_settings` | `CacheRule` | `action_parameters.cache`、`edge_ttl.default` |
  | `http_request_origin` | `OriginRule` | `action_parameters.{host_header, origin.host, origin.port, sni.value}` |

- 接口（都在 `/zones/{zone_id}/rulesets` 下）：列出各阶段的入口规则集；按 id 读取；
  `GET` / `PUT …/phases/{phase}/entrypoint`（`PUT` 整体替换该阶段的规则，顺序即优先级）；
  `POST …/{ruleset_id}/rules`；`PATCH` / `DELETE …/{ruleset_id}/rules/{rule_id}`。
  规则集 id 由域名 id 和阶段确定性地生成；规则 id 就是现有对象的 id。
- 一条 `TransformRule` 同时有路径、请求头、响应头时，它在三个阶段里各出现一次；经某个阶段修改时只动那一部分。
- 遇到映射不了的字段或动作，返回 400 并说明是哪个字段，不要静默丢弃。
- 权限：`need()` 里按 `phase` 映射到对应的现有 `Area`；不带阶段的路径用 `Area::Firewall`。
- 测试：每个阶段"Cloudflare JSON → 现有对象 → Cloudflare JSON"往返一致；`PUT` 替换后的顺序与删除；未知动作被拒绝。

### [x] T4 IP 列表

- 目标：可复用的地址列表，规则里写 `ip.src in $office`。
- 存储：全局对象 `IpList { id, name, description, items: [{ id, ip, comment }] }`，`ip` 是单个地址或 CIDR。名字只允许小写字母、数字、下划线。
- 接口（内部路径，并在 `account_path` 里把 Cloudflare 的 `/accounts/{id}/rules/lists…` 映射过来）：
  `/rules/lists` 列出、创建；`/rules/lists/{list_id}` 读、改、删；`/rules/lists/{list_id}/items` 列出、追加、整体替换、按 id 删除。
- 表达式：`src/expr.rs` 让 `in` 的右边可以是 `$名字`。规则在快照构建时编译，名字在那时解析成地址集合；
  找不到的名字不匹配任何地址。被规则引用的列表不许删除（返回冲突）。
- 权限：新 `Area::Lists`（账户级），读、写两个权限组。
- 测试：解析与匹配（IPv4、IPv6、CIDR）；列表改了以后规则跟着变；删除被引用的列表被拒绝。

### [x] T5 自定义错误页

- 目标：域名可以替换边缘自己产生的错误页。
- 区域设置 `error_pages`：键为 `5xx`、`block`、`ratelimit`、`1xxx`（节点自身的 4xx/5xx 提示）的映射，值是 HTML，每个不超过 64 KiB。
- 模板里可用占位符：`::RAY_ID::`、`::STATUS::`、`::CLIENT_IP::`、`::HOST::`、`::NODE::`、`::ERROR_BOX::`（替换成默认页的主体）。
  占位符的值要做 HTML 转义。
- 只替换给浏览器看的页面：gRPC、非页面请求（参见 `challenge::is_navigation`）、人机验证页保持原样。
- 测试：占位符替换与转义；没配置时与现在完全一致；超长被拒绝。

### [x] T6 告警

- 目标：出事时主动通知。新文件 `src/alerts.rs`。
- 通道：全局对象 `AlertChannel { id, name, kind, enabled, events, … }`，`kind` 为 `webhook`（POST JSON）或 `telegram`（机器人令牌加 chat id）。
  接口输出里把令牌和带密钥的 URL 打码（做法参见 `src/auth.rs` 里 `oauth_config` 对 `client_secret` 的处理）。
- 事件（第一版）：`node_offline`（节点连续 3 次检查不在线）、`sync_lagging`（在线但超过 5 分钟未同步）、
  `certificate_failing`（证书包签发失败，或 14 天内到期）、`traffic_limit`（节点流量到档）、
  `under_attack`（域名被自动切到受攻击模式）、`origin_errors`（某域名 5 分钟内回源错误事件达到阈值）。
- 行为：只在面板所在节点评估和发送；状态变化时发（触发和恢复各一次），持续触发时每 6 小时重发；进程启动后 2 分钟内不发 `node_offline`。
  状态只放内存。
- 接口：`/alerts/channels` 增删改查；`POST /alerts/channels/{id}/test` 发一条测试；`GET /alerts/active` 当前触发中的告警。
- 评估逻辑写成不依赖时钟和网络的纯函数（输入机群状态，输出告警集合），便于测试。
- 测试：各事件的触发与恢复；重发间隔；启动宽限期；打码。

### [x] T7 请求日志

- 目标：能看到最近的每一个请求，并能推送到外部。新文件 `src/edge/reqlog.rs`。
- 每个节点在内存里保留最近 5000 条：时间、ray、节点、域名、主机、方法、路径（不含查询串，最长 512 字节）、状态码、
  缓存标签、字节数、耗时、访客地址、国家、ASN、User-Agent（最长 256 字节）、协议版本、被拦截的动作。在 `respond(` 里 `edge.stats.record(` 旁边记录。
- 接口：`GET /zones/{zone_id}/logs/requests`，参数 `since`（序号游标）、`limit`、`status`、`host`、`path`、`ip`；只返回应答的这个节点上的日志。
- 面板：域名下加"实时日志"页，每 2 秒用游标拉取，可按状态码和路径过滤。
- 推送：全局对象 `LogJob { id, name, zone_id, destination, enabled, status_min, batch_seconds }`，每个节点把自己的日志按批以 NDJSON POST 到 `destination`；
  失败丢弃该批并记一条警告，不无限重试。
- README 里说明日志含访客地址，以及保留条数。
- 测试：环形缓冲的容量与游标；过滤；路径和 UA 的截断。

### [x] T8 Waiting Room

- 目标：源站扛不住时让访客排队。新文件 `src/edge/waiting.rs`，在 `process(` 里回源之前检查。
- 域名下的对象 `WaitingRoom { host, path_prefix, total_active_users, new_users_per_minute, session_minutes, enabled, … }`。
- 行为：已放行的访客带签名 Cookie（`Waf::mac`），在 `session_minutes` 内直接通过；名额满或进入速率超限时返回排队页
  （自动刷新，显示大致位置），先到的先放行。计数是每个节点各自的，文档里写明。
- 只对页面请求排队；`/cdn-cgi/`、已有 Cookie 的后续请求、防火墙 `skip` 的请求不排队。
- 测试：名额与速率；Cookie 的签名与过期；先到先放行；伪造 Cookie 无效。

### [x] T9 人机验证对外开放

- 目标：让任意页面嵌入我们的人机验证，并由后端校验结果（相当于 Turnstile）。
- 全局对象 `ChallengeWidget { id（即 sitekey）, name, domains, secret, … }`，`secret` 只在创建时返回一次。
- 前端：`/cdn-cgi/challenge-platform/widget.js`，在带 `data-sitekey` 的容器里渲染，复用现有的检测与计算逻辑，
  通过后把令牌写进隐藏字段 `fcf-challenge-response`。
- 后端：`POST /cdn-cgi/challenge-platform/siteverify`（表单或 JSON：`secret`、`response`、`remoteip`），
  返回 `{ success, challenge_ts, hostname, error-codes }`。令牌无状态、带签名、5 分钟有效、绑定 sitekey 与主机名；
  同一节点上同一令牌只接受一次。
- 测试：令牌的签发与校验；过期；主机名不在 `domains`；`secret` 错误；重复提交。

### [x] T10 转发邮件的 DKIM 签名

- 目标：经邮件路由转发出去的信带上本域名的 DKIM 签名。新文件 `src/dkim.rs`。
- 密钥由用户提供：域名的邮件设置里加 `dkim_selector` 和 `dkim_private_key`（RSA，PKCS#8 PEM），用 `ring` 的 `RsaKeyPair` 做 rsa-sha256 签名。
  面板显示用户需要添加的 TXT 记录内容。接口输出不返回私钥。
- 规范化用 relaxed/relaxed；签名的头至少包括 From、To、Subject、Date、Message-ID；在 `src/mail.rs` 转发出去之前加签。
- ARC 封装作为第二步，DKIM 部分完成并记录后再做。
- 测试：两种规范化对照 RFC 6376 的例子；用测试密钥签名后再用 `ring` 验证通过；没配置密钥时邮件不变。

### [-] T11 Access（已取消）

- 已取消：仓库所有者决定不做，OAuth Worker 已经覆盖了这个需求。

- 目标：在站点前面加登录。**这是安全功能：宁可少做，不可放宽任何现有检查。**
- 域名下的对象 `AccessApp { host, path_prefix, allow_emails, allow_email_domains, session_hours, enabled, … }`。
- 流程：未登录的请求被重定向到面板主机的登录页，用现有的面板账户（含通行密钥）登录，邮箱在允许范围内则签发短期令牌，
  带回站点后由边缘换成该主机的签名 Cookie。源站收到 `fcf-access-authenticated-user-email` 头；访客自带的同名头必须先去掉。
- 回跳地址只允许回到该应用自己的主机；令牌绑定应用 id 与主机，单次使用。
- 测试：未登录被重定向；不在名单被拒；Cookie 伪造和过期；回跳地址被篡改；访客伪造身份头被去掉。

### [ ] T12 多租户：域名归属用户

- 目标：域名属于创建它的用户，普通用户只能看到和修改自己的域名。**同样是安全功能，规则同 T11。**
- `Zone` 加 `owner`（用户 id）；已有的域名归属为空，只有管理员可见，管理员可以改归属。
- 用一处统一的检查覆盖所有 `/zones/{zone_id}/…` 路径（在 `src/api.rs` 的 `auth` 中间件里，参见 `tokens.rs` 的 `sees_zone`），
  不要在每个处理函数里各写一遍。域名列表按归属过滤。账户级的对象（节点、调度、Workers、KV、D1 等）第一版仍只有管理员可写。
- 测试：两个普通用户互相看不到、改不了对方的域名（逐类接口各测一个）；管理员都能看到；令牌不能越过归属。

### [ ] T13 兼容性验证的 CI 工作流（草稿）

- 新文件 `.github/workflows/compat.yml`，只在 `workflow_dispatch` 时运行：启动一个本地 fucf（做法照 `ci.yml` 的 UI 作业），
  然后用真实工具指向它：Terraform 的 cloudflare provider（建域名、记录、T3 的规则）、wrangler（部署一个 Worker）、
  一个 DNS-01 插件、一个 DDNS 客户端。每个工具一个作业，互不影响。
- 这份工作流需要实际运行后再调整，写清楚每一步预期什么即可。

## 4. 交接记录

每个任务完成后追加一段：加了什么文件、在哪里接的线、哪些地方没把握或需要第 1.4 节那些文件配合。

### T1

- 改了 `README.md`：模块表的多节点与 WAF 两行、`--role` / `--peers`（`--primary` 记为已不推荐）、`/system`、区域设置表（`security_level` 全部取值、`challenge_script`、`decoy_subdomains`、`auto_firewall*`）、防火墙动作加 `managed_challenge`、`fcf-cache-status` / `fcf-ipcountry`、账户在对等节点间同步、"已知限制"的多节点和 DNS 两条。
- `docs/api.md` 新增"Reference"一节，覆盖 `src/api.rs` 里全部 `.route(` 和 `crud::<`，含字段、取值范围和示例；节点之间用的 `/replication/*` 单列。
- 没把握所以没改：README 里"证书""滚动更新""节点限流""三节点部署"几节仍按主节点 / 副本描述（发布由哪个节点协调、限流状态由谁写入配置，需要看 `src/release.rs`、`src/fleet.rs` 的人确认）；`src/auth.rs` 顶部注释也还写着账户不同步给副本。

### 部署准备

- 按第 5 节加了 `.github/workflows/release.yml` 和 `scripts/deploy/node-upgrade.sh`（照原文，LF，可执行）。
- `ci` 的产物 `fucf-linux-x86_64` 只保留 30 天（`retention-days: 30`），超过 30 天的提交 `release` 取不到二进制，要先重跑一次 `ci`。

### T2

- `scripts/e2e_tiers/harness.py`：`KV_NAMESPACES_PATH` 改成 `/kv/namespaces`，`D1_DATABASES_PATH` 改成 `/d1/database`；补上被引用却没定义的 `WORKER_CRON_TRIGGER_PATH`（`/workers/scripts/{name}/scheduled`），新增 `PASSKEY_REGISTER_PATH`（`/account/passkeys`）。
- `tier1_features.py` / `tier2_boundaries.py`：浏览器里直接写的 D1 路径、`/account/passkeys/finish`（实际是 `POST /account/passkeys`）、T1-025 读的 `/schedules`（实际在 `GET …/settings` 的 `crons`）；`tier2` 里调 `/replication/sync` 时去掉了 `prefix=""`（路由在 `/client/v4` 下）。
- 响应头：分层测试里已经全是 `fcf-*`；射线头实际是 `fucf-ray`（`src/edge/mod.rs`），测试写的也是它，没改；顺手把 README 里写成 `fcf-ray` 的一处改正。
- 疑点（没改，留给能运行的人）：`OAUTH_CLIENTS_PATH = "/oauth/clients"` 在 `src/api.rs` 里没有这条路由，OAuth 客户端是 `workers/auth/` 那个 Worker 自己管的（D1 表 `oauth_clients`），T1-08x 和 T2 里注册客户端的几个测试应该改走 Worker 的管理接口；`PANEL_HOST` / `AUTH_HOST` 用的不是示例域名；`tier2` 里 `scheduledTime` / `dedup` 这两个请求体字段 `trigger_worker_scheduled` 不认识（它只读 `cron`）。

### T3

- `src/rulesets.rs`：八个阶段各是一种现有规则的另一种写法，不新增存储；规则集 id 是 SHA-256(域名 id、阶段) 的前 16 字节。整阶段替换走新加的 `Store::batch_items_async`（`src/store.rs`，在一次写入里做完，失败就全部不生效）。
- 除了任务里列的接口，为了 Terraform 的建、改、删还加了 `POST /rulesets`、`PUT` / `DELETE /rulesets/{id}`。`POST /rulesets` 路径里没有阶段，`need()` 按任务要求给 `Area::Firewall`，处理函数里另外用令牌按请求体里的阶段再查一次权限。
- 为了不放宽：只跳过一部分的 `skip` 被拒（这里的 skip 会跳过安全级别、限速和托管规则）；限速只按 `cf.colo.id` + `ip.src` 计数，别的 characteristics、`counting_expression`、`requests_to_origin` 都拒。自动防火墙的规则不显示也不会被替换。
- 拿不准、留给能连 Cloudflare 的人核对：重定向的 `status_code` 现在是必填（没查到 Cloudflare 的默认值，宁可要求写明）；规则集的 `version` 恒为 `"1"`、`name` 不保存，Terraform 是否在意没法在这里验证；共享的改写规则经一个阶段重排会影响它在别的阶段里的顺序；限速不能重排。
- 面板：域名的"规则"页最下面有 Rulesets 卡片，每个阶段可以按 Cloudflare JSON 查看和整体替换。

### T4

- `src/lists.rs`：全局对象 `IpList`，表达式 `ip.src in $name`（`src/expr.rs` 新增 `Expr::parse_with`），列表在 `Snapshot::build` 时解析一次；名字不存在的列表不匹配任何地址，但保存引用了不存在列表的规则直接 400。
- 被规则引用（停用的规则也算）的列表，删除或改名都回 409 并列出规则；带主机位的网段、IPv4 映射地址、同一请求里重复的地址一律拒绝。条目写操作照 Cloudflare 返回 `operation_id`，操作状态只在本节点内存里。
- 权限：账户级 `Area::Lists`（Account Filter Lists Read / Write）；`/accounts/{id}/rules/lists…` 经 `account_path` 映射。`account_path` 现在改写路径后清空 extensions，顺带修好了带 id 的账户路径（之前 KV namespace 这类会拿到 3 个路径参数）；以后在账户路径下加 WebSocket 要另想办法。
- 拿不准：Cloudflare 是否允许改名、重复追加时是否覆盖备注；权限组 id 不是 Cloudflare 的真实 id；条目没有游标分页。`ip_lists` 进了同步和全量对账：滚动升级时还没升级的节点若做全量对账的来源，可能把列表清掉，建议全部节点升级后再建列表。

### T5

- 新文件 `src/edge/errpages.rs`：区域设置 `error_pages`（键只能是 `5xx` / `block` / `ratelimit` / `1xxx`，每个最多 65536 字节，空字符串读入时丢掉；未知键读入时保留、`validate` 拒绝，免得新旧节点混跑时读不出区域）、`Kind` 标记、一遍扫描的占位符替换（值做 HTML 转义，`::ERROR_BOX::` 原样插入）和 `apply()`。
- 接线：`src/items.rs` 的 `Settings` 加字段并校验；`src/edge/mod.rs` 在 `process` 的拦截页、429 页上 `errpages::mark`，`respond` 里给 `Err` 页标记、匹配之后调一次 `errpages::apply`。gRPC 和 `challenge::is_navigation` 为假的请求不替换，人机验证页没有标记；没配置时字节和响应头完全不变。
- 对应关系：带回源故障的 `EdgeError`（502、521、522、525、530）对应 `5xx`，WAF 拦截对应 `block`，限速对应 `ratelimit`，其余认出域名之后写的错误页对应 `1xxx`；认出域名之前的页（未知主机、`/cdn-cgi/`、508、509、节点更新中）不替换。`::NODE::` 是默认页上显示的节点位置代码，不是内部节点名。
- 拿不准：旧版本节点改写区域设置时会丢掉 `error_pages`；`compress.rs` 里中途读不出源站响应体时的 502 没有接；模板会让 `GET /zones` 和配置快照变大（每个域名最多 256 KiB）。
- 面板："安全"页最下面的"自定义错误页"卡片。

### T6

- 新文件 `src/alerts.rs`：Webhook 和 Telegram 两种通道（全局集合 `alert_channels`，为空时不参与序列化），覆盖 6 种事件。判定 `evaluate` 是纯函数，只在面板节点上（和自动防火墙同一个条件）每 30 秒检查一次；触发、恢复各通知一次，持续触发每 6 小时再提醒，启动后 2 分钟内的离线检查不计数。
- 接口 `/alerts/channels`（增删改查）、`/alerts/channels/{id}/test`、`/alerts/active`。输出里令牌和 Webhook 地址打码，原样送回打码值保留原密钥；写操作只限管理员，令牌要新的账户级 Notifications Read / Write。Webhook 只接受 https 和公网地址，发送时也拒绝解析到内网的名字，不跟随跳转。
- 近似处理：Fleet 没有"上次同步时间"，`sync_lagging` 用"在线但连续 5 分钟未同步"；`origin_errors` 阈值固定为 5 分钟内 3 次；证书只看证书包，不看各节点自己的站点证书。
- 拿不准：多个 peer 都没设 `--panel-origin` 时，每个 peer 都满足条件，会各发一份；通道和其他全局密钥一样随配置同步、进备份；没有做 Cloudflare `/accounts/{id}/alerting` 的兼容路径。

### T7

- 新文件 `src/edge/reqlog.rs`：每个节点内存里一个 5000 条的环形缓冲（锁内只做入队出队和取 Arc），序号连续，游标就是序号。比最旧还旧的游标从最旧开始并返回 `gap: true`，比最新还新的游标返回空和当前最新游标。在 `respond(` 里 `edge.stats.record(` 旁边一行接入；method、ASN、UA 加进了 `Seen`。
- 接口 `GET /zones/{id}/logs/requests`（参数写错一律 400）；推送任务 `LogJob` 按 `Item` 存储，走 `/zones/{id}/logpush/jobs`（照 Cloudflare 的路径）。新的域名级令牌区域 `Logs`（Logs Read / Write），`Analytics Read` 看不到日志；面板里只有管理员能写推送任务。推送循环在所有节点上跑，NDJSON，10 秒超时，失败丢弃并记一条只含主机名的警告。
- 没把握：`bytes` 是响应声明的长度（流式无长度时为 null），`duration_ms` 只算到响应头；质询不区分 js_challenge 和 managed_challenge；推送目标禁止内网（局域网收集器用不了）；多个推送任务串行发送；没有对真实 HTTPS 收集器跑过；Logs Read 能看到推送目标地址（地址里若带令牌也看得到）。

### T8
- 新文件 `src/edge/waiting.rs`：域名对象 `WaitingRoom`（`/zones/{id}/waiting_rooms`，`Item`，接线照 `log_jobs`，Data 和 Tombstones 为空时不序列化）。`process(` 里在重定向之后、改写规则之前调用 `waiting::gate`，回源之后用 `waiting::stamp` 加 Cookie，缓存看不到这个 Set-Cookie。为了识别防火墙放行，`waf.rs` 新增 `Verdict::Skipped`。
- 放行 Cookie 和排队票都用 `Waf::mac` 签名、`mac_ok` 校验，只认规范写法；会话过半时打开页面会续期。排队按到达秒先到先放，120 秒没刷新或已经用过的票作废。排队页返回 200、`no-store`、`Retry-After: 20`。名额按节点各自计算，状态只在内存里且有上限。
- 只有 GET/HEAD 的页面请求排队；`/cdn-cgi/`、`skip` 放行、暂停的域名不排队。路径先解码百分号转义、合并连续的 `/` 再匹配前缀，`/%73hop`、`//shop` 绕不过 `/shop`。令牌新开 `Waiting Rooms Read / Write`，面板在 网络与协议 → 等候室。
- 没把握：字段名没有照 Cloudflare（`path` / `session_duration`）；Rulesets 的 skip 现在也会跳过等候室；前缀区分大小写；用编码路径访问的人带不上 Path 为前缀的 Cookie，会一直排队；多个节点时源站可能看到名额的节点数倍；给 `public` 的响应加 Set-Cookie 时没改 Cache-Control。

### T9
- 新文件 `src/edge/widget.rs` 和 `src/edge/challenge-widget.js`：组件对象、令牌和题目的签名（各有自己的前缀和标签，和域名自己的验证 Cookie 互不通用）、防重放、四个 `/cdn-cgi/challenge-platform` 端点和 siteverify，复用 challenge.rs 的检测和计算（challenge.rs 只把 3 个函数改成 `pub(super)`）。
- 接线照 `alert_channels`：store.rs 的 `challenge_widgets`，api.rs 的 `/challenges/widgets`（也认 `/accounts/{id}/challenges/widgets`，写操作只给管理员），tokens.rs 新开 Turnstile Sites Read / Write，面板导航加"人机验证"页。
- 密钥只存 SHA-256、只在创建和轮换时显示一次；令牌 5 分钟、绑定 sitekey、主机名和 IP，同一节点只认一次，记录满了就拒绝；只给开了代理、列在 domains 里的精确主机名发题，不开放跨域。
- 没把握：防重放按节点算，跨节点会多认一次；轮换没有宽限期；只支持 managed 模式；`remoteip` 不一致直接拒绝，比 Turnstile 严；`/cdn-cgi/` 不经过域名的 WAF 和限流；前端脚本只做了语法检查，没在浏览器里跑过。

### T10
- 新增 src/dkim.rs：私钥存在 `Zone.email_dkim`，不放在 settings 里，所以 API 永远不返回私钥。通过 `PATCH /zones/{id}/email` 设置 `dkim_selector` 和 `dkim_private_key`；私钥留空就保留原来的，选择器为 null 或空就移除。
- mail.rs 的 `hand_on` 在 send 之前给转发和 Worker 转发的信加签名（relaxed/relaxed，rsa-sha256，From 多签一次防止追加），退信不签；签名失败照常转发，只记一条不含密钥的警告。没配置的域名原样转发。
- GET 返回 `dkim_record` 等字段，公钥 TXT 没发布时会列进 `needed_records`；面板"电子邮件"卡片可以设置、更换和移除。
- 没把握：旧节点不认识 `email_dkim`，滚动升级期间可能被 LWW 覆盖掉。ARC 没做，私钥每封信都重新解析一次。

## 5. 部署（通过 Komari）

本节覆盖第 0 节"不能运行测试"的说法中与上线有关的部分：代码仍然由 CI 编译和测试，你通过 Komari 的远程执行把
**CI 测过的那个二进制**换到节点上。除本节写明的两条命令外，不在节点上执行任何其他命令。

### 5.1 什么可以部署

- 只部署 `master` 上、`ci` 工作流全部作业（check / test、musl 构建、UI、gitleaks）都通过的提交。`duet`、`next` 上的提交不部署。
- `duet` 的内容进 `master` 走 PR：PR 上的 `ci` 就是你的编译器，失败就读日志修，直到全绿。这一步可以等 CI。
  合并要所有者同意。只改文档的提交不触发 `ci`，部署时取最近一个有绿色 `ci` 的提交。
- 每一轮部署前，先向所有者说明要部署哪个提交、哪些节点，得到同意后再开始。一次同意只管这一轮。
- 部署记录、节点地址、Komari 的地址和令牌一律不写进仓库。

### 5.2 发布产物

新增 `.github/workflows/release.yml`（手动触发，把 `ci` 测过的二进制原样发布成 Release，节点才能不带令牌下载），内容见该文件。

### 5.3 节点上的脚本

新增 `scripts/deploy/node-upgrade.sh`（第 1.4 节里 `scripts/deploy/` 的唯一例外；LF 换行），内容见该文件。

### 5.4 一轮部署的步骤

1. 取要部署的提交 `SHA`（完整 40 位）。手动触发 `release` 工作流，得到标签 `build-<SHA 前 12 位>`；
   从 Release 的 `fucf-linux-x86_64.sha256` 里读出二进制的 `SHA256`（64 位十六进制）。
2. 顺序固定，**一次只动一个节点**：`my` → `sgp` → `eu` → `us2` → `us` → `jp` → `au`（`au` 运行面板，永远最后）。
3. 在该节点上用 Komari 远程执行（把三个尖括号换成实际值，整条是一行）：

   ```
   curl -fsSL -o /tmp/node-upgrade.sh https://raw.githubusercontent.com/is-hp-is-mad/fucloudflare/<SHA>/scripts/deploy/node-upgrade.sh && nohup setsid bash /tmp/node-upgrade.sh deploy build-<SHA前12位> <SHA256> > /tmp/node-upgrade.log 2>&1 < /dev/null &
   ```

   升级在后台进行，不受远程执行超时影响。约 90 秒后在同一节点执行 `cat /tmp/node-upgrade.log`：
   最后两行必须是 `OK running <SHA256 前 12 位>` 和 `exit 0`。还没有 `exit` 行就再等。
4. 出现 `!!!!` 或 `exit` 不是 0：**立即停止，不要继续下一个节点，也不要重试**，把日志原样交给所有者。
   脚本在不健康时已经自己换回了之前的版本。
5. 每个节点成功后，在 `au` 上执行 `bash /tmp/node-upgrade.sh status`（`au` 上没有脚本时先用第 3 步的 `curl` 部分下载）：
   所有节点应为 `online` 和 `in sync`。升级后一分钟内配置版本会变动几次，出现 `DIFFERENT` 时隔 60 秒再看一次，
   连续两次都是才算有问题。确认无误再做下一个节点。
6. 全部完成后向所有者报告：部署的提交、每个节点的结果。

### 5.5 回滚

脚本失败时自动回滚。事后需要人工回滚某个节点（要所有者同意）：

```
install -m 0755 /usr/local/bin/fucf.prev /usr/local/bin/fucf && systemctl restart fucf
```

`fucf.prev` 只保留上一次升级之前的那个版本。

### 5.6 禁止

- 不修改 `/etc/fucf/fucf.env`、systemd 单元，不运行 `install-node.sh` 和 `fleet.sh`（它们会重写节点配置）。
- 不动节点上的其他服务（haproxy、hysteria、xray、sing-box、caddy），不安装软件，不重启机器。
- 不输出 `/etc/fucf/fucf.env` 的内容，不在命令里写令牌。
- 不同时升级两个节点，不跳过第 5 步的检查。
