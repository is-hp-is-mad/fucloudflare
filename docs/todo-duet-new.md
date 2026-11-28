# todo-duet-new.md：追加任务单（第二批）

**先读 `docs/todo-duet.md` 的第 1、2 节**：那里的全部规则适用于本文件——只在 `duet` 分支提交、不碰 `master`/`next`、公开仓库只用示例地址、不加依赖、没有编译器时的写法约束、不许碰的文件清单、交接记录格式。本文件是**追加**，不替代原任务单：先把原单的 T2–T10、T12、T13 做完（T11 Access 已取消），再做这里的 N 系列任务。

## 0. 现状（写完原任务单前必读，避免做重）

`next` 分支上已经写完并推送的功能（只编译过，测试最后由别人统一跑）。**不要重复实现**，但 N3/N4/N5 要为它们写界面、文档和 e2e：

| 功能 | 对外接口 / 位置 |
|---|---|
| 实测调度：节点记录访客握手往返时间 | `GET /steering/measured`（`{记录: [{"net","node","ms","at"}], "now"}`）；调度规则动作新增 `fastest`（面板已有） |
| TLS 会话票据全机群通用；`--edge-ttl` 对代理记录也生效 | 无新接口 |
| 源站主动健康检查、权重、会话保持 | 域名设置 `origin_check_path`、`session_affinity`（面板已有输入框）；`GET /zones/{id}/origins/health` |
| 限速增强 | 限速规则新增 `characteristics`（`["IP","Header:x-x","Cookie:x","ASN","Country"]`）和 `status_codes`（`[404]`）字段；面板表单已有 |
| DNS 扩充 | 记录类型新增 HTTPS/SVCB/TLSA/SSHFP/DS/NAPTR/URI（HTTPS/SVCB 面板已有表单）；域名设置 `dns_transfer_to`（允许 AXFR 的地址）；`GET /zones/{id}/dns_analytics` |
| 权威 DNS 响应限速；封禁导出 | 仅命令行：`--dns-rrl`、`--ban-export` |
| 缓存扩充 | 清除接口的 body 新增 `hosts`、`tags`；缓存规则新增 `ignore_query`、`swr`；域名设置 `cache_tier_node`（分层缓存上层节点名） |
| TLS 指纹 JA4 | 表达式字段 `fcf.ja4`；`/cdn-cgi/fucf-trace` 的 `ja4=` |
| 回源客户端证书 | 仅命令行：`--origin-client-cert` / `--origin-client-key` |
| 遥测全网同步 | 无对外接口（面板数据天然变全） |

**明确不做、不要捡起来的**：Tunnel、Access（T11）、anycast/BGP。

## 1. 追加任务

### [ ] N1 Bot 综合评分（`fcf.bot_score`）

- 新文件 `src/edge/botscore.rs`：一个纯函数，把请求特征合成 1–99 的分数（1 = 几乎确定是机器人，99 = 几乎确定是人；和 Cloudflare 方向一致），附评分因素表（代码注释）。输入至少考虑：连接有无 TLS ClientHello 却拿不出 JA4（指纹缺失）、`info.threat` 纯净度分、HTTP 版本、常见浏览器头是否存在（`User-Agent`/`Accept`/`Accept-Language`）、是否是已知爬虫（`reputation` 的爬虫判定，已知爬虫应得稳定的中等分而非随机低分）。每个因素写成小函数，便于以后加 JA3、HTTP/2 指纹。
- 接线：`src/edge/mod.rs` 搜 `info.threat = rep.assess`，在同一处算出 bot 分存进 `ReqInfo` 新字段 `bot_score`；`src/edge/cgi.rs` 的 trace 加 `bot=`；`src/expr.rs` 加 `Val::BotScore`（照抄 `Val::Threat` 的三处写法：枚举、`parse` 里 `fcf.bot_score`/`cf.bot_management.score` 都识别、`eval`、`ty()` 返回 `Ty::Int`）。
- 单元测试：分数在 1–99 内、缺指纹的裸 TLS 客户端比完整浏览器低、已知爬虫分数稳定。
- 可选延伸（做完主体再说）：JA3 摘要（MD5，可用 `fmt::Write` 手写 16 字节 hex，不引入 md5 crate）放在 JA4 旁边；HTTP/2 指纹不要碰（要拆帧，留给有编译器的人）。

### [ ] N2 自定义缓存键（请求头 / Cookie 参与键）

- 缓存规则（`src/items.rs` 搜 `pub struct CacheRule`）新增可选字段：`cache_key_headers`、`cache_key_cookies`（字符串数组，serde default）。
- 求值：`src/edge/mod.rs` 搜 `cache::cache_key(` 的调用处，键里追加指定头/Cookie 的值（不存在按空串）；键总长设上限（如 2 KB），超长截断并跳过缓存写入，避免键爆炸。注意大写小写统一、值里控制字符剔除。
- 校验、面板：照抄 `ignore_query` 的 4 处接线（校验、清除域名缓存提醒——键变了按 URL 清除的语义不变，因为 URL 部分仍在键首）。表单加两个逗号分隔输入框。
- 单元测试：不同头值进不同条目；未配置时行为不变。
- 不要尝试"大文件分片缓存"：那是磁盘层大手术，留给有编译器的人。

### [ ] N3 新功能的面板界面

`src/panel.html` 很大（187 KB），只许按锚点搜片段、不许整读。锚点：卡片函数搜 `function card(`，网络页表格搜 `steerTest`，域名设置行搜 `setRow`，请求封装搜 `async function api(`。

- 网络页：加"实测延迟"小表，数据来自 `GET /steering/measured`（注意响应形状：`result` 是 `{records, now}`，不是裸数组）；按节点分组显示最近样本的毫秒数和时间。
- 域名页：加"源站健康"小表，数据来自 `GET /zones/{id}/origins/health`（数组：`origin/ok/last/error`）。
- DNS 页：加"查询统计"小表，数据来自 `GET /zones/{id}/dns_analytics`（`{queries, by_type}`）。
- 域名设置（照抄 `origin_check_path` 的输入框写法）：`cache_tier_node`（文本，上层缓存节点名）、`dns_transfer_to`（逗号分隔 IP 列表，放在 DNS 页）。空字符串=未设置，提交时按现有 setRow 的null 处理惯例。
- 每处都做无数据时的空态（接口可能返回空数组/空对象，面板不能报错）。

### [ ] N4 新接口与行为的文档补齐

- `docs/api.md` 补上第 0 节表格里所有接口/字段：`GET /steering/measured`、`GET /zones/{id}/origins/health`、`GET /zones/{id}/dns_analytics`、purge body 的 `hosts`/`tags`、缓存规则 `ignore_query`/`swr`/`cache_key_headers`/`cache_key_cookies`、限速规则 `characteristics`/`status_codes`、域名设置 `cache_tier_node`/`dns_transfer_to`/`origin_check_path`/`session_affinity`、新 DNS 记录类型与 AXFR 用法（`@dns_transfer` ACL 标签、`--dns-notify`）、限速规则匹配条件里的 `threshold` 单位说明（每分钟）。
- 核对 README 已有小节是否与代码一致（别人已写过 JA4、AXFR、限速、缓存、回源证书等小节），发现过期就修；命令行新 flag 以 README 为准。
- 例子只用保留地址与示例域名。

### [ ] N5 e2e 脚本覆盖新功能（只写静态能确定的）

- `scripts/e2e.py` baseline 段照抄现有检查风格，新增小而稳的检查：按 `tags`/`hosts` 清除的 API 形状（其余缓存语义由别人跑的时候验证）、`dns_analytics` 在发过查询后出现记录、`/steering/measured` 形状、`characteristics` 限速在缺该头时按 IP 计数。
- 只写不依赖真源站行为的；拿不准语义的宁可不写，在交接里注明"留待验证"。

## 2. 不分配给本任务单的剩余项（列出以免遗漏，由有编译器的一方做）

- 大文件分片缓存（缓存层大手术，必须实测）。
- 访客客户端证书 mTLS、给源站签发自有 CA（TLS 服务端配置，安全关键）。
- 后量子密钥交换（aws-lc-rs 替换 ring，涉及新依赖与 musl 构建风险）。
- zstd、0-RTT、Early Hints、`/cdn-cgi/image/` 图片缩放（涉及新依赖；0-RTT 有重放安全分析）。
- 自定义主机名（别人的域名 CNAME 过来、自动签证书；牵动 ACME 与证书管线）。
- Workers 引擎替换（选型待所有者定）及之后的 Workers 周边（wrangler 格式、密钥绑定、HTMLRewriter、Cache API、WebSocket）。
- 全机群近似限速计数（同步核心，需要实测）。
- 已评估后放弃：DNS 一次应答两个节点做故障切换（多 A 记录会均分流量，违背调度目的）。

## 3. 交接记录（每个任务做完在此追加一段，格式同原任务单第 3 节）
