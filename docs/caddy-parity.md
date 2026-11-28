# Caddy parity for the native reverse proxy

Goal: everything a typical Caddyfile does can be expressed as fucf
`LocalProxyRule`s (plus a few node flags), so fucf can replace Caddy on a node
— and the feature stays general, not tied to one deployment.

Status legend: ✅ done · 🟡 partial · ⬜ to do

## Sites and TLS

| Caddy | fucf | Status |
|---|---|---|
| site blocks by host name, wildcards | `hosts` (`example.com`, `*.example.com`, `*`) | ✅ |
| `tls cert key` (files) | `--tls-cert-dir` (acme.sh / certbot / Caddy storage / `name.crt`+`name.key`, reloaded every minute) | ✅ |
| `default_sni` | `--tls-default-sni` | ✅ |
| uploaded certificates | zone `custom_certificates` | ✅ (zone-bound) |
| automatic HTTPS (ACME) for every site | zones: managed certificates; proxy rules scoped to a node: `auto_https` (per host, HTTP-01 / TLS-ALPN-01 answered by that node, IPs with the `shortlived` profile, key stays on the node, renewed in the last third) | ✅ |
| on-demand TLS | — | ⬜ |
| automatic HTTP→HTTPS redirect | per-rule `https_redirect` (308; ACME challenges still answered) | ✅ |
| HTTP/3 | `--proxy-h3-listen`, or Hysteria front / QUIC SNI split | ✅ |

## Routing

| Caddy | fucf | Status |
|---|---|---|
| `handle`, `route` (ordered) | `priority` + longest path prefix | ✅ |
| `handle_path` / `uri strip_prefix` | `strip_prefix` | ✅ |
| `rewrite` | `rewrite_path` | 🟡 (prefix/whole path; no placeholders/regex) |
| path matchers `/api/*`, exact | `path_prefix`, `exact_path` | 🟡 (no glob/regex) |
| `method`, `header`, `query`, `remote_ip`, `not` matchers | — | ⬜ |
| `redir` | `redirect_url` + `redirect_status` | ✅ (no placeholders) |
| `respond` | `respond {status, body, content_type}` | ✅ |
| `try_files` (SPA fallback) | — | ⬜ |

## Proxying

| Caddy | fucf | Status |
|---|---|---|
| `reverse_proxy` http / https / h2c | `upstreams` (`http`, `https`, `h2c`, `ws`, `wss`) | ✅ |
| `tls_insecure_skip_verify` | `tls_insecure` | ✅ |
| WebSocket | HTTP/1.1 Upgrade, HTTP/2 RFC 8441, HTTP/3 RFC 9220 (h3 crate pending) | ✅/🟡 |
| `flush_interval -1` (streaming) | always streams | ✅ |
| several upstreams, weights | weighted round robin, passive cool-down | 🟡 |
| `lb_policy` (least_conn, ip_hash, cookie, header…) | — | ⬜ |
| active health checks | — | ⬜ |
| `header_up` / `header_down` | `set_request_headers`, `set_response_headers`, `strip_response_headers` | 🟡 (no placeholders like `{remote_host}`) |
| `X-Forwarded-*` | added automatically | ✅ |
| unix socket upstreams | — | ⬜ |
| upstream names only resolvable inside Docker (`app:8080`) | — (publish ports on 127.0.0.1, or run fucf in the network) | ⬜ (Docker-aware resolution) |
| timeouts, retries, `max_fails` | built-in defaults | 🟡 |

## Static files and responses

| Caddy | fucf | Status |
|---|---|---|
| `file_server` | `file_root` + `index_files`; ETag/Last-Modified, ranges, streaming; only below `--file-root-allow` | ✅ |
| `file_server browse` | — | ⬜ |
| `precompressed` | — | ⬜ |
| `encode gzip zstd` | gzip/br on compressible responses (all routes) | 🟡 (no per-rule switch, no zstd) |
| `header` (static) | `set_response_headers` | ✅ |

## Security and operations

| Caddy | fucf | Status |
|---|---|---|
| `basicauth` | — | ⬜ |
| `forward_auth` | — | ⬜ |
| `request_body max_size` | global limit | 🟡 |
| per-site access log | edge stats + origin-error events | 🟡 |
| `import` / snippets | — | ⬜ |
| Caddyfile → rules | — | ⬜ (`fucf caddy-import` planned) |

## Order of work

1. ✅ Disk certificates, `default_sni`, `respond`, `file_server`, per-node `domains.lst`.
2. ✅ ACME for proxy-rule hosts (TLS-ALPN-01 / HTTP-01 on the node that serves them) and automatic HTTP→HTTPS.
3. Matchers (method, header, query, remote IP, glob paths) and placeholders in headers/redirects (`{host}`, `{uri}`, `{remote_host}`).
4. `try_files`, `basicauth`, `forward_auth`.
5. Load-balancing policies, active health checks, unix sockets, Docker-aware upstream names.
6. `fucf caddy-import Caddyfile` to turn an existing Caddyfile into rules.
