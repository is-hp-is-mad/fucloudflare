# fucf API

The management API speaks Cloudflare's v4 dialect: same paths where Cloudflare has them, the same
envelope (`{"success", "errors", "messages", "result", "result_info"}`), the same field names. Tools
written for Cloudflare (certbot-dns-cloudflare, acme.sh `dns_cf`, lego, Terraform, DDNS scripts) work
once they are pointed at your panel instead of `api.cloudflare.com`.

Throughout this page, `panel.example.com` stands for your panel's host name and `example.com` for one
of your zones.

```
BASE=https://panel.example.com/client/v4
```

A path with a trailing slash is the same path without it (`GET $BASE/zones/?name=example.com` lists zones
like `GET $BASE/zones?name=example.com`), for every method, and is checked as that path: who may see a zone
does not depend on the slash. The one exception is Workers KV, where a key is part of the path
(`.../values/{key}`) and may itself end in `/`.

## Authentication

| How | Header | For |
| --- | --- | --- |
| API token | `Authorization: Bearer <token>` | Tools. Scoped by policies, see below. |
| Global API Key | `X-Auth-Email: you@example.com` + `X-Auth-Key: <key>` | Old tools. Everything its owner may do, except `/account/*`. |
| Panel session | `Authorization: Bearer fucf_s_...` | The panel itself. |
| Fleet token | `Authorization: Bearer <FUCF_API_TOKEN>` | The fleet's own tooling (node-local, `127.0.0.1:8787`). |

Check a token:

```sh
curl -s -H "Authorization: Bearer $TOKEN" $BASE/user/tokens/verify
# {"success":true,"result":{"id":"…","status":"active","not_before":null,"expires_on":null},…}
```

A token never does more than its owner's role allows (viewer, editor, admin). Signing in, passwords,
two-step verification, users and replication are never reachable with a token.

## API tokens

```
GET    /user/tokens                       your tokens
POST   /user/tokens                       create; the answer carries "value" (shown this once)
GET    /user/tokens/{id}
PUT    /user/tokens/{id}                  replace (the value stays)
DELETE /user/tokens/{id}
PUT    /user/tokens/{id}/value            roll: a new value, the old one stops working
GET    /user/tokens/verify
GET    /user/tokens/permission_groups
POST   /account/api_key                   {"password", "remove": false}: make (or remove) your Global API Key
GET    /user                              who the credentials belong to
GET    /accounts, /accounts/{id}          the one account (tools look up its id)
```

A token for certbot that may only change DNS records of one zone, from one network, until the end of
2027:

```sh
curl -s -X POST $BASE/user/tokens -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" -d '{
  "name": "certbot",
  "policies": [{
    "effect": "allow",
    "resources": { "com.cloudflare.api.account.zone.<zone id>": "*" },
    "permission_groups": [{ "name": "Zone Read" }, { "name": "DNS Write" }]
  }],
  "condition": { "request.ip": { "in": ["198.51.100.0/24"], "not_in": [] } },
  "expires_on": "2027-12-31T23:59:59Z"
}'
```

Resources, as on Cloudflare:

| Resource | Means |
| --- | --- |
| `com.cloudflare.api.account.zone.<zone id>` | one zone |
| `com.cloudflare.api.account.zone.*` | every zone, also those added later |
| `com.cloudflare.api.account.<account id>` = `"*"` | account-level things (Workers, KV, D1, fleet, backups) and every zone |
| `com.cloudflare.api.account.<account id>` = `{"com.cloudflare.api.account.zone.*": "*"}` | every zone of the account |
| `com.cloudflare.api.user.<user id>` | your own tokens |

`deny` policies win over `allow`; a write group includes reading; any permission on a zone lets the
token see that zone (`GET /zones` lists only the zones a token names). Permission groups can be given
by `id` or by `name`:

| Group | Scope | Covers |
| --- | --- | --- |
| Zone Read / Zone Write | zone | `/zones`, `/zones/{id}` (Write: add, change, delete zones) |
| Zone Settings Read / Write | zone | `/zones/{id}/settings…`, `/dnssec` |
| DNS Read / DNS Write | zone | `/zones/{id}/dns_records…` |
| Cache Purge | zone | `/zones/{id}/purge_cache` |
| Firewall Services Read / Write | zone | firewall rules, rate limits, security events |
| SSL and Certificates Read / Write | zone | certificate packs, custom certificates, `/zones/{id}/custom_hostnames…`, `/zones/{id}/origin_ca…` |
| Origin Rules, Dynamic Redirect, Transform Rules, Cache Rules Read / Write | zone | the rule lists of those names |
| Workers Routes Read / Write | zone | `/zones/{id}/workers/routes` |
| Email Routing Rules Read / Write | zone | `/zones/{id}/email…` |
| Zone Spectrum Read / Write | zone | `/zones/{id}/spectrum/apps` |
| Analytics Read | zone | `/zones/{id}/analytics`, `/zones/{id}/dns_analytics`, `/zones/{id}/origins/health` |
| Logs Read / Logs Write | zone | `/zones/{id}/logs/requests` (visitor addresses included), `/zones/{id}/logpush/jobs` (Write: change jobs) |
| Waiting Rooms Read / Write | zone | `/zones/{id}/waiting_rooms` |
| Workers Scripts, Workers KV Storage, D1 Read / Write | account | `/workers/scripts…`, `/kv/…`, `/d1/…` |
| Fleet Read / Write | account | nodes, fleet actions, steering, local proxy rules, releases |
| Notifications Read / Write | account | `/alerts…` (alert channels, test messages, active alerts) |
| Account Analytics Read, Audit Logs Read | account | `/analytics`, `/audit` |
| Backup Read | account | `GET /backup` (everything, secrets included: guard such a token) |
| Account Filter Lists Read / Write | account | `/rules/lists…` (IP lists) |
| Turnstile Sites Read / Write | account | `/challenges/widgets…` (human-check widgets) |
| API Tokens Read / Write | user | `/user/tokens…` |

Cloudflare's account-level paths work too: `/accounts/{account id}/workers/scripts/…`,
`/accounts/{account id}/storage/kv/namespaces/…`, `/accounts/{account id}/d1/database/…`,
`/accounts/{account id}/tokens/…`, `/accounts/{account id}/rules/lists/…`,
`/accounts/{account id}/challenges/widgets/…`, and `/accounts/{account id}/audit_logs` (the same as `/audit`).
Any other path under `/accounts/{account id}/` answers `404` (code `7000`), and an account id that is
not this one `404` (code `7003`).

## Zones and DNS records

```
GET    /zones?name=example.com&status=active
POST   /zones                             {"name", "type": "full|partial"}
GET    /zones/{id}  PATCH  DELETE
GET    /zones/{id}/dns_records            filters below
POST   /zones/{id}/dns_records
GET    /zones/{id}/dns_records/{id}  PUT  PATCH  DELETE
POST   /zones/{id}/dns_records/batch      {"deletes", "patches", "puts", "posts"}
GET    /zones/{id}/dns_records/export     BIND zone file
POST   /zones/{id}/dns_records/import     multipart field "file" (or the file as the body); proxied=true
```

A record proxied through the edge, with its own way to the origin (a port, HTTPS, the TLS name and
Host header the origin wants, or one of the fleet's nodes as the origin):

```sh
curl -s -X POST $BASE/zones/$ZONE/dns_records -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d '{
  "type": "A", "name": "app", "content": "192.0.2.10", "proxied": true, "ttl": 1,
  "origin": { "port": 8443, "scheme": "https", "sni": "app.internal.example", "host_header": "app.example.com" }
}'
```

`origin` fields (all optional): `port`, `scheme` (`http` / `https`, whatever the zone's SSL mode),
`sni`, `host_header`, `node` (route to that edge node's local port), `weight` (1 to 100, 1 when not
given: this address's share of the requests among the name's addresses, see
[Origins](#origins-health-checks-weights-and-session-affinity)). An empty object removes them.

Record types: `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `NS`, `SRV`, `CAA`, `PTR`, and these, written in
`content` as in a zone file (a word in double quotes may hold spaces; the content is kept as written):

| Type | `content` |
| --- | --- |
| `HTTPS`, `SVCB` | `priority target [key=value ...]`, such as `1 . alpn=h2,h3 port=443 ipv4hint=192.0.2.1` (`.`: the record's own name). Keys: `alpn`, `no-default-alpn`, `port`, `ipv4hint`, `ipv6hint`, `ech` (base64), each at most once; priority 0 (the alias form) takes none |
| `TLSA` | `usage selector matching-type data`, the data in hexadecimal |
| `SSHFP` | `algorithm type fingerprint`, the fingerprint in hexadecimal |
| `DS` | `key-tag algorithm digest-type digest`, the digest in hexadecimal: the DS of a name the zone delegates with NS records, answered for that name |
| `NAPTR` | `order preference "flags" "services" "regexp" replacement` (`.` for no replacement) |
| `URI` | `priority weight "target"` |

Only `A`, `AAAA` and `CNAME` can be proxied. At a proxied name the edge answers `HTTPS` queries with
its own record (HTTP/3 and HTTP/2), not with the zone's.

SRV and CAA (and only they) can be written as `data`, the way Cloudflare takes them:

```json
{ "type": "SRV", "name": "_sip._tcp", "data": { "priority": 10, "weight": 5, "port": 5060, "target": "sip.example.com" } }
{ "type": "CAA", "name": "@", "data": { "flags": 0, "tag": "issue", "value": "letsencrypt.org" } }
```

List filters: `type`, `proxied`, `search`, `match=any|all`; for `name`, `content` and `comment`:
`x`, `x.exact`, `x.contains`, `x.startswith`, `x.endswith` (`comment.present`, `comment.absent`);
`order=type|name|content|ttl|proxied` with `direction=asc|desc`; `page`, `per_page`.

Batches run deletes, then patches, puts and posts. Everything is checked first; should a change still
fail half way, the ones before it stay done and the error says where it stopped (Cloudflare's batches
are atomic, these are not).

Export marks proxied records as Cloudflare does (`; cf_tags=cf-proxied:true`), and import reads that
mark back.

## Security

```
GET    /zones/{id}/settings                         every setting
PATCH  /zones/{id}/settings/{name}                  {"value": …}
CRUD   /zones/{id}/firewall/rules                   {"expression", "action", "priority", "enabled", "description"}
CRUD   /zones/{id}/rate_limits                      {"expression", "threshold", "period", "mitigation_timeout", "action",
                                                     "characteristics", "status_codes"}
GET    /zones/{id}/security/events?limit=
GET    /steering/test?ip=&ua=                       where an address is placed, and its threat score
```

Firewall actions: `block`, `js_challenge` (the human check; a click only when the browser looks
doubtful), `managed_challenge` (always one click), `log`, `skip`. Expressions use Cloudflare's rules
language: `http.host`, `http.request.uri.path`, `http.request.method`, `http.user_agent`,
`http.request.headers["x"]`, `ip.src`, `ip.geoip.country`, `ip.geoip.continent`, `ip.geoip.asnum`,
`ip.geoip.as_org`, `cf.threat_score` (also `fcf.threat_score`), `cf.bot_management.score` (also
`fcf.bot_score`), `fcf.ja4` (also
`cf.bot_management.ja4`: the JA4 fingerprint of the visitor's TLS ClientHello, empty over plain HTTP
and HTTP/3; `/cdn-cgi/fucf-trace` shows it as `ja4=`), `cf.tls_client_auth.cert_verified` (also
`fcf.client_cert_verified`: whether the visitor presented a client certificate the node verified,
see [Visitor client certificates](#visitor-client-certificates-mtls)), with `eq ne lt le gt ge contains
matches in {…} and or not`. `ip.src in $name` asks an IP list (see [IP lists](#ip-lists)).

Settings that belong here:

| Setting | Values |
| --- | --- |
| `security_level` | `off` (also `essentially_off`, the same here), `low` (threat score ≥ 80 is challenged), `medium` (≥ 50), `high` (≥ 25: data centres too), `under_attack` (everybody). Higher levels also ask for more work and tolerate less doubt. |
| `challenge_script` | `true`: the fcf script goes into the site's HTML pages. It passes the check quietly in the background, and settles challenged `fetch` requests in place (a click box over the page, then the request is sent again: no reload). |
| `waf` | managed ruleset: `block`, `log`, `off` |
| `auto_firewall` | ban addresses from recent security events (see below) |
| `decoy_subdomains` | every name without records resolves, and nothing answers there |

The threat score (0 to 100) comes from public lists every node fetches twice a day (FireHOL level 1
and 2, Tor exit nodes, VPN and data centre ranges), hosting networks by name, and what the fleet itself
banned lately. Private addresses, the fleet's own and search engine crawlers coming from their own
networks score 0.

The bot score (1 to 99, Cloudflare's direction: 1 is almost certainly automated, 99 almost certainly
a human) adds up a few signals of each request: a TLS connection whose ClientHello gave no JA4
fingerprint, the shape of the fingerprint (TLS 1.3 with a server name and ALPN, or older), the
threat score, the HTTP version, whether `User-Agent`, `Accept`, `Accept-Language`,
`Accept-Encoding` and `Sec-Fetch-Mode` are there and whether the User-Agent names a tool or
crawler. It involves no randomness: a request gets the same score on every node that gives its
address the same threat score.
Search engine crawlers coming from their own networks always score 50, so that a rule like
`fcf.bot_score lt 30` (block or challenge likely bots) leaves them alone; one that only claims to be
a crawler scores like any script. `/cdn-cgi/fucf-trace` shows the score of the request as `bot=`.
Unlike Cloudflare there is no `cf.bot_management.verified_bot` field and no machine learning:
treat the score as a heuristic and prefer challenging to blocking.

A challenged request that is not a page load (`Sec-Fetch-Mode` other than `navigate`, or an `Accept`
without `text/html`) gets JSON rather than a page:

```
HTTP/1.1 403 Forbidden
fcf-mitigated: challenge
fcf-challenge: /cdn-cgi/challenge-platform/verify
content-type: application/json

{"success":false,"errors":[{"code":1020,"message":"a human check is needed…"}],"challenge":{"t":"…","b":17,"c":false,"v":"/cdn-cgi/challenge-platform/verify"},"ray":"…"}
```

Every response says whether it came from the cache: `fcf-cache-status` (Cloudflare's labels: `HIT`,
`MISS`, `EXPIRED`, `STALE`, `UPDATING`, `REVALIDATED`, `BYPASS`, `DYNAMIC`, `NONE` for what the edge
answered itself) and `x-cache: HIT|MISS from <colo>`. Nothing the edge sends starts with `cf-`; what an origin
behind Cloudflare sends that does is dropped. Origins receive `fcf-connecting-ip` and `fcf-ipcountry`
(and, for software written for Cloudflare, `cf-connecting-ip` and `cf-ipcountry`).

### The automatic firewall

With `auto_firewall` on, every 30 seconds the zone's recent security events (managed rule hits,
firewall blocks, rate limit hits) are counted, and the zone's own rules are kept up to date:

| Rule | When | Does |
| --- | --- | --- |
| addresses (`managed_by: auto_firewall`) | `auto_firewall_threshold` attacks (default 10) within `auto_firewall_window` seconds (600) | `auto_firewall_action` (`block`, `managed_challenge` or `js_challenge`) for `auto_firewall_ban` seconds (86400), extended while it goes on; IPv6 by /64 |
| networks (`managed_by: auto_firewall_networks`) | `auto_firewall_networks` on and at least `auto_firewall_network_ips` (10) data centre / VPN / listed addresses of one ASN attacked | `managed_challenge` for the whole ASN (the fleet's own addresses excepted); home ISPs are never taken as a whole |
| security level | `auto_firewall_surge` (50; 0 off) different attackers within the window | `under_attack` for an hour after the surge was last seen, then back to the level before |

Banned addresses also count against their threat score on every zone.

A node started with `--ban-export <file>` (`FUCF_BAN_EXPORT`) writes the addresses banned by rules
with the action `block` (not `managed_challenge`) into that file as an nftables script: three
sets of the table `inet fucf` (below), each element with the time its ban has left. It
is checked every 30 seconds and written again when the addresses change. The host loads it (`nft -f`)
and drops those addresses itself, with rules of its own choosing. IPv6 bans of the automatic firewall,
which are by /64, go into a third set, `banned6net`, as prefixes (`2001:db8:1:2::/64`); it is declared
with `flags interval`, which a set of prefixes needs, while `banned4` and `banned6` keep the flags they
had, so a host that loaded an older file loads the new one without deleting its sets first. A rule's own
key is read the same way: an address goes into `banned4` or `banned6`, an IPv6 network of /16 or longer
into `banned6net`; IPv4 networks and shorter IPv6 networks are not exported. A set can only be used by
rules of its own table, so the host's rules go into `inet fucf` too, for example:

```
nft add chain inet fucf input '{ type filter hook input priority -10; }'
nft add rule inet fucf input tcp dport { 80, 443 } ip saddr @banned4 drop
nft add rule inet fucf input tcp dport { 80, 443 } ip6 saddr @banned6 drop
nft add rule inet fucf input tcp dport { 80, 443 } ip6 saddr @banned6net drop
```

## Backups

```
GET /backup        everything the fleet replicates (configuration, accounts, Workers KV, D1) as one
                   gzipped JSON bundle; admins, or a token with "Backup Read"
```

Every node also writes one every 6 hours into `<data dir>/backups` (the last 28 are kept;
`FUCF_BACKUP_DIR`, `FUCF_BACKUP_EVERY_HOURS`, `FUCF_BACKUP_KEEP`). A node started with
`--restore-from <bundle>` (`FUCF_RESTORE_FROM`) merges one in (what is newer there stays).
`.github/workflows/backup.yml` keeps an encrypted copy away from every node.

## Reference

Every route below sits under `$BASE` (`/client/v4`). What a call needs beyond the route is given as
its JSON body; fields not named are left alone by `PATCH` and take their defaults on `POST` / `PUT`.

Conventions:

- `CRUD /x` means `GET /x` (list), `POST /x` (create), and `GET`, `PUT` (replace), `PATCH` (change the
  fields given), `DELETE` on `/x/{id}`. A delete answers `{"id": "…"}`.
- Lists take `page` and `per_page` (1 to 5000) and answer `result_info`
  (`page`, `per_page`, `count`, `total_count`, `total_pages`).
- Objects that belong to a zone carry `id`, `zone_id`, `created_on` and `modified_on`.
- Accelerate nodes (`--role accelerate`) answer every write with `409`.
- Errors: `400` for a body that does not check out (the message says which field), `404` for an
  unknown object, `409` for a conflict (a name taken, a node out of touch), `403` for what the
  credentials may not do.

### Signing in (no credentials needed)

```
GET    /auth/status                       {"initialized", "role", "writable", "panel_host"}
POST   /auth/setup                        {"token", "email", "password"}: the first administrator; only while there is none,
                                          and only with this node's API token
POST   /auth/login                        {"email", "password"}: a session, or {"second_step": {"ticket", "methods"}}
POST   /auth/second_step                  {"ticket", and one of "code" (TOTP), "backup_code", "passkey" (a WebAuthn assertion)}
POST   /auth/passkey/begin                a challenge for signing in with a passkey alone
POST   /auth/passkey/finish               the WebAuthn assertion
GET    /auth/oauth/login                  starts single sign-on with the OIDC provider set in /oauth/config
GET    /auth/oauth/callback               where the provider sends the browser back
```

### Your account (panel sessions only)

```
GET    /account                           who is signed in, sessions, passkeys, whether two-step verification is on
POST   /account/logout
POST   /account/password                  {"current", "new"}
POST   /account/totp/begin                {"secret", "uri", "qr_svg"} for an authenticator app
POST   /account/totp/enable               {"code"}: answers ten {"backup_codes"}
POST   /account/two_factor/disable        {"password"}
POST   /account/backup_codes              {"password"}: ten new codes, the old ones stop working
POST   /account/passkeys/begin            registration options
POST   /account/passkeys                  the WebAuthn registration
DELETE /account/passkeys/{id}
DELETE /account/sessions/{id}             sign one session out
```

### Users, single sign-on and the audit trail (admins)

```
GET    /users
POST   /users                             {"email", "role": "admin|editor|viewer", "password"}; without "password" one is
                                          made up and answered this once as "password"
PATCH  /users/{id}                        {"role", "disabled", "reset_password": true, "reset_two_factor": true}
DELETE /users/{id}                        the last administrator cannot be removed, demoted or disabled
GET    /oauth/config                      the OIDC provider for single sign-on; "client_secret" comes back as "***"
PUT    /oauth/config                      the whole configuration
GET    /audit                             the last 300 sign-ins, account and user changes, node actions
```

### Zones

See "Zones and DNS records" above. `PATCH /zones/{id}` takes `{"type": "full|partial"}` and
`{"paused": true|false}`.

#### Who a zone belongs to

A zone belongs to the user who made it. Users who are not administrators (editors and viewers)
see and change only their own zones: `GET /zones` and `GET /analytics` leave the others out, and
every path under `/zones/{id}` answers another user's zone with `404` (code `1001`, "Zone not
found"), the same as a zone id that does not exist. Zones that have no owner (those from before
owners existed, and those made with the fleet's own API token) are the administrators' only.
Administrators see every zone.

```
GET    /zones/{id}                        "owner": {"id": "<user id>" | null, "type": "user"}
PATCH  /zones/{id}                        {"owner": "<user id>"}, {"owner": {"id": "<user id>"}}, or
                                          {"owner": null} (administrators only): give the zone to that user,
                                          or to nobody; an unknown user id is 400 and changes nothing
POST   /zones                             a zone made by somebody who is not an administrator may not be
                                          at, below or above a zone of another user (409);
                                          "owner" may not be sent here (400)
```

On top of their role, users who are not administrators may only read account-level objects
(Workers, KV, D1, IP lists, steering, proxy rules, nodes, ...): any other method there is `403`
(code `2010`). A user's API tokens and Global API Key reach no further than the user, whatever
zones the token names.

### Zone settings

```
GET    /zones/{id}/settings               [{"id": name, "value": …, "editable": true}, …]
GET    /zones/{id}/settings/{name}
PATCH  /zones/{id}/settings/{name}        {"value": …}
```

| Setting | Values (default first) |
| --- | --- |
| `ssl` | `flexible` (HTTP to the origin), `full` (HTTPS, certificate not checked), `strict` (HTTPS, checked) |
| `mtls` | `off`, `on`: only visitors with a verified client certificate, see [Visitor client certificates](#visitor-client-certificates-mtls) |
| `always_use_https` | `false`, `true`: 301 from HTTP to HTTPS |
| `waf` | `block`, `log`, `off`: the managed ruleset |
| `development_mode` | `false`, `true`: bypass the cache |
| `http2`, `http3` | `true`, `false` |
| `edge_nodes` | `[]` (every node) or node names |
| `security_level` | `medium`, `off`, `essentially_off`, `low`, `high`, `under_attack` |
| `challenge_script` | `true`, `false` |
| `browser_cache_ttl` | `0` (leave the origin's headers alone) to `31536000` seconds |
| `hsts_max_age` | `0` (no header) to `63072000` seconds; `hsts_include_subdomains`: `false`, `true` |
| `grpc` | `true`, `false` |
| `email_routing` | `false`, `true` |
| `decoy_subdomains` | `false`, `true` |
| `auto_firewall` | `false`, `true`, with `auto_firewall_threshold` (10), `auto_firewall_window` (600), `auto_firewall_ban` (86400), `auto_firewall_action` (`block`, `managed_challenge`, `js_challenge`), `auto_firewall_networks` (`true`), `auto_firewall_network_ips` (10), `auto_firewall_surge` (50; 0 off); ranges: threshold 1 to 100000, window 60 to 86400 s, ban 60 to 2592000 s, network ips 2 to 100000, surge 0 or 5 to 1000000 |
| `auto_level_restore`, `auto_level_until` | `""`, `0`: kept by the automatic firewall while it holds the zone in `under_attack` (the level to go back to, and until when in unix seconds); not meant to be set by hand |
| `error_pages` | `{}`, or HTML templates by key: see "Custom error pages" below |
| `origin_check_path` | `""` (no checks), or a path such as `/healthz` (at most 256 bytes): see [Origins](#origins-health-checks-weights-and-session-affinity) |
| `origin_check_interval` | `30`: 10 to 3600 seconds between two checks of an address |
| `session_affinity` | `false`, `true`: requests from one visitor address start with the same origin address |
| `cache_tier_node` | `""`, or the name of a node (at most 64 bytes): tiered cache, see [Cache](#cache) |
| `cache_chunking` | `0` (off), or `524288` to `33554432` bytes: objects of at least this size are cached in 512 KiB chunks, see [Cache](#large-objects-in-chunks) |
| `early_hints_links` | `[]`, or at most 16 `Link` header entries added to the zone's HTML pages: see [Preload hints](#preload-hints-instead-of-early-hints) |
| `image_resizing` | `false`, `true`: `/cdn-cgi/image/<options>/<path>` serves the zone's own images resized, see [Image resizing](#image-resizing) |
| `dns_transfer_to` | `[]`, or at most 16 addresses or networks (`192.0.2.53`, `2001:db8:53::/48`) that may transfer the zone: see [Zone transfers](#zone-transfers-axfr) |

```sh
curl -s -X PATCH $BASE/zones/$ZONE/settings/security_level -H "Authorization: Bearer $TOKEN" -d '{"value": "high"}'
```

#### Preload hints (instead of Early Hints)

No `103 Early Hints` answer is ever sent: hyper 1.x, which serves the visitors, has no way to send
an informational answer before the final one (its HTTP/1 encoder turns a 1xx into a 500, and a
request gets exactly one answer). In its place, `early_hints_links` lists `Link` header entries that
the edge joins into one `Link` header on the zone's `200` answers whose `Content-Type` is HTML. A
`Link` header from the origin is kept next to it; other answers (assets, redirects, errors, the
edge's own pages) get nothing. The hints arrive with the page's headers, so they help while the body
is on its way, not while the origin is still working on the page.

```sh
curl -s -X PATCH $BASE/zones/$ZONE/settings/early_hints_links -H "Authorization: Bearer $TOKEN" -d '{"value": [
  "</app.css>; rel=preload; as=style",
  "</fonts/a.woff2>; rel=preload; as=font; crossorigin",
  "<https://cdn.example.com>; rel=preconnect"
]}'
```

- Two forms only: `<URL>; rel=preload; as=TYPE` and `<URL>; rel=preconnect`, each optionally with
  `crossorigin` (bare, `=anonymous` or `=use-credentials`). Parameters are unquoted, in any order and
  case; they are sent written one way (`</app.css>; rel=preload; as=style`).
- `URL` is a path of the site (`/app.css`, not `//…`) or an `https://` URL, in printable ASCII
  without spaces, quotes, commas, semicolons, angle brackets or backslashes.
- `TYPE` is one of `audio`, `document`, `embed`, `fetch`, `font`, `image`, `object`, `script`,
  `style`, `track`, `video`, `worker`; `as` is refused on a preconnect.
- At most 16 entries of at most 512 bytes each, and at most 4096 bytes for the header they make.
  Anything else (another `rel`, an unknown parameter, a second link in one entry) refuses the whole
  value with `400`, naming the entry (`early_hints_links[1]: …`).
- Response header rules (transform rules) run after it and can remove or replace the header.

#### Image resizing

With `image_resizing` on, `https://<host>/cdn-cgi/image/<options>/<path>` answers with the zone's
own `<path>` (and the request's query), resized and encoded again. Off (the default), such a path
goes to the origin like any other.

```sh
curl -s -X PATCH $BASE/zones/$ZONE/settings/image_resizing -H "Authorization: Bearer $TOKEN" -d '{"value": true}'
curl -sI https://example.com/cdn-cgi/image/width=400,format=webp/photos/a.jpg
```

- The original is fetched as if the visitor had asked for `<path>` with `GET`: the firewall, rate
  limits, waiting rooms, rules, Workers and the cache all see that path, not `/cdn-cgi/image/…`
  (so a rule that blocks `/photos/` also blocks the resized copies). Conditional and `Range` headers
  are not passed on for the original; they apply to the result.
- `<path>` is a path of the site, or an `http(s)://` URL of the request's own host. Another host,
  `//…`, a user name in the URL, a bare `/` and the edge's own `/cdn-cgi/` paths answer `400`; the
  endpoint is no proxy for other sites. Methods other than `GET` and `HEAD` answer `405`.
- Options, comma separated; unknown options and unusable values are ignored:

  | Option | Values |
  | --- | --- |
  | `width`, `w` / `height`, `h` | pixels; larger values are taken as 4096 |
  | `fit` | `scale-down` (default: fit in the box, never enlarge), `contain` (fit in the box, enlarging if needed), `cover` (fill the box, cutting off what is over, enlarging if needed), `crop` (as `cover`, but an original smaller than the box is cut to it, not enlarged), `pad` (as `contain`, centred on a canvas of the box's size: white for JPEG, transparent otherwise) |
  | `quality`, `q` | 1 to 100, JPEG only (default 85) |
  | `format`, `f` | `jpeg` (or `jpg`), `png`, `webp`; `auto` and anything else keep the original's format |

  With one side given, the other follows the original's ratio. WebP is written lossless (the encoder
  is pure Rust and has no lossy mode). EXIF rotation is applied and an ICC profile is kept; other
  metadata is dropped.
- Only a `200` JPEG, PNG or WebP of at most 16 MiB and 50 megapixels (read from the image header
  before anything is decoded) is transformed; no side of a result is longer than 4096 pixels. Each
  node runs two transformations at a time on blocking threads; a request that waits more than
  10 seconds for its turn gets the original.
- Anything else goes to the visitor as it came, with `fcf-resized: original; <why>`, where `<why>` is
  `animated` (APNG, animated WebP), `unsupported` (another type), `unchanged` (no size and no other
  format or JPEG quality asked), `too-large`, `undecodable` or `busy`. Errors, redirects and other
  statuses from the original's pipeline pass through untouched, without the header.
- A result carries `fcf-resized: <width>x<height>`, its own `Content-Type`, `Content-Length` and
  `ETag` (`If-None-Match` answers `304`), and `fcf-cache-status: MISS` or `HIT`. It is cached under
  the original's bytes and the options, for as long as the cache may keep the original: an original
  the cache does not keep (`DYNAMIC`, `BYPASS`) is transformed on every request. The original still
  goes through the pipeline each time, so once the edge serves a new original (it expired or was
  purged), its results are made again.

#### Custom error pages

`error_pages` replaces the pages the edge writes by itself with the zone's own HTML. The value is an
object with at most these four keys (any other key is refused); each template is at most 64 KiB
(65536 bytes of UTF-8, longer is refused). An empty string is the same as leaving the key out and is
not stored. The whole object is replaced on every `PATCH`; `{}` removes every template.

| Key | Replaces |
| --- | --- |
| `5xx` | the edge's page for an error in reaching the origin: 502, 521, 522, 525, 530 (a 5xx the origin itself sends is passed on untouched) |
| `block` | the firewall's block page (403: managed rules and `block` firewall rules) |
| `ratelimit` | the rate limit page (429) |
| `1xxx` | any other page the edge writes for a request of the zone: unreadable requests (400), payload too large (413), HTTP/3 not enabled (421), worker failures (500, 503) |

Placeholders, each replaced in a single pass (a value that looks like a placeholder is not expanded
again). Every value but `::ERROR_BOX::` is HTML-escaped (`& < > " '`), so it is safe in text and in
quoted attributes.

| Placeholder | Value |
| --- | --- |
| `::RAY_ID::` | the request's Ray ID (as in the `fucf-ray` header) |
| `::STATUS::` | the status code |
| `::CLIENT_IP::` | the visitor's address |
| `::HOST::` | the host name the visitor asked for |
| `::NODE::` | the node's location code, as the default page shows it (`SIN`) |
| `::ERROR_BOX::` | the main part of the default page: its stylesheet and everything in its `<body>`, as is (what it takes from the request is escaped where the default page is built) |

Only pages meant for a browser are replaced. gRPC requests, requests that are not page loads
(`Sec-Fetch-Mode` other than `navigate`, an `X-Requested-With` header, or no `text/html` in
`Accept`) and the human check's pages are answered as before, and so are pages written before the
request is known to belong to the zone (unknown hosts, `/cdn-cgi/`, loops, the node's traffic limit,
the "node updating" page). The status code and the headers stay as they are (`Retry-After`,
`Cache-Control: no-store`, ...); only the body changes, with `Content-Type: text/html; charset=utf-8`.

```sh
curl -s -X PATCH $BASE/zones/$ZONE/settings/error_pages -H "Authorization: Bearer $TOKEN" \
  -d '{"value": {"5xx": "<h1>Back soon</h1><p>Error ::STATUS::, Ray ID ::RAY_ID::</p>::ERROR_BOX::", "ratelimit": ""}}'
```

### DNSSEC

```
GET    /zones/{id}/dnssec                 status, and the DS record to give the registrar
PATCH  /zones/{id}/dnssec                 {"status": "active|disabled"}
```

Records are signed online (ECDSA P-256, algorithm 13) with minimal NSEC answers.

### Zone transfers (AXFR)

A secondary name server at another provider keeps the zone resolving when the whole fleet is gone.
The zone setting `dns_transfer_to` lists who may transfer it: addresses, or networks written as
`address/prefix`, at most 16.

```sh
curl -s -X PATCH $BASE/zones/$ZONE/settings/dns_transfer_to -H "Authorization: Bearer $TOKEN" \
  -d '{"value": ["192.0.2.53", "2001:db8:53::/48"]}'
# from 192.0.2.53, against any node's DNS listener:
dig @ns1.example.net example.com AXFR
```

- Transfers are AXFR over TCP, on the DNS listener of every node (`--dns-listen`). A query from an
  address not listed, for a zone with DNSSEC on (it is signed per query, there is nothing to hand
  over) or of a class other than IN is answered `REFUSED`. There is no IXFR and no TSIG: the address
  is the only check, so list the secondaries' own addresses rather than wide networks.
- What is sent: the SOA, the zone's NS records, every record, and the SOA again. A proxied name
  (of a zone that is not paused) is sent as the addresses of every edge node that is not an
  accelerate node (TTL 300) in place of its A, AAAA and CNAME records: the origin stays hidden, and
  a secondary cannot steer visitors, so it answers with all the nodes.
- NOTIFY: about 2 seconds after the zone's serial changes, each node that is not an accelerate node
  sends a NOTIFY (UDP, port 53) to every single address in `dns_transfer_to` (networks get none),
  once, without waiting for an answer; the secondary then transfers the zone at once instead of at
  its next refresh. It is always on: there is no flag for it.

### DNS query counts

```
GET    /zones/{id}/dns_analytics          the queries the node answering this call answered for the zone
```

```json
{ "total": 1520, "by_type": { "A": 900, "AAAA": 400, "HTTPS": 200, "MX": 20 }, "by_rcode": { "NOERROR": 1500, "NXDOMAIN": 20 } }
```

Every standard query of class IN for a name in the zone is counted, over UDP and TCP, by the type
asked (`TYPE<n>` for types without a name here) and by the answer (`NOERROR`, `NXDOMAIN`, `REFUSED`,
otherwise `RCODE<n>`; a name that does not exist counts as `NXDOMAIN` even where DNSSEC answers it
with a minimal NSEC). Zone transfers are not counted. The counts are kept in this node's memory
since it started, so they start again at zero after a restart and other nodes have their own; a zone
nobody asked about answers `{"total": 0, "by_type": {}, "by_rcode": {}}`.

### Cache

```
POST   /zones/{id}/purge_cache            {"purge_everything": true} | {"files": [url, …]} | {"prefixes": [url prefix, …]}
                                          | {"hosts": [host, …]} | {"tags": [tag, …]}
POST   /warp/purge_cache                  the same, for the edge's own /cdn-cgi/fucf-warp cache
```

- `files`, `prefixes`, `hosts` and `tags` can be given together; everything any of them names goes.
  A body that names nothing (and no `purge_everything`) is refused. The answer is
  `{"id": "<zone id>", "purged": <objects removed on this node>}`.
- `files` are whole URLs with their query (`https://www.example.com/app.js?v=2`), `prefixes` the
  start of URLs (`https://www.example.com/images/`); the scheme is ignored, so both the HTTP and the
  HTTPS copy go.
- `hosts`: everything of these host names (`www.example.com`; the zone's other names stay).
- `tags`: what the origin tagged with one of these in a `Cache-Tag` response header (comma
  separated, `Cache-Tag: product-1, listing`). Tags are compared exactly, case included. The header
  is kept with the copy and never sent to visitors.

A purge reaches every node through the configuration.

More of the cache:

- `stale-while-revalidate=N` in the origin's `Cache-Control` (N at most a day): for N seconds past
  its freshness an expired copy is answered at once (`fcf-cache-status: UPDATING`) while one
  background request fetches a new one. Range requests, and requests made while the background queue
  is full, go to the origin as usual.
- Cache rules decide what is cached (see [Rules](#rules)); their `ignore_query` keeps one copy per path.
- Tiered cache: with the zone setting `cache_tier_node` naming a node, every other node fetches the
  zone's GET and HEAD requests through that node (over HTTPS, the way a visitor would ask it), so
  its cache serves the whole fleet and only it asks the origin; pick one close to the origin. While
  that node has just failed, the origin is asked directly. The setting does nothing on the node it
  names, nor when it names no node of the fleet (it is not checked when saved), nor for requests
  that an origin rule or the record's `origin.node` already sends somewhere.

#### Large objects in chunks

With the zone setting `cache_chunking` at N bytes (524288 to 33554432; `0`, the default, is off), an
answer the cache stores that is a `200` of announced length (`Content-Length`) of at least N bytes,
sent without `Content-Encoding`, is kept in chunks of 512 KiB (524288 bytes) instead of as one copy:

- Visitors get the same answers as from a whole copy: the whole object, single ranges (`206`),
  `If-Range`, `304` to `If-None-Match` / `If-Modified-Since`, `HEAD`, `416`. A range request reads only
  the chunks it covers.
- The memory and disk tiers keep and drop chunks one by one like any other object, so a large object
  does not have to fit in a tier whole (the disk tier takes no single object over an eighth of its
  size). Node status counts chunks as objects.
- A chunk that was dropped while the copy is fresh is fetched again by itself: one request to the
  origin for the missing chunks, with `Range`, `If-Range` (the copy's strong `ETag`, else its
  `Last-Modified`) and `Accept-Encoding: identity`. Its answer is used only if it is a `206` for exactly
  those bytes of an object of the same length, `ETag` and `Last-Modified`
  (`fcf-cache-status: MISS`). A `200` (the origin ignores ranges, or the object changed) is used as the
  answer and stored whole this once; any other answer drops the copy and the request goes to the
  origin as it would without chunks. A copy with no validator (or only a weak `ETag`) is fetched again
  whole when a chunk is missing.
- Chunks of two versions are never served together: every fill is marked, and a chunk is only used
  with the copy it was cut for.
- An expired copy is answered stale (`stale-while-revalidate`, `UPDATING`; the origin failing,
  `STALE`) only when every chunk the request needs is still there; it is not revalidated with a
  conditional request but fetched again whole.
- Purges by URL, prefix, host, tag or everything take the chunks with the copy; `purged` counts the
  object once.
- Turning the setting off makes copies kept in chunks misses; they are replaced by whole ones.

What has not changed: no object over 32 MiB is cached; the origin's answer is read whole before the
visitor gets its first byte (it is cut into chunks as it is read); answers without `Content-Length`
are kept whole; a range request for an object that is not cached still goes to the origin as it is,
and its answer is not kept.

#### Compression

The edge compresses text answers (`text/*`, JSON, JavaScript, XML, SVG, WASM and the like) of 1 KiB
to 8 MiB with a known length on the way out, when the visitor's `Accept-Encoding` takes one of
`br` (brotli, quality 4), `zstd` (level 3) or `gzip` (level 5). The order is fixed, whatever the
q-values above zero say: brotli, then zstd, then gzip, so a browser that sends
`gzip, deflate, br, zstd` keeps getting brotli; `zstd` is used for clients that take it but not
brotli. A coding with `q=0` is never used. Answers already compressed by the origin, ranges, non-`200`
answers and `Cache-Control: no-transform` are left alone; the answer gets `Vary: accept-encoding` and
a strong `ETag` becomes weak. Nothing to configure.

The visitor's `Accept-Encoding` goes to the origin as it is, so an origin may answer compressed
itself. The cache keeps such a copy under the codings the visitor takes, out of `br`, `gzip` and
`zstd` (by q-value, as above), and only ever serves it to visitors that take exactly the same set:
a visitor without `zstd` never gets the copy an origin compressed with zstd for another one. A
compressed answer in a coding the visitor did not take (zstd or deflate to a client that did not
ask for it, several codings, or anything to a client that sent no `Accept-Encoding`) is passed on as
it came but not stored. An uncompressed answer is kept once for every client, as before.

Pages that get the challenge script put in (zone setting `challenge_script`) may come from the
origin as gzip, deflate, brotli or zstd; a zstd page with a window over 8 MiB is passed on as it is.

### Origins: health checks, weights and session affinity

```
GET    /zones/{id}/origins/health         what this node's checks say about the zone's origins
```

```json
[{ "name": "app.example.com", "address": "192.0.2.10", "healthy": false, "failures": 2,
   "checked_at": "2026-11-28T12:00:00.000000Z", "detail": "HTTP 503" }]
```

- With `origin_check_path` set, every node asks each address of the zone's proxied A and AAAA
  records (wildcard names aside) for that path every `origin_check_interval` seconds: a GET for that
  name, reaching the address the way a request for the name would (the record's origin options, the
  zone's origin rules and SSL mode), with a 5 second timeout and the User-Agent
  `fucf-health/<version>`. Addresses an origin rule sends elsewhere, and paused zones, are not asked.
- A 2xx or 3xx status passes. After two failures in a row (no answer in time, an error, any other
  status) the address goes last for that name; one pass brings it back. `failures` counts the
  failures in a row, `detail` says what the last check got (`HTTP 200`, or why there was no answer),
  `checked_at` is empty until a first check is done. An empty array: nothing is checked.
- The answer is the checks of the node that answers the call: each node checks for itself, since
  what it can reach is what it sends requests to.
- A name with several proxied addresses takes them in turn by their `origin.weight` (1 when not
  given: weights 3 and 1 give the first address three requests of every four). With the zone
  setting `session_affinity`, the turn comes from the visitor's address, so the same visitor starts
  with the same origin address while the name's addresses stay the same. Addresses that fail their
  check, or refused a connection in the last 10 seconds, go last either way; only addresses reached
  the same way (the same origin options, the weight aside) stand in for each other.

### Certificates

```
GET    /zones/{id}/ssl/certificate_packs
POST   /zones/{id}/ssl/certificate_packs           {"hosts": [], "validation_method": "auto|dns|tls-alpn|http"}
GET    /zones/{id}/ssl/certificate_packs/{id}
PATCH  /zones/{id}/ssl/certificate_packs/{id}      try again now
DELETE /zones/{id}/ssl/certificate_packs/{id}
CRUD   /zones/{id}/custom_certificates             {"certificate": PEM, "private_key": PEM, "hosts": []}
```

Without `hosts`, a certificate is for the apex and its wildcard. A pack answers `status`
(`pending`, `active`, `failed`), `error`, `issued_on`, `expires_on`, `attempts`, `next_attempt`, and,
when the edge has a `--cname-base`, `dns_delegation`: the CNAME records a zone hosted elsewhere adds
once so that DNS-01 can be answered here. Private keys are never answered.

#### Visitor client certificates (mTLS)

A node started with `--mtls-ca <file>` (`FUCF_MTLS_CA`: one or more PEM CA certificates) asks every
visitor on its HTTPS and HTTP/3 listeners for a client certificate signed by one of them. It does not
require one: a visitor without a certificate goes on as before. A certificate that does not verify
(another CA, expired, not made for client authentication) fails the TLS handshake, for any host of
that node. Without the flag, nothing is asked and TLS is as before. Every node that serves such a zone
should have the same CA file.

A zone with the setting `mtls` at `on` answers 403 to every request without a verified certificate,
before its `/cdn-cgi/` paths, rules and origin. Plain HTTP, the HTTP/3 front (`--h3-front-listen`) and any
other way in that cannot see a verified certificate count as without one, so on a node without
`--mtls-ca` such a zone refuses everyone. The panel's own host and the answers to the fleet's ACME
HTTP-01 challenges are not affected. Rules can test `cf.tls_client_auth.cert_verified` (also
`fcf.client_cert_verified`) whatever the setting, and `/cdn-cgi/fucf-trace` shows
`client_cert=verified` or `client_cert=none`.

The CA is the node's, not the zone's: a certificate it signed passes every zone with `mtls` on.

#### Origin CA

```
GET    /zones/{id}/origin_ca          {"present": false}, or {"present": true, "certificate": PEM, "common_name",
                                      "created_on", "expires_on"}; never the CA's private key
POST   /zones/{id}/origin_ca          make the zone's CA (409 if it has one already)
DELETE /zones/{id}/origin_ca          remove it with its key; certificates it signed no longer chain to a new one
POST   /zones/{id}/origin_ca/sign     {"hostnames": [...], "days": 365}: sign a certificate for the origin
```

A zone can have its own private CA that signs certificates for its origin servers, so an origin can
serve HTTPS without a public CA. The CA is valid for 20 years, is constrained to the zone's names and
signs server certificates only (extended key usage `serverAuth`), so its certificates do not pass as
[visitor client certificates](#visitor-client-certificates-mtls). Its private key is kept with the zone,
like a DKIM key, so any node can sign; no answer ever holds it. There is one CA per zone: to rotate it,
`DELETE` it and `POST` a new one.

Signing takes `hostnames` (or `names`): 1 to 50 names, each the zone itself or a name below it, a
wildcard only as a leading `*.`, no IP addresses; and `days` (or `requested_validity`, required): 1 to
5475. A certificate that would outlive the CA is refused. The answer holds `certificate`,
`private_key` (made for this certificate and kept nowhere: it is shown this once), `ca_certificate`,
`hostnames`, `requested_validity` and `expires_on`. An origin serving such a certificate works with
`ssl` at `full`; `strict` checks against the public CAs only and refuses it.

```sh
curl -s -X POST $BASE/zones/$ZONE/origin_ca -H "Authorization: Bearer $TOKEN"
curl -s -X POST $BASE/zones/$ZONE/origin_ca/sign -H "Authorization: Bearer $TOKEN" \
  -d '{"hostnames": ["example.com", "*.example.com"], "days": 365}'
```

#### Custom hostnames (SSL for SaaS)

```
GET    /zones/{id}/custom_hostnames
POST   /zones/{id}/custom_hostnames          {"hostname": "shop.example.net", "custom_origin_server": "app.example.com"}
GET    /zones/{id}/custom_hostnames/{id}
PATCH  /zones/{id}/custom_hostnames/{id}     {"custom_origin_server": ...}: the only thing that changes
DELETE /zones/{id}/custom_hostnames/{id}
```

A custom hostname is a name that belongs to somebody else (a customer of a SaaS that runs on this
zone) served as this zone, with a certificate the fleet obtains for it. Requests for it go through the
zone's own pipeline: its firewall, rules, cache and settings apply, `http.host` is the
custom hostname, and cache entries are kept per host name. They reach the origin of
`custom_origin_server`, a host of the zone with a proxied record (empty: the zone apex), with the
custom hostname as `Host`. The token permission is `SSL and Certificates Read` / `Write`.

`hostname` is lowercased and stored without a trailing dot. It is refused (400) when it is not a public
DNS name a CA could certify: empty, longer than 253 characters, an IP address, a wildcard, non-ASCII
(use the `xn--` form), a reserved or private name (`.test`, `.local`, a single label, ...). It is refused
(409) when it is a zone of this fleet, a name below one or above one, whoever owns that zone; when it
is already a custom hostname of any zone; or when it is a name the fleet keeps for itself. It cannot be
renamed: delete it and create the new name. A zone has at most 100. Certificate-only zones have none,
and a zone whose DNS is hosted elsewhere has none unless the fleet has a `--cname-base` (see below).

Everything else in the answer is the server's and is ignored in a request body:

| Field | Meaning |
|-------|---------|
| `status` | `pending`, `active` or `failed` |
| `verify_txt` | a random label made for this custom hostname; part of its DCV delegation |
| `dcv_delegation` | `{"type": "CNAME", "name": "_acme-challenge.<hostname>", "content": "_acme-challenge.<verify_txt>.<zone>"}` (zone hosted elsewhere: `_acme-challenge.<verify_txt>.<zone>.<cname base>`); `null` when the fleet could not answer it |
| `cname_target` | where the owner points the name itself (`custom_origin_server`, or the zone) |
| `seen_at` | when a visitor first asked for it |
| `error`, `attempts`, `last_attempt`, `next_attempt` | the last failure and when the next order may start |
| `issued_on`, `expires_on`, `certificate` | the certificate in use; its private key is never answered |

The name's owner adds two records at their DNS: the name itself as a CNAME to `cname_target` (or an
address of the fleet), and `dcv_delegation`. The second one is the proof. The fleet makes no DNS
lookups of its own, and it cannot see other people's DNS; it orders the certificate with a DNS-01
challenge whose answer it publishes only at the delegation target of this one custom hostname. The CA
follows the owner's CNAME, so it validates only when the owner pointed the delegation at this zone's
custom hostname. HTTP-01 and TLS-ALPN-01 are never used for custom hostnames: they would only show that
the name reaches some node of the fleet, which is just as true when it points at another user's zone.
Authorizations the CA remembers from an earlier order are withdrawn, and the attempt fails, so that a
name proven for one zone never hands its certificate to another one.

Status changes:

- `pending`: created. Nothing is ordered until a visitor asks for it (a TLS handshake with its server
  name, or an HTTP request with its Host, at any node but an accelerate one), which shows that the
  name points here. A name that is not a created custom hostname never leads to an order, and never
  writes anything.
- `pending` or `failed` → `active`: the CA validated the delegation and issued. The name is served from
  then on.
- `pending` or `failed` → `failed`: the order failed (for example, no delegation yet); `error` says why.
  It is tried again after 10 minutes, doubling up to a day. A `failed` custom hostname is not served.
- `active`: renewed in the last third of the certificate's lifetime, whether or not anybody visits. A
  failed renewal keeps the certificate and the status, with the reason in `error`.

Orders are limited to 10 per zone and 30 for the whole fleet per hour (renewals included), and to 3
per pass (every minute and on every configuration change), one after the other, on the node holding
the fleet's ACME lease. When two nodes accept the same name for two zones at the same moment, the
older custom hostname keeps it on every node and the other one is neither served nor ordered. A zone created later at or above the name takes it over: the custom hostname is then
neither served nor renewed. Deleting a custom hostname, or its zone, deletes its certificate.

```sh
curl -s -X POST $BASE/zones/$ZONE/custom_hostnames -H "Authorization: Bearer $TOKEN" \
  -d '{"hostname": "shop.example.net", "custom_origin_server": "app.example.com"}'
# answer: "dcv_delegation": {"type": "CNAME", "name": "_acme-challenge.shop.example.net",
#                            "content": "_acme-challenge.0f3c...e9.example.com"}
```

#### Key exchange

Every TLS configuration of the process (the HTTPS and HTTP/3 listeners, origin pulls, ACME and the
outbound probes) is built from one crypto provider, aws-lc-rs. Next to `X25519`, `secp256r1` and
`secp384r1` it offers the post-quantum hybrid `X25519MLKEM768`. In TLS 1.3 the edge takes the group
the visitor's client prefers, so a browser that offers the hybrid gets it, and TLS 1.2 or a client
without it gets `X25519`; nothing to configure. Origin pulls offer the hybrid first, with a plain
`X25519` share alongside, so an origin without it costs no extra round trip.
`/cdn-cgi/fucf-trace` names the group of the connection as `kex=` (for example
`kex=X25519MLKEM768`); it is empty over plain HTTP and HTTP/3.

#### 0-RTT (early data)

Not offered, on HTTPS nor HTTP/3, and there is no switch for it. Session tickets are the fleet's
stateless ones (a visitor resumes on any node), and rustls only accepts early data with stateful,
single-use resumption, as a guard against replays. Over TCP the TLS layer also hands the connection
to HTTP only once the whole handshake is done and never reads early data out, so accepting it would
lose the request, and reading it after the handshake would save no round trip. Doing it soundly
means driving the handshake ourselves. Until then the tickets the edge hands out do not allow early
data, so clients resume with a normal 1-RTT handshake.

### Rules

All rule lists take an `expression` (empty matches every request), `description`, `enabled` (true)
and, where it applies, `priority` (lower first).

```
CRUD   /zones/{id}/firewall/rules         {"expression", "action", "priority", "enabled", "description"}
CRUD   /zones/{id}/rate_limits            {"expression", "threshold", "period", "mitigation_timeout", "action",
                                           "characteristics", "status_codes", "enabled"}
CRUD   /zones/{id}/redirect_rules         {"expression", "target_url", "status_code", "preserve_query_string", "priority"}
CRUD   /zones/{id}/transform_rules        {"expression", "rewrite_path", "set_request_headers", "remove_request_headers",
                                           "set_response_headers", "remove_response_headers", "priority"}
CRUD   /zones/{id}/cache_rules            {"expression", "cache", "edge_ttl", "ignore_query", "cache_key_headers",
                                           "cache_key_cookies", "priority"}
CRUD   /zones/{id}/origin_rules           {"expression", "origin_host", "origin_node", "origin_port", "origin_scheme",
                                           "host_header", "sni", "priority"}
```

| List | Fields |
| --- | --- |
| firewall rules | `action`: `block`, `js_challenge`, `managed_challenge`, `log`, `skip`. Rules kept by the automatic firewall carry `managed_by`. |
| rate limits | `threshold` (≥ 1) requests per client per `period` (1 to 86400 s); `mitigation_timeout` 0 to 86400 s; `action`: `block` (default), `log`; `characteristics` and `status_codes`: see below |
| redirect rules | `target_url`: an `http(s)://` URL or a path; `status_code`: 301, 302 (default), 303, 307, 308 |
| transform rules | at least one action; `rewrite_path` starts with `/` and has no query; `host`, `content-length`, `transfer-encoding`, `connection` and `upgrade` cannot be set or removed. Every matching rule applies. |
| cache rules | `cache`: `true` caches whatever the file type, `false` never caches; `edge_ttl` 1 to 31536000 s; `ignore_query`: `true` keys the cache on the path alone, one copy whatever the query string (the origin still gets the query of the request that fetches it); `cache_key_headers` / `cache_key_cookies`: one copy per value of these request headers / cookies (see below). The first matching rule wins. |
| origin rules | at least one of the overrides; `origin_scheme`: `http`, `https`; `origin_node`: an edge node to go through |

A rate limit's clients:

- `characteristics` (at most 4) say what tells one client from another: `ip` (alone when none is
  given), `asn`, `country`, `host`, `path`, `header:NAME`, `cookie:NAME` (names of letters, digits,
  `-` and `_`, at most 64). They are taken case-insensitively and kept in lower case, cookie names
  with their case. Several make one key: `["ip", "path"]` counts each address on each path apart.
  A request without the header or cookie counts under an empty value, so all such requests share
  one count; add `ip` to keep them apart. `asn` and `country` need the GeoIP databases.
- `status_codes` (at most 20, 100 to 599, as numbers or strings): only requests answered with one of
  these count (`[401, 403]` against password guessing). They are counted once the answer is there,
  so the client that goes over is stopped from its next request on. Empty: every matching request.
- Counting is per node, with an approximate share of the other nodes' counts weighed in (see below).
  A client that one node holds back for 10 seconds or more is held back by the other nodes too, once
  they hear of it with the reports.
- Through the Rulesets API these are the `characteristics` and `counting_expression` of
  `http_ratelimit`: see [Rulesets](#rulesets). A cache rule's `ignore_query` is not shown there, and a
  change of the rule through its phase leaves it as it is.

Across the fleet a rate limit is approximate, not exact. With the reports the nodes send each other
anyway (every 15 to 60 seconds), each node tells the others its hottest counts: the clients whose
count in the current window passed half of the rule's `threshold`, at most 64 of them, each with
the end of the window it was counted in. A request is then judged by its count on the node that
serves it plus half the sum of the other nodes' counts for the same rule and client. A client
spread evenly over N nodes is then held back after about N/2 times its limit (4/3 of it on two
nodes) instead of N times, report lag aside.

- A node's count stops weighing in when its window ends; a node that tells the same client again
  in the same window replaces its count (a report that comes twice adds nothing), and a node never
  counts its own reports, which come back through the peers.
- It can let through more than the limit (a client under half of it on every node is never told,
  and reports lag) and, briefly, hold back a client a little early (the nodes' windows do not line
  up). For a hard limit, send the clients to one node.
- Memory is bounded: a node keeps at most 1024 of its own hot counts and 4096 clients of the
  others; clients whose key is longer than 512 bytes are counted on their node only.
- The key that is sent is what the rule tells clients apart by: visitor addresses, header and
  cookie values. It travels only inside the fleet's own authenticated report channel (`rate` in the
  reports of the `reports` sync domain) and is never logged. A node of an earlier build ignores it,
  so a fleet in the middle of a rolling upgrade counts as before on the nodes not yet upgraded.

```sh
curl -s -X POST $BASE/zones/$ZONE/rate_limits -H "Authorization: Bearer $TOKEN" -d '{
  "expression": "http.request.uri.path eq \"/login\"", "threshold": 5, "period": 60,
  "mitigation_timeout": 600, "characteristics": ["ip"], "status_codes": [401, 403]
}'
curl -s -X POST $BASE/zones/$ZONE/firewall/rules -H "Authorization: Bearer $TOKEN" -d '{
  "expression": "http.request.uri.path contains \"/admin\" and not ip.src in {198.51.100.0/24}",
  "action": "managed_challenge", "priority": 10, "description": "admin pages"
}'
curl -s -X POST $BASE/zones/$ZONE/redirect_rules -H "Authorization: Bearer $TOKEN" -d '{
  "expression": "http.host eq \"old.example.com\"", "target_url": "https://www.example.com/", "status_code": 301,
  "preserve_query_string": true
}'
```

#### Custom cache keys

By default a cached copy is keyed by scheme, host, path and query (without tracking parameters such
as `utm_*`) and the compressions the client takes. A cache rule can add the values of some request
headers and cookies, for an origin that answers differently by them (a language, a device class, an
A/B variant held in a cookie): each value then gets a copy of its own.

```sh
curl -s -X POST $BASE/zones/$ZONE/cache_rules -H "Authorization: Bearer $TOKEN" -d '{
  "expression": "starts_with(http.request.uri.path, \"/shop/\")", "cache": true, "edge_ttl": 600,
  "cache_key_headers": ["Accept-Language"], "cache_key_cookies": ["variant"]
}'
```

- At most 8 names in each list, none empty or longer than 64 characters. Header names may hold
  letters, digits, `-` and `_` and are stored in lower case; cookie names may hold the token
  characters of RFC 6265 (letters, digits and ``!#$%&'*+-.^_`|~``) and keep their case
  (`Sess` and `sess` are two cookies). A name listed twice is refused.
- A header or cookie the request does not carry counts as an empty value. A header sent more than
  once counts as its values joined by commas; a cookie named more than once counts by its first
  value. Control characters in values are dropped.
- A key that grows past 2048 bytes this way is neither looked up nor stored: such a request goes to
  the origin and is answered `fcf-cache-status: BYPASS`, so long header values cannot fill the
  cache. Rules without these fields key exactly as before, with no length limit.
- Purges find every copy: by URL or prefix they match the URL, whatever the header and cookie values.
- An origin's `Vary` may name `Accept-Encoding` and the headers in `cache_key_headers`, which the
  key already holds; a `Vary` on anything else (`Cookie` and `*` included) still keeps the response
  out of the cache. Each name multiplies the copies kept of every matching URL, so name only what
  the origin really varies on.

### Rulesets

The same rules as Cloudflare rulesets, for Terraform's `cloudflare_ruleset`, cf-terraforming and
scripts written for Cloudflare. Nothing is stored twice: each phase's entrypoint ruleset is a view of
one of the lists above, its id is derived from the zone and the phase (the same on every node, for
good), and a rule's id is the id of the object behind it.

```
GET    /zones/{id}/rulesets                                   the phases that have rules (without the rules)
POST   /zones/{id}/rulesets                                   {"phase", "kind": "zone", "name", "rules": [...]}: a phase without rules yet
GET    /zones/{id}/rulesets/phases/{phase}/entrypoint         one phase (an empty one answers with no rules)
PUT    /zones/{id}/rulesets/phases/{phase}/entrypoint         {"rules": [...]}: the phase becomes these rules, in this order
GET    /zones/{id}/rulesets/{ruleset_id}
PUT    /zones/{id}/rulesets/{ruleset_id}                      as the entrypoint PUT
DELETE /zones/{id}/rulesets/{ruleset_id}                      the phase loses all its rules
POST   /zones/{id}/rulesets/{ruleset_id}/rules                one rule, last unless "position" says otherwise
PATCH  /zones/{id}/rulesets/{ruleset_id}/rules/{rule_id}      the top-level fields given change, the rest stays
DELETE /zones/{id}/rulesets/{ruleset_id}/rules/{rule_id}
```

Changes answer with the whole ruleset. In a PATCH, an `action_parameters` given replaces the old one
whole, and a new `action` starts without the old action's parameters. `position` is `{"before": id}` (`""` for the top), `{"after": id}`
(`""` for the bottom) or `{"index": n}` (from 1).

| Phase | List | Actions and parameters |
| --- | --- | --- |
| `http_request_firewall_custom` | firewall rules | `block`, `js_challenge`, `managed_challenge`, `log`, `skip` |
| `http_ratelimit` | rate limits | `block`, `log`; `ratelimit`: `requests_per_period`, `period`, `mitigation_timeout`, `characteristics`, `counting_expression` (see below) |
| `http_request_dynamic_redirect` | redirect rules | `redirect`; `action_parameters.from_value`: `target_url.value`, `status_code` (required), `preserve_query_string` |
| `http_request_transform` | transform rules (path) | `rewrite`; `action_parameters.uri.path.value` |
| `http_request_late_transform` | transform rules (request headers) | `rewrite`; `action_parameters.headers.{name}`: `{"operation": "set", "value"}` or `{"operation": "remove"}` |
| `http_response_headers_transform` | transform rules (response headers) | as above |
| `http_request_cache_settings` | cache rules | `set_cache_settings`; `action_parameters.cache` (required), `edge_ttl`: `{"mode": "override_origin", "default"}` or `{"mode": "respect_origin"}`, `cache_key.custom_key`: `header.include`, `cookie.include` (`check_presence` only empty) |
| `http_request_origin` | origin rules | `route`; `action_parameters`: `host_header`, `origin.host`, `origin.port`, `sni.value` |

- Whatever a rule says that this server cannot do is refused with a 400 that names the field
  (`rules[2].action_parameters.uri.query is not supported by this server`), never dropped. A PUT
  either lands whole or not at all.
- An expression of `true` is every request (stored as an empty expression, shown as `true`).
- A rate limit's `characteristics` must hold `cf.colo.id` (requests are counted on each node) and
  may add `ip.src` (the default), `ip.src.asnum`, `ip.geoip.country`, `http.host`,
  `http.request.uri.path`, `http.request.headers["name"]` and `http.request.cookies["name"]`, at most
  four besides `cf.colo.id`; they are the rate limit's own `characteristics` (`ip`, `asn`, `country`,
  `host`, `path`, `header:NAME`, `cookie:NAME`). `counting_expression` can only be the rule's own
  expression and the response code, `<expression> and http.response.code in {401 403}` (bracketed
  when the expression has an `or` or `xor`; the code alone for a rule of every request); it becomes
  `status_codes`. `requests_to_origin` is refused.
- A `skip` here skips the remaining custom rules, the security level, rate limits and the managed rules,
  so its `action_parameters` must say at least `"ruleset": "current"`, `"phases": ["http_ratelimit",
  "http_request_firewall_managed"]` and `"products": ["securityLevel"]` (or be left out). A narrower
  skip is refused rather than widened.
- A transform rule with a path, request headers and response headers shows in all three transform
  phases. A change through one phase touches only its part; the expression, description and
  `enabled` are shared, so changing them through one phase is refused while the rule is in others
  (change them with `/transform_rules`). Reordering one phase can change the order of a shared rule
  in the others, since the rule has one priority.
- Rate limits run in the order they were made: new ones can be added last, reordering is refused.
- The automatic firewall's rules are not shown and never replaced. An origin rule's `origin_node` and
  `origin_scheme` have no Cloudflare words: they are not shown and stay as they are.
- The ruleset's `name` and `description` are accepted and not kept (every entrypoint is `default`);
  `version` is always `"1"`, and a rule's `ref` is its id.
- Tokens: a path that names a phase (by name or by ruleset id) needs that phase's permission
  (Firewall Services for the first two, then Dynamic Redirect, Transform Rules, Cache Rules, Origin
  Rules); the list and `POST /rulesets` need Firewall Services, and the POST also the phase's own.

```sh
curl -s -X PUT $BASE/zones/$ZONE/rulesets/phases/http_request_late_transform/entrypoint \
  -H "Authorization: Bearer $TOKEN" -d '{
  "rules": [{
    "expression": "starts_with(http.request.uri.path, \"/api/\")", "action": "rewrite",
    "action_parameters": { "headers": { "x-from-edge": { "operation": "set", "value": "1" } } }
  }]
}'
```

### IP lists

Named lists of addresses and networks for the whole account, used in the rules of any zone as
`ip.src in $name`, as Cloudflare's account lists (also under `/accounts/{account id}/rules/lists…`).

```
GET    /rules/lists                                   every list, by name
POST   /rules/lists                                   {"name", "description", "kind": "ip"}
GET    /rules/lists/{list_id}
PUT    /rules/lists/{list_id}                         {"name", "description"}: what is given changes (PATCH too)
DELETE /rules/lists/{list_id}                         refused (409) while a rule uses the list
GET    /rules/lists/{list_id}/items?search=           every item; search: in the address or the comment
POST   /rules/lists/{list_id}/items                   [{"ip", "comment"}, …]: added
PUT    /rules/lists/{list_id}/items                   [{"ip", "comment"}, …]: the list holds exactly these afterwards
DELETE /rules/lists/{list_id}/items                   {"items": [{"id"}, …]}
GET    /rules/lists/{list_id}/items/{item_id}
GET    /rules/lists/bulk_operations/{operation_id}    {"id", "status": "completed", "completed"}
```

A list answers `id`, `name`, `description`, `kind` (`ip`), `num_items`, `num_referencing_filters` (the
rules that use it, in every zone), `created_on`, `modified_on`; an item `id`, `ip`, `comment` (when
there is one), `created_on`, `modified_on`. The three item changes answer `{"operation_id"}`, as on
Cloudflare; here the change is done by then, and polling `bulk_operations` says `completed`.

- `name`: lowercase letters, digits and `_`, 1 to 50 of them, unique. Only `kind` `ip` is kept:
  hostname, ASN and redirect lists are refused.
- `ip`: one IPv4 or IPv6 address, or a network in CIDR form. A network is written with its host bits
  clear (`192.0.2.0/24`, not `192.0.2.1/24`: refused, the message says which network was meant); an
  address is kept without its `/32` or `/128`; IPv6 is kept in its short lowercase form; IPv4-mapped
  IPv6 addresses (`::ffff:192.0.2.1`) are refused: write them as IPv4. A visitor coming over an
  IPv4-mapped address is matched as IPv4.
- At most 100 lists and 10000 items a list; `description` and `comment` at most 500 characters.
- A body that names an address twice is refused. `POST` of an address the list has already keeps its
  item (and id); a `comment` given replaces the old one. `PUT` keeps the ids of the addresses that
  stay. A `DELETE` naming an id the list does not have is refused whole. Each change lands whole or
  not at all.
- Rules name lists, so a list a rule uses (enabled or not, in any zone) can be neither deleted nor
  renamed (`409`, naming the rules); change those rules first. A rule naming a list that does not
  exist is refused (`400`). Should a name still have no list behind it (a peer that has not caught up),
  `ip.src in $name` matches no address, so `not ip.src in $name` matches every one.
- A change to a list reaches the rules that use it at once: they are compiled again with the new
  addresses.

```sh
L=$(curl -s -X POST $BASE/rules/lists -H "Authorization: Bearer $TOKEN" \
  -d '{"name": "office", "kind": "ip", "description": "office networks"}' | jq -r .result.id)
curl -s -X POST $BASE/rules/lists/$L/items -H "Authorization: Bearer $TOKEN" \
  -d '[{"ip": "198.51.100.0/24", "comment": "head office"}, {"ip": "2001:db8:10::/48"}]'
curl -s -X POST $BASE/zones/$ZONE/firewall/rules -H "Authorization: Bearer $TOKEN" -d '{
  "expression": "http.request.uri.path contains \"/admin\" and not ip.src in $office",
  "action": "block", "description": "admin only from the office"
}'
curl -s -X DELETE $BASE/rules/lists/$L/items -H "Authorization: Bearer $TOKEN" \
  -d '{"items": [{"id": "<item id>"}]}'
```

### Security events

```
GET    /zones/{id}/security/events?limit=100      newest first (at most 5000), from the whole fleet
GET    /steering/test?ip=&ua=                     where an address is placed, and its threat score
```

### Workers

```
GET    /workers/scripts
GET    /workers/scripts/{name}            the script (not for viewers)
PUT    /workers/scripts/{name}            the body is the JavaScript source, or a wrangler-style multipart
                                          upload with one module (below); it is syntax-checked
DELETE /workers/scripts/{name}
GET    /workers/scripts/{name}/settings   {"vars", "kv_bindings", "d1_bindings", "crons"}
PATCH  /workers/scripts/{name}/settings   any of those; bindings map a name in env to a namespace / database id
POST   /workers/scripts/{name}/scheduled  {"cron": "*/5 * * * *"}: run scheduled() now
CRUD   /zones/{id}/workers/routes         {"pattern": "example.com/api/*", "script": "name"} ("script": null turns
                                          Workers off for what matches)
```

What `wrangler deploy` asks around the upload (below) is answered too, on the same paths with or without
`/accounts/{id}`:

```
GET    /workers/services/{name}             the script as a service: default_environment.script has tag, tags,
                                            last_deployed_from ("api")
GET    /workers/workers/{name}              id (the tag), name, subdomain {"enabled": false, "previews_enabled": false}
GET    /workers/subdomain                   404, code 1002: there is no workers.dev subdomain
GET    /workers/scripts/{name}/subdomain    {"enabled": false, "previews_enabled": false}
POST   /workers/scripts/{name}/subdomain    {"enabled": false, "previews_enabled": false}; true for either is a 400
GET    /workers/scripts/{name}/secrets      [] (variables are plain text, in .../settings)
GET    /workers/scripts/{name}/deployments  {"deployments": []}
GET    /workers/scripts/{name}/schedules    {"schedules": [{"cron": "*/5 * * * *"}]}: the settings' crons
PUT    /workers/scripts/{name}/schedules    [{"cron": "..."}]: replaces the crons; [] removes them
PUT    /workers/scripts/{name}/routes       [{"pattern", "zone_id"?, "zone_name"?}]: replaces the script's routes
POST   /workers/scripts/{name}/versions     400: no versions (below)
POST   /workers/scripts/{name}/deployments  400: no versions (below)
```

Each of these answers Cloudflare's `404` with code `10007` ("This Worker does not exist on your account.")
while there is no script of that name, which is how wrangler tells a first deploy. Reading them follows the
rules of `GET /workers/scripts`; the writes are for administrators (and their tokens with Workers Scripts
Write), like every other change to a Worker. The service's `tag` is derived from the name, so it is the same
on every node and after every upload; fucf does not record where a script came from and says `"api"`.

`PUT .../routes` resolves each pattern to a zone: the one `zone_id` or `zone_name` names (the host must be in
it), or else the closest zone the host is in. The script's routes in every zone they are in or go to are then
replaced; a route that stays keeps its id. The whole body is checked before anything changes: a pattern
another script (or `"script": null`) holds is a `409`, an unknown zone, a host outside its zone, the same
pattern twice, more than 100 routes, a `script` other than `{name}` and `custom_domain: true` are a `400`.
Each zone's routes change as one step. An API token also needs Workers Routes Write in each zone touched,
as it would on `/zones/{id}/workers/routes`; without it the answer is `403` with code `10000`, on which
wrangler goes on through the zones' own routes paths.

`crons` are five-field UTC expressions.

**Uploading.** A Worker here is one file: `export default { ... }`, esbuild's closing
`export { name as default };`, or `addEventListener("fetch", ...)`; there is no module loader, so any other
`import` or `export` is refused at upload. A `PUT` with `Content-Type: multipart/form-data` is read the way
Cloudflare's API reads `wrangler deploy`'s upload: a `metadata` part (JSON) that names the script in
`main_module` (or `body_part` for a service-worker script), and exactly one other part, of that name, with a
JavaScript type (`application/javascript+module`, `application/javascript`, `text/javascript`). The module is
stored as the script, byte for byte; other metadata fields (`compatibility_date`, `observability`, ...) are
ignored. Refused with `400`, nothing stored: more than one module or any extra part (wasm, text or data
modules, source maps), a non-JavaScript type, a missing or second `metadata` part, a `bindings` list that is
not empty (set `vars`, `kv_bindings` and `d1_bindings` with `PATCH .../settings` instead), and `assets`.

So bundle into one file first. `wrangler deploy` bundles with esbuild by default, so a Worker that is one
module after bundling deploys with it, pointed at the panel (`CLOUDFLARE_API_BASE_URL=$BASE`,
`CLOUDFLARE_ACCOUNT_ID`, `CLOUDFLARE_API_TOKEN`), as long as `wrangler.toml` has:

- `workers_dev = false` and `preview_urls = false`: there is no workers.dev here;
- no `vars` or other bindings (wrangler would send them in the upload's `bindings`): set them with
  `PATCH .../settings`;
- `routes` with patterns (not `custom_domain = true`) in zones of the panel, and `triggers.crons` if any.

That covers the first deploy of a name. A later `wrangler deploy` of the same name does not finish: for a
Worker that is already there, wrangler uploads through the versions API (`POST .../versions`, then
`POST .../deployments`), and fucf keeps no versions, so both are refused with a `400` that says so (wrangler
does not retry a `400`). Nor are `wrangler versions`, `wrangler rollback`, `wrangler delete` and custom
domains (`/workers/domains`). `wrangler deploy --dry-run --outdir dist` writes the bundle without calling any
API; upload it yourself to replace a Worker, either form:

```
curl -s -X PUT $BASE/accounts/$ACCOUNT/workers/scripts/my-worker -H "Authorization: Bearer $TOKEN" \
  -F 'metadata={"main_module":"index.js","bindings":[]};type=application/json' \
  -F 'index.js=@dist/index.js;type=application/javascript+module'

curl -s -X PUT $BASE/workers/scripts/my-worker -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/javascript" --data-binary @dist/index.js
```

**Runtime.** Every request (and every email or cron run) gets a fresh JavaScript context: globals,
module-level variables, changed prototypes and unsettled promises of one request are gone in the next, and
two scripts share nothing. Nothing about the context is reused between requests, by design, so state that
must outlive a request goes in KV or D1. Request and response bodies are bytes: `request.arrayBuffer()` and
`request.bytes()` give them exactly (`text()` and `json()` decode as UTF-8, replacing invalid sequences), and
`new Response(body)` takes a string, an `ArrayBuffer` or any view on one (`Uint8Array`, `DataView`, ...),
copied when the response is made. A byte body gets no `Content-Type` of its own. Bodies are limited to 16 MiB
each, and one invocation may hand at most 64 MiB of byte bodies to the edge in all.

### Workers KV

```
GET    /kv/namespaces
POST   /kv/namespaces                     {"title"}
GET    /kv/namespaces/{id}
PATCH  /kv/namespaces/{id}                {"title"}
DELETE /kv/namespaces/{id}
GET    /kv/namespaces/{id}/keys           ?prefix=&limit=&cursor=
GET    /kv/namespaces/{id}/values/{key}   the value as it was stored
PUT    /kv/namespaces/{id}/values/{key}   the body is the value; ?expiration= (unix seconds), ?expiration_ttl=, ?metadata= (JSON)
DELETE /kv/namespaces/{id}/values/{key}
```

### D1

```
GET    /d1/database
POST   /d1/database                       {"name"}
GET    /d1/database/{id}
DELETE /d1/database/{id}
POST   /d1/database/{id}/query            {"sql", "params": [...]}: rows as objects
POST   /d1/database/{id}/raw              the same; rows as arrays
```

```sh
curl -s -X POST $BASE/d1/database/$DB/query -H "Authorization: Bearer $TOKEN" -d '{"sql": "SELECT * FROM users WHERE id = ?", "params": [1]}'
```

### E-mail routing

```
GET    /email/status                      this node's SMTP listener, host names, relay and recent activity
GET    /zones/{id}/email                  whether routing is on, the rules, the zone's MX and SPF, its DKIM key, and
                                           "needed_records"
PATCH  /zones/{id}/email                  {"dkim_selector", "dkim_private_key"}: set, change or remove the DKIM key;
                                           answers what GET does
CRUD   /zones/{id}/email/rules            {"address", "action": "forward|drop|worker", "destinations": [...], "worker",
                                           "enabled", "description"}
```

`address` is a local part (`postmaster`), a full address in the zone, or `*` for every address no
other rule is for. A forwarding rule has 1 to 10 destinations outside the zones routed here.

```json
{ "address": "hello", "action": "forward", "destinations": ["someone@example.net"] }
```

#### DKIM

Mail that a zone forwards (by a rule or by an Email Worker) is signed with the zone's DKIM key
just before it goes out, when the zone has one: a `DKIM-Signature` with `d=` the zone, `a=rsa-sha256`,
`c=relaxed/relaxed`, `t=` the time of signing, and `h=` the fields of From, To, Cc, Subject, Date,
Message-ID, Reply-To, In-Reply-To, References, MIME-Version, Content-Type and
Content-Transfer-Encoding that the message has (each instance), plus From once more, so that a
second From cannot be added without breaking the signature. Nothing else in the message changes.
A message without exactly one From is passed on unsigned (with a warning in the log), as is all
mail of a zone without a key; bounces handed back to an original sender are not signed. ARC is not
done yet.

`PATCH /zones/{id}/email` reads only these two fields (others, such as the rest of what GET
answers, are ignored, so that answer can be sent back as it is):

| Field | Value |
|---|---|
| `dkim_selector` | a DNS name of letters, digits and hyphens in dot-separated labels, at most 63 characters (stored lowercase); `null` or `""` removes the key |
| `dkim_private_key` | an unencrypted RSA private key of 2048 to 4096 bits as PKCS#8 PEM (`openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048`); left out, `null` or `""` keeps the stored key. Encrypted keys, PKCS#1 (`RSA PRIVATE KEY`) and other algorithms are refused |

The private key is never answered. GET (and PATCH) answer these fields alongside the routing ones:

| Field | Meaning |
|---|---|
| `dkim_selector` | the selector, or `null` |
| `has_dkim_private_key` | whether a key is set |
| `dkim_record` | the TXT record to publish, `{"type": "TXT", "name": "<selector>._domainkey.<zone>", "content": "v=DKIM1; k=rsa; p=<SubjectPublicKeyInfo, base64>"}`, or `null` |
| `dkim_key_bits` | the key's size |
| `dkim_published` | whether the zone's DNS has a TXT record at that name with that `p=` (quoted strings are joined) |
| `dkim_error` | why a stored key cannot be read, or `null` |

While `dkim_published` is false the record is also in `needed_records`.

```sh
jq -n --arg key "$(cat dkim.pem)" '{dkim_selector: "fucf", dkim_private_key: $key}' |
  curl -s -X PATCH $BASE/zones/$ZONE/email -H "Authorization: Bearer $TOKEN" -d @-
```

Tokens need Email Routing Rules Read to see these fields and Email Routing Rules Write to change them.

### Spectrum

```
CRUD   /zones/{id}/spectrum/apps          {"protocol": "tcp/2222", "dns": {"name": "ssh"},
                                           "origin_direct": ["tcp://192.0.2.1:22"], "proxy_protocol": "off|v1"}
```

One app per protocol and port across the fleet; `proxy_protocol` is for TCP only.

### Analytics

```
GET    /analytics                         every zone: ?since=24h (90m, 24h, 7d, or minutes like -1440; at most 30d)
GET    /zones/{id}/analytics              one zone: ?since= as above, ?step= minutes
```

### Request log

```
GET    /zones/{id}/logs/requests          the newest requests of the zone on the node that answers
CRUD   /zones/{id}/logpush/jobs           {"name", "destination", "enabled", "status_min", "batch_seconds"}
```

Every node keeps its own newest 5000 requests in memory (all zones together, lost on restart) and
answers only from those: behind the panel host that is the panel's node. Entries hold the visitor's
address. Parameters of `GET …/logs/requests`, all optional; an unknown, empty or malformed one is a 400:

| Parameter | Meaning |
|---|---|
| `since` | the `cursor` of an earlier answer: entries after it, oldest first. Without it: the newest entries |
| `limit` | 1 to 1000 (default 100) |
| `status` | an exact code (`404`) or a class (`5xx`) |
| `host` | exact host name |
| `path` | path prefix, starting with `/` |
| `ip` | the visitor's address (exact) |

```json
{ "entries": [{ "seq": 41, "time": "2026-01-01T00:00:00.000Z", "ray": "0123456789abcdef", "node": "ams",
    "zone_id": "…", "host": "www.example.com", "method": "GET", "path": "/api/items", "status": 200,
    "cache": "MISS", "bytes": 512, "duration_ms": 12, "client_ip": "192.0.2.10", "country": "NL",
    "asn": 64496, "user_agent": "curl/8.5.0", "protocol": "HTTP/2", "action": "" }],
  "cursor": 41, "gap": false, "node": "ams" }
```

- Poll with `since` set to the last `cursor`. The cursor moves past entries the filters skipped, so a
  filtered poll does not look at them again. A cursor older than the oldest entry kept starts from the
  oldest one and sets `gap` (entries were dropped unread); a cursor beyond the newest entry (from before
  the node restarted) gets nothing and the newest entry's number back.
- `path` has no query string and is cut to 512 bytes, `user_agent` to 256 bytes (at a character
  boundary). `bytes` is the size the response declared, `null` for a body streamed without a length;
  `duration_ms` runs until the response head was ready. `asn` is `null` when unknown. `action` is
  `block`, `challenge` or `rate_limit` when the security rules stopped the request.
- Tokens need `Logs Read` (reading the log and the jobs) or `Logs Write` (changing jobs) for the zone;
  `Analytics Read` is not enough. In the panel only admins may create, change or delete jobs.

A log job makes every node post its own entries of the zone to `destination` every `batch_seconds`
(10 to 3600, default 60), as NDJSON (`application/x-ndjson`, one entry per line, fields as above), only
requests with at least `status_min` (0, the default, for all; otherwise 100 to 599). A job starts with
the requests that come after it reaches the node. `destination` must be `https://`, without a user name
or password, and not a private, loopback or link-local address (names that resolve to one are refused
when connecting). A batch that fails (no answer within 10 seconds, or not a 2xx) is dropped and logged
once as a warning; it is not sent again.

```json
{ "name": "errors to the collector", "destination": "https://logs.example.com/ingest?token=test-token", "status_min": 500, "batch_seconds": 30 }
```

### Waiting rooms

```
CRUD   /zones/{id}/waiting_rooms          {"name", "host", "path_prefix", "total_active_users", "new_users_per_minute", "session_minutes", "enabled", "description"}
```

A waiting room puts a queue in front of one host and path prefix of the zone. It is checked after the
security rules and redirects, and before transform rules, Workers, the cache and the origin.

| Field | Meaning |
|---|---|
| `name` | required, at most 64 characters |
| `host` | one host name of the zone, no wildcard; not one that a more specific zone serves |
| `path_prefix` | default `/`. Covers the path and everything below it on segment boundaries: `/shop` covers `/shop` and `/shop/cart`, not `/shopping`. Starts with `/`, at most 256 of `a-z A-Z 0-9 / - . _ ~ ! $ & ' ( ) * + = : @ %`; a trailing `/` is dropped. Compared with the path as sent, case-sensitive |
| `total_active_users` | admitted sessions active at once, 1 to 100000 (per node) |
| `new_users_per_minute` | new visitors let in over any 60 seconds, 1 to `total_active_users` (per node) |
| `session_minutes` | 1 to 30, default 5: how long a session lasts after the visitor's last page load |
| `enabled` | default `true` |
| `description` | optional, one line of at most 256 characters |

- At most one enabled room per host and path prefix (another one is a 409), at most 20 rooms per zone.
  Where rooms of one host overlap, the longest prefix wins.
- Only page loads wait: `GET` or `HEAD` requests that a browser makes to show a page (`Sec-Fetch-Mode:
  navigate`, or without that header an `Accept` that names `text/html` or is missing; never with
  `X-Requested-With`). Assets, API calls and form posts pass, and so does everything under `/cdn-cgi/`
  and every request a firewall `skip` rule let through.
- A visitor who is let in gets the cookie `fucf_waiting_room` (`HttpOnly`, `SameSite=Lax`, `Secure` over
  HTTPS, `Path` the room's prefix, `Max-Age` the session), signed with the fleet's key and bound to the
  room, a random visitor id and an expiry, and passes directly until it expires; a page load in the second
  half of a session renews it. A cookie that does not verify, belongs to another room, has expired or runs
  longer than the room's sessions do now counts as no cookie.
- A visitor who has to wait gets the queue page: status 200 (as Cloudflare answers), `Cache-Control:
  no-store`, `Retry-After: 20`, `fcf-waiting-room: queued`, reloading itself every 20 seconds and showing
  roughly how many are ahead. It carries the cookie `fucf_waiting_ticket` with the visitor's arrival time;
  each reload shows the ticket again and gets it back with the same arrival. Earlier tickets are let in
  first; a ticket not shown again for 120 seconds is void (the visitor left the line), and so is one
  already used to get in.
- Counting is per node: each node keeps its own sessions, admissions and line in memory and applies the
  limits to what it sees (visitors admitted by another node count once they load a page here). With
  several nodes serving a zone, the origin may see up to that many times the limits. A restart forgets
  the sessions (cookies stay valid) and the line (tickets keep their arrival time).
- Tokens need `Waiting Rooms Read` or `Waiting Rooms Write` for the zone.

```json
{ "name": "launch", "host": "www.example.com", "path_prefix": "/shop", "total_active_users": 500, "new_users_per_minute": 100, "session_minutes": 10 }
```

### The fleet

```
GET    /system                            this node: role, build, configuration version, name servers, the peers' sync state
GET    /fleet                             every node in detail (what it runs, its traffic, its sync and release state)
POST   /fleet/{node}/actions              {"action": "restart|purge_cache"}: this node at once, a peer when it next gets in touch
GET    /nodes
POST   /nodes                             {"name", "ipv4", "ipv6", "continents", "enabled", "traffic_dns_gb", "traffic_throttle_gb",
                                           "traffic_limit_gb", "traffic_period": "month|day", "traffic_reset_day", "rate_limit_mbps",
                                           "dns_offload_mode": "drop|linear", "dns_silent_on_limit", "dc", "colo",
                                           "role": "peer|accelerate", "accel_hosts"}
GET    /nodes/{id}  PUT  PATCH  DELETE
GET    /steering
POST   /steering                          {"name", "priority", "countries", "regions", "continents", "asns", "as_orgs",
                                           "action": "route|fastest|block", "nodes", "enabled"}
PUT    /steering/{id}  PATCH  DELETE
GET    /steering/test?ip=&ua=
GET    /steering/measured                 the handshake round trips the nodes measured, per network and node
GET    /proxy/rules                       the nodes' local reverse proxy
POST   /proxy/rules                       {"name", "nodes", "listen_port", "hosts", "path_prefix", "exact_path", "rewrite_path",
                                           "strip_prefix", "redirect_url", "redirect_status", "upstreams": [{"url", "weight",
                                           "tls_insecure"}], "respond": {"status", "body", "content_type"}, "file_root",
                                           "index_files", "auto_https", "https_redirect", "preserve_host",
                                           "set_request_headers", "set_response_headers", "strip_response_headers",
                                           "is_fallback", "priority"}
GET    /proxy/rules/{id}  PUT  PATCH  DELETE
GET    /releases                          the binary each node runs, and the roll-out
PUT    /releases/{sha256}?signature=      the body is the signed binary: start rolling it out
DELETE /releases/{sha256}                 take it back (nodes return to what they ran); ?forget=true only drops it
GET    /releases/{sha256}/binary          for peers
GET    /backup                            see "Backups"
```

A node with traffic limits:

```sh
curl -s -X POST $BASE/nodes -H "Authorization: Bearer $TOKEN" -d '{
  "name": "nrt1", "ipv4": "203.0.113.10", "continents": ["AS"],
  "traffic_dns_gb": 1000, "traffic_throttle_gb": 1250, "traffic_limit_gb": 1400, "rate_limit_mbps": 10
}'
```

#### Steering by measured round trips

A steering rule's `action` is `route` (the first node of `nodes` that can take the visitor; `nodes`
is required), `block` (the DNS refuses these visitors; `nodes` is dropped) or `fastest`: the node
that the visitor's network reaches soonest, as the nodes measured it. For `fastest`, `nodes` are the
candidates (empty: every node).

With the GeoIP database, each node takes the round trip of every visitor's TLS 1.3 handshake over
TCP and every QUIC handshake, and keeps a running mean per network: the country with the province or
state and the AS number (`CN-JS/4134`), the country and the AS number (`CN/4134`), the country with
the province or state (`CN-JS`), and the country (`CN`). TLS 1.2 takes two round trips and is left
out, and so are the fleet's own nodes and connections through the HTTP/3 front (that round trip is
not the visitor's). What is new goes to the other nodes with the reports. A rule
compares the candidates on the most precise of these networks that at least two of them have 5 or
more handshakes of within the last day, and answers the fastest, for each address family. While
nothing tells them apart, a candidate is picked at random; and 5 answers in a hundred go to a random
candidate anyway, so every node keeps being measured.

```
GET /steering/measured
```

```json
{ "CN": { "hkg1": { "ms": 41.3, "samples": 87, "age": 12 }, "nrt1": { "ms": 63.0, "samples": 40, "age": 95 } },
  "CN/4134": { "hkg1": { "ms": 44.8, "samples": 31, "age": 12 } } }
```

Network, then node: `ms` is the running mean (a new handshake weighs a fifth), `samples` the
handshakes in it, `age` the seconds since the last one. Measurements older than a day are left out, so
a fleet that measured nothing yet answers `{}`; each node keeps at most 4000 networks.
`GET /steering/test` answers `measured` too: the network a `fastest` rule would go by for that
address and the nodes fastest first (`{"network", "nodes": [{"name", "ms"}]}`), or `null`. Both need
Fleet Read.

### Alerts

The node that runs the panel (the one without `--panel-origin`) looks at the fleet every 30 seconds
and tells the alert channels what changed: once when an alert starts, every 6 hours while it lasts,
and once when it is over. What fires is kept in memory only: after a restart, whatever still fires
is told again.

| Event | Fires when | Over when |
| --- | --- | --- |
| `node_offline` | an enabled node (not the panel's own) missed 3 checks in a row; never within 2 minutes of the start, and the checks count from then on | it reports again |
| `sync_lagging` | a node has been online for 5 minutes without running this node's configuration version | it runs it, or goes offline |
| `certificate_failing` | a certificate pack failed to issue (no certificate at all), or the one in use ends within 14 days | it is renewed or deleted |
| `traffic_limit` | a node is past a threshold of its traffic allowance (`dns_limited`, `throttled`, `limited`); a new tier is told again | it is back under |
| `under_attack` | the automatic firewall switched a zone to under attack mode (not when it was set by hand) | the zone is switched back |
| `origin_errors` | 3 origin error events of one zone within 5 minutes (each failing host is logged at most once a minute per status and node) | 5 minutes pass without one |

```
GET    /alerts/channels
POST   /alerts/channels                   {"name", "kind": "webhook|telegram", "enabled", "events": [...],
                                           "url" (webhook), "bot_token", "chat_id" (telegram)}
GET    /alerts/channels/{id}
PUT    /alerts/channels/{id}  PATCH       the fields given change (PUT and PATCH alike)
DELETE /alerts/channels/{id}
POST   /alerts/channels/{id}/test         one test message, on or off; 502 with the reason if it did not arrive
GET    /alerts/active                     {"evaluating", "checked_at", "alerts": [{"key", "event", "subject", "level",
                                           "message", "since", "last_sent"}]}; "evaluating" is false on nodes that do not check
```

- `events` names at least one of the events above; an empty list is refused (a channel told of
  nothing is a mistake), and so are unknown names.
- A webhook `url` must be `https://`, name a public host (no `localhost`, no private, loopback or
  reserved address, no `user:password@`) and is never sent to a private address whatever its name
  resolves to. Redirects are not followed; anything but a 2xx answer counts as not delivered.
- `bot_token` is the token BotFather gives (`<bot id>:<secret>`); `chat_id` is a numeric chat id
  (negative for groups and channels) or `@channelname`. Messages go to the Bot API's `sendMessage`
  as plain text.
- At most 20 channels. Writes need an administrator (editors and viewers read); tokens need
  Notifications Read / Write, which Fleet permissions do not include.
- Secrets never come back: `url` shows as `https://host/***` and `bot_token` as `***`. Sending the
  masked value back (or an empty one) keeps the stored secret, so a channel can be read, changed and
  put back whole. Channels are part of the configuration (and of backups), secrets included.

A webhook gets:

```json
{
  "source": "fucf", "node": "eu-1", "sent_at": "2026-11-28T12:00:30.000000Z", "test": false,
  "alerts": [{ "event": "node_offline", "subject": "us-1", "state": "firing", "repeat": false, "level": "",
               "message": "节点 us-1 连续 3 次检查不在线 · node us-1 missed 3 checks in a row",
               "since": "2026-11-28T12:00:30.000000Z", "at": "2026-11-28T12:00:30.000000Z" }],
  "text": "fucf 告警 · alerts from eu-1\n\n触发 · FIRING node_offline us-1\n…"
}
```

`state` is `firing` or `resolved`; `repeat` marks the 6-hourly reminder. A test message has
`"test": true` and no alerts. Everything found in one check goes out as one message per channel.

```sh
curl -s -X POST $BASE/alerts/channels -H "Authorization: Bearer $TOKEN" -d '{
  "name": "ops", "kind": "webhook", "url": "https://hooks.example.com/fucf",
  "events": ["node_offline", "certificate_failing", "under_attack"]
}'
```

### Human-check widgets (Turnstile-like)

A widget puts the edge's challenge (the same detection and proof of work as a zone's challenge)
into a site's own forms, and lets the site's backend check what came back, in the manner of
Cloudflare Turnstile. Widgets belong to the account, like Turnstile sites; the id is the public
sitekey.

```
GET    /challenges/widgets                         (also /accounts/{account_id}/challenges/widgets[...])
POST   /challenges/widgets                         {"name", "domains": ["shop.example.com", ...], "mode": "managed"}
                                                   the answer holds "secret": the only time it is shown
GET    /challenges/widgets/{sitekey}
PUT    /challenges/widgets/{sitekey}  PATCH        the fields given change (PUT and PATCH alike); the secret stays
DELETE /challenges/widgets/{sitekey}
POST   /challenges/widgets/{sitekey}/rotate_secret {} or {"invalidate_immediately": true}; the answer holds the
                                                   new "secret", and the old one stops working at once
```

A widget reads back as `{"id", "sitekey", "name", "domains", "mode", "created_on", "modified_on"}`:
never the secret or anything derived from it. Only the secret's SHA-256 is stored (and synced
between nodes, and kept in backups); a lost secret can only be replaced by rotating it.

- `domains`: 1 to 10 exact host names, lowercase (they are lowercased), at least two labels, no
  wildcards, ports, paths or addresses. Each one a page may use the widget on; the puzzle is only
  handed out on a host that is one of them and that a zone here proxies.
- `name`: 1 to 254 characters, no control characters.
- `mode`: only `managed` (a click is asked for when the browser looks doubtful; the puzzle is
  never easier than a zone at `medium`, and as hard as the zone's when that is `high` or
  `under_attack`).
- Cloudflare's other fields are accepted at their defaults only (`bot_fight_mode`, `offlabel`,
  `ephemeral_id`: false; `clearance_level`: `no_clearance`; `region`: `world`); `secret`,
  `secret_sha256` and any other field are refused. `rotate_secret` with
  `"invalidate_immediately": false` is refused, since there is no grace period for the old secret.
- At most 50 widgets. Writes need an administrator (editors and viewers read); API tokens need
  Turnstile Sites Read / Write, which Fleet permissions do not include.

The page:

```html
<form method="post" action="/sign-up">
  <script src="/cdn-cgi/challenge-platform/widget.js" async defer></script>
  <div data-sitekey="0123456789abcdef0123456789abcdef"></div>
  <button>Sign up</button>
</form>
```

The script is loaded from the page's own host (every proxied host has it). It fetches its puzzle
from `/cdn-cgi/challenge-platform/widget/ticket` and answers it at
`/cdn-cgi/challenge-platform/widget/verify`, both on the page's own host: no CORS is offered,
and requests a browser marks as cross-site are refused. A browser that passes gets a token, which
the script writes into a hidden `fcf-challenge-response` field inside the element, and the element
fires `fcf-challenge-success` (`event.detail.token`). A token is refreshed a little before its five
minutes are up (`fcf-challenge-expired`); a failure fires `fcf-challenge-error` and shows a retry
link. `window.fcfChallenge` has `render(el)` for elements added later, `reset(el)` for a new token
(after a form was sent, since each token is accepted once) and `getResponse(el)`.

The backend:

```sh
curl -s https://shop.example.com/cdn-cgi/challenge-platform/siteverify \
  -d secret=fcfws_test-secret -d response="$TOKEN_FROM_THE_FORM" -d remoteip=198.51.100.7
# {"success":true,"error-codes":[],"challenge_ts":"2026-11-28T12:00:30.000Z","hostname":"shop.example.com"}
```

- `POST` only, as `application/x-www-form-urlencoded` or `application/json` (string fields; a
  field given twice in a form is refused), at most 16 KiB. It answers on any host a zone here
  proxies and on the panel's host, over HTTPS only (plain HTTP from the node itself aside).
- A token is good for five minutes, for the widget it was made for, on one of that widget's
  domains, and once: a second check of the same token on the same node fails with
  `timeout-or-duplicate`. The edge cannot tell the nodes apart in time, so a backend that checks a
  token against two different nodes could have it accepted twice: check each token once.
- `remoteip` is optional. When it is given it must be the address the browser had when it got the
  token (IPv4 and IPv6 forms of one address are the same); otherwise the token is refused, which is
  stricter than Turnstile.
- Error codes: `missing-input-secret`, `invalid-input-secret` (no widget has that secret),
  `missing-input-response`, `invalid-input-response` (not a token of this widget, or of another
  host or address), `timeout-or-duplicate`, `bad-request` (not a POST, too large, not a form or JSON,
  an unreadable `remoteip`, or a host that does not answer siteverify), `internal-error` (this node
  remembers too many tokens to take a new one; try again). Nothing about a token, or about whether
  a sitekey exists, is said before the secret is right.
- `challenge_ts` and `hostname` are only in a successful answer. `idempotency_key` is not
  supported (it is ignored).
- A token is no clearance for the zone's own challenge, and the zone's clearance cookie is no
  token: each is signed under a prefix of its own.

### Between nodes

These are for the fleet itself (the API token or a peer's credentials), not for tools:

```
GET    /replication/state                 what a node reports, and what it should run
POST   /replication/report                a node's traffic, security events and status
GET    /replication/sync                  ?since=&epoch=&since_accounts=&epoch_accounts=: what changed since then
POST   /replication/sync                  changes pushed by a peer
```
