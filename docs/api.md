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
| SSL and Certificates Read / Write | zone | certificate packs, custom certificates |
| Origin Rules, Dynamic Redirect, Transform Rules, Cache Rules Read / Write | zone | the rule lists of those names |
| Workers Routes Read / Write | zone | `/zones/{id}/workers/routes` |
| Email Routing Rules Read / Write | zone | `/zones/{id}/email…` |
| Zone Spectrum Read / Write | zone | `/zones/{id}/spectrum/apps` |
| Analytics Read | zone | `/zones/{id}/analytics` |
| Workers Scripts, Workers KV Storage, D1 Read / Write | account | `/workers/scripts…`, `/kv/…`, `/d1/…` |
| Fleet Read / Write | account | nodes, fleet actions, steering, local proxy rules, releases |
| Account Analytics Read, Audit Logs Read | account | `/analytics`, `/audit` |
| Backup Read | account | `GET /backup` (everything, secrets included: guard such a token) |
| API Tokens Read / Write | user | `/user/tokens…` |

Cloudflare's account-level paths work too: `/accounts/{account id}/workers/scripts/…`,
`/accounts/{account id}/storage/kv/namespaces/…`, `/accounts/{account id}/d1/database/…`,
`/accounts/{account id}/tokens/…`.

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
`sni`, `host_header`, `node` (route to that edge node's local port). An empty object removes them.

SRV and CAA can be written as `data`, the way Cloudflare takes them:

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
CRUD   /zones/{id}/rate_limits                      {"expression", "threshold", "period", "mitigation_timeout", "action"}
GET    /zones/{id}/security/events?limit=
GET    /steering/test?ip=&ua=                       where an address is placed, and its threat score
```

Firewall actions: `block`, `js_challenge` (the human check; a click only when the browser looks
doubtful), `managed_challenge` (always one click), `log`, `skip`. Expressions use Cloudflare's rules
language: `http.host`, `http.request.uri.path`, `http.request.method`, `http.user_agent`,
`http.request.headers["x"]`, `ip.src`, `ip.geoip.country`, `ip.geoip.continent`, `ip.geoip.asnum`,
`ip.geoip.as_org`, `cf.threat_score` (also `fcf.threat_score`), with `eq ne lt le gt ge contains
matches in {…} and or not`.

Settings that belong here:

| Setting | Values |
| --- | --- |
| `security_level` | `off`, `low` (threat score ≥ 80 is challenged), `medium` (≥ 50), `high` (≥ 25: data centres too), `under_attack` (everybody). Higher levels also ask for more work and tolerate less doubt. |
| `challenge_script` | `true`: the fcf script goes into the site's HTML pages. It passes the check quietly in the background, and settles challenged `fetch` requests in place (a click box over the page, then the request is sent again: no reload). |
| `waf` | managed ruleset: `block`, `log`, `off` |
| `auto_firewall` | ban addresses from recent security events (see below) |
| `decoy_subdomains` | every name without records resolves, and nothing answers there |

The threat score (0 to 100) comes from public lists every node fetches twice a day (FireHOL level 1
and 2, Tor exit nodes, VPN and data centre ranges), hosting networks by name, and what the fleet itself
banned lately. Private addresses, the fleet's own and search engine crawlers coming from their own
networks score 0.

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
`MISS`, `EXPIRED`, `STALE`, `REVALIDATED`, `BYPASS`, `DYNAMIC`, `NONE` for what the edge answered
itself) and `x-cache: HIT|MISS from <colo>`. Nothing the edge sends starts with `cf-`; what an origin
behind Cloudflare sends that does is dropped. Origins receive `fcf-connecting-ip` and `fcf-ipcountry`
(and, for software written for Cloudflare, `cf-connecting-ip` and `cf-ipcountry`).

### The automatic firewall

With `auto_firewall` on, every 30 seconds the zone's recent security events (managed rule hits,
firewall blocks, rate limit hits) are counted, and the zone's own rules are kept up to date:

| Rule | When | Does |
| --- | --- | --- |
| addresses (`managed_by: auto_firewall`) | `auto_firewall_threshold` attacks (default 10) within `auto_firewall_window` seconds (600) | `auto_firewall_action` (`block` or `managed_challenge`) for `auto_firewall_ban` seconds (86400), extended while it goes on; IPv6 by /64 |
| networks (`managed_by: auto_firewall_networks`) | `auto_firewall_networks` on and at least `auto_firewall_network_ips` (10) data centre / VPN / listed addresses of one ASN attacked | `managed_challenge` for the whole ASN (the fleet's own addresses excepted); home ISPs are never taken as a whole |
| security level | `auto_firewall_surge` (50; 0 off) different attackers within the window | `under_attack` for an hour after the surge was last seen, then back to the level before |

Banned addresses also count against their threat score on every zone.

## Backups

```
GET /backup        everything the fleet replicates (configuration, accounts, Workers KV, D1) as one
                   gzipped JSON bundle; admins, or a token with "Backup Read"
```

Every node also writes one every 6 hours into `<data dir>/backups` (the last 28 are kept;
`FUCF_BACKUP_DIR`, `FUCF_BACKUP_EVERY_HOURS`, `FUCF_BACKUP_KEEP`). A node started with
`--restore-from <bundle>` (`FUCF_RESTORE_FROM`) merges one in (what is newer there stays).
`.github/workflows/backup.yml` keeps an encrypted copy away from every node.

## Everything else

```
/system                                  this node, the fleet's sync state
/analytics                               all zones' traffic; ?since=24h
/nodes[/{id}]                            edge nodes
/fleet, /fleet/{node}/actions            what nodes report; ask a node to do something
/steering[/{id}]                         where visitors are sent, by place and network
/proxy/rules[/{id}]                      the nodes' local reverse proxy
/releases[/{sha256}]                     rolling releases
/zones/{id}/purge_cache                  {"purge_everything": true} | {"files": […]} | {"prefixes": […]}
/zones/{id}/ssl/certificate_packs[/{id}] {"hosts": […], "validation_method": "auto|dns|tls-alpn|http"}
/zones/{id}/custom_certificates[/{id}]   {"certificate", "private_key", "hosts"}
/zones/{id}/origin_rules[/{id}]          {"expression", "origin_host", "origin_port", "origin_scheme", "host_header", "sni"}
/zones/{id}/redirect_rules[/{id}]        {"expression", "target_url", "status_code", "preserve_query_string"}
/zones/{id}/transform_rules[/{id}]       {"expression", "rewrite_path", "set_request_headers", …}
/zones/{id}/cache_rules[/{id}]           {"expression", "cache", "edge_ttl"}
/zones/{id}/workers/routes[/{id}]        {"pattern", "script"}
/zones/{id}/email, /email/rules[/{id}]   e-mail routing
/zones/{id}/spectrum/apps[/{id}]         TCP / UDP proxying
/zones/{id}/analytics                    ?since=24h&step=60
/workers/scripts[/{name}]                PUT: the body is the script
/workers/scripts/{name}/settings         {"vars": {…}}
/kv/namespaces[/{id}[/keys|/values/{key}]]
/d1/database[/{id}[/query|/raw]]
```
