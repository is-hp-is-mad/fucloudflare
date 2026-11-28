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
| Account Filter Lists Read / Write | account | `/rules/lists…` (IP lists) |
| API Tokens Read / Write | user | `/user/tokens…` |

Cloudflare's account-level paths work too: `/accounts/{account id}/workers/scripts/…`,
`/accounts/{account id}/storage/kv/namespaces/…`, `/accounts/{account id}/d1/database/…`,
`/accounts/{account id}/tokens/…`, `/accounts/{account id}/rules/lists/…`.

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
matches in {…} and or not`. `ip.src in $name` asks an IP list (see [IP lists](#ip-lists)).

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

### Zone settings

```
GET    /zones/{id}/settings               [{"id": name, "value": …, "editable": true}, …]
GET    /zones/{id}/settings/{name}
PATCH  /zones/{id}/settings/{name}        {"value": …}
```

| Setting | Values (default first) |
| --- | --- |
| `ssl` | `flexible` (HTTP to the origin), `full` (HTTPS, certificate not checked), `strict` (HTTPS, checked) |
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
| `auto_firewall` | `false`, `true`, with `auto_firewall_threshold` (10), `auto_firewall_window` (600), `auto_firewall_ban` (86400), `auto_firewall_action` (`block`, `managed_challenge`, `js_challenge`), `auto_firewall_networks` (`true`), `auto_firewall_network_ips` (10), `auto_firewall_surge` (50; 0 off) |

```sh
curl -s -X PATCH $BASE/zones/$ZONE/settings/security_level -H "Authorization: Bearer $TOKEN" -d '{"value": "high"}'
```

### DNSSEC

```
GET    /zones/{id}/dnssec                 status, and the DS record to give the registrar
PATCH  /zones/{id}/dnssec                 {"status": "active|disabled"}
```

Records are signed online (ECDSA P-256, algorithm 13) with minimal NSEC answers.

### Cache

```
POST   /zones/{id}/purge_cache            {"purge_everything": true} | {"files": [url, …]} | {"prefixes": [url prefix, …]}
POST   /warp/purge_cache                  the same, for the edge's own /cdn-cgi/fucf-warp cache
```

A purge reaches every node through the configuration.

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

### Rules

All rule lists take an `expression` (empty matches every request), `description`, `enabled` (true)
and, where it applies, `priority` (lower first).

```
CRUD   /zones/{id}/firewall/rules         {"expression", "action", "priority", "enabled", "description"}
CRUD   /zones/{id}/rate_limits            {"expression", "threshold", "period", "mitigation_timeout", "action", "enabled"}
CRUD   /zones/{id}/redirect_rules         {"expression", "target_url", "status_code", "preserve_query_string", "priority"}
CRUD   /zones/{id}/transform_rules        {"expression", "rewrite_path", "set_request_headers", "remove_request_headers",
                                           "set_response_headers", "remove_response_headers", "priority"}
CRUD   /zones/{id}/cache_rules            {"expression", "cache", "edge_ttl", "priority"}
CRUD   /zones/{id}/origin_rules           {"expression", "origin_host", "origin_node", "origin_port", "origin_scheme",
                                           "host_header", "sni", "priority"}
```

| List | Fields |
| --- | --- |
| firewall rules | `action`: `block`, `js_challenge`, `managed_challenge`, `log`, `skip`. Rules kept by the automatic firewall carry `managed_by`. |
| rate limits | `threshold` (≥ 1) requests per client address per `period` (1 to 86400 s); `mitigation_timeout` 0 to 86400 s; `action`: `block` (default), `log` |
| redirect rules | `target_url`: an `http(s)://` URL or a path; `status_code`: 301, 302 (default), 303, 307, 308 |
| transform rules | at least one action; `rewrite_path` starts with `/` and has no query; `host`, `content-length`, `transfer-encoding`, `connection` and `upgrade` cannot be set or removed. Every matching rule applies. |
| cache rules | `cache`: `true` caches whatever the file type, `false` never caches; `edge_ttl` 1 to 31536000 s. The first matching rule wins. |
| origin rules | at least one of the overrides; `origin_scheme`: `http`, `https`; `origin_node`: an edge node to go through |

```sh
curl -s -X POST $BASE/zones/$ZONE/firewall/rules -H "Authorization: Bearer $TOKEN" -d '{
  "expression": "http.request.uri.path contains \"/admin\" and not ip.src in {198.51.100.0/24}",
  "action": "managed_challenge", "priority": 10, "description": "admin pages"
}'
curl -s -X POST $BASE/zones/$ZONE/redirect_rules -H "Authorization: Bearer $TOKEN" -d '{
  "expression": "http.host eq \"old.example.com\"", "target_url": "https://www.example.com/", "status_code": 301,
  "preserve_query_string": true
}'
```

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
| `http_ratelimit` | rate limits | `block`, `log`; `ratelimit`: `requests_per_period`, `period`, `mitigation_timeout`, `characteristics` `["cf.colo.id", "ip.src"]` |
| `http_request_dynamic_redirect` | redirect rules | `redirect`; `action_parameters.from_value`: `target_url.value`, `status_code` (required), `preserve_query_string` |
| `http_request_transform` | transform rules (path) | `rewrite`; `action_parameters.uri.path.value` |
| `http_request_late_transform` | transform rules (request headers) | `rewrite`; `action_parameters.headers.{name}`: `{"operation": "set", "value"}` or `{"operation": "remove"}` |
| `http_response_headers_transform` | transform rules (response headers) | as above |
| `http_request_cache_settings` | cache rules | `set_cache_settings`; `action_parameters.cache` (required), `edge_ttl`: `{"mode": "override_origin", "default"}` or `{"mode": "respect_origin"}` |
| `http_request_origin` | origin rules | `route`; `action_parameters`: `host_header`, `origin.host`, `origin.port`, `sni.value` |

- Whatever a rule says that this server cannot do is refused with a 400 that names the field
  (`rules[2].action_parameters.uri.query is not supported by this server`), never dropped. A PUT
  either lands whole or not at all.
- An expression of `true` is every request (stored as an empty expression, shown as `true`).
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
PUT    /workers/scripts/{name}            the body is the JavaScript source; it is syntax-checked
DELETE /workers/scripts/{name}
GET    /workers/scripts/{name}/settings   {"vars", "kv_bindings", "d1_bindings", "crons"}
PATCH  /workers/scripts/{name}/settings   any of those; bindings map a name in env to a namespace / database id
POST   /workers/scripts/{name}/scheduled  {"cron": "*/5 * * * *"}: run scheduled() now
CRUD   /zones/{id}/workers/routes         {"pattern": "example.com/api/*", "script": "name"} ("script": null turns
                                          Workers off for what matches)
```

`crons` are five-field UTC expressions.

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
GET    /zones/{id}/email                  whether routing is on, the rules, the zone's MX and SPF, and "needed_records"
CRUD   /zones/{id}/email/rules            {"address", "action": "forward|drop|worker", "destinations": [...], "worker",
                                           "enabled", "description"}
```

`address` is a local part (`postmaster`), a full address in the zone, or `*` for every address no
other rule is for. A forwarding rule has 1 to 10 destinations outside the zones routed here.

```json
{ "address": "hello", "action": "forward", "destinations": ["someone@example.net"] }
```

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
                                           "action": "route|block", "nodes", "enabled"}
PUT    /steering/{id}  PATCH  DELETE
GET    /steering/test?ip=&ua=
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

### Between nodes

These are for the fleet itself (the API token or a peer's credentials), not for tools:

```
GET    /replication/state                 what a node reports, and what it should run
POST   /replication/report                a node's traffic, security events and status
GET    /replication/sync                  ?since=&epoch=&since_accounts=&epoch_accounts=: what changed since then
POST   /replication/sync                  changes pushed by a peer
```
