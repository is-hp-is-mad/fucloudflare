//! Management REST API, wire-compatible with the Cloudflare v4 API for the
//! zone and DNS record endpoints (same paths, envelope and field names), so
//! existing tooling (curl scripts, Terraform-style clients) can be pointed here.

use crate::edge::cache::Cache;
use crate::edge::waf::Waf;
use crate::sync::SyncProvider;
use crate::items::{
    CacheRule, Certificate, CertificatePack, EmailRule, FirewallRule, Item, OriginRule, RateLimit, RedirectRule, SpectrumApp,
    TransformRule, WorkerRoute, WorkerScript,
};
use crate::auth::{Accounts, Assertion, AuthError, Client, Login, Principal, Proof, Registration, Role, TokenSpec, Via};
use crate::store::{proxiable, Record, RecordInput, RecordOrigin, Store, StoreError, Zone};
use axum::body::Bytes;
use axum::extract::{Path, Query, Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;

pub struct ApiState {
    pub store: Arc<Store>,
    pub token: String,
    pub cache: Arc<Cache>,
    pub waf: Arc<Waf>,
    pub stats: Arc<crate::edge::stats::Stats>,
    pub cname_base: Option<String>,
    pub name_servers: Vec<String>,
    pub panel_host: Option<String>,
    pub health: Arc<crate::geo::Health>,
    pub fleet: Arc<crate::fleet::Fleet>,
    /// The reports of the nodes, taken here and kept for the peers.
    pub reports: Arc<crate::reports::Reports>,
    pub limits: Arc<crate::limits::Limits>,
    /// This node's public addresses and, if given, its name.
    pub edge_ips: Vec<std::net::IpAddr>,
    pub node_name: Option<String>,
    pub started_at: String,
    /// The binaries this node runs and, on the primary, their roll-out.
    pub releases: Arc<crate::release::Releases>,
    /// The people who may use the panel.
    pub accounts: Arc<Accounts>,
    /// This node, as it describes itself.
    pub info: Arc<crate::node::NodeInfo>,
    /// Checking a password is expensive on purpose: only so many at a time.
    pub password_checks: tokio::sync::Semaphore,
    /// This node's SMTP side, when e-mail routing is switched on here.
    pub mail: Option<Arc<crate::mail::Mail>>,
    /// Node role (`peer` or `accelerate`).
    pub role: crate::sync::NodeRole,
    /// Optional peer-to-peer sync coordinator.
    pub sync: Option<Arc<crate::sync::PeerSync>>,
    /// Replicated storage besides the configuration (Workers KV, D1): served
    /// to and merged from peers whether or not this node pulls from any itself.
    pub providers: Vec<Arc<dyn crate::sync::SyncProvider>>,
    /// Edge runtime (for Workers KV / D1 / scheduled execution).
    pub edge: Arc<crate::edge::Edge>,
}

impl ApiState {
    /// What peers sync with this node beyond the configuration and the accounts.
    fn synced(&self) -> Vec<Arc<dyn crate::sync::SyncProvider>> {
        let reports = (!self.role.is_accelerate()).then(|| self.reports.clone() as Arc<dyn crate::sync::SyncProvider>);
        self.providers.iter().cloned().chain(reports).collect()
    }

    /// The name of the node this process runs on.
    fn node(&self) -> String {
        crate::fleet::self_name(&self.store, &self.edge_ips, self.node_name.as_deref())
    }
}

type St = State<Arc<ApiState>>;
type Params = Query<HashMap<String, String>>;
type Who = axum::Extension<Principal>;
type Caller = axum::Extension<Client>;

pub fn router(state: Arc<ApiState>) -> Router {
    // signing in: open to anybody who can reach the panel
    let open = Router::new()
        .route("/auth/status", get(auth_status))
        .route("/auth/setup", post(auth_setup))
        .route("/auth/login", post(auth_login))
        .route("/auth/second_step", post(auth_second_step))
        .route("/auth/passkey/begin", post(auth_passkey_begin))
        .route("/auth/passkey/finish", post(auth_passkey_finish))
        .route("/auth/oauth/login", get(oauth_login))
        .route("/auth/oauth/callback", get(oauth_callback))
        .layer(middleware::from_fn(client_of));
    let v4 = Router::new()
        .route("/account", get(account))
        .route("/account/logout", post(account_logout))
        .route("/account/password", post(account_password))
        .route("/account/totp/begin", post(totp_begin))
        .route("/account/totp/enable", post(totp_enable))
        .route("/account/two_factor/disable", post(two_factor_disable))
        .route("/account/backup_codes", post(backup_codes))
        .route("/account/passkeys/begin", post(passkey_begin))
        .route("/account/passkeys", post(passkey_add))
        .route("/account/passkeys/{id}", axum::routing::delete(passkey_delete))
        .route("/account/sessions/{id}", axum::routing::delete(session_delete))
        .route("/users", get(list_users).post(create_user))
        .route("/users/{id}", axum::routing::patch(update_user).delete(delete_user))
        .route("/oauth/config", get(get_oauth_config).put(put_oauth_config))
        .route("/audit", get(audit))
        .route("/fleet", get(fleet_overview))
        .route("/fleet/{node}/actions", post(fleet_action))
        .route("/user", get(user_details))
        .route("/user/tokens", get(list_tokens).post(create_token))
        .route("/user/tokens/verify", get(verify_token))
        .route("/user/tokens/permission_groups", get(permission_groups))
        .route("/user/tokens/{token_id}", get(get_token).put(update_token).delete(delete_token))
        .route("/user/tokens/{token_id}/value", axum::routing::put(roll_token))
        .route("/account/api_key", post(roll_api_key))
        .route("/accounts", get(list_accounts))
        .route("/accounts/{account_id}", get(get_account))
        .route("/system", get(system))
        .route("/backup", get(get_backup))
        .route("/replication/state", get(replication_state))
        .route("/replication/report", post(replication_report).layer(axum::extract::DefaultBodyLimit::max(32 << 20)))
        .route(
            "/replication/sync",
            get(replication_sync)
                .post(replication_sync_push)
                .layer(axum::extract::DefaultBodyLimit::max(32 << 20)),
        )
        .route("/analytics", get(analytics_summary))
        .route("/releases", get(release_status))
        .route(
            "/releases/{sha256}",
            axum::routing::put(submit_release).delete(withdraw_release).layer(axum::extract::DefaultBodyLimit::max(256 << 20)),
        )
        .route("/releases/{sha256}/binary", get(release_binary))
        .route("/warp/purge_cache", post(purge_warp_cache))
        .route("/nodes", get(list_nodes).post(create_node))
        .route("/nodes/{node_id}", get(get_node).put(update_node).patch(update_node).delete(delete_node))
        .route("/steering", get(list_steering).post(create_steering))
        .route("/steering/test", get(test_steering))
        .route("/steering/measured", get(measured_steering))
        .route("/steering/{rule_id}", axum::routing::put(update_steering).patch(update_steering).delete(delete_steering))
        .route("/proxy/rules", get(list_proxy_rules).post(create_proxy_rule))
        .route(
            "/proxy/rules/{rule_id}",
            get(get_proxy_rule)
                .put(update_proxy_rule)
                .patch(update_proxy_rule)
                .delete(delete_proxy_rule),
        )
        .route("/email/status", get(email_status))
        .route("/zones", get(list_zones).post(create_zone))
        .route("/zones/{zone_id}", get(get_zone).patch(patch_zone).delete(delete_zone))
        .route("/zones/{zone_id}/dns_records", get(list_records).post(create_record))
        .route("/zones/{zone_id}/dns_records/batch", post(batch_records))
        .route("/zones/{zone_id}/dns_records/export", get(export_records))
        .route(
            "/zones/{zone_id}/dns_records/import",
            post(import_records).layer(axum::extract::DefaultBodyLimit::max(4 << 20)),
        )
        .route("/zones/{zone_id}/dnssec", get(get_dnssec).patch(patch_dnssec))
        .route(
            "/zones/{zone_id}/dns_records/{record_id}",
            get(get_record).put(put_record).patch(patch_record).delete(delete_record),
        )
        .route("/zones/{zone_id}/settings", get(get_settings))
        .route("/zones/{zone_id}/settings/{name}", get(get_setting).patch(patch_setting))
        .route("/zones/{zone_id}/purge_cache", post(purge_cache))
        .route("/zones/{zone_id}/security/events", get(security_events))
        .route("/zones/{zone_id}/ssl/certificate_packs", get(list_packs).post(create_pack))
        .route(
            "/zones/{zone_id}/ssl/certificate_packs/{pack_id}",
            get(get_pack).patch(retry_pack).delete(delete_item::<CertificatePack>),
        )
        .route("/workers/scripts", get(list_workers))
        .route("/workers/scripts/{name}", get(get_worker).put(put_worker).delete(delete_worker))
        .route("/workers/scripts/{name}/settings", get(get_worker_settings).patch(patch_worker_settings))
        .route("/workers/scripts/{name}/scheduled", post(trigger_worker_scheduled))
        .route("/kv/namespaces", get(kv_list_namespaces).post(kv_create_namespace))
        .route("/kv/namespaces/{ns_id}", get(kv_get_namespace).patch(kv_rename_namespace).delete(kv_delete_namespace))
        .route("/kv/namespaces/{ns_id}/keys", get(kv_list_keys))
        .route("/kv/namespaces/{ns_id}/values/{key}", get(kv_get_value).put(kv_put_value).delete(kv_delete_value))
        .route("/d1/database", get(d1_list_databases).post(d1_create_database))
        .route("/d1/database/{db_id}", get(d1_get_database).delete(d1_delete_database))
        .route("/d1/database/{db_id}/query", post(d1_query))
        .route("/d1/database/{db_id}/raw", post(d1_raw))
        .merge(crud::<FirewallRule>("/zones/{zone_id}/firewall/rules"))
        .merge(crud::<RateLimit>("/zones/{zone_id}/rate_limits"))
        .merge(crud::<OriginRule>("/zones/{zone_id}/origin_rules"))
        .merge(crud::<Certificate>("/zones/{zone_id}/custom_certificates"))
        .merge(crud::<SpectrumApp>("/zones/{zone_id}/spectrum/apps"))
        .merge(crud::<WorkerRoute>("/zones/{zone_id}/workers/routes"))
        .merge(crud::<RedirectRule>("/zones/{zone_id}/redirect_rules"))
        .merge(crud::<TransformRule>("/zones/{zone_id}/transform_rules"))
        .merge(crud::<CacheRule>("/zones/{zone_id}/cache_rules"))
        .route("/zones/{zone_id}/email", get(email_zone).patch(patch_email))
        .route("/zones/{zone_id}/origin_ca", get(get_origin_ca).post(create_origin_ca).delete(delete_origin_ca))
        .route("/zones/{zone_id}/origin_ca/sign", post(sign_origin_ca))
        .merge(crud::<EmailRule>("/zones/{zone_id}/email/rules"))
        .route("/zones/{zone_id}/rulesets", get(list_rulesets).post(create_ruleset))
        .route("/zones/{zone_id}/rulesets/phases/{phase}/entrypoint", get(get_entrypoint).put(put_entrypoint))
        .route("/zones/{zone_id}/rulesets/{ruleset_id}", get(get_ruleset).put(put_ruleset).delete(delete_ruleset))
        .route("/zones/{zone_id}/rulesets/{ruleset_id}/rules", post(add_ruleset_rule))
        .route("/zones/{zone_id}/rulesets/{ruleset_id}/rules/{rule_id}", axum::routing::patch(patch_ruleset_rule).delete(delete_ruleset_rule))
        .route("/rules/lists", get(list_ip_lists).post(create_ip_list))
        .route("/rules/lists/bulk_operations/{operation_id}", get(ip_list_operation))
        .route("/rules/lists/{list_id}", get(get_ip_list).put(update_ip_list).patch(update_ip_list).delete(delete_ip_list))
        .route(
            "/rules/lists/{list_id}/items",
            get(list_ip_list_items)
                .post(append_ip_list_items)
                .put(replace_ip_list_items)
                .delete(delete_ip_list_items)
                .layer(axum::extract::DefaultBodyLimit::max(4 << 20)),
        )
        .route("/rules/lists/{list_id}/items/{item_id}", get(get_ip_list_item))
        .route("/alerts/channels", get(list_alert_channels).post(create_alert_channel))
        .route("/alerts/channels/{channel_id}", get(get_alert_channel).put(update_alert_channel).patch(update_alert_channel).delete(delete_alert_channel))
        .route("/alerts/channels/{channel_id}/test", post(test_alert_channel))
        .route("/alerts/active", get(active_alerts))
        .route("/challenges/widgets", get(list_challenge_widgets).post(create_challenge_widget))
        .route("/challenges/widgets/{sitekey}", get(get_challenge_widget).put(update_challenge_widget).patch(update_challenge_widget).delete(delete_challenge_widget))
        .route("/challenges/widgets/{sitekey}/rotate_secret", post(rotate_challenge_widget_secret))
        .route("/zones/{zone_id}/logs/requests", get(request_log))
        .merge(crud::<crate::edge::reqlog::LogJob>("/zones/{zone_id}/logpush/jobs"))
        .merge(crud::<crate::edge::waiting::WaitingRoom>("/zones/{zone_id}/waiting_rooms"))
        .merge(custom_hostname_routes())
        .route("/zones/{zone_id}/origins/health", get(origin_health))
        .route("/zones/{zone_id}/dns_analytics", get(dns_analytics))
        .route("/zones/{zone_id}/analytics", get(analytics))
        .layer(middleware::from_fn_with_state(state.clone(), auth));
    let app: Router = Router::new()
        .route("/", get(panel_html))
        .route("/fonts/{name}", get(font))
        .nest("/client/v4", open.merge(v4))
        .fallback(|| async { ApiError(StatusCode::NOT_FOUND, 7000, "No route for that URI".into()) })
        .layer(middleware::from_fn(security_headers))
        .with_state(state);
    // Cloudflare's account-level paths (`/accounts/{id}/workers/...`, `.../storage/kv/...`,
    // `.../d1/...`, `.../tokens`, `.../rules/lists`, `.../challenges/widgets`) are the same as the ones here without the account
    let inner = app.clone();
    let by_account = axum::routing::any(move |req: Request| {
        let mut inner = inner.clone();
        async move {
            match account_path(req) {
                Ok(req) => tower_service::Service::call(&mut inner, req).await.unwrap_or_else(|never| match never {}),
                Err(e) => e.into_response(),
            }
        }
    });
    Router::new().route("/client/v4/accounts/{account_id}/{*rest}", by_account).merge(app)
}

/// `/client/v4/accounts/{account}/{rest}` as the path it stands for here.
fn account_path(mut req: Request) -> Result<Request, ApiError> {
    let path = req.uri().path().to_string();
    let rest = path.strip_prefix("/client/v4/accounts/").unwrap_or_default();
    let (account, rest) = rest.split_once('/').unwrap_or((rest, ""));
    if account != crate::tokens::account_id() {
        return Err(ApiError(StatusCode::NOT_FOUND, 7003, "Could not route to this account: perhaps the identifier is wrong".into()));
    }
    let under = |prefix: &str| rest == prefix || rest.strip_prefix(prefix).is_some_and(|r| r.starts_with('/'));
    let mapped = if under("workers/scripts") {
        format!("/{rest}")
    } else if under("storage/kv/namespaces") {
        format!("/kv/{}", &rest["storage/kv/".len()..])
    } else if under("d1/database") {
        format!("/{rest}")
    } else if under("tokens") {
        format!("/user/{rest}")
    } else if under("audit_logs") {
        "/audit".to_string()
    } else if under("rules/lists") {
        format!("/{rest}")
    } else if under("challenges/widgets") {
        format!("/{rest}")
    } else {
        return Err(ApiError(StatusCode::NOT_FOUND, 7000, "No route for that URI".into()));
    };
    let query = req.uri().query().map(|q| format!("?{q}")).unwrap_or_default();
    *req.uri_mut() = format!("/client/v4{mapped}{query}").parse().map_err(|_| bad("bad path"))?;
    // The outer route's own path parameters (account id, rest) ride in the
    // extensions, and the inner router adds its parameters to them instead
    // of starting afresh: a handler taking one (`/rules/lists/{list_id}`)
    // would be handed three. Nothing else here needs them: the client is
    // read from headers, the server adds no ConnectInfo, and no API route
    // upgrades the connection (hyper's upgrade handle goes with the rest).
    *req.extensions_mut() = axum::http::Extensions::new();
    Ok(req)
}

async fn panel_html() -> Response {
    let mut resp = axum::response::Html(include_str!("panel.html")).into_response();
    resp.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        header::HeaderValue::from_static(
            "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        ),
    );
    resp
}

/// The panel's typefaces (see `src/fonts/README.md`).
async fn font(Path(name): Path<String>) -> Response {
    let bytes: &'static [u8] = match name.as_str() {
        "inter-latin-wght.woff2" => include_bytes!("fonts/inter-latin-wght.woff2"),
        "source-serif-4-latin-wght.woff2" => include_bytes!("fonts/source-serif-4-latin-wght.woff2"),
        _ => return ApiError(StatusCode::NOT_FOUND, 7000, "No route for that URI".into()).into_response(),
    };
    let mut resp = bytes.into_response();
    let h = resp.headers_mut();
    h.insert(header::CONTENT_TYPE, header::HeaderValue::from_static("font/woff2"));
    h.insert(header::CACHE_CONTROL, header::HeaderValue::from_static("public, max-age=31536000, immutable"));
    resp
}

async fn security_headers(req: Request, next: Next) -> Response {
    let is_api = req.uri().path().starts_with("/client/v4/");
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    h.insert(header::X_FRAME_OPTIONS, header::HeaderValue::from_static("DENY"));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, header::HeaderValue::from_static("nosniff"));
    h.insert(header::REFERRER_POLICY, header::HeaderValue::from_static("no-referrer"));
    if is_api {
        h.insert(header::CACHE_CONTROL, header::HeaderValue::from_static("no-store"));
    }
    resp
}

// ------------------------------------------------------------ envelope ----

pub struct ApiError(StatusCode, u32, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = json!({
            "success": false,
            "errors": [{ "code": self.1, "message": self.2 }],
            "messages": [],
            "result": null,
        });
        (self.0, Json(body)).into_response()
    }
}

impl From<StoreError> for ApiError {
    fn from(e: StoreError) -> Self {
        match e {
            StoreError::ZoneNotFound => ApiError(StatusCode::NOT_FOUND, 1001, "Zone not found".into()),
            StoreError::RecordNotFound => ApiError(StatusCode::NOT_FOUND, 81044, "Record does not exist".into()),
            StoreError::NotFound => ApiError(StatusCode::NOT_FOUND, 1002, "Resource not found".into()),
            StoreError::ReadOnly => ApiError(
                StatusCode::CONFLICT,
                1003,
                "this node is in accelerate mode; make changes on a peer node".into(),
            ),
            StoreError::Conflict(m) => ApiError(StatusCode::CONFLICT, 81057, m),
            StoreError::Invalid(m) => ApiError(StatusCode::BAD_REQUEST, 1004, m),
            StoreError::Io(m) => {
                tracing::error!("state persistence failed: {m}");
                ApiError(StatusCode::INTERNAL_SERVER_ERROR, 1000, "failed to persist state".into())
            }
        }
    }
}

type ApiResult = Result<Json<Value>, ApiError>;

fn ok(result: Value) -> ApiResult {
    Ok(Json(json!({ "success": true, "errors": [], "messages": [], "result": result })))
}

fn bad(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, 1004, msg.into())
}

fn body<T: DeserializeOwned>(bytes: &Bytes) -> Result<T, ApiError> {
    serde_json::from_slice(bytes).map_err(|e| bad(format!("invalid request body: {e}")))
}

fn paginated(items: Vec<Value>, q: &HashMap<String, String>, default_per_page: usize) -> ApiResult {
    let int = |k: &str, d: usize| q.get(k).and_then(|v| v.parse().ok()).unwrap_or(d);
    let page = int("page", 1).max(1);
    let per_page = int("per_page", default_per_page).clamp(1, 5000);
    let total = items.len();
    let slice: Vec<Value> = items.into_iter().skip((page - 1).saturating_mul(per_page)).take(per_page).collect();
    Ok(Json(json!({
        "success": true, "errors": [], "messages": [],
        "result_info": {
            "page": page, "per_page": per_page, "count": slice.len(),
            "total_count": total, "total_pages": total.div_ceil(per_page),
        },
        "result": slice,
    })))
}

// ---------------------------------------------------------------- auth ----

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Where a request comes from. The API listens on loopback; what reaches it
/// from outside came through the edge, which names the visitor.
fn client(headers: &header::HeaderMap) -> Client {
    let text = |name: &str| headers.get(name).and_then(|v| v.to_str().ok()).unwrap_or_default().to_string();
    let forwarded = text("x-forwarded-for");
    let ip = forwarded.rsplit(',').next().map(str::trim).filter(|ip| !ip.is_empty()).unwrap_or("local").to_string();
    Client { ip, agent: text("user-agent") }
}

async fn client_of(mut req: Request, next: Next) -> Response {
    let from = client(req.headers());
    if req.method() == axum::http::Method::POST {
        static AUTH_RATE: std::sync::LazyLock<std::sync::Mutex<HashMap<String, (std::time::Instant, u32)>>> =
            std::sync::LazyLock::new(Default::default);
        let now = std::time::Instant::now();
        let window = std::time::Duration::from_secs(60);
        let limited = {
            let mut map = AUTH_RATE.lock().unwrap();
            if map.len() > 10_000 {
                map.retain(|_, (at, _)| now.duration_since(*at) < window);
                if map.len() > 10_000 {
                    map.clear();
                }
            }
            let entry = map.entry(from.ip.clone()).or_insert((now, 0));
            if now.duration_since(entry.0) >= window {
                *entry = (now, 0);
            }
            entry.1 += 1;
            entry.1 > 60
        };
        if limited {
            return ApiError(StatusCode::TOO_MANY_REQUESTS, 2002, "too many authentication attempts: try again later".into()).into_response();
        }
    }
    req.extensions_mut().insert(from);
    next.run(req).await
}

/// May somebody with this role make this request? Everybody may look after
/// their own account; viewers only read; users, the audit trail, releases,
/// nodes, spectrum listeners, what nodes are told to do and where alerts go
/// are the administrators', and so are changes to the human-check widgets.
fn permitted(role: Role, method: &axum::http::Method, path: &str) -> bool {
    let under = |prefix: &str| path == prefix || path.strip_prefix(prefix).is_some_and(|rest| rest.starts_with('/'));
    let reads = method == axum::http::Method::GET || method == axum::http::Method::HEAD;
    let own = under("/account") || under("/user");
    let admins = under("/users")
        || under("/oauth")
        || under("/audit")
        || under("/replication")
        || under("/backup")
        || path.starts_with("/releases/")
        || (!reads && (under("/releases") || under("/fleet") || under("/nodes") || under("/alerts") || path.contains("/spectrum/apps")))
        // a log job sends visitor addresses off this fleet
        || (!reads && path.contains("/logpush/jobs"))
        // a widget's secret is shown to whoever creates or rotates it
        || (!reads && under("/challenges"));
    match role {
        Role::Admin => true,
        Role::Editor => own || !admins,
        Role::Viewer => own || (reads && !admins),
    }
}

/// Who is asking: the API token (the fleet's own tooling), or somebody
/// signed in to the panel.
async fn auth(State(st): St, mut req: Request, next: Next) -> Response {
    let from = client(req.headers());
    // (in a block: nothing borrowed from the request may live across the await below)
    let who = {
        let headers = req.headers();
        let text = |name: &str| headers.get(name).and_then(|v| v.to_str().ok()).map(str::trim).filter(|v| !v.is_empty());
        let presented = text(header::AUTHORIZATION.as_str()).and_then(|v| v.strip_prefix("Bearer ")).map(str::trim);
        let who = match presented {
            Some(t) if ct_eq(t.as_bytes(), st.token.as_bytes()) => Ok(Some(Principal::system())),
            Some(t) if t.starts_with("fucf_s_") => Ok(st.accounts.session(t)),
            // a user's API token, Cloudflare style
            Some(t) => st.accounts.token(t, from.ip.parse().ok()).transpose(),
            // or the Global API Key
            None => match (text("x-auth-email"), text("x-auth-key")) {
                (Some(email), Some(key)) => Ok(st.accounts.api_key(email, key)),
                _ => Ok(None),
            },
        };
        who
    };
    let who = match who {
        Ok(Some(who)) => who,
        Ok(None) => return ApiError(StatusCode::UNAUTHORIZED, 10000, "Authentication error".into()).into_response(),
        Err(e) => return ApiError::from(e).into_response(),
    };
    let path = req.uri().path().to_string();
    let path = path.as_str();
    if who.must_change_password
        && !matches!((req.method().as_str(), path), ("GET", "/account") | ("POST", "/account/password") | ("POST", "/account/logout"))
    {
        return ApiError(StatusCode::FORBIDDEN, 2016, "you must change your password before continuing".into()).into_response();
    }
    if !permitted(who.role, req.method(), path) {
        return ApiError(StatusCode::FORBIDDEN, 2010, "your role does not allow this".into()).into_response();
    }
    let token_allows = match who.via {
        Via::Token => who.grant.as_ref().is_some_and(|g| g.allows(req.method().as_str(), path, who.user_id.as_deref().unwrap_or_default())),
        // the key opens what its owner may do, but not the owner's credentials
        Via::ApiKey => !(path == "/account" || path.starts_with("/account/") || path.starts_with("/replication")),
        Via::Session | Via::System => true,
    };
    if !token_allows {
        return ApiError(StatusCode::FORBIDDEN, 9109, "Unauthorized to access requested resource".into()).into_response();
    }
    // zones are their owners' (crate::tenancy), for every path under /zones/{zone_id}
    let reads = req.method() == axum::http::Method::GET || req.method() == axum::http::Method::HEAD;
    match crate::tenancy::check(&who, reads, path, &st.store) {
        Ok(()) => {}
        Err(crate::tenancy::Denied::Zone) => return ApiError::from(StoreError::ZoneNotFound).into_response(),
        Err(crate::tenancy::Denied::Account) => {
            return ApiError(StatusCode::FORBIDDEN, 2010, "only administrators change account-level objects".into()).into_response();
        }
    }
    // an e-mail rule that hands mail to a Worker is the administrators', as a route to one is
    if who.role != Role::Admin && !reads && crate::tenancy::is_email_rule(path) {
        let (parts, body) = req.into_parts();
        let Ok(bytes) = axum::body::to_bytes(body, 64 << 10).await else {
            return ApiError(StatusCode::PAYLOAD_TOO_LARGE, 1000, "an e-mail rule is at most 64 KiB".into()).into_response();
        };
        if crate::tenancy::binds_worker(&bytes) {
            return ApiError(StatusCode::FORBIDDEN, 2010, "only administrators hand mail to Workers".into()).into_response();
        }
        req = Request::from_parts(parts, axum::body::Body::from(bytes));
    }
    req.extensions_mut().insert(who);
    req.extensions_mut().insert(from);
    next.run(req).await
}

impl From<AuthError> for ApiError {
    fn from(e: AuthError) -> Self {
        ApiError(StatusCode::from_u16(e.status).unwrap_or(StatusCode::BAD_REQUEST), e.code, e.message)
    }
}

// ------------------------------------------------------------- accounts ----

/// Run something that checks or makes a password hash, off the async
/// threads and not too many at once.
async fn hashing<T: Send + 'static>(st: &Arc<ApiState>, work: impl FnOnce(&Accounts) -> Result<T, AuthError> + Send + 'static) -> Result<T, ApiError> {
    let _permit = tokio::time::timeout(std::time::Duration::from_secs(2), st.password_checks.acquire())
        .await
        .map_err(|_| ApiError(StatusCode::TOO_MANY_REQUESTS, 2002, "too many password checks in flight: try again in a moment".into()))?
        .map_err(|_| bad("shutting down"))?;
    let accounts = st.accounts.clone();
    let done = tokio::task::spawn_blocking(move || work(&accounts)).await.map_err(|e| bad(e.to_string()))?;
    Ok(done?)
}

async fn accounts_blocking<T: Send + 'static>(
    st: &Arc<ApiState>,
    work: impl FnOnce(&Accounts) -> Result<T, ApiError> + Send + 'static,
) -> Result<T, ApiError> {
    let accounts = st.accounts.clone();
    tokio::task::spawn_blocking(move || work(&accounts)).await.map_err(|e| bad(e.to_string()))?
}

async fn push_auth_critical(st: &Arc<ApiState>) {
    if let Some(sync) = &st.sync {
        sync.push_now_bounded(std::time::Duration::from_millis(400)).await;
    }
}

fn signed_in((token, user): (String, Value)) -> ApiResult {
    ok(json!({ "token": token, "user": user }))
}

/// What the panel needs to know before anybody is signed in.
async fn auth_status(State(st): St) -> ApiResult {
    ok(json!({
        "initialized": st.accounts.initialized(),
        "role": st.role.as_str(),
        "writable": !st.role.is_accelerate(),
        "replica": st.role.is_accelerate(),
        "panel_host": st.panel_host,
    }))
}

#[derive(Deserialize)]
struct SetupBody {
    /// The API token: proof that whoever sets the panel up runs the node.
    token: String,
    email: String,
    password: String,
}

/// The first account: an administrator, by e-mail address. Only while
/// there is none, and only with the API token.
async fn auth_setup(State(st): St, axum::Extension(from): Caller, bytes: Bytes) -> ApiResult {
    if st.role.is_accelerate() {
        return Err(StoreError::ReadOnly.into());
    }
    let b: SetupBody = body(&bytes)?;
    if st.accounts.initialized() {
        return Err(ApiError(StatusCode::CONFLICT, 2013, "this panel is set up already: sign in".into()));
    }
    if !ct_eq(b.token.trim().as_bytes(), st.token.as_bytes()) {
        return Err(ApiError(StatusCode::FORBIDDEN, 2015, "that is not this node's API token".into()));
    }
    let (email, password) = (b.email.clone(), b.password.clone());
    let who = from.clone();
    hashing(&st, move |accounts| accounts.create_user(&email, Role::Admin, Some(&password), &email.trim().to_ascii_lowercase(), &who)).await?;
    let res = match hashing(&st, move |accounts| accounts.login(&b.email, &b.password, &from)).await? {
        Login::Session(token, user) => signed_in((token, user)),
        Login::SecondStep { .. } => Err(bad("sign in")),
    };
    push_auth_critical(&st).await;
    res
}

#[derive(Deserialize)]
struct LoginBody {
    email: String,
    password: String,
}

async fn auth_login(State(st): St, axum::Extension(from): Caller, bytes: Bytes) -> ApiResult {
    let b: LoginBody = body(&bytes)?;
    match hashing(&st, move |accounts| accounts.login(&b.email, &b.password, &from)).await? {
        Login::Session(token, user) => {
            push_auth_critical(&st).await;
            signed_in((token, user))
        }
        Login::SecondStep { ticket, methods } => ok(json!({ "second_step": { "ticket": ticket, "methods": methods } })),
    }
}

#[derive(Deserialize)]
struct SecondStepBody {
    ticket: String,
    code: Option<String>,
    backup_code: Option<String>,
    passkey: Option<Assertion>,
}

async fn auth_second_step(State(st): St, axum::Extension(from): Caller, bytes: Bytes) -> ApiResult {
    let b: SecondStepBody = body(&bytes)?;
    let proof = match (b.code, b.backup_code, b.passkey) {
        (Some(code), _, _) => Proof::Totp(code),
        (_, Some(code), _) => Proof::BackupCode(code),
        (_, _, Some(assertion)) => Proof::Passkey(assertion),
        _ => return Err(bad("one of 'code', 'backup_code' and 'passkey' is required")),
    };
    let ticket = b.ticket;
    let res = accounts_blocking(&st, move |accounts| Ok(accounts.second_step(&ticket, proof, &from)?)).await?;
    push_auth_critical(&st).await;
    signed_in(res)
}

async fn auth_passkey_begin(State(st): St) -> ApiResult {
    ok(json!({ "challenge": st.accounts.passkey_login_begin() }))
}

async fn auth_passkey_finish(State(st): St, axum::Extension(from): Caller, bytes: Bytes) -> ApiResult {
    let assertion = body::<Assertion>(&bytes)?;
    let res = accounts_blocking(&st, move |accounts| Ok(accounts.passkey_login(&assertion, &from)?)).await?;
    push_auth_critical(&st).await;
    signed_in(res)
}

fn oauth_redirect_response(location: &str, cookies: &[String]) -> Response {
    let mut resp = (StatusCode::FOUND, [(header::LOCATION, location.to_string())]).into_response();
    for c in cookies {
        if let Ok(v) = axum::http::HeaderValue::from_str(c) {
            resp.headers_mut().append(header::SET_COOKIE, v);
        }
    }
    resp
}

fn oauth_error_redirect(msg: &str, clear_cookie: bool) -> Response {
    let enc = percent_encoding::utf8_percent_encode(msg, percent_encoding::NON_ALPHANUMERIC).to_string();
    let cookies = if clear_cookie {
        vec!["fucf_oauth=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0".to_string()]
    } else {
        Vec::new()
    };
    oauth_redirect_response(&format!("/#/?oauth_error={enc}"), &cookies)
}

fn oauth_redirect_uri(cfg: &crate::auth::OAuthConfig, headers: &axum::http::HeaderMap, panel_host: Option<&str>) -> (String, bool) {
    if !cfg.redirect_base_url.is_empty() {
        let base = cfg.redirect_base_url.trim_end_matches('/');
        let secure = base.starts_with("https://");
        return (format!("{base}/client/v4/auth/oauth/callback"), secure);
    }
    if let Some(ph) = panel_host.map(str::trim).filter(|s| !s.is_empty()) {
        return (format!("https://{ph}/client/v4/auth/oauth/callback"), true);
    }
    let host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("localhost");
    let proto = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_ascii_lowercase())
        .unwrap_or_else(|| {
            if host.starts_with("127.0.0.1") || host.starts_with("localhost") || host.starts_with("[::1]") {
                "http".into()
            } else {
                "https".into()
            }
        });
    (format!("{proto}://{host}/client/v4/auth/oauth/callback"), proto == "https")
}

fn oauth_random_b64url(len: usize) -> String {
    use base64::Engine;
    use ring::rand::{SecureRandom, SystemRandom};
    let mut buf = vec![0u8; len];
    let _ = SystemRandom::new().fill(&mut buf);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
}

fn extract_cookie(headers: &axum::http::HeaderMap, name: &str) -> Option<String> {
    for hv in headers.get_all(header::COOKIE) {
        if let Ok(s) = hv.to_str() {
            for part in s.split(';') {
                if let Some((k, v)) = part.trim().split_once('=') {
                    if k.trim() == name {
                        return Some(v.trim().to_string());
                    }
                }
            }
        }
    }
    None
}

async fn oauth_http_exchange(
    edge: &crate::edge::Edge,
    url: &str,
    method: axum::http::Method,
    headers: Vec<(&str, String)>,
    body: Bytes,
) -> Result<(StatusCode, Bytes), String> {
    use http_body_util::BodyExt;
    let uri: hyper::Uri = url.parse().map_err(|e| format!("invalid URL '{url}': {e}"))?;
    let path_q = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    let target = crate::edge::upstream::Target::from_url(url)?;
    let mut req = hyper::Request::builder()
        .method(method)
        .uri(path_q)
        .body(crate::edge::full(body))
        .map_err(|e| e.to_string())?;
    for (k, v) in headers {
        if let (Ok(hn), Ok(hv)) = (
            hyper::header::HeaderName::from_bytes(k.as_bytes()),
            hyper::header::HeaderValue::from_str(&v),
        ) {
            req.headers_mut().insert(hn, hv);
        }
    }
    let resp = edge.upstream.send(&target, req).await.map_err(|e| format!("{e:?}"))?;
    let status = resp.status();
    let bytes = resp.into_body().collect().await.map_err(|e| e.to_string())?.to_bytes();
    Ok((status, bytes))
}

async fn oauth_login(State(st): St, headers: axum::http::HeaderMap) -> Response {
    let cfg = st.accounts.oauth_config();
    if !cfg.enabled || cfg.issuer_url.is_empty() || cfg.client_id.is_empty() {
        return oauth_error_redirect("oauth_not_configured", false);
    }
    let code_verifier = oauth_random_b64url(32);
    let state = oauth_random_b64url(16);
    let nonce = oauth_random_b64url(16);
    let challenge = {
        use base64::Engine;
        let d = ring::digest::digest(&ring::digest::SHA256, code_verifier.as_bytes());
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(d.as_ref())
    };
    let sealed = match st.accounts.seal_oauth_state(&code_verifier, &state, &nonce) {
        Ok(s) => s,
        Err(_) => return oauth_error_redirect("oauth_state_seal_failed", false),
    };
    let (redirect_uri, secure) = oauth_redirect_uri(&cfg, &headers, st.panel_host.as_deref());
    let scopes = if cfg.scopes.is_empty() { "openid profile email" } else { cfg.scopes.as_str() };
    let enc = |s: &str| percent_encoding::utf8_percent_encode(s, percent_encoding::NON_ALPHANUMERIC).to_string();
    let auth_url = format!(
        "{}/authorize?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&nonce={}&code_challenge={}&code_challenge_method=S256",
        cfg.issuer_url,
        enc(&cfg.client_id),
        enc(&redirect_uri),
        enc(scopes),
        enc(&state),
        enc(&nonce),
        enc(&challenge),
    );
    let mut cookie = format!("fucf_oauth={sealed}; Path=/; HttpOnly; SameSite=Lax; Max-Age=600");
    if secure {
        cookie.push_str("; Secure");
    }
    oauth_redirect_response(&auth_url, &[cookie])
}

async fn oauth_callback(
    State(st): St,
    axum::Extension(from): Caller,
    headers: axum::http::HeaderMap,
    Query(q): Params,
) -> Response {
    if let Some(err) = q.get("error").filter(|s| !s.is_empty()) {
        return oauth_error_redirect(err, true);
    }
    let Some(code) = q.get("code").filter(|s| !s.is_empty()) else {
        return oauth_error_redirect("missing_code", true);
    };
    let Some(state) = q.get("state").filter(|s| !s.is_empty()) else {
        return oauth_error_redirect("missing_state", true);
    };
    let Some(cookie_val) = extract_cookie(&headers, "fucf_oauth") else {
        return oauth_error_redirect("missing_oauth_cookie", true);
    };
    let Ok((code_verifier, _nonce)) = st.accounts.verify_oauth_state(&cookie_val, state) else {
        return oauth_error_redirect("invalid_or_expired_state", true);
    };

    let cfg = st.accounts.oauth_config();
    if !cfg.enabled || cfg.issuer_url.is_empty() || cfg.client_id.is_empty() {
        return oauth_error_redirect("oauth_not_configured", true);
    }
    let (redirect_uri, secure) = oauth_redirect_uri(&cfg, &headers, st.panel_host.as_deref());
    let enc = |s: &str| percent_encoding::utf8_percent_encode(s, percent_encoding::NON_ALPHANUMERIC).to_string();
    let mut form = format!(
        "grant_type=authorization_code&code={}&redirect_uri={}&client_id={}&code_verifier={}",
        enc(code),
        enc(&redirect_uri),
        enc(&cfg.client_id),
        enc(&code_verifier),
    );
    if !cfg.client_secret.is_empty() {
        form.push_str(&format!("&client_secret={}", enc(&cfg.client_secret)));
    }
    let token_url = format!("{}/token", cfg.issuer_url);
    let (tok_status, tok_bytes) = match oauth_http_exchange(
        &st.edge,
        &token_url,
        axum::http::Method::POST,
        vec![
            ("content-type", "application/x-www-form-urlencoded".into()),
            ("accept", "application/json".into()),
        ],
        Bytes::from(form),
    )
    .await
    {
        Ok(r) => r,
        Err(_) => return oauth_error_redirect("token_exchange_failed", true),
    };
    if !tok_status.is_success() {
        return oauth_error_redirect("token_exchange_rejected", true);
    }
    let Ok(tok_json) = serde_json::from_slice::<Value>(&tok_bytes) else {
        return oauth_error_redirect("invalid_token_response", true);
    };
    let access_token = tok_json["access_token"].as_str().unwrap_or_default();

    let mut email = String::new();
    if !access_token.is_empty() {
        let userinfo_url = format!("{}/userinfo", cfg.issuer_url);
        if let Ok((ui_status, ui_bytes)) = oauth_http_exchange(
            &st.edge,
            &userinfo_url,
            axum::http::Method::GET,
            vec![
                ("authorization", format!("Bearer {access_token}")),
                ("accept", "application/json".into()),
            ],
            Bytes::new(),
        )
        .await
        {
            if ui_status.is_success() {
                if let Ok(ui_json) = serde_json::from_slice::<Value>(&ui_bytes) {
                    if let Some(e) = ui_json["email"].as_str() {
                        email = e.to_string();
                    }
                }
            }
        }
    }
    if email.is_empty() {
        if let Some(id_tok) = tok_json["id_token"].as_str() {
            if let Some(payload_b64) = id_tok.split('.').nth(1) {
                use base64::Engine;
                if let Ok(bytes) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload_b64) {
                    if let Ok(claims) = serde_json::from_slice::<Value>(&bytes) {
                        if let Some(e) = claims["email"].as_str() {
                            email = e.to_string();
                        }
                    }
                }
            }
        }
    }
    if email.is_empty() {
        return oauth_error_redirect("userinfo_missing_email", true);
    }

    let (token, _) = match accounts_blocking(&st, move |accounts| Ok(accounts.login_or_provision_oauth(&email, &from)?)).await {
        Ok(res) => res,
        Err(e) => return oauth_error_redirect(&e.2, true),
    };
    push_auth_critical(&st).await;

    let mut sess_cookie = format!("fucf_session={token}; Path=/; HttpOnly; SameSite=Lax");
    if secure {
        sess_cookie.push_str("; Secure");
    }
    let clear_oauth = "fucf_oauth=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0".to_string();
    let tok_enc = enc(&token);
    oauth_redirect_response(&format!("/#/?oauth_token={tok_enc}"), &[clear_oauth, sess_cookie])
}

async fn get_oauth_config(State(st): St) -> ApiResult {
    let mut cfg = st.accounts.oauth_config();
    let has_secret = !cfg.client_secret.is_empty();
    if has_secret {
        cfg.client_secret = "***".into();
    }
    let mut val = serde_json::to_value(&cfg).unwrap_or_default();
    if let Some(o) = val.as_object_mut() {
        o.remove("sync");
        o.insert("has_client_secret".into(), json!(has_secret));
    }
    ok(val)
}

async fn put_oauth_config(State(st): St, axum::Extension(who): Who, axum::Extension(from): Caller, bytes: Bytes) -> ApiResult {
    let cfg: crate::auth::OAuthConfig = body(&bytes)?;
    let actor = who.email.clone();
    let mut updated = accounts_blocking(&st, move |accounts| Ok(accounts.set_oauth_config(cfg, &actor, &from)?)).await?;
    push_auth_critical(&st).await;
    let has_secret = !updated.client_secret.is_empty();
    if has_secret {
        updated.client_secret = "***".into();
    }
    let mut val = serde_json::to_value(&updated).unwrap_or_default();
    if let Some(o) = val.as_object_mut() {
        o.remove("sync");
        o.insert("has_client_secret".into(), json!(has_secret));
    }
    ok(val)
}

/// Who is signed in, and what protects the account.
async fn account(State(st): St, axum::Extension(who): Who) -> ApiResult {
    match &who.user_id {
        Some(id) => ok(st.accounts.me(id, who.session_id.as_deref()).ok_or(StoreError::NotFound)?),
        None => ok(json!({ "email": who.email, "role": who.role, "api_token": true, "initialized": st.accounts.initialized() })),
    }
}

async fn account_logout(State(st): St, axum::Extension(who): Who) -> ApiResult {
    if let Some(session) = who.session_id {
        accounts_blocking(&st, move |accounts| {
            accounts.logout(&session);
            Ok(())
        })
        .await?;
        push_auth_critical(&st).await;
    }
    ok(json!({}))
}

#[derive(Deserialize)]
struct PasswordBody {
    #[serde(default)]
    current: String,
    #[serde(default)]
    new: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    code: String,
}

async fn account_password(State(st): St, axum::Extension(who): Who, axum::Extension(from): Caller, bytes: Bytes) -> ApiResult {
    if st.role.is_accelerate() {
        return Err(StoreError::ReadOnly.into());
    }
    let b: PasswordBody = body(&bytes)?;
    hashing(&st, move |accounts| accounts.change_password(&who, &b.current, &b.new, &from)).await?;
    push_auth_critical(&st).await;
    ok(json!({}))
}

/// Start setting up an authenticator app: the secret, as text and as a QR code.
async fn totp_begin(State(st): St, axum::Extension(who): Who) -> ApiResult {
    if st.role.is_accelerate() {
        return Err(StoreError::ReadOnly.into());
    }
    let (secret, uri) = accounts_blocking(&st, move |accounts| Ok(accounts.totp_begin(&who)?)).await?;
    let uri_qr = uri.clone();
    let svg = tokio::task::spawn_blocking(move || -> Result<String, ApiError> {
        let qr = qrcode::QrCode::new(uri_qr.as_bytes()).map_err(|e| bad(e.to_string()))?;
        Ok(qr.render::<qrcode::render::svg::Color>().min_dimensions(200, 200).quiet_zone(true).build())
    })
    .await
    .map_err(|e| bad(e.to_string()))??;
    ok(json!({ "secret": secret, "uri": uri, "qr_svg": svg }))
}

async fn totp_enable(State(st): St, axum::Extension(who): Who, axum::Extension(from): Caller, bytes: Bytes) -> ApiResult {
    if st.role.is_accelerate() {
        return Err(StoreError::ReadOnly.into());
    }
    let b: PasswordBody = body(&bytes)?;
    let codes = accounts_blocking(&st, move |accounts| Ok(accounts.totp_enable(&who, &b.code, &from)?)).await?;
    push_auth_critical(&st).await;
    ok(json!({ "backup_codes": codes }))
}

async fn two_factor_disable(State(st): St, axum::Extension(who): Who, axum::Extension(from): Caller, bytes: Bytes) -> ApiResult {
    if st.role.is_accelerate() {
        return Err(StoreError::ReadOnly.into());
    }
    let b: PasswordBody = body(&bytes)?;
    hashing(&st, move |accounts| accounts.two_factor_disable(&who, &b.password, &from)).await?;
    push_auth_critical(&st).await;
    ok(json!({}))
}

/// Ten new backup codes; the ones before stop working.
async fn backup_codes(State(st): St, axum::Extension(who): Who, axum::Extension(from): Caller, bytes: Bytes) -> ApiResult {
    if st.role.is_accelerate() {
        return Err(StoreError::ReadOnly.into());
    }
    let b: PasswordBody = body(&bytes)?;
    let codes = hashing(&st, move |accounts| accounts.backup_codes_regenerate(&who, &b.password, &from)).await?;
    push_auth_critical(&st).await;
    ok(json!({ "backup_codes": codes }))
}

async fn passkey_begin(State(st): St, axum::Extension(who): Who) -> ApiResult {
    ok(accounts_blocking(&st, move |accounts| Ok(accounts.passkey_register_begin(&who)?)).await?)
}

async fn passkey_add(State(st): St, axum::Extension(who): Who, axum::Extension(from): Caller, bytes: Bytes) -> ApiResult {
    if st.role.is_accelerate() {
        return Err(StoreError::ReadOnly.into());
    }
    let reg = body::<Registration>(&bytes)?;
    let res = accounts_blocking(&st, move |accounts| Ok(accounts.passkey_register(&who, &reg, &from)?)).await?;
    push_auth_critical(&st).await;
    ok(res)
}

async fn passkey_delete(State(st): St, axum::Extension(who): Who, axum::Extension(from): Caller, Path(id): Path<String>) -> ApiResult {
    if st.role.is_accelerate() {
        return Err(StoreError::ReadOnly.into());
    }
    let del_id = id.clone();
    accounts_blocking(&st, move |accounts| Ok(accounts.passkey_delete(&who, &del_id, &from)?)).await?;
    push_auth_critical(&st).await;
    ok(json!({ "id": id }))
}

async fn session_delete(State(st): St, axum::Extension(who): Who, Path(id): Path<String>) -> ApiResult {
    if st.role.is_accelerate() {
        return Err(StoreError::ReadOnly.into());
    }
    let del_id = id.clone();
    accounts_blocking(&st, move |accounts| Ok(accounts.revoke_session(&who, &del_id)?)).await?;
    push_auth_critical(&st).await;
    ok(json!({ "id": id }))
}

async fn list_users(State(st): St) -> ApiResult {
    ok(Value::Array(st.accounts.users()))
}

#[derive(Deserialize)]
struct UserBody {
    email: Option<String>,
    role: Option<Role>,
    /// Left out: one is made up, and returned this once.
    password: Option<String>,
    disabled: Option<bool>,
    #[serde(default)]
    reset_password: bool,
    #[serde(default)]
    reset_two_factor: bool,
}

async fn create_user(State(st): St, axum::Extension(who): Who, axum::Extension(from): Caller, bytes: Bytes) -> ApiResult {
    if st.role.is_accelerate() {
        return Err(StoreError::ReadOnly.into());
    }
    let b: UserBody = body(&bytes)?;
    let email = b.email.ok_or_else(|| bad("'email' is required"))?;
    let role = b.role.unwrap_or(Role::Viewer);
    let (user, generated) = hashing(&st, move |accounts| accounts.create_user(&email, role, b.password.as_deref(), &who.email, &from)).await?;
    push_auth_critical(&st).await;
    ok(json!({ "user": user, "password": generated }))
}

async fn update_user(State(st): St, axum::Extension(who): Who, axum::Extension(from): Caller, Path(id): Path<String>, bytes: Bytes) -> ApiResult {
    if st.role.is_accelerate() {
        return Err(StoreError::ReadOnly.into());
    }
    let b: UserBody = body(&bytes)?;
    let (user, generated) =
        hashing(&st, move |accounts| accounts.update_user(&id, b.role, b.disabled, b.reset_password, b.reset_two_factor, &who, &from)).await?;
    push_auth_critical(&st).await;
    ok(json!({ "user": user, "password": generated }))
}

async fn delete_user(State(st): St, axum::Extension(who): Who, axum::Extension(from): Caller, Path(id): Path<String>) -> ApiResult {
    if st.role.is_accelerate() {
        return Err(StoreError::ReadOnly.into());
    }
    let del_id = id.clone();
    accounts_blocking(&st, move |accounts| Ok(accounts.delete_user(&del_id, &who, &from)?)).await?;
    push_auth_critical(&st).await;
    ok(json!({ "id": id }))
}

async fn audit(State(st): St) -> ApiResult {
    ok(Value::Array(st.accounts.audit()))
}

// ---------------------------------------------------------------- fleet ----

/// Every node of the fleet in detail: what it runs, how it is doing, where
/// it stands with the configuration and the release.
async fn fleet_overview(State(st): St) -> ApiResult {
    let (me, version, accel) = (st.node(), st.store.version(), st.role.is_accelerate());
    let target = st.releases.target();
    let configured = st.store.list_nodes();
    let mut names: Vec<String> = configured.iter().map(|n| n.name.clone()).collect();
    for known in std::iter::once(me.clone()).chain(st.fleet.all(&version).as_object().into_iter().flat_map(|peers| peers.keys().cloned())) {
        if !names.contains(&known) {
            names.push(known);
        }
    }
    let nodes: Vec<Value> = names
        .iter()
        .map(|name| {
            let own = *name == me;
            let peer = if own { None } else { st.fleet.status(name, &version) };
            let status = if own { st.info.status() } else { peer.as_ref().map(|p| p["status"].clone()).unwrap_or(Value::Null) };
            let exe = if own { st.info.updater.own().to_string() } else { peer.as_ref().and_then(|p| p["exe"].as_str()).unwrap_or_default().to_string() };
            let usage = if own { Some(st.limits.usage()) } else { st.fleet.usage(name) };
            let node_role = if own { st.role.as_str().to_string() } else { st.fleet.role(name) };
            json!({
                "name": name,
                "self": own,
                "role": node_role,
                "configured": configured.iter().find(|n| n.name == *name),
                "healthy": st.health.is_up(name),
                "online": own || peer.as_ref().is_some_and(|p| p["online"] == true),
                "in_sync": own || peer.as_ref().is_some_and(|p| p["in_sync"] == true),
                "config_version": if own { json!(version) } else { peer.as_ref().map(|p| p["version"].clone()).unwrap_or(Value::Null) },
                "last_seen": peer.as_ref().map(|p| p["last_seen"].clone()),
                "build": if own { json!(env!("CARGO_PKG_VERSION")) } else { peer.as_ref().map(|p| p["build"].clone()).unwrap_or(Value::Null) },
                "exe": exe,
                "takes_releases": if own { st.info.updater.enabled() } else { !exe.is_empty() },
                "on_release": target.as_ref().is_some_and(|(_, sha)| *sha == exe),
                "traffic": usage,
                "status": status,
            })
        })
        .collect();
    let peers = match &target {
        _ if accel => Vec::new(),
        Some((submission, sha256)) => st.fleet.views(&version, submission, sha256),
        None => st.fleet.views(&version, "", ""),
    };
    let acme_leader = crate::sync::acme_lease::preferred_leader(&me, &st.fleet.online_peers());
    ok(json!({
        "node": me,
        "role": st.role.as_str(),
        "writable": !accel,
        "config_version": version,
        "sync_rev": st.store.current_rev(),
        "acme_leader": acme_leader,
        "nodes": nodes,
        "actions": crate::node::ACTIONS,
        "release": st.releases.status(&me, &peers),
    }))
}

#[derive(Deserialize)]
struct ActionBody {
    action: String,
}

/// Tell a node to do something: this one at once, a peer when it next
/// gets in touch (within seconds).
async fn fleet_action(State(st): St, axum::Extension(who): Who, axum::Extension(from): Caller, Path(node): Path<String>, bytes: Bytes) -> ApiResult {
    let b: ActionBody = body(&bytes)?;
    if !crate::node::ACTIONS.contains(&b.action.as_str()) {
        return Err(bad(format!("'{}' is not something a node can be told to do ({})", b.action, crate::node::ACTIONS.join(", "))));
    }
    let said = if node == st.node() {
        st.info.run(&b.action).await.map_err(bad)?
    } else {
        if st.role.is_accelerate() {
            return Err(StoreError::ReadOnly.into());
        }
        if !st.fleet.status(&node, &st.store.version()).is_some_and(|p| p["online"] == true) {
            return Err(ApiError(StatusCode::CONFLICT, 1006, format!("{node} is not in touch with this node right now")));
        }
        st.fleet.command(&node, &b.action);
        format!("{node} is told when it next gets in touch (within a few seconds)")
    };
    let note_text = format!("{node}: {}", b.action);
    let _ = accounts_blocking(&st, move |accounts| {
        accounts.note(&who, "node.action", note_text, &from);
        Ok(())
    })
    .await;
    ok(json!({ "node": node, "action": b.action, "message": said }))
}

async fn verify_token(State(st): St, axum::Extension(who): Who) -> ApiResult {
    match &who.grant {
        Some(g) => {
            let view = st.accounts.token_view(&who, &g.token_id)?;
            ok(json!({ "id": g.token_id, "status": "active", "not_before": view["not_before"], "expires_on": view["expires_on"] }))
        }
        None => ok(json!({ "status": "active" })),
    }
}

/// `GET /backup`: everything the fleet replicates, as this node has it
/// (see crate::backup), to keep somewhere else.
async fn get_backup(State(st): St) -> Result<Response, ApiError> {
    let mut providers: Vec<Arc<dyn SyncProvider>> = vec![st.store.clone(), st.accounts.clone()];
    providers.extend(st.providers.iter().cloned());
    let node = st.node();
    let bytes = tokio::task::spawn_blocking(move || crate::backup::take(&providers, &node))
        .await
        .map_err(|e| bad(e.to_string()))?
        .map_err(bad)?;
    let name = format!("attachment; filename=\"fucf-backup-{}.json.gz\"", chrono::Utc::now().format("%Y%m%dT%H%M%SZ"));
    let headers = [(header::CONTENT_TYPE, "application/gzip".to_string()), (header::CONTENT_DISPOSITION, name), (header::CACHE_CONTROL, "no-store".to_string())];
    Ok((headers, bytes).into_response())
}

/// `/user`: who the credentials belong to.
async fn user_details(axum::Extension(who): Who) -> ApiResult {
    ok(json!({
        "id": who.user_id, "email": who.email, "role": who.role,
        "has_pro_zones": false, "has_business_zones": false, "has_enterprise_zones": false, "suspended": false,
        "two_factor_authentication_enabled": false,
    }))
}

fn account_json() -> Value {
    json!({
        "id": crate::tokens::account_id(), "name": crate::tokens::ACCOUNT_NAME, "type": "standard",
        "settings": { "enforce_twofactor": false }, "created_on": "2026-01-01T00:00:00Z",
    })
}

async fn list_accounts(Query(q): Params) -> ApiResult {
    paginated(vec![account_json()], &q, 20)
}

async fn get_account(Path(account_id): Path<String>) -> ApiResult {
    if account_id != crate::tokens::account_id() {
        return Err(StoreError::NotFound.into());
    }
    ok(account_json())
}

async fn permission_groups(Query(q): Params) -> ApiResult {
    paginated(crate::tokens::groups_json(), &q, 100)
}

async fn list_tokens(State(st): St, axum::Extension(who): Who, Query(q): Params) -> ApiResult {
    paginated(st.accounts.tokens(&who), &q, 20)
}

async fn get_token(State(st): St, axum::Extension(who): Who, Path(id): Path<String>) -> ApiResult {
    ok(st.accounts.token_view(&who, &id)?)
}

fn writable(st: &ApiState) -> Result<(), ApiError> {
    if st.role.is_accelerate() {
        return Err(StoreError::ReadOnly.into());
    }
    Ok(())
}

async fn create_token(State(st): St, axum::Extension(who): Who, axum::Extension(from): Caller, bytes: Bytes) -> ApiResult {
    writable(&st)?;
    let spec: TokenSpec = body(&bytes)?;
    let (mut view, value) = accounts_blocking(&st, move |accounts| Ok(accounts.create_token(&who, spec, &from)?)).await?;
    push_auth_critical(&st).await;
    view["value"] = json!(value);
    ok(view)
}

async fn update_token(State(st): St, axum::Extension(who): Who, axum::Extension(from): Caller, Path(id): Path<String>, bytes: Bytes) -> ApiResult {
    writable(&st)?;
    let spec: TokenSpec = body(&bytes)?;
    let view = accounts_blocking(&st, move |accounts| Ok(accounts.update_token(&who, &id, spec, &from)?)).await?;
    push_auth_critical(&st).await;
    ok(view)
}

async fn roll_token(State(st): St, axum::Extension(who): Who, axum::Extension(from): Caller, Path(id): Path<String>) -> ApiResult {
    writable(&st)?;
    let value = accounts_blocking(&st, move |accounts| Ok(accounts.roll_token(&who, &id, &from)?)).await?;
    push_auth_critical(&st).await;
    ok(json!(value))
}

async fn delete_token(State(st): St, axum::Extension(who): Who, axum::Extension(from): Caller, Path(id): Path<String>) -> ApiResult {
    writable(&st)?;
    let gone = id.clone();
    accounts_blocking(&st, move |accounts| Ok(accounts.delete_token(&who, &gone, &from)?)).await?;
    push_auth_critical(&st).await;
    ok(json!({ "id": id }))
}

#[derive(Deserialize)]
struct ApiKeyBody {
    #[serde(default)]
    password: String,
    #[serde(default)]
    remove: bool,
}

/// A new Global API Key for oneself (`remove` takes it away); the password again.
async fn roll_api_key(State(st): St, axum::Extension(who): Who, axum::Extension(from): Caller, bytes: Bytes) -> ApiResult {
    writable(&st)?;
    let b: ApiKeyBody = body(&bytes)?;
    let key = hashing(&st, move |accounts| accounts.roll_api_key(&who, &b.password, b.remove, &from)).await?;
    push_auth_critical(&st).await;
    ok(json!({ "api_key": key }))
}

// --------------------------------------------------------------- zones ----

fn zone_json(z: &Zone) -> Value {
    json!({
        "id": z.id, "name": z.name, "status": z.status, "paused": z.paused, "type": z.kind,
        "settings": z.settings,
        "name_servers": z.name_servers, "created_on": z.created_on, "modified_on": z.modified_on,
        "owner": { "id": z.owner, "type": "user" },
        "account": { "id": crate::tokens::account_id(), "name": crate::tokens::ACCOUNT_NAME },
        "plan": { "id": "free", "name": "Free Website", "price": 0, "currency": "USD", "is_subscribed": true, "can_subscribe": false },
        "permissions": [],
    })
}

async fn list_zones(State(st): St, axum::Extension(who): Who, Query(q): Params) -> ApiResult {
    let name = q.get("name").map(|n| n.trim_end_matches('.').to_ascii_lowercase());
    let status = q.get("status");
    let zones = st.store.list_zones();
    let items = zones
        .iter()
        .filter(|z| name.as_ref().is_none_or(|n| &z.name == n))
        .filter(|z| status.is_none_or(|s| &z.status == s))
        // a token sees the zones it names; nobody but administrators sees other users' zones
        .filter(|z| who.grant.as_ref().is_none_or(|g| g.sees_zone(&z.id)))
        .filter(|z| crate::tenancy::may_see(&who, z.owner.as_deref()))
        .map(zone_json)
        .collect();
    paginated(items, &q, 20)
}

#[derive(Deserialize)]
struct ZoneBody {
    name: Option<String>,
    #[serde(rename = "type")]
    kind: Option<String>,
    paused: Option<bool>,
    /// `{"owner": {"id": "<user id>"}}`, `{"owner": "<user id>"}`, or
    /// null (the administrators' only); administrators alone may send it.
    #[serde(default, deserialize_with = "present")]
    owner: Option<Value>,
}

/// A field that is there, even as null, is `Some` (null included).
fn present<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Value>, D::Error> {
    Value::deserialize(d).map(Some)
}

/// The zone belongs to whoever makes it (crate::tenancy); one made by
/// somebody who is not an administrator may not overlap another user's.
async fn create_zone(State(st): St, axum::Extension(who): Who, bytes: Bytes) -> ApiResult {
    let b: ZoneBody = body(&bytes)?;
    let name = b.name.ok_or_else(|| bad("'name' is required"))?;
    if b.owner.is_some() {
        return Err(bad("a new zone belongs to whoever makes it: an administrator gives it to somebody else with PATCH"));
    }
    let guarded = who.role != Role::Admin;
    let zone = st.store.create_zone_owned_async(&name, b.kind.as_deref().unwrap_or("full"), who.user_id.clone(), guarded).await?;
    ok(zone_json(&zone))
}

async fn get_zone(State(st): St, Path(zone_id): Path<String>) -> ApiResult {
    ok(zone_json(&st.store.get_zone(&zone_id)?))
}

/// The user id a PATCH gives a zone to: none for null or "".
fn owner_of(v: &Value, users: &[Value]) -> Result<Option<String>, ApiError> {
    let id = match v {
        Value::Null => return Ok(None),
        Value::String(s) => s.as_str(),
        Value::Object(o) => match o.get("id") {
            Some(Value::Null) => return Ok(None),
            Some(Value::String(s)) => s.as_str(),
            _ => return Err(bad("'owner' must be a user id, {\"id\": \"<user id>\"} or null")),
        },
        _ => return Err(bad("'owner' must be a user id, {\"id\": \"<user id>\"} or null")),
    };
    if id.is_empty() {
        return Ok(None);
    }
    if !users.iter().any(|u| u["id"] == id) {
        return Err(bad(format!("no user with the id '{id}'")));
    }
    Ok(Some(id.to_string()))
}

async fn patch_zone(State(st): St, axum::Extension(who): Who, Path(zone_id): Path<String>, bytes: Bytes) -> ApiResult {
    let b: ZoneBody = body(&bytes)?;
    // checked before anything changes, so a refused owner changes nothing else either
    let owner = match &b.owner {
        Some(_) if who.role != Role::Admin => {
            return Err(ApiError(StatusCode::FORBIDDEN, 2010, "only administrators change who a zone belongs to".into()));
        }
        Some(v) => Some(owner_of(v, &st.accounts.users())?),
        None => None,
    };
    st.store.get_zone(&zone_id)?;
    if let Some(owner) = owner {
        st.store.set_zone_owner_async(&zone_id, owner).await?;
    }
    if let Some(kind) = &b.kind {
        st.store.set_zone_kind_async(&zone_id, kind).await?;
    }
    let zone = match b.paused {
        Some(p) => st.store.set_zone_paused_async(&zone_id, p).await?,
        None => st.store.get_zone(&zone_id)?,
    };
    ok(zone_json(&zone))
}

async fn delete_zone(State(st): St, Path(zone_id): Path<String>) -> ApiResult {
    st.store.delete_zone_async(&zone_id).await?;
    ok(json!({ "id": zone_id }))
}

// ------------------------------------------------------------- records ----

fn record_json(z: &Zone, r: &Record) -> Value {
    let mut v = json!({
        "id": r.id, "zone_id": r.zone_id, "zone_name": z.name, "name": r.name, "type": r.rtype,
        "content": r.content, "ttl": r.ttl, "proxied": r.proxied, "proxiable": proxiable(&r.rtype),
        "comment": r.comment, "origin": r.origin, "created_on": r.created_on, "modified_on": r.modified_on,
        "tags": [], "settings": {}, "locked": false,
        "meta": { "auto_added": false, "managed_by_apps": false, "managed_by_argo_tunnel": false },
    });
    if let Some(p) = r.priority {
        v["priority"] = json!(p);
    }
    v
}

#[derive(Deserialize)]
struct RecordBody {
    #[serde(rename = "type")]
    rtype: Option<String>,
    name: Option<String>,
    content: Option<String>,
    ttl: Option<u32>,
    priority: Option<u16>,
    proxied: Option<bool>,
    comment: Option<String>,
    /// Origin options of a proxied record; an empty object removes them.
    origin: Option<RecordOrigin>,
    /// Cloudflare's structured content (SRV, CAA), used when there is no `content`.
    data: Option<Value>,
}

/// Cloudflare's `data` for SRV and CAA records as content (and priority).
fn content_of_data(rtype: &str, data: &Value) -> Result<(String, Option<u16>), ApiError> {
    let num = |k: &str| data[k].as_u64().ok_or_else(|| bad(format!("data.{k} must be a number")));
    let text = |k: &str| data[k].as_str().map(str::to_string).ok_or_else(|| bad(format!("data.{k} must be text")));
    match rtype.to_ascii_uppercase().as_str() {
        "SRV" => {
            let priority = u16::try_from(num("priority")?).map_err(|_| bad("data.priority is too large"))?;
            Ok((format!("{} {} {}", num("weight")?, num("port")?, text("target")?), Some(priority)))
        }
        "CAA" => Ok((format!("{} {} \"{}\"", num("flags")?, text("tag")?, text("value")?.replace('"', "")), None)),
        other => Err(bad(format!("'data' is for SRV and CAA records here, not {other}: use 'content'"))),
    }
}

impl RecordBody {
    /// Build a full record, taking missing fields from `base` (PATCH) or
    /// requiring them (POST/PUT).
    fn into_input(mut self, base: Option<&Record>) -> Result<RecordInput, ApiError> {
        let need = |v: Option<String>, old: Option<&String>, field: &str| {
            v.or_else(|| old.cloned()).ok_or_else(|| bad(format!("'{field}' is required")))
        };
        if let (None, Some(data)) = (&self.content, &self.data) {
            let rtype = self.rtype.clone().or_else(|| base.map(|b| b.rtype.clone())).unwrap_or_default();
            let (content, priority) = content_of_data(&rtype, data)?;
            self.content = Some(content);
            self.priority = self.priority.or(priority);
        }
        Ok(RecordInput {
            rtype: need(self.rtype, base.map(|b| &b.rtype), "type")?,
            name: need(self.name, base.map(|b| &b.name), "name")?,
            content: need(self.content, base.map(|b| &b.content), "content")?,
            ttl: self.ttl.or(base.map(|b| b.ttl)).unwrap_or(1),
            priority: self.priority.or(base.and_then(|b| b.priority)),
            proxied: self.proxied.or(base.map(|b| b.proxied)).unwrap_or(false),
            comment: self.comment.or(base.and_then(|b| b.comment.clone())),
            origin: self.origin.or(base.and_then(|b| b.origin.clone())),
        })
    }
}

type RecordTest = Box<dyn Fn(&Record) -> bool>;

/// Cloudflare's record filters: `type`, `proxied`, `search`, and for name,
/// content and comment `x`, `x.exact`, `x.contains`, `x.startswith`,
/// `x.endswith` (comment also `.present` / `.absent`); `match=any|all`.
fn record_tests(q: &HashMap<String, String>) -> Result<Vec<RecordTest>, ApiError> {
    let mut tests: Vec<RecordTest> = Vec::new();
    let fields: [(&str, fn(&Record) -> String); 3] = [
        ("name", |r| r.name.clone()),
        ("content", |r| r.content.clone()),
        ("comment", |r| r.comment.clone().unwrap_or_default()),
    ];
    for (field, get) in fields {
        for (key, raw) in q {
            let Some(rest) = key.strip_prefix(field) else { continue };
            let op = match rest {
                "" => "exact",
                _ => match rest.strip_prefix('.') {
                    Some(op) => op,
                    None => continue,
                },
            };
            // content compares as given; names and comments regardless of case
            let fold = |v: &str| if field == "content" { v.to_string() } else { v.to_ascii_lowercase() };
            let want = if field == "name" { fold(raw.trim_end_matches('.')) } else { fold(raw) };
            let test: RecordTest = match op {
                "exact" => Box::new(move |r| fold_of(field, &get(r)) == want),
                "contains" => Box::new(move |r| fold_of(field, &get(r)).contains(&want)),
                "startswith" => Box::new(move |r| fold_of(field, &get(r)).starts_with(&want)),
                "endswith" => Box::new(move |r| fold_of(field, &get(r)).ends_with(&want)),
                "present" => Box::new(move |r| !get(r).is_empty()),
                "absent" => Box::new(move |r| get(r).is_empty()),
                _ => return Err(bad(format!("unknown filter '{key}'"))),
            };
            tests.push(test);
        }
    }
    if let Some(t) = q.get("type") {
        let t = t.to_ascii_uppercase();
        tests.push(Box::new(move |r| r.rtype == t));
    }
    if let Some(p) = q.get("proxied") {
        let p = p == "true";
        tests.push(Box::new(move |r| r.proxied == p));
    }
    if let Some(s) = q.get("search").map(|s| s.to_ascii_lowercase()).filter(|s| !s.is_empty()) {
        tests.push(Box::new(move |r| {
            r.name.contains(&s) || r.content.to_ascii_lowercase().contains(&s) || r.comment.as_deref().is_some_and(|c| c.to_ascii_lowercase().contains(&s))
        }));
    }
    Ok(tests)
}

fn fold_of(field: &str, v: &str) -> String {
    if field == "content" {
        v.to_string()
    } else {
        v.to_ascii_lowercase()
    }
}

async fn list_records(State(st): St, Path(zone_id): Path<String>, Query(q): Params) -> ApiResult {
    let (zone, mut records) = st.store.list_records(&zone_id)?;
    let tests = record_tests(&q)?;
    let any = q.get("match").is_some_and(|m| m == "any");
    records.retain(|r| tests.is_empty() || if any { tests.iter().any(|t| t(r)) } else { tests.iter().all(|t| t(r)) });
    match q.get("order").map(String::as_str) {
        Some("type") => records.sort_by(|a, b| a.rtype.cmp(&b.rtype).then(a.name.cmp(&b.name))),
        Some("name") => records.sort_by(|a, b| a.name.cmp(&b.name).then(a.rtype.cmp(&b.rtype))),
        Some("content") => records.sort_by(|a, b| a.content.cmp(&b.content)),
        Some("ttl") => records.sort_by_key(|r| r.ttl),
        Some("proxied") => records.sort_by_key(|r| r.proxied),
        _ => {}
    }
    if q.get("direction").is_some_and(|d| d == "desc") {
        records.reverse();
    }
    let items = records.iter().map(|r| record_json(&zone, r)).collect();
    paginated(items, &q, 100)
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct BatchBody {
    deletes: Vec<Value>,
    patches: Vec<Value>,
    puts: Vec<Value>,
    posts: Vec<Value>,
}

/// `POST /dns_records/batch`: deletes, then patches, puts and posts, in
/// that order. Everything is checked first; should a change still fail
/// half way, the ones before it stay done (the error says where it stopped).
async fn batch_records(State(st): St, Path(zone_id): Path<String>, bytes: Bytes) -> ApiResult {
    let b: BatchBody = body(&bytes)?;
    if b.deletes.len() + b.patches.len() + b.puts.len() + b.posts.len() > 1000 {
        return Err(bad("at most 1000 changes in one batch"));
    }
    let id_of = |v: &Value, at: &str| v["id"].as_str().map(str::to_string).ok_or_else(|| bad(format!("{at}: 'id' is required")));
    let mut parsed_patches = Vec::new();
    for (i, v) in b.patches.iter().enumerate() {
        let id = id_of(v, &format!("patches[{i}]"))?;
        let rb: RecordBody = serde_json::from_value(v.clone()).map_err(|e| bad(format!("patches[{i}]: {e}")))?;
        parsed_patches.push((id, rb));
    }
    let mut parsed_puts = Vec::new();
    for (i, v) in b.puts.iter().enumerate() {
        let id = id_of(v, &format!("puts[{i}]"))?;
        let rb: RecordBody = serde_json::from_value(v.clone()).map_err(|e| bad(format!("puts[{i}]: {e}")))?;
        parsed_puts.push((id, rb.into_input(None).map_err(|e| bad(format!("puts[{i}]: {}", e.2)))?));
    }
    let mut parsed_posts = Vec::new();
    for (i, v) in b.posts.iter().enumerate() {
        let rb: RecordBody = serde_json::from_value(v.clone()).map_err(|e| bad(format!("posts[{i}]: {e}")))?;
        parsed_posts.push(rb.into_input(None).map_err(|e| bad(format!("posts[{i}]: {}", e.2)))?);
    }
    let mut deletes = Vec::new();
    for (i, v) in b.deletes.iter().enumerate() {
        let id = id_of(v, &format!("deletes[{i}]"))?;
        deletes.push(st.store.get_record(&zone_id, &id).map_err(|e| bad(format!("deletes[{i}]: {}", ApiError::from(e).2)))?);
    }
    let changed = parsed_patches.iter().map(|(id, _)| ("patches", id)).chain(parsed_puts.iter().map(|(id, _)| ("puts", id)));
    for (what, id) in changed {
        st.store.get_record(&zone_id, id).map_err(|e| bad(format!("{what}: {id}: {}", ApiError::from(e).2)))?;
    }
    let stopped = |what: &str, i: usize, e: StoreError| {
        let e = ApiError::from(e);
        ApiError(e.0, e.1, format!("{what}[{i}]: {} (the changes before it were made)", e.2))
    };
    let mut out = json!({ "deletes": [], "patches": [], "puts": [], "posts": [] });
    for (i, (zone, rec)) in deletes.into_iter().enumerate() {
        st.store.delete_record_async(&zone_id, &rec.id).await.map_err(|e| stopped("deletes", i, e))?;
        out["deletes"].as_array_mut().unwrap().push(record_json(&zone, &rec));
    }
    for (i, (id, rb)) in parsed_patches.into_iter().enumerate() {
        let (_, existing) = st.store.get_record(&zone_id, &id).map_err(|e| stopped("patches", i, e))?;
        let input = rb.into_input(Some(&existing)).map_err(|e| ApiError(e.0, e.1, format!("patches[{i}]: {}", e.2)))?;
        let (zone, rec) = st.store.update_record_async(&zone_id, &id, input).await.map_err(|e| stopped("patches", i, e))?;
        out["patches"].as_array_mut().unwrap().push(record_json(&zone, &rec));
    }
    for (i, (id, input)) in parsed_puts.into_iter().enumerate() {
        let (zone, rec) = st.store.update_record_async(&zone_id, &id, input).await.map_err(|e| stopped("puts", i, e))?;
        out["puts"].as_array_mut().unwrap().push(record_json(&zone, &rec));
    }
    for (i, input) in parsed_posts.into_iter().enumerate() {
        let (zone, rec) = st.store.create_record_async(&zone_id, input).await.map_err(|e| stopped("posts", i, e))?;
        out["posts"].as_array_mut().unwrap().push(record_json(&zone, &rec));
    }
    ok(out)
}

/// A name as it goes in a zone file.
fn dotted(name: &str) -> String {
    if name.is_empty() {
        ".".into()
    } else {
        format!("{}.", name.trim_end_matches('.'))
    }
}

/// `GET /dns_records/export`: the zone as a BIND file (Cloudflare's
/// `cf_tags=cf-proxied:true` marks the proxied ones).
async fn export_records(State(st): St, Path(zone_id): Path<String>) -> Result<Response, ApiError> {
    let (zone, records) = st.store.list_records(&zone_id)?;
    let mut out = format!(";;\n;; Domain:     {}.\n;; Exported:   {}\n;;\n$ORIGIN {}.\n", zone.name, crate::store::now(), zone.name);
    for r in &records {
        let ttl = if r.ttl == 1 { 300 } else { r.ttl };
        let content = match r.rtype.as_str() {
            "CNAME" | "NS" | "PTR" => dotted(&r.content),
            "MX" => format!("{} {}", r.priority.unwrap_or(10), dotted(&r.content)),
            "SRV" => {
                let f: Vec<&str> = r.content.split_whitespace().collect();
                match (f.len(), r.priority) {
                    (3, Some(p)) => format!("{p} {} {} {}", f[0], f[1], dotted(f[2])),
                    (4, _) => format!("{} {} {} {}", f[0], f[1], f[2], dotted(f[3])),
                    _ => r.content.clone(),
                }
            }
            "TXT" if !r.content.starts_with('"') => format!("\"{}\"", r.content.replace('\\', "\\\\").replace('"', "\\\"")),
            _ => r.content.clone(),
        };
        let mut tags = Vec::new();
        if r.proxied {
            tags.push("cf_tags=cf-proxied:true".to_string());
        }
        if let Some(c) = r.comment.as_deref().filter(|c| !c.is_empty()) {
            tags.push(c.replace('\n', " "));
        }
        let note = if tags.is_empty() { String::new() } else { format!(" ; {}", tags.join(" ")) };
        out.push_str(&format!("{}\t{ttl}\tIN\t{}\t{content}{note}\n", dotted(&r.name), r.rtype));
    }
    Ok(([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], out).into_response())
}

/// Words of a zone file line, quotes kept together; what follows `;` is the note.
fn zone_words(line: &str) -> (Vec<String>, String) {
    let (mut words, mut cur, mut quoted, mut escaped) = (Vec::new(), String::new(), false, false);
    for (i, c) in line.char_indices() {
        if escaped {
            cur.push(c);
            escaped = false;
            continue;
        }
        match c {
            '\\' if quoted => {
                cur.push(c);
                escaped = true;
            }
            '"' => {
                cur.push(c);
                quoted = !quoted;
            }
            ';' if !quoted => {
                if !cur.is_empty() {
                    words.push(std::mem::take(&mut cur));
                }
                return (words, line[i + 1..].trim().to_string());
            }
            c if c.is_whitespace() && !quoted => {
                if !cur.is_empty() {
                    words.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        words.push(cur);
    }
    (words, String::new())
}

/// A zone file line without its note and without parentheses outside
/// quotes; the note; whether a parenthesis is still open.
fn without_parens(line: &str) -> (String, String, bool) {
    let (mut out, mut depth, mut quoted, mut escaped) = (String::new(), 0i32, false, false);
    for (i, c) in line.char_indices() {
        if escaped {
            out.push(c);
            escaped = false;
            continue;
        }
        match c {
            '\\' if quoted => {
                out.push(c);
                escaped = true;
            }
            '"' => {
                out.push(c);
                quoted = !quoted;
            }
            ';' if !quoted => return (out, line[i + 1..].trim().to_string(), depth > 0),
            '(' if !quoted => {
                depth += 1;
                out.push(' ');
            }
            ')' if !quoted => {
                depth -= 1;
                out.push(' ');
            }
            c => out.push(c),
        }
    }
    (out, String::new(), depth > 0)
}

/// Records of a BIND zone file (SOA and the apex NS are the platform's and left out).
fn parse_zone_file(text: &str, zone: &str, proxied_default: bool) -> (Vec<RecordInput>, Vec<String>) {
    let (mut out, mut skipped) = (Vec::new(), Vec::new());
    let mut origin = zone.to_string();
    let mut default_ttl = 1u32;
    let mut last_name = zone.to_string();
    let mut pending = String::new();
    let fqdn = |n: &str, origin: &str| -> String {
        if n == "@" {
            origin.to_string()
        } else if let Some(abs) = n.strip_suffix('.') {
            abs.to_ascii_lowercase()
        } else {
            format!("{}.{origin}", n.to_ascii_lowercase())
        }
    };
    for (no, raw) in text.lines().enumerate() {
        // records spread over lines with ( ... )
        let line = if pending.is_empty() { raw.to_string() } else { format!("{pending} {raw}") };
        let (code, note, open) = without_parens(&line);
        if open {
            pending = code;
            continue;
        }
        pending.clear();
        let line = if note.is_empty() { code } else { format!("{code};{note}") };
        let starts_blank = line.starts_with([' ', '\t']);
        let (words, note) = zone_words(&line);
        if words.is_empty() {
            continue;
        }
        match words[0].to_ascii_uppercase().as_str() {
            "$ORIGIN" => {
                if let Some(o) = words.get(1) {
                    origin = o.trim_end_matches('.').to_ascii_lowercase();
                }
                continue;
            }
            "$TTL" => {
                default_ttl = words.get(1).and_then(|t| t.parse().ok()).unwrap_or(default_ttl);
                continue;
            }
            w if w.starts_with('$') => {
                skipped.push(format!("line {}: {w} is not supported", no + 1));
                continue;
            }
            _ => {}
        }
        let mut it = words.iter();
        let name = if starts_blank { last_name.clone() } else { fqdn(it.next().map(String::as_str).unwrap_or("@"), &origin) };
        last_name = name.clone();
        let mut ttl = default_ttl;
        let mut rtype = String::new();
        for w in it.by_ref() {
            if let Ok(t) = w.parse::<u32>() {
                ttl = t;
                continue;
            }
            let up = w.to_ascii_uppercase();
            if matches!(up.as_str(), "IN" | "CH" | "HS") {
                continue;
            }
            rtype = up;
            break;
        }
        let rest: Vec<String> = it.cloned().collect();
        if rtype.is_empty() || rest.is_empty() {
            skipped.push(format!("line {}: not a record", no + 1));
            continue;
        }
        if rtype == "SOA" || (rtype == "NS" && name == zone) {
            continue;
        }
        if !crate::dns::wire::SUPPORTED_TYPES.contains(&rtype.as_str()) {
            skipped.push(format!("line {}: {rtype} records are not supported", no + 1));
            continue;
        }
        let target = |n: &str| if n == "." { ".".to_string() } else { fqdn(n, &origin) };
        let (content, priority) = match rtype.as_str() {
            "CNAME" | "NS" | "PTR" => (target(&rest[0]), None),
            "MX" if rest.len() >= 2 => (target(&rest[1]), rest[0].parse().ok()),
            "SRV" if rest.len() >= 4 => (format!("{} {} {}", rest[1], rest[2], target(&rest[3])), rest[0].parse().ok()),
            _ => (rest.join(" "), None),
        };
        let proxied = crate::store::proxiable(&rtype) && !note.contains("cf-proxied:false") && (proxied_default || note.contains("cf-proxied:true"));
        let comment = note
            .split_whitespace()
            .filter(|w| !w.starts_with("cf_tags="))
            .collect::<Vec<_>>()
            .join(" ");
        out.push(RecordInput {
            rtype,
            name,
            content,
            ttl: if ttl <= 1 { 1 } else { ttl.clamp(30, 86400) },
            priority,
            proxied,
            comment: (!comment.is_empty()).then_some(comment),
            origin: None,
        });
    }
    (out, skipped)
}

/// The file of a `multipart/form-data` upload (field `file`), and the
/// other fields; any other body is the file itself.
fn upload(content_type: &str, bytes: &[u8]) -> (String, HashMap<String, String>) {
    let mut fields = HashMap::new();
    let boundary = content_type
        .split(';')
        .filter_map(|p| p.trim().strip_prefix("boundary="))
        .next()
        .map(|b| b.trim_matches('"').to_string());
    let (Some(boundary), true) = (boundary, content_type.starts_with("multipart/form-data")) else {
        return (String::from_utf8_lossy(bytes).into_owned(), fields);
    };
    let text = String::from_utf8_lossy(bytes);
    let mut file = String::new();
    for part in text.split(&format!("--{boundary}")) {
        let Some((head, body)) = part.split_once("\r\n\r\n").or_else(|| part.split_once("\n\n")) else { continue };
        let body = body.strip_suffix("\r\n").or_else(|| body.strip_suffix('\n')).unwrap_or(body);
        let name = head
            .split(';')
            .filter_map(|p| p.trim().strip_prefix("name="))
            .next()
            .map(|n| n.split(['\r', '\n']).next().unwrap_or(n).trim_matches('"').to_string())
            .unwrap_or_default();
        if name == "file" {
            file = body.to_string();
        } else if !name.is_empty() {
            fields.insert(name, body.trim().to_string());
        }
    }
    (file, fields)
}

/// `POST /dns_records/import`: a BIND file (multipart field `file`, as
/// Cloudflare takes it, or the body itself); `proxied=true` proxies what can be.
async fn import_records(State(st): St, Path(zone_id): Path<String>, Query(q): Params, headers: header::HeaderMap, bytes: Bytes) -> ApiResult {
    let zone = st.store.get_zone(&zone_id)?;
    let content_type = headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or_default();
    let (file, fields) = upload(content_type, &bytes);
    let proxied = fields.get("proxied").or(q.get("proxied")).is_some_and(|p| p == "true");
    let (records, mut skipped) = parse_zone_file(&file, &zone.name, proxied);
    let total = records.len() + skipped.len();
    let mut added = 0;
    for r in records {
        let line = format!("{} {} {}", r.name, r.rtype, r.content);
        match st.store.create_record_async(&zone_id, r).await {
            Ok(_) => added += 1,
            Err(e) => skipped.push(format!("{line}: {}", ApiError::from(e).2)),
        }
    }
    let mut v = ok(json!({ "recs_added": added, "total_records_parsed": total }))?;
    v.0["messages"] = skipped.iter().map(|m| json!({ "code": 0, "message": m })).collect();
    Ok(v)
}

async fn create_record(State(st): St, Path(zone_id): Path<String>, bytes: Bytes) -> ApiResult {
    let input = body::<RecordBody>(&bytes)?.into_input(None)?;
    let (zone, rec) = st.store.create_record_async(&zone_id, input).await?;
    ok(record_json(&zone, &rec))
}

async fn get_record(State(st): St, Path((zone_id, record_id)): Path<(String, String)>) -> ApiResult {
    let (zone, rec) = st.store.get_record(&zone_id, &record_id)?;
    ok(record_json(&zone, &rec))
}

async fn put_record(State(st): St, Path((zone_id, record_id)): Path<(String, String)>, bytes: Bytes) -> ApiResult {
    let input = body::<RecordBody>(&bytes)?.into_input(None)?;
    let (zone, rec) = st.store.update_record_async(&zone_id, &record_id, input).await?;
    ok(record_json(&zone, &rec))
}

async fn patch_record(State(st): St, Path((zone_id, record_id)): Path<(String, String)>, bytes: Bytes) -> ApiResult {
    let (_, existing) = st.store.get_record(&zone_id, &record_id)?;
    let input = body::<RecordBody>(&bytes)?.into_input(Some(&existing))?;
    let (zone, rec) = st.store.update_record_async(&zone_id, &record_id, input).await?;
    ok(record_json(&zone, &rec))
}

async fn delete_record(State(st): St, Path((zone_id, record_id)): Path<(String, String)>) -> ApiResult {
    st.store.delete_record_async(&zone_id, &record_id).await?;
    ok(json!({ "id": record_id }))
}

#[derive(Deserialize)]
struct DnssecBody {
    status: String,
}

async fn get_dnssec(State(st): St, Path(zone_id): Path<String>) -> ApiResult {
    ok(st.store.get_dnssec(&zone_id)?)
}

async fn patch_dnssec(State(st): St, Path(zone_id): Path<String>, bytes: Bytes) -> ApiResult {
    let b: DnssecBody = body(&bytes)?;
    let enable = match b.status.to_ascii_lowercase().as_str() {
        "active" | "enabled" | "on" => true,
        "disabled" | "off" => false,
        other => return Err(bad(format!("status must be 'active' or 'disabled', not '{other}'"))),
    };
    ok(st.store.set_dnssec_async(&zone_id, enable).await?)
}

// ------------------------------------------- generic zone-scoped CRUD ----

/// List/create/read/update/delete routes for one [`Item`] type.
fn crud<T: Item>(path: &str) -> Router<Arc<ApiState>> {
    Router::new()
        .route(path, get(list_items::<T>).post(create_item::<T>))
        .route(
            &format!("{path}/{{item_id}}"),
            get(get_item::<T>).put(put_item::<T>).patch(patch_item::<T>).delete(delete_item::<T>),
        )
}

async fn list_items<T: Item>(State(st): St, Path(zone_id): Path<String>, Query(q): Params) -> ApiResult {
    let items = st.store.items::<T>(&zone_id)?;
    paginated(items.iter().map(Item::public).collect(), &q, 100)
}

async fn create_item<T: Item>(State(st): St, Path(zone_id): Path<String>, bytes: Bytes) -> ApiResult {
    ok(st.store.save_item_async::<T>(&zone_id, None, body(&bytes)?, true).await?.public())
}

async fn get_item<T: Item>(State(st): St, Path((zone_id, id)): Path<(String, String)>) -> ApiResult {
    ok(st.store.item::<T>(&zone_id, &id)?.public())
}

async fn put_item<T: Item>(State(st): St, Path((zone_id, id)): Path<(String, String)>, bytes: Bytes) -> ApiResult {
    ok(st.store.save_item_async::<T>(&zone_id, Some(&id), body(&bytes)?, true).await?.public())
}

async fn patch_item<T: Item>(State(st): St, Path((zone_id, id)): Path<(String, String)>, bytes: Bytes) -> ApiResult {
    ok(st.store.save_item_async::<T>(&zone_id, Some(&id), body(&bytes)?, false).await?.public())
}

async fn delete_item<T: Item>(State(st): St, Path((zone_id, id)): Path<(String, String)>) -> ApiResult {
    st.store.delete_item_async::<T>(&zone_id, &id).await?;
    ok(json!({ "id": id }))
}

// ---------------------------------------------------- custom hostnames ----

// The generic item routes, except that every answer carries the DCV
// delegation its owner has to add (crate::custom_hostnames::view), a zone
// whose DNS this fleet could not answer gets none, and there is no PUT (a
// replace could only set what a PATCH sets).
fn custom_hostname_routes() -> Router<Arc<ApiState>> {
    let path = "/zones/{zone_id}/custom_hostnames";
    Router::new()
        .route(path, get(list_custom_hostnames).post(create_custom_hostname))
        .route(&format!("{path}/{{item_id}}"), get(get_custom_hostname).patch(patch_custom_hostname).delete(delete_item::<crate::custom_hostnames::CustomHostname>))
}

async fn list_custom_hostnames(State(st): St, Path(zone_id): Path<String>, Query(q): Params) -> ApiResult {
    let zone = st.store.get_zone(&zone_id)?;
    let items = st.store.items::<crate::custom_hostnames::CustomHostname>(&zone_id)?;
    paginated(items.iter().map(|h| crate::custom_hostnames::view(h, &zone, st.cname_base.as_deref())).collect(), &q, 100)
}

async fn create_custom_hostname(State(st): St, Path(zone_id): Path<String>, bytes: Bytes) -> ApiResult {
    let zone = st.store.get_zone(&zone_id)?;
    crate::custom_hostnames::may_create(&zone, st.cname_base.as_deref()).map_err(bad)?;
    let h = st.store.save_item_async::<crate::custom_hostnames::CustomHostname>(&zone_id, None, body(&bytes)?, true).await?;
    ok(crate::custom_hostnames::view(&h, &zone, st.cname_base.as_deref()))
}

async fn get_custom_hostname(State(st): St, Path((zone_id, id)): Path<(String, String)>) -> ApiResult {
    let zone = st.store.get_zone(&zone_id)?;
    ok(crate::custom_hostnames::view(&st.store.item(&zone_id, &id)?, &zone, st.cname_base.as_deref()))
}

async fn patch_custom_hostname(State(st): St, Path((zone_id, id)): Path<(String, String)>, bytes: Bytes) -> ApiResult {
    let zone = st.store.get_zone(&zone_id)?;
    let h = st.store.save_item_async::<crate::custom_hostnames::CustomHostname>(&zone_id, Some(&id), body(&bytes)?, false).await?;
    ok(crate::custom_hostnames::view(&h, &zone, st.cname_base.as_deref()))
}

// ------------------------------------------------------------ rulesets ----

/// Cloudflare's Rulesets API over the existing rule types (crate::rulesets).
async fn list_rulesets(State(st): St, Path(zone_id): Path<String>) -> ApiResult {
    ok(crate::rulesets::list(&st.store, &zone_id)?)
}

async fn create_ruleset(State(st): St, Extension(who): Who, Path(zone_id): Path<String>, bytes: Bytes) -> ApiResult {
    let b: Value = body(&bytes)?;
    let phase = crate::rulesets::phase_in(&b)?;
    // the path (no phase in it) only asks a token for the firewall permission;
    // what is created needs the phase's own as well
    if who.via == Via::Token {
        let path = format!("/zones/{zone_id}/rulesets/phases/{phase}/entrypoint");
        if !who.grant.as_ref().is_some_and(|g| g.allows("PUT", &path, who.user_id.as_deref().unwrap_or_default())) {
            return Err(ApiError(StatusCode::FORBIDDEN, 9109, "Unauthorized to access requested resource".into()));
        }
    }
    ok(crate::rulesets::create(&st.store, &zone_id, b).await?)
}

async fn get_entrypoint(State(st): St, Path((zone_id, phase)): Path<(String, String)>) -> ApiResult {
    ok(crate::rulesets::entrypoint(&st.store, &zone_id, crate::rulesets::phase_named(&phase)?)?)
}

async fn put_entrypoint(State(st): St, Path((zone_id, phase)): Path<(String, String)>, bytes: Bytes) -> ApiResult {
    let phase = crate::rulesets::phase_named(&phase)?;
    ok(crate::rulesets::put_entrypoint(&st.store, &zone_id, phase, body(&bytes)?).await?)
}

async fn get_ruleset(State(st): St, Path((zone_id, id)): Path<(String, String)>) -> ApiResult {
    ok(crate::rulesets::get(&st.store, &zone_id, &id)?)
}

async fn put_ruleset(State(st): St, Path((zone_id, id)): Path<(String, String)>, bytes: Bytes) -> ApiResult {
    ok(crate::rulesets::put_ruleset(&st.store, &zone_id, &id, body(&bytes)?).await?)
}

async fn delete_ruleset(State(st): St, Path((zone_id, id)): Path<(String, String)>) -> ApiResult {
    crate::rulesets::delete_ruleset(&st.store, &zone_id, &id).await?;
    ok(Value::Null)
}

async fn add_ruleset_rule(State(st): St, Path((zone_id, id)): Path<(String, String)>, bytes: Bytes) -> ApiResult {
    ok(crate::rulesets::add_rule(&st.store, &zone_id, &id, body(&bytes)?).await?)
}

async fn patch_ruleset_rule(State(st): St, Path((zone_id, id, rule_id)): Path<(String, String, String)>, bytes: Bytes) -> ApiResult {
    ok(crate::rulesets::update_rule(&st.store, &zone_id, &id, &rule_id, body(&bytes)?).await?)
}

async fn delete_ruleset_rule(State(st): St, Path((zone_id, id, rule_id)): Path<(String, String, String)>) -> ApiResult {
    ok(crate::rulesets::delete_rule(&st.store, &zone_id, &id, &rule_id).await?)
}

// ------------------------------------------------------------ IP lists ----

/// Address lists for `ip.src in $name` (crate::lists), at Cloudflare's
/// account paths too (see `account_path`).
async fn list_ip_lists(State(st): St) -> ApiResult {
    ok(crate::lists::list(&st.store))
}

async fn create_ip_list(State(st): St, bytes: Bytes) -> ApiResult {
    ok(crate::lists::create(&st.store, body(&bytes)?).await?)
}

async fn get_ip_list(State(st): St, Path(id): Path<String>) -> ApiResult {
    ok(crate::lists::get(&st.store, &id)?)
}

async fn update_ip_list(State(st): St, Path(id): Path<String>, bytes: Bytes) -> ApiResult {
    ok(crate::lists::update(&st.store, &id, body(&bytes)?).await?)
}

async fn delete_ip_list(State(st): St, Path(id): Path<String>) -> ApiResult {
    ok(crate::lists::delete(&st.store, &id).await?)
}

async fn list_ip_list_items(State(st): St, Path(id): Path<String>, Query(q): Params) -> ApiResult {
    ok(crate::lists::items(&st.store, &id, q.get("search").map(String::as_str))?)
}

async fn get_ip_list_item(State(st): St, Path((id, item_id)): Path<(String, String)>) -> ApiResult {
    ok(crate::lists::item(&st.store, &id, &item_id)?)
}

async fn append_ip_list_items(State(st): St, Path(id): Path<String>, bytes: Bytes) -> ApiResult {
    ok(crate::lists::append_items(&st.store, &id, body(&bytes)?).await?)
}

async fn replace_ip_list_items(State(st): St, Path(id): Path<String>, bytes: Bytes) -> ApiResult {
    ok(crate::lists::replace_items(&st.store, &id, body(&bytes)?).await?)
}

async fn delete_ip_list_items(State(st): St, Path(id): Path<String>, bytes: Bytes) -> ApiResult {
    ok(crate::lists::delete_items(&st.store, &id, body(&bytes)?).await?)
}

async fn ip_list_operation(Path(id): Path<String>) -> ApiResult {
    ok(crate::lists::operation(&id)?)
}

// ------------------------------------------------ managed certificates ----

/// A pack as the API shows it. `dns_delegation` lists the CNAME records with
/// which a zone hosted elsewhere lets this server answer its DNS challenges.
fn pack_json(st: &ApiState, pack: &CertificatePack) -> Value {
    let mut v = pack.public();
    if let Some(base) = &st.cname_base {
        let mut names: Vec<&str> = pack.hosts.iter().map(|h| h.trim_start_matches("*.")).collect();
        names.sort();
        names.dedup();
        let record = |h: &&str| json!({ "type": "CNAME", "name": format!("_acme-challenge.{h}"), "content": format!("_acme-challenge.{h}.{base}") });
        v["dns_delegation"] = Value::Array(names.iter().map(record).collect());
    }
    v
}

async fn list_packs(State(st): St, Path(zone_id): Path<String>, Query(q): Params) -> ApiResult {
    let packs = st.store.items::<CertificatePack>(&zone_id)?;
    paginated(packs.iter().map(|p| pack_json(&st, p)).collect(), &q, 100)
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct PackBody {
    hosts: Vec<String>,
    validation_method: String,
}

/// Order a certificate: it is requested from the CA right away and renewed
/// from then on. Without `hosts`, for the zone's apex and wildcard.
async fn create_pack(State(st): St, Path(zone_id): Path<String>, bytes: Bytes) -> ApiResult {
    let b: PackBody = if bytes.is_empty() { PackBody::default() } else { body(&bytes)? };
    let order = json!({ "hosts": b.hosts, "validation_method": b.validation_method });
    ok(pack_json(&st, &st.store.save_item_async::<CertificatePack>(&zone_id, None, order, true).await?))
}

async fn get_pack(State(st): St, Path((zone_id, id)): Path<(String, String)>) -> ApiResult {
    ok(pack_json(&st, &st.store.item::<CertificatePack>(&zone_id, &id)?))
}

/// Try again now instead of waiting out the pause after a failure.
async fn retry_pack(State(st): St, Path((zone_id, id)): Path<(String, String)>) -> ApiResult {
    st.store.item::<CertificatePack>(&zone_id, &id)?;
    let pack = st
        .store
        .update_pack_async(&id, |p| {
            (p.next_attempt, p.attempts) = (None, 0);
            if p.certificate.is_empty() {
                (p.status, p.error) = ("pending".into(), String::new());
            }
        })
        .await?;
    ok(pack_json(&st, &pack))
}

// ------------------------------------------------------------ settings ----

fn setting_json(z: &Zone, name: &str) -> Result<Value, ApiError> {
    let all = serde_json::to_value(&z.settings).unwrap_or_default();
    let value = all.get(name).cloned().ok_or_else(|| bad(format!("unknown setting '{name}'")))?;
    Ok(json!({ "id": name, "value": value, "modified_on": z.modified_on, "editable": true }))
}

async fn get_settings(State(st): St, Path(zone_id): Path<String>) -> ApiResult {
    let z = st.store.get_zone(&zone_id)?;
    let all = serde_json::to_value(&z.settings).unwrap_or_default();
    let names: Vec<String> = all.as_object().map(|o| o.keys().cloned().collect()).unwrap_or_default();
    ok(Value::Array(names.iter().filter_map(|n| setting_json(&z, n).ok()).collect()))
}

async fn get_setting(State(st): St, Path((zone_id, name)): Path<(String, String)>) -> ApiResult {
    ok(setting_json(&st.store.get_zone(&zone_id)?, &name)?)
}

async fn patch_setting(State(st): St, Path((zone_id, name)): Path<(String, String)>, bytes: Bytes) -> ApiResult {
    let mut b: Value = body(&bytes)?;
    let value = b.get_mut("value").map(Value::take).ok_or_else(|| bad("'value' is required"))?;
    let z = st.store.update_setting_async(&zone_id, &name, value).await?;
    ok(setting_json(&z, &name)?)
}

// ------------------------------------------------------------- e-mail ----

/// This node's side of mail routing: the listener, its names, where it
/// hands mail on, and what came through lately.
async fn email_status(State(st): St) -> ApiResult {
    let mut v = st.mail.as_ref().map(|m| m.status()).unwrap_or_else(|| {
        json!({ "listening": Value::Null, "hosts": [], "relay": Value::Null })
    });
    v["activity"] = Value::Array(st.mail.as_ref().map(|m| m.activity()).unwrap_or_default());
    ok(v)
}

/// A zone's mail routing: is it on, its rules, its DKIM key (never the
/// private part), and whether the DNS the world needs (MX at the zone, an
/// SPF that allows the exchangers, the DKIM key's TXT) is there; what is
/// missing comes back ready to paste.
async fn email_zone(State(st): St, Path(zone_id): Path<String>) -> ApiResult {
    let (z, records) = st.store.list_records(&zone_id)?;
    let rules = st.store.items::<EmailRule>(&zone_id)?;
    let apex = |rtype: &str| {
        records.iter().filter(|r| r.rtype == rtype && r.name == z.name).map(|r| r.content.clone()).collect::<Vec<_>>()
    };
    let mx = apex("MX");
    let spf: Vec<String> = apex("TXT").into_iter().filter(|t| t.starts_with("v=spf1")).collect();
    let mut needed = Vec::new();
    if mx.is_empty() {
        needed.push(json!({ "type": "MX", "name": z.name, "priority": 10,
            "content": st.mail.as_ref().and_then(|m| m.hosts.first().cloned()).unwrap_or_else(|| "mx.example".into()) }));
    }
    if spf.is_empty() {
        // the exchangers are the only machines that send as this zone
        needed.push(json!({ "type": "TXT", "name": z.name, "content": "v=spf1 mx -all" }));
    }
    let (dkim, dkim_needed) = crate::dkim::view(&z, &records);
    needed.extend(dkim_needed);
    let mut v = json!({
        "enabled": z.settings.email_routing,
        "rules": rules.iter().map(Item::public).collect::<Vec<_>>(),
        "mx": mx,
        "spf": spf,
        "needed_records": needed,
    });
    if let Some(o) = v.as_object_mut() {
        o.extend(dkim);
    }
    ok(v)
}

/// Change a zone's e-mail settings: for now its DKIM key
/// (`dkim_selector`, `dkim_private_key`; see crate::dkim::patch). Answers
/// what GET does.
async fn patch_email(State(st): St, Path(zone_id): Path<String>, bytes: Bytes) -> ApiResult {
    crate::dkim::patch(&st.store, &zone_id, &body::<Value>(&bytes)?).await?;
    email_zone(State(st), Path(zone_id)).await
}

// ----------------------------------------------------------- origin CA ----

/// A zone's private origin CA (crate::origin_ca): its certificate, never its key.
async fn get_origin_ca(State(st): St, Path(zone_id): Path<String>) -> ApiResult {
    ok(crate::origin_ca::view(&st.store.get_zone(&zone_id)?))
}

/// Make the zone's origin CA (409 if it has one).
async fn create_origin_ca(State(st): St, Path(zone_id): Path<String>) -> ApiResult {
    ok(crate::origin_ca::view(&crate::origin_ca::create(&st.store, &zone_id).await?))
}

async fn delete_origin_ca(State(st): St, Path(zone_id): Path<String>) -> ApiResult {
    crate::origin_ca::remove(&st.store, &zone_id).await?;
    ok(json!({ "id": zone_id }))
}

/// Sign a certificate for names of the zone; its key is in this answer only.
async fn sign_origin_ca(State(st): St, Path(zone_id): Path<String>, bytes: Bytes) -> ApiResult {
    let zone = st.store.get_zone(&zone_id)?;
    ok(crate::origin_ca::sign(&zone, &body(&bytes)?)?)
}

// ------------------------------------------------- cache and security ----

#[derive(Deserialize)]
struct PurgeBody {
    #[serde(default)]
    purge_everything: bool,
    #[serde(default)]
    files: Vec<String>,
    #[serde(default)]
    prefixes: Vec<String>,
    /// What the origin tagged with one of these in its `Cache-Tag` header.
    #[serde(default)]
    tags: Vec<String>,
    /// Everything of these host names (Cloudflare's `hosts`).
    #[serde(default)]
    hosts: Vec<String>,
}

async fn purge_cache(State(st): St, Path(zone_id): Path<String>, bytes: Bytes) -> ApiResult {
    st.store.get_zone(&zone_id)?;
    purge(&st, &zone_id, body(&bytes)?).await
}

/// Purge what the reserved `/cdn-cgi/fucf-warp` endpoint keeps in the edge
/// cache; `files` and `prefixes` name its objects by their keys.
async fn purge_warp_cache(State(st): St, bytes: Bytes) -> ApiResult {
    purge(&st, crate::edge::warp::CACHE_SCOPE, body(&bytes)?).await
}

/// Drop cached objects of one scope (a zone, or the edge's own) on this
/// node and, through the configuration, on every other one.
async fn purge(st: &ApiState, scope: &str, mut b: PurgeBody) -> ApiResult {
    // a host is the prefix that ends where its paths begin
    let hosts = std::mem::take(&mut b.hosts);
    b.prefixes.extend(hosts.iter().map(|h| h.trim().trim_end_matches('/').to_ascii_lowercase()).filter(|h| !h.is_empty()).map(|h| format!("{h}/")));
    b.tags = b.tags.iter().map(|t| t.trim().to_string()).filter(|t| !t.is_empty()).collect();
    if !b.purge_everything && b.files.is_empty() && b.prefixes.is_empty() && b.tags.is_empty() {
        return Err(bad("specify purge_everything, files, prefixes, hosts or tags"));
    }
    st.store.add_purge_async(scope, b.purge_everything, b.files.clone(), b.prefixes.clone(), b.tags.clone()).await?;
    let purged = if b.purge_everything {
        st.cache.purge_zone(scope)
    } else {
        st.cache.purge_urls(scope, &b.files, false) + st.cache.purge_urls(scope, &b.prefixes, true) + st.cache.purge_tags(scope, &b.tags)
    };
    ok(json!({ "id": scope, "purged": purged }))
}

async fn security_events(State(st): St, Path(zone_id): Path<String>, Query(q): Params) -> ApiResult {
    st.store.get_zone(&zone_id)?;
    let limit = q.get("limit").and_then(|v| v.parse().ok()).unwrap_or(100usize).min(5000);
    let mut events = st.waf.events(&zone_id, limit);
    let me = st.node();
    events.iter_mut().filter(|e| e.node.is_empty()).for_each(|e| e.node = me.clone());
    ok(serde_json::to_value(events).unwrap_or_default())
}

// ------------------------------------------------------------- workers ----

fn worker_json(w: &WorkerScript) -> Value {
    json!({
        "id": w.name,
        "size": w.script.len(),
        "kv_bindings": w.kv_bindings,
        "d1_bindings": w.d1_bindings,
        "crons": w.crons,
        "created_on": w.created_on,
        "modified_on": w.modified_on,
    })
}

async fn list_workers(State(st): St) -> ApiResult {
    ok(Value::Array(st.store.list_workers().iter().map(worker_json).collect()))
}

/// Upload a script: the request body is the JavaScript source.
async fn put_worker(State(st): St, Path(name): Path<String>, bytes: Bytes) -> ApiResult {
    let script = String::from_utf8(bytes.to_vec()).map_err(|_| bad("script must be UTF-8"))?;
    if script.trim().is_empty() {
        return Err(bad("script is empty"));
    }
    crate::workers::check_syntax(&script).map_err(bad)?;
    ok(worker_json(&st.store.put_worker_async(&name, Some(script), None).await?))
}

async fn get_worker(State(st): St, Extension(who): Extension<Principal>, Path(name): Path<String>) -> Result<Response, ApiError> {
    if who.role == Role::Viewer {
        return Err(ApiError(StatusCode::FORBIDDEN, 2010, "your role does not allow this".into()));
    }
    let w = st.store.get_worker(&name)?;
    Ok(([(header::CONTENT_TYPE, "application/javascript")], w.script).into_response())
}

async fn delete_worker(State(st): St, Path(name): Path<String>) -> ApiResult {
    st.store.delete_worker_async(&name).await?;
    ok(json!({ "id": name }))
}

async fn get_worker_settings(State(st): St, Extension(who): Extension<Principal>, Path(name): Path<String>) -> ApiResult {
    let w = st.store.get_worker(&name)?;
    let vars = if who.role == Role::Viewer {
        w.vars.keys().map(|k| (k.clone(), "***".to_string())).collect()
    } else {
        w.vars
    };
    ok(json!({
        "vars": vars,
        "kv_bindings": w.kv_bindings,
        "d1_bindings": w.d1_bindings,
        "crons": w.crons,
    }))
}

#[derive(Deserialize)]
struct WorkerSettings {
    #[serde(default)]
    vars: Option<std::collections::BTreeMap<String, String>>,
    #[serde(default)]
    kv_bindings: Option<std::collections::BTreeMap<String, String>>,
    #[serde(default)]
    d1_bindings: Option<std::collections::BTreeMap<String, String>>,
    #[serde(default)]
    crons: Option<Vec<String>>,
}

async fn patch_worker_settings(State(st): St, Path(name): Path<String>, bytes: Bytes) -> ApiResult {
    let b: WorkerSettings = body(&bytes)?;
    if let Some(crons) = &b.crons {
        for expr in crons {
            crate::workers::cron::CronExpr::parse(expr).map_err(bad)?;
        }
    }
    let w = st
        .store
        .patch_worker_bindings_async(&name, b.vars, b.kv_bindings, b.d1_bindings, b.crons)
        .await?;
    wake_push(&st);
    ok(json!({
        "vars": w.vars,
        "kv_bindings": w.kv_bindings,
        "d1_bindings": w.d1_bindings,
        "crons": w.crons,
    }))
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct TriggerScheduledBody {
    cron: Option<String>,
}

async fn trigger_worker_scheduled(State(st): St, Path(name): Path<String>, bytes: Bytes) -> ApiResult {
    let req: TriggerScheduledBody = if bytes.is_empty() {
        TriggerScheduledBody::default()
    } else {
        body(&bytes)?
    };
    let w = std::sync::Arc::new(st.store.get_worker(&name)?);
    let cron_expr = req
        .cron
        .or_else(|| w.crons.first().cloned())
        .unwrap_or_else(|| "* * * * *".into());
    crate::workers::cron::CronExpr::parse(&cron_expr).map_err(bad)?;
    let ms = crate::sync::clock::unix_ms();
    crate::workers::run_scheduled(st.edge.clone(), st.store.snapshot(), w, &cron_expr, ms)
        .await
        .map_err(bad)?;
    ok(json!({ "triggered": true, "cron": cron_expr, "scheduledTime": ms }))
}

// ------------------------------------------------------------------ kv ----

fn kv_store(st: &ApiState) -> Result<std::sync::Arc<crate::workers::kv::KvStore>, ApiError> {
    st.edge
        .kv
        .get()
        .cloned()
        .ok_or_else(|| ApiError(StatusCode::SERVICE_UNAVAILABLE, 5030, "KV store not initialized".into()))
}

fn d1_store(st: &ApiState) -> Result<std::sync::Arc<crate::workers::db::D1Store>, ApiError> {
    st.edge
        .d1
        .get()
        .cloned()
        .ok_or_else(|| ApiError(StatusCode::SERVICE_UNAVAILABLE, 5031, "D1 store not initialized".into()))
}

fn wake_push(st: &ApiState) {
    if let Some(s) = &st.sync {
        s.wake_push();
    }
}

async fn kv_list_namespaces(State(st): St) -> ApiResult {
    let kv = kv_store(&st)?;
    let list = tokio::task::spawn_blocking(move || kv.list_namespaces())
        .await
        .map_err(|e| bad(e.to_string()))?;
    ok(json!(list))
}

#[derive(Deserialize)]
struct KvNamespaceInput {
    title: String,
}

async fn kv_create_namespace(State(st): St, bytes: Bytes) -> ApiResult {
    if st.role.is_accelerate() {
        return Err(StoreError::ReadOnly.into());
    }
    let inp: KvNamespaceInput = body(&bytes)?;
    let kv = kv_store(&st)?;
    let ns = tokio::task::spawn_blocking(move || kv.create_namespace(&inp.title))
        .await
        .map_err(|e| bad(e.to_string()))?
        .map_err(bad)?;
    wake_push(&st);
    ok(json!(ns))
}

async fn kv_get_namespace(State(st): St, Path(ns_id): Path<String>) -> ApiResult {
    let kv = kv_store(&st)?;
    let ns = tokio::task::spawn_blocking(move || kv.get_namespace(&ns_id))
        .await
        .map_err(|e| bad(e.to_string()))?
        .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, 1001, "KV namespace not found".into()))?;
    ok(json!(ns))
}

async fn kv_rename_namespace(State(st): St, Path(ns_id): Path<String>, bytes: Bytes) -> ApiResult {
    if st.role.is_accelerate() {
        return Err(StoreError::ReadOnly.into());
    }
    let inp: KvNamespaceInput = body(&bytes)?;
    let kv = kv_store(&st)?;
    let ns = tokio::task::spawn_blocking(move || kv.rename_namespace(&ns_id, &inp.title))
        .await
        .map_err(|e| bad(e.to_string()))?
        .map_err(bad)?;
    wake_push(&st);
    ok(json!(ns))
}

async fn kv_delete_namespace(State(st): St, Path(ns_id): Path<String>) -> ApiResult {
    if st.role.is_accelerate() {
        return Err(StoreError::ReadOnly.into());
    }
    let kv = kv_store(&st)?;
    let id = ns_id.clone();
    tokio::task::spawn_blocking(move || kv.delete_namespace(&id))
        .await
        .map_err(|e| bad(e.to_string()))?
        .map_err(bad)?;
    wake_push(&st);
    ok(json!({ "id": ns_id }))
}

async fn kv_list_keys(State(st): St, Path(ns_id): Path<String>, Query(q): Params) -> ApiResult {
    let kv = kv_store(&st)?;
    let prefix = q.get("prefix").cloned();
    let limit = q.get("limit").and_then(|s| s.parse::<usize>().ok());
    let cursor = q.get("cursor").cloned();
    let res = tokio::task::spawn_blocking(move || {
        kv.list(&ns_id, prefix.as_deref(), limit, cursor.as_deref())
    })
    .await
    .map_err(|e| bad(e.to_string()))?
    .map_err(bad)?;
    ok(res)
}

async fn kv_get_value(
    State(st): St,
    Extension(who): Extension<Principal>,
    Path((ns_id, key)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    if who.role == Role::Viewer {
        return Err(ApiError(StatusCode::FORBIDDEN, 2010, "your role does not allow this".into()));
    }
    let kv = kv_store(&st)?;
    let got = tokio::task::spawn_blocking(move || kv.get_with_metadata(&ns_id, &key))
        .await
        .map_err(|e| bad(e.to_string()))?
        .map_err(bad)?;
    match got {
        Some((bytes, _)) => Ok(([(header::CONTENT_TYPE, "application/octet-stream")], bytes).into_response()),
        None => Err(ApiError(StatusCode::NOT_FOUND, 1009, "key not found".into())),
    }
}

async fn kv_put_value(
    State(st): St,
    Path((ns_id, key)): Path<(String, String)>,
    Query(q): Params,
    bytes: Bytes,
) -> ApiResult {
    if st.role.is_accelerate() {
        return Err(StoreError::ReadOnly.into());
    }
    let expiration = q.get("expiration").and_then(|s| s.parse::<u64>().ok());
    let expiration_ttl = q.get("expiration_ttl").and_then(|s| s.parse::<u64>().ok());
    let metadata: Option<Value> = match q.get("metadata") {
        Some(m) => Some(serde_json::from_str(m).map_err(|e| bad(e.to_string()))?),
        None => None,
    };
    let kv = kv_store(&st)?;
    tokio::task::spawn_blocking(move || kv.put(&ns_id, &key, &bytes, expiration, expiration_ttl, metadata))
        .await
        .map_err(|e| bad(e.to_string()))?
        .map_err(bad)?;
    wake_push(&st);
    ok(json!({ "saved": true }))
}

async fn kv_delete_value(State(st): St, Path((ns_id, key)): Path<(String, String)>) -> ApiResult {
    if st.role.is_accelerate() {
        return Err(StoreError::ReadOnly.into());
    }
    let kv = kv_store(&st)?;
    tokio::task::spawn_blocking(move || kv.delete(&ns_id, &key))
        .await
        .map_err(|e| bad(e.to_string()))?
        .map_err(bad)?;
    wake_push(&st);
    ok(json!({ "deleted": true }))
}

// ------------------------------------------------------------------ d1 ----

async fn d1_list_databases(State(st): St) -> ApiResult {
    let d1 = d1_store(&st)?;
    let list = tokio::task::spawn_blocking(move || d1.list_databases())
        .await
        .map_err(|e| bad(e.to_string()))?;
    ok(json!(list))
}

#[derive(Deserialize)]
struct D1CreateInput {
    name: String,
}

async fn d1_create_database(State(st): St, bytes: Bytes) -> ApiResult {
    if st.role.is_accelerate() {
        return Err(StoreError::ReadOnly.into());
    }
    let inp: D1CreateInput = body(&bytes)?;
    let d1 = d1_store(&st)?;
    let db = tokio::task::spawn_blocking(move || d1.create_database(&inp.name))
        .await
        .map_err(|e| bad(e.to_string()))?
        .map_err(bad)?;
    wake_push(&st);
    ok(json!(db))
}

async fn d1_get_database(State(st): St, Path(db_id): Path<String>) -> ApiResult {
    let d1 = d1_store(&st)?;
    let db = tokio::task::spawn_blocking(move || d1.get_database(&db_id))
        .await
        .map_err(|e| bad(e.to_string()))?
        .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, 1002, "D1 database not found".into()))?;
    ok(json!(db))
}

async fn d1_delete_database(State(st): St, Path(db_id): Path<String>) -> ApiResult {
    if st.role.is_accelerate() {
        return Err(StoreError::ReadOnly.into());
    }
    let d1 = d1_store(&st)?;
    let id = db_id.clone();
    tokio::task::spawn_blocking(move || d1.delete_database(&id))
        .await
        .map_err(|e| bad(e.to_string()))?
        .map_err(bad)?;
    wake_push(&st);
    ok(json!({ "id": db_id }))
}

#[derive(Deserialize)]
struct D1QueryBody {
    sql: String,
    #[serde(default)]
    params: Vec<Value>,
}

async fn d1_query(State(st): St, Path(db_id): Path<String>, bytes: Bytes) -> ApiResult {
    let req: D1QueryBody = body(&bytes)?;
    let params = req
        .params
        .iter()
        .map(crate::workers::db::D1Param::from_json)
        .collect::<Result<Vec<_>, _>>()
        .map_err(bad)?;
    let d1 = d1_store(&st)?;
    let res = tokio::task::spawn_blocking(move || d1.query(&db_id, &req.sql, params, false, false, None))
        .await
        .map_err(|e| bad(e.to_string()))?
        .map_err(bad)?;
    if !st.role.is_accelerate() {
        wake_push(&st);
    }
    ok(json!([res]))
}

async fn d1_raw(State(st): St, Path(db_id): Path<String>, bytes: Bytes) -> ApiResult {
    let req: D1QueryBody = body(&bytes)?;
    let params = req
        .params
        .iter()
        .map(crate::workers::db::D1Param::from_json)
        .collect::<Result<Vec<_>, _>>()
        .map_err(bad)?;
    let d1 = d1_store(&st)?;
    let res = tokio::task::spawn_blocking(move || d1.query(&db_id, &req.sql, params, true, true, None))
        .await
        .map_err(|e| bad(e.to_string()))?
        .map_err(bad)?;
    if !st.role.is_accelerate() {
        wake_push(&st);
    }
    ok(res)
}

/// The look-back window of an analytics query, in minutes: `since=-1440`
/// (as Cloudflare writes it), `1440`, `90m`, `24h` or `7d`.
fn window(q: &HashMap<String, String>, default: u64) -> Result<u64, ApiError> {
    let Some(raw) = q.get("since") else { return Ok(default) };
    let s = raw.trim().trim_start_matches('-');
    let (digits, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len()));
    let per_unit = match unit {
        "" | "m" => 1,
        "h" => 60,
        "d" => 1440,
        _ => 0,
    };
    match digits.parse::<u64>() {
        Ok(n) if per_unit > 0 && n > 0 => Ok(n.saturating_mul(per_unit).min(crate::edge::stats::MAX_WINDOW)),
        _ => Err(bad("'since' must look like -1440 (minutes), 90m, 24h or 7d")),
    }
}

/// Traffic of one zone: totals, time series, split by node and breakdowns.
async fn analytics(State(st): St, Path(zone_id): Path<String>, Query(q): Params) -> ApiResult {
    st.store.get_zone(&zone_id)?;
    let step = q.get("step").and_then(|v| v.parse().ok());
    ok(st.stats.report(&zone_id, &st.node(), window(&q, 1440)?, step))
}

/// The newest requests of one zone, as the node answering this call saw
/// them (crate::edge::reqlog): other nodes keep their own.
async fn request_log(State(st): St, Path(zone_id): Path<String>, Query(q): Params) -> ApiResult {
    st.store.get_zone(&zone_id)?;
    let query = crate::edge::reqlog::LogQuery::parse(&zone_id, &q).map_err(bad)?;
    ok(st.edge.reqlog.answer(&query, &st.node()))
}

/// Traffic totals of every zone.
async fn analytics_summary(State(st): St, axum::Extension(who): Who, Query(q): Params) -> ApiResult {
    let window = window(&q, 1440)?;
    let mut by_zone = st.stats.summary(window);
    let mut totals = crate::edge::stats::Counters::default();
    let mut zones = serde_json::Map::new();
    // the totals are of the zones the asker may see (crate::tenancy)
    for z in st.store.list_zones().into_iter().filter(|z| crate::tenancy::may_see(&who, z.owner.as_deref())) {
        let c = by_zone.remove(&z.id).unwrap_or_default();
        totals.add(&c);
        let mut v = c.json();
        v["name"] = json!(z.name);
        zones.insert(z.id, v);
    }
    ok(json!({ "window": window, "totals": totals.json(), "zones": zones }))
}

// ------------------------------------------------ fleet: nodes, system ----

async fn system(State(st): St) -> ApiResult {
    let (accel, version) = (st.role.is_accelerate(), st.store.version());
    let fleet = if accel { Value::Null } else { st.fleet.all(&version) };
    ok(json!({
        "role": st.role.as_str(),
        "writable": !accel,
        "node": st.node(),
        "build": env!("CARGO_PKG_VERSION"),
        "exe": st.releases.updater.own(),
        "started_at": st.started_at,
        "version": version,
        "sync_rev": st.store.current_rev(),
        "cname_base": st.cname_base,
        "name_servers": st.name_servers,
        "panel_host": st.panel_host,
        "continents": crate::geo::CONTINENTS,
        "peers": fleet,
        "replicas": fleet,
    }))
}

fn record_peer_query(st: &ApiState, q: &HashMap<String, String>) {
    if let (Some(node), Some(theirs)) = (q.get("node").filter(|n| !n.is_empty()), q.get("version")) {
        st.fleet.seen(node, theirs, q.get("build").map(String::as_str).unwrap_or(""));
        if let Some(role) = q.get("role").filter(|r| !r.is_empty()) {
            st.fleet.set_role(node, role);
        }
        if let Some(exe) = q.get("exe").filter(|exe| !exe.is_empty()) {
            let list = |key: &str| q.get(key).map(|l| l.split(',').filter(|s| !s.is_empty()).map(String::from).collect());
            st.fleet.runs(
                node,
                crate::fleet::PeerExe {
                    sha256: exe.clone(),
                    trusted: q.get("trusted").is_none_or(|t| t != "0"),
                    submission: q.get("submission").cloned().unwrap_or_default(),
                    rejected: list("rejected").unwrap_or_default(),
                },
            );
        }
    }
}

/// Legacy state endpoint (compat for older tools/replicas).
async fn replication_state(State(st): St, Query(q): Params) -> ApiResult {
    let version = st.store.version();
    record_peer_query(&st, &q);
    let (release, commands) = match q.get("node").filter(|n| !n.is_empty()) {
        Some(node) if !st.role.is_accelerate() => (st.releases.directive(node), st.fleet.take_commands(node)),
        _ => (Value::Null, Vec::new()),
    };
    if q.get("version") == Some(&version) {
        return ok(json!({ "version": version, "changed": false, "release": release, "commands": commands }));
    }
    ok(json!({ "version": version, "changed": true, "data": st.store.export(), "release": release, "commands": commands }))
}

fn caller_is_accelerate(headers: &axum::http::HeaderMap, role_hint: Option<&str>) -> bool {
    headers
        .get("x-fucf-node-role")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|s| s.eq_ignore_ascii_case("accelerate"))
        || role_hint.is_some_and(|s| s.eq_ignore_ascii_case("accelerate"))
}

/// Incremental (or epoch-mismatch full-resync) peer sync pull endpoint.
async fn replication_sync(State(st): St, headers: axum::http::HeaderMap, Query(q): Params) -> ApiResult {
    record_peer_query(&st, &q);
    let is_accel_caller = caller_is_accelerate(&headers, q.get("role").map(|s| s.as_str()));
    let (release, commands) = match q.get("node").filter(|n| !n.is_empty()) {
        Some(node) if !st.role.is_accelerate() => (st.releases.directive(node), st.fleet.take_commands(node)),
        _ => (Value::Null, Vec::new()),
    };

    let since_cfg: u64 = q.get("since").and_then(|v| v.parse().ok()).unwrap_or(0);
    let ep_cfg = q.get("epoch").filter(|s| !s.is_empty()).cloned();
    let cfg_cur_ep = st.store.epoch();
    let need_cfg = st.store.current_rev() > since_cfg
        || ep_cfg.as_deref() != Some(cfg_cur_ep.as_str());
    let config_delta = if need_cfg {
        Some(st.store.export_since_async(since_cfg, ep_cfg.as_deref()).await.map_err(bad)?)
    } else {
        None
    };

    let since_acc: u64 = q.get("since_accounts").and_then(|v| v.parse().ok()).unwrap_or(0);
    let ep_acc = q.get("epoch_accounts").filter(|s| !s.is_empty()).cloned();
    let acc_cur_ep = st.accounts.epoch();
    let need_acc = !is_accel_caller
        && (st.accounts.current_rev() > since_acc
            || ep_acc.as_deref() != Some(acc_cur_ep.as_str()));
    let accounts_delta = if need_acc {
        let ep_opt = ep_acc.clone();
        Some(
            accounts_blocking::<crate::sync::DomainDelta>(&st, move |accounts| {
                accounts.export_since(since_acc, ep_opt.as_deref()).map_err(bad)
            })
            .await?,
        )
    } else {
        None
    };

    let mut domains_out: Vec<crate::sync::DomainDelta> = Vec::new();
    if let Some(dom_json) = q.get("domains") {
        if let Ok(cursors) = serde_json::from_str::<HashMap<String, (String, u64)>>(dom_json) {
            for p in st.synced() {
                if p.passive() && !cursors.contains_key(p.domain()) {
                    continue;
                }
                let (ep, since) = cursors.get(p.domain()).map(|(e, r)| (Some(e.clone()), *r)).unwrap_or((None, 0));
                if p.current_rev() > since || ep.as_deref() != Some(p.epoch().as_str()) {
                    let delta = tokio::task::spawn_blocking(move || p.export_since(since, ep.as_deref()))
                        .await
                        .map_err(|e| bad(e.to_string()))?
                        .map_err(bad)?;
                    domains_out.push(delta);
                }
            }
        }
    }

    let (hlc_ms, hlc_seq) = st.sync.as_ref().map(|s| s.clock.current()).unwrap_or_else(|| st.store.clock().current());
    ok(json!({
        "node": st.node(),
        "role": st.role.as_str(),
        "version": st.store.version(),
        "build": env!("CARGO_PKG_VERSION"),
        "hlc": { "ms": hlc_ms, "seq": hlc_seq },
        "config": config_delta,
        "accounts": accounts_delta,
        "domains": domains_out,
        "release": release,
        "commands": commands,
    }))
}

#[derive(Deserialize)]
struct SyncHlc {
    ms: u64,
    seq: u64,
}

#[derive(Deserialize)]
struct TelemetryPush {
    #[serde(default)]
    boot: String,
    #[serde(default)]
    seq: u64,
    #[serde(default)]
    stats: HashMap<String, crate::edge::stats::Series>,
    #[serde(default)]
    events: Vec<crate::edge::waf::Event>,
    #[serde(default)]
    usage: Option<crate::limits::Usage>,
    #[serde(default)]
    status: Value,
    #[serde(default)]
    rtt: HashMap<String, crate::rtt::Measure>,
    #[serde(default)]
    blocks: Vec<crate::edge::waf::Block>,
    #[serde(default, deserialize_with = "crate::edge::fleetrate::lenient")]
    rate: Vec<crate::edge::fleetrate::RateCount>,
}

#[derive(Deserialize)]
struct SyncPushBody {
    #[serde(default)]
    node: String,
    #[serde(default)]
    role: String,
    #[serde(default)]
    version: String,
    #[serde(default)]
    build: String,
    #[serde(default)]
    hlc: Option<SyncHlc>,
    #[serde(default)]
    config: Option<crate::sync::DomainDelta>,
    #[serde(default)]
    accounts: Option<crate::sync::DomainDelta>,
    #[serde(default)]
    domains: Vec<crate::sync::DomainDelta>,
    #[serde(default)]
    telemetry: Option<TelemetryPush>,
}

/// Peer push-notify & telemetry absorption endpoint.
async fn replication_sync_push(State(st): St, headers: axum::http::HeaderMap, bytes: Bytes) -> ApiResult {
    if st.role.is_accelerate() {
        return Err(StoreError::ReadOnly.into());
    }
    let req: SyncPushBody = body(&bytes)?;
    if caller_is_accelerate(&headers, Some(req.role.as_str()))
        && (req.config.is_some() || req.accounts.is_some() || !req.domains.is_empty())
    {
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            2010,
            "accelerate nodes cannot push config, accounts, or domain state".into(),
        ));
    }
    let clock = st.sync.as_ref().map(|s| s.clock.clone()).unwrap_or_else(|| st.store.clock());
    if let Some(h) = &req.hlc {
        clock.observe(h.ms, h.seq);
    }
    let peer_node = req.node.trim().to_ascii_lowercase();
    if !peer_node.is_empty() && peer_node.len() <= 64 {
        st.fleet.seen(&peer_node, &req.version, &req.build);
        if !req.role.is_empty() {
            st.fleet.set_role(&peer_node, &req.role);
        }
        if let Some(tele) = req.telemetry {
            st.reports.take(
                crate::reports::Report {
                    node: peer_node.clone(),
                    role: req.role.clone(),
                    version: req.version.clone(),
                    build: req.build.clone(),
                    boot: tele.boot,
                    seq: tele.seq,
                    at: 0,
                    stats: tele.stats,
                    events: tele.events,
                    usage: tele.usage,
                    status: tele.status,
                    rtt: tele.rtt,
                    blocks: tele.blocks,
                    rate: tele.rate,
                },
                true,
            );
        }
    }

    let mut adopted = false;
    if let Some(cfg) = req.config {
        adopted |= st.store.merge_delta_async(&cfg).await?;
    }
    if let Some(acc) = req.accounts {
        let clk = clock.clone();
        adopted |= accounts_blocking(&st, move |accounts| accounts.merge_delta(&acc, &clk).map_err(bad)).await?;
    }
    for d in req.domains {
        if let Some(p) = st.synced().into_iter().find(|p| p.domain() == d.domain) {
            let clk = clock.clone();
            adopted |= tokio::task::spawn_blocking(move || p.merge_delta(&d, &clk))
                .await
                .map_err(|e| bad(e.to_string()))?
                .map_err(bad)?;
        }
    }

    ok(json!({
        "node": st.node(),
        "role": st.role.as_str(),
        "version": st.store.version(),
        "build": env!("CARGO_PKG_VERSION"),
        "adopted": adopted,
        "accepted": true,
    }))
}

// ------------------------------------------------------------ releases ----

/// Where this node's binary and, across peers, the roll-out stand.
async fn release_status(State(st): St) -> ApiResult {
    let peers = match st.releases.target() {
        _ if st.role.is_accelerate() => Vec::new(),
        Some((submission, sha256)) => st.fleet.views(&st.store.version(), &submission, &sha256),
        None => st.fleet.views(&st.store.version(), "", ""),
    };
    ok(st.releases.status(&st.node(), &peers))
}

/// Upload a release (the body is the binary, signed with the release key)
/// and start rolling it out.
async fn submit_release(State(st): St, Path(sha256): Path<String>, Query(q): Params, bytes: Bytes) -> ApiResult {
    if st.role.is_accelerate() {
        return Err(StoreError::ReadOnly.into());
    }
    let signature = q.get("signature").cloned().ok_or_else(|| bad("'signature' is required"))?;
    let deaf: Vec<String> =
        st.fleet.views(&st.store.version(), "", "").into_iter().filter(|p| p.online && p.exe.is_empty()).map(|p| p.name).collect();
    if !deaf.is_empty() {
        let message = format!("{} would not take the release (an older build there): install the current build by hand first", deaf.join(", "));
        return Err(ApiError(StatusCode::CONFLICT, 1005, message));
    }
    let releases = st.releases.clone();
    let submitted = tokio::task::spawn_blocking(move || releases.submit(&sha256, &signature, &bytes)).await;
    submitted.map_err(|e| bad(e.to_string()))?.map_err(bad)?;
    release_status(State(st)).await
}

/// Take the release back: the nodes that run it go back to what they ran
/// before. With forget=true it is only dropped, and the nodes stay as they are.
async fn withdraw_release(State(st): St, Path(sha256): Path<String>, Query(q): Params) -> ApiResult {
    if st.role.is_accelerate() {
        return Err(StoreError::ReadOnly.into());
    }
    let releases = st.releases.clone();
    let forget = q.get("forget").is_some_and(|f| f == "true" || f == "1");
    tokio::task::spawn_blocking(move || releases.withdraw(&sha256, forget))
        .await
        .map_err(|e| bad(e.to_string()))?
        .map_err(|e| ApiError(StatusCode::NOT_FOUND, 1002, e))?;
    release_status(State(st)).await
}

/// The binary of the fleet's release, for peers.
async fn release_binary(State(st): St, Path(sha256): Path<String>) -> Result<Response, ApiError> {
    let releases = st.releases.clone();
    let bytes = tokio::task::spawn_blocking(move || releases.binary(&sha256)).await.ok().flatten().ok_or(StoreError::NotFound)?;
    Ok(([(header::CONTENT_TYPE, "application/octet-stream")], bytes).into_response())
}

#[derive(Deserialize)]
struct Report {
    node: String,
    version: String,
    #[serde(default)]
    build: String,
    /// One run of the replica's process, and the number of this report in it.
    #[serde(default)]
    boot: String,
    #[serde(default)]
    seq: u64,
    #[serde(default)]
    stats: HashMap<String, crate::edge::stats::Series>,
    #[serde(default)]
    events: Vec<crate::edge::waf::Event>,
    /// Where the replica stands with its traffic allowance.
    #[serde(default)]
    usage: Option<crate::limits::Usage>,
    /// What the replica says about itself (see crate::node).
    #[serde(default)]
    status: Value,
}

/// Replicas/peers deliver what they recorded: traffic counters and security events.
async fn replication_report(State(st): St, bytes: Bytes) -> ApiResult {
    if st.role.is_accelerate() {
        return Err(StoreError::ReadOnly.into());
    }
    let report: Report = body(&bytes)?;
    let node = report.node.trim().to_ascii_lowercase();
    if node.is_empty() || node.len() > 64 {
        return Err(bad("'node' must be the name of the reporting node"));
    }
    st.fleet.seen(&node, &report.version, &report.build);
    let fresh = st.reports.take(
        crate::reports::Report {
            role: st.fleet.role(&node),
            node,
            version: report.version,
            build: report.build,
            boot: report.boot,
            seq: report.seq,
            at: 0,
            stats: report.stats,
            events: report.events,
            usage: report.usage,
            status: report.status,
            rtt: Default::default(),
            blocks: Default::default(),
            rate: Default::default(),
        },
        true,
    );
    ok(json!({ "accepted": fresh, "version": st.store.version() }))
}

/// Nodes with their health as probed from this node and what each peer last reported.
async fn list_nodes(State(st): St) -> ApiResult {
    let list = st.store.list_nodes();
    let (me, version, accel) = (st.node(), st.store.version(), st.role.is_accelerate());
    let nodes = list.iter().map(|n| {
        let mut v = serde_json::to_value(n).unwrap_or_default();
        v["healthy"] = json!(st.health.is_up(&n.name));
        v["self"] = json!(n.name == me);
        v["replica"] = if accel || n.name == me { Value::Null } else { st.fleet.status(&n.name, &version).unwrap_or(Value::Null) };
        let usage = if n.name == me { Some(st.limits.usage()) } else { st.fleet.usage(&n.name) };
        v["traffic"] = serde_json::to_value(usage).unwrap_or_default();
        v
    });
    ok(Value::Array(nodes.collect()))
}

/// The DNS queries this node answered for the zone since it started, by type and by answer.
async fn dns_analytics(State(st): St, Path(zone_id): Path<String>) -> ApiResult {
    st.store.get_zone(&zone_id)?;
    ok(serde_json::to_value(crate::dns::resolver::query_count(&zone_id)).unwrap_or_default())
}

/// What this node's health checks say about the zone's origins (see crate::edge::origins).
async fn origin_health(State(st): St, Path(zone_id): Path<String>) -> ApiResult {
    st.store.get_zone(&zone_id)?;
    ok(st.edge.origins.report(&zone_id))
}

async fn list_steering(State(st): St) -> ApiResult {
    ok(serde_json::to_value(st.store.list_steering()).unwrap_or_default())
}

/// Where a visitor at `ip` is placed, and which steering rule takes it
/// (the first enabled one by priority that matches; health and traffic
/// allowances aside).
async fn test_steering(State(st): St, Query(q): Params) -> ApiResult {
    let ip: std::net::IpAddr = q
        .get("ip")
        .and_then(|v| v.trim().parse().ok())
        .ok_or_else(|| StoreError::Invalid("ip must be an IPv4 or IPv6 address".into()))?;
    let geo = st.edge.geo.get().cloned().unwrap_or_default();
    let loc = geo.locate(ip);
    let snap = st.store.snapshot();
    let rule = snap.steering.iter().find(|r| r.matches(&loc));
    let continent: Vec<&str> = match &loc.continent {
        Some(c) => snap.nodes.iter().filter(|n| n.continents.contains(c)).map(|n| n.name.as_str()).collect(),
        None => Vec::new(),
    };
    ok(json!({
        "ip": ip.to_string(),
        "location": {
            "continent": loc.continent,
            "country": loc.country,
            "region": loc.region,
            "asn": loc.asn,
            "as_org": loc.as_org,
        },
        "databases": { "country": geo.has_country_db(), "cn_provinces": geo.has_cn_db() },
        "rule": rule.map(|r| json!({ "id": r.id, "name": r.name, "action": r.action, "nodes": r.nodes, "priority": r.priority })),
        "continent_nodes": continent,
        // what a `fastest` rule goes by: the nodes that measured this visitor's network, fastest first
        "measured": st.edge.rtt.ranking(&loc, &snap.nodes.iter().map(|n| n.name.as_str()).collect::<Vec<_>>(), &st.node()).map(|(network, order)| json!({
            "network": network,
            "nodes": order.iter().map(|(name, ms)| json!({ "name": name, "ms": ms })).collect::<Vec<_>>(),
        })),
        "reputation": st.edge.reputation.get().map(|r| json!({
            "assessment": r.assess(ip, loc.asn.unwrap_or(0) as i64, loc.as_org.as_deref().unwrap_or(""), q.get("ua").map(String::as_str).unwrap_or("")),
            "lists": r.loaded().into_iter().map(|(name, n)| json!({ "name": name, "networks": n })).collect::<Vec<_>>(),
        })),
    }))
}

/// The round trips the nodes measured with their visitors, per network
/// (`CN-JS/4134`, `CN/4134`, `CN-JS`, `CN`) and node: what `fastest` steering rules go by.
async fn measured_steering(State(st): St) -> ApiResult {
    ok(st.edge.rtt.table(&st.node()))
}

async fn create_steering(State(st): St, bytes: Bytes) -> ApiResult {
    ok(serde_json::to_value(st.store.save_steering_async(None, body(&bytes)?).await?).unwrap_or_default())
}

async fn update_steering(State(st): St, Path(id): Path<String>, bytes: Bytes) -> ApiResult {
    ok(serde_json::to_value(st.store.save_steering_async(Some(&id), body(&bytes)?).await?).unwrap_or_default())
}

async fn delete_steering(State(st): St, Path(id): Path<String>) -> ApiResult {
    st.store.delete_steering_async(&id).await?;
    ok(json!({ "id": id }))
}

// ----------------------------------------------------------- alerts ----
// (what is checked and how it is sent: crate::alerts; secrets never leave masked)

async fn list_alert_channels(State(st): St) -> ApiResult {
    ok(Value::Array(st.store.list_alert_channels().iter().map(crate::alerts::AlertChannel::public).collect()))
}

async fn get_alert_channel(State(st): St, Path(id): Path<String>) -> ApiResult {
    ok(st.store.get_alert_channel(&id).ok_or(StoreError::NotFound)?.public())
}

async fn create_alert_channel(State(st): St, bytes: Bytes) -> ApiResult {
    ok(st.store.save_alert_channel_async(None, body(&bytes)?).await?.public())
}

/// PUT and PATCH alike: the fields given change; a secret sent back masked stays.
async fn update_alert_channel(State(st): St, Path(id): Path<String>, bytes: Bytes) -> ApiResult {
    ok(st.store.save_alert_channel_async(Some(&id), body(&bytes)?).await?.public())
}

async fn delete_alert_channel(State(st): St, Path(id): Path<String>) -> ApiResult {
    st.store.delete_alert_channel_async(&id).await?;
    ok(json!({ "id": id }))
}

/// Send one test message through the channel (whether it is on or not).
async fn test_alert_channel(State(st): St, Path(id): Path<String>) -> ApiResult {
    let channel = st.store.get_alert_channel(&id).ok_or(StoreError::NotFound)?;
    let node = st.node();
    crate::alerts::send_test(&st.edge, &channel, &node)
        .await
        .map_err(|e| ApiError(StatusCode::BAD_GATEWAY, 1100, format!("the test message was not delivered: {e}")))?;
    ok(json!({ "id": id, "sent": true }))
}

/// What fires now, on the node that checks (the panel's); elsewhere `evaluating` is false.
async fn active_alerts() -> ApiResult {
    ok(crate::alerts::active())
}

// ------------------------------------------------ challenge widgets ----
// (the check itself and siteverify: crate::edge::widget). Only a digest of
// a widget's secret is kept; the secret is in the answer to its creation
// and to a rotation, and nowhere else.

async fn list_challenge_widgets(State(st): St) -> ApiResult {
    ok(Value::Array(st.store.list_challenge_widgets().iter().map(crate::edge::widget::ChallengeWidget::public).collect()))
}

async fn get_challenge_widget(State(st): St, Path(sitekey): Path<String>) -> ApiResult {
    ok(st.store.get_challenge_widget(&sitekey).ok_or(StoreError::NotFound)?.public())
}

/// A fresh secret from the system's randomness, as the secret and its digest.
fn new_widget_secret() -> Result<(String, String), ApiError> {
    crate::edge::widget::new_secret().ok_or_else(|| ApiError(StatusCode::INTERNAL_SERVER_ERROR, 1000, "no randomness for a secret".into()))
}

async fn create_challenge_widget(State(st): St, bytes: Bytes) -> ApiResult {
    let request: Value = body(&bytes)?;
    let (secret, digest) = new_widget_secret()?;
    ok(st.store.save_challenge_widget_async(None, request, Some(digest)).await?.with_secret(&secret))
}

/// PUT and PATCH alike: the fields given change, the secret stays.
async fn update_challenge_widget(State(st): St, Path(sitekey): Path<String>, bytes: Bytes) -> ApiResult {
    let request: Value = body(&bytes)?;
    ok(st.store.save_challenge_widget_async(Some(&sitekey), request, None).await?.public())
}

async fn delete_challenge_widget(State(st): St, Path(sitekey): Path<String>) -> ApiResult {
    st.store.delete_challenge_widget_async(&sitekey).await?;
    ok(json!({ "id": sitekey, "sitekey": sitekey }))
}

/// A new secret; the old one stops working at once. Cloudflare keeps the
/// old one for two hours unless `invalidate_immediately` is true: here
/// only the immediate kind exists, so `false` is refused rather than
/// quietly treated as true.
async fn rotate_challenge_widget_secret(State(st): St, Path(sitekey): Path<String>, bytes: Bytes) -> ApiResult {
    st.store.get_challenge_widget(&sitekey).ok_or(StoreError::NotFound)?;
    let request: Value = if bytes.iter().all(u8::is_ascii_whitespace) { json!({}) } else { body(&bytes)? };
    let Value::Object(request) = request else { return Err(bad("request body must be a JSON object")) };
    for (key, value) in &request {
        match key.as_str() {
            "invalidate_immediately" if value == &json!(true) => {}
            "invalidate_immediately" => return Err(bad("invalidate_immediately: only true is supported (the old secret stops working at once)")),
            other => return Err(bad(format!("unknown field '{other}'"))),
        }
    }
    let (secret, digest) = new_widget_secret()?;
    ok(st.store.save_challenge_widget_async(Some(&sitekey), json!({}), Some(digest)).await?.with_secret(&secret))
}

// ------------------------------------------------ local proxy rules ----

async fn list_proxy_rules(State(st): St) -> ApiResult {
    ok(serde_json::to_value(st.store.list_proxy_rules()).unwrap_or_default())
}

async fn get_proxy_rule(State(st): St, Path(id): Path<String>) -> ApiResult {
    let rule = st.store.get_proxy_rule(&id).ok_or(StoreError::NotFound)?;
    ok(serde_json::to_value(rule).unwrap_or_default())
}

async fn create_proxy_rule(State(st): St, bytes: Bytes) -> ApiResult {
    let rule = st.store.save_proxy_rule_async(None, body(&bytes)?).await?;
    if let Some(sync) = &st.sync {
        sync.wake_push();
    }
    ok(serde_json::to_value(rule).unwrap_or_default())
}

async fn update_proxy_rule(State(st): St, Path(id): Path<String>, bytes: Bytes) -> ApiResult {
    let rule = st.store.save_proxy_rule_async(Some(&id), body(&bytes)?).await?;
    if let Some(sync) = &st.sync {
        sync.wake_push();
    }
    ok(serde_json::to_value(rule).unwrap_or_default())
}

async fn delete_proxy_rule(State(st): St, Path(id): Path<String>) -> ApiResult {
    st.store.delete_proxy_rule_async(&id).await?;
    if let Some(sync) = &st.sync {
        sync.wake_push();
    }
    ok(json!({ "id": id }))
}

async fn create_node(State(st): St, bytes: Bytes) -> ApiResult {
    ok(serde_json::to_value(st.store.save_node_async(None, body(&bytes)?).await?).unwrap_or_default())
}

async fn get_node(State(st): St, Path(id): Path<String>) -> ApiResult {
    let node = st.store.list_nodes().into_iter().find(|n| n.id == id).ok_or(StoreError::NotFound)?;
    ok(serde_json::to_value(node).unwrap_or_default())
}

async fn update_node(State(st): St, Path(id): Path<String>, bytes: Bytes) -> ApiResult {
    ok(serde_json::to_value(st.store.save_node_async(Some(&id), body(&bytes)?).await?).unwrap_or_default())
}

async fn delete_node(State(st): St, Path(id): Path<String>) -> ApiResult {
    st.store.delete_node_async(&id).await?;
    ok(json!({ "id": id }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;
    use tower_service::Service;

    fn make_test_state(dir: &std::path::Path, role: crate::sync::NodeRole) -> Arc<ApiState> {
        let store = Arc::new(Store::open(&dir.join("store.json"), vec![]).unwrap());
        let cache = Arc::new(Cache::new(1 << 20));
        let waf = Arc::new(Waf::new());
        let edge_val = crate::edge::Edge::new(store.clone(), cache.clone(), waf.clone(), vec![]).unwrap();
        let kv = if role.is_accelerate() {
            crate::workers::kv::KvStore::open_ephemeral(store.clock(), "jp".into())
        } else {
            crate::workers::kv::KvStore::open(dir.join("kv"), store.clock(), "au".into()).unwrap()
        };
        let d1 = if role.is_accelerate() {
            crate::workers::db::D1Store::open_ephemeral(store.clock(), "jp".into())
        } else {
            crate::workers::db::D1Store::open(dir.join("d1"), store.clock(), "au".into()).unwrap()
        };
        let _ = edge_val.kv.set(kv);
        let _ = edge_val.d1.set(d1);
        let edge = Arc::new(edge_val);
        let stats = Arc::new(crate::edge::stats::Stats::load(&dir.join("stats.json")));
        let health = Arc::new(crate::geo::Health::default());
        let fleet = Arc::new(crate::fleet::Fleet::default());
        let limits = Arc::new(crate::limits::Limits::load(&dir.join("limits.json")));
        let gfw = Arc::new(crate::gfw::GfwMonitor::default());
        let updater = Arc::new(crate::release::Updater::new(dir, None));
        let releases = Arc::new(crate::release::Releases::new(updater.clone(), !role.is_accelerate()));
        let accounts = Arc::new(Accounts::open(dir.join("accounts.json"), None));
        let info = Arc::new(crate::node::NodeInfo {
            started: std::time::Instant::now(),
            started_at: "2026-01-01T00:00:00Z".into(),
            listeners: vec![],
            cache: cache.clone(),
            limits: limits.clone(),
            gfw,
            updater,
            front: None,
        });
        Arc::new(ApiState {
            reports: Arc::new(crate::reports::Reports::new(stats.clone(), waf.clone(), fleet.clone(), edge.rtt.clone(), || "au".to_string())),
            store,
            token: "test-token".into(),
            cache,
            waf,
            stats,
            cname_base: None,
            name_servers: vec![],
            panel_host: None,
            health,
            fleet,
            limits,
            edge_ips: vec![],
            node_name: Some("au".into()),
            started_at: "2026-01-01T00:00:00Z".into(),
            releases,
            accounts,
            info,
            password_checks: tokio::sync::Semaphore::new(4),
            mail: None,
            role,
            sync: None,
            providers: vec![edge.kv.get().unwrap().clone(), edge.d1.get().unwrap().clone()],
            edge,
        })
    }

    async fn call(app: &mut Router, method: &str, uri: &str, body: Vec<u8>) -> (StatusCode, Vec<u8>) {
        let req = axum::http::Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", "Bearer test-token")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(body))
            .unwrap();
        let resp = app.call(req).await.unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes().to_vec();
        (status, bytes)
    }

    #[tokio::test]
    async fn kv_d1_and_scheduled_http_api_routes() {
        let dir = std::env::temp_dir().join(format!("fucf-api-m2-{}", uuid::Uuid::new_v4().simple()));
        let st = make_test_state(&dir, crate::sync::NodeRole::Peer);
        let mut app = router(st);

        // 1. KV namespace + CRUD routes
        let (sc, b) = call(&mut app, "POST", "/client/v4/kv/namespaces", br#"{"title":"sessions"}"#.to_vec()).await;
        assert_eq!(sc, StatusCode::OK);
        let ns_id = serde_json::from_slice::<Value>(&b).unwrap()["result"]["id"].as_str().unwrap().to_string();

        let (sc, _) = call(&mut app, "PUT", &format!("/client/v4/kv/namespaces/{ns_id}/values/k1?expiration_ttl=120"), b"hello-kv".to_vec()).await;
        assert_eq!(sc, StatusCode::OK);

        let (sc, b) = call(&mut app, "GET", &format!("/client/v4/kv/namespaces/{ns_id}/values/k1"), vec![]).await;
        assert_eq!(sc, StatusCode::OK);
        assert_eq!(b, b"hello-kv");

        let (sc, b) = call(&mut app, "GET", &format!("/client/v4/kv/namespaces/{ns_id}/keys?prefix=k"), vec![]).await;
        assert_eq!(sc, StatusCode::OK);
        assert_eq!(serde_json::from_slice::<Value>(&b).unwrap()["result"]["keys"].as_array().unwrap().len(), 1);

        let (sc, _) = call(&mut app, "DELETE", &format!("/client/v4/kv/namespaces/{ns_id}/values/k1"), vec![]).await;
        assert_eq!(sc, StatusCode::OK);
        let (sc, _) = call(&mut app, "GET", &format!("/client/v4/kv/namespaces/{ns_id}/values/k1"), vec![]).await;
        assert_eq!(sc, StatusCode::NOT_FOUND);

        // 2. D1 database + query/raw routes
        let (sc, b) = call(&mut app, "POST", "/client/v4/d1/database", br#"{"name":"appdb"}"#.to_vec()).await;
        assert_eq!(sc, StatusCode::OK);
        let db_id = serde_json::from_slice::<Value>(&b).unwrap()["result"]["id"].as_str().unwrap().to_string();

        let (sc, _) = call(&mut app, "POST", &format!("/client/v4/d1/database/{db_id}/query"), br#"{"sql":"CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT)"}"#.to_vec()).await;
        assert_eq!(sc, StatusCode::OK);
        let (sc, _) = call(&mut app, "POST", &format!("/client/v4/d1/database/{db_id}/query"), br#"{"sql":"INSERT INTO items (id, name) VALUES (?, ?)","params":[1,"alpha"]}"#.to_vec()).await;
        assert_eq!(sc, StatusCode::OK);
        let (sc, b) = call(&mut app, "POST", &format!("/client/v4/d1/database/{db_id}/raw"), br#"{"sql":"SELECT id, name FROM items"}"#.to_vec()).await;
        assert_eq!(sc, StatusCode::OK);
        assert_eq!(serde_json::from_slice::<Value>(&b).unwrap()["result"], json!([["id", "name"], [1, "alpha"]]));

        // 3. Worker upload + bindings + scheduled trigger route
        let worker_js = br#"export default { async scheduled(ctrl, env, ctx) { await env.KV.put("ran", ctrl.cron); } }"#.to_vec();
        let (sc, _) = call(&mut app, "PUT", "/client/v4/workers/scripts/cronw", worker_js).await;
        assert_eq!(sc, StatusCode::OK);
        let patch = serde_json::to_vec(&json!({
            "kv_bindings": { "KV": ns_id },
            "d1_bindings": { "DB": db_id },
            "crons": ["*/5 * * * *"]
        })).unwrap();
        let (sc, _) = call(&mut app, "PATCH", "/client/v4/workers/scripts/cronw/settings", patch).await;
        assert_eq!(sc, StatusCode::OK);
        let (sc, _) = call(&mut app, "POST", "/client/v4/workers/scripts/cronw/scheduled", br#"{"cron":"*/5 * * * *"}"#.to_vec()).await;
        assert_eq!(sc, StatusCode::OK);
        let (sc, b) = call(&mut app, "GET", &format!("/client/v4/kv/namespaces/{ns_id}/values/ran"), vec![]).await;
        assert_eq!(sc, StatusCode::OK);
        assert_eq!(b, b"*/5 * * * *");

        // 4. Accelerate node rejects KV/D1 writes with 409 Conflict
        let dir_acc = std::env::temp_dir().join(format!("fucf-api-acc-{}", uuid::Uuid::new_v4().simple()));
        let mut acc_app = router(make_test_state(&dir_acc, crate::sync::NodeRole::Accelerate));
        let (sc, _) = call(&mut acc_app, "POST", "/client/v4/kv/namespaces", br#"{"title":"ro"}"#.to_vec()).await;
        assert_eq!(sc, StatusCode::CONFLICT);
        let (sc, _) = call(&mut acc_app, "POST", "/client/v4/d1/database", br#"{"name":"ro"}"#.to_vec()).await;
        assert_eq!(sc, StatusCode::CONFLICT);

        let _ = std::fs::remove_dir_all(dir);
        let _ = std::fs::remove_dir_all(dir_acc);
    }

    #[tokio::test]
    async fn proxy_rules_api_crud_and_sync() {
        let dir_a = std::env::temp_dir().join(format!("fucf-api-proxy-a-{}", uuid::Uuid::new_v4().simple()));
        let dir_b = std::env::temp_dir().join(format!("fucf-api-proxy-b-{}", uuid::Uuid::new_v4().simple()));
        let st_a = make_test_state(&dir_a, crate::sync::NodeRole::Peer);
        let st_b = make_test_state(&dir_b, crate::sync::NodeRole::Peer);
        let mut app_a = router(st_a.clone());

        let body = serde_json::to_vec(&json!({
            "name": "caddy-app",
            "hosts": ["app.example.com"],
            "upstreams": [{"url": "h2c://127.0.0.1:10002", "weight": 2}]
        })).unwrap();
        let (sc, b) = call(&mut app_a, "POST", "/client/v4/proxy/rules", body).await;
        assert_eq!(sc, StatusCode::OK);
        let rule_id = serde_json::from_slice::<Value>(&b).unwrap()["result"]["id"].as_str().unwrap().to_string();

        let (sc, b) = call(&mut app_a, "GET", &format!("/client/v4/proxy/rules/{rule_id}"), vec![]).await;
        assert_eq!(sc, StatusCode::OK);
        assert_eq!(serde_json::from_slice::<Value>(&b).unwrap()["result"]["name"], "caddy-app");

        // Replicate from A to B via delta sync
        let delta = st_a.store.export_since_async(0, None).await.unwrap();
        assert!(st_b.store.merge_delta_async(&delta).await.unwrap());
        assert_eq!(st_b.store.list_proxy_rules().len(), 1);

        // Update + delete on A
        let patch = serde_json::to_vec(&json!({"name": "caddy-app-v2"})).unwrap();
        let (sc, _) = call(&mut app_a, "PUT", &format!("/client/v4/proxy/rules/{rule_id}"), patch).await;
        assert_eq!(sc, StatusCode::OK);
        let (sc, _) = call(&mut app_a, "DELETE", &format!("/client/v4/proxy/rules/{rule_id}"), vec![]).await;
        assert_eq!(sc, StatusCode::OK);
        let delta2 = st_a.store.export_since_async(delta.to_rev, Some(&delta.epoch)).await.unwrap();
        assert!(st_b.store.merge_delta_async(&delta2).await.unwrap());
        assert!(st_b.store.list_proxy_rules().is_empty());

        let _ = std::fs::remove_dir_all(dir_a);
        let _ = std::fs::remove_dir_all(dir_b);
    }

    /// Give a test zone to the user with this e-mail (crate::tenancy), so
    /// their role, not ownership, is what a test looks at.
    async fn give(st: &ApiState, zone_id: &str, email: &str) {
        let id = st.accounts.users().iter().find(|u| u["email"] == email).unwrap()["id"].as_str().unwrap().to_string();
        st.store.set_zone_owner_async(zone_id, Some(id)).await.unwrap();
    }

    async fn call_raw(
        app: &mut Router,
        method: &str,
        uri: &str,
        extra_headers: Vec<(&str, &str)>,
        body: Vec<u8>,
    ) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
        use http_body_util::BodyExt;
        use tower_service::Service;
        let mut builder = axum::http::Request::builder().method(method).uri(uri);
        for (k, v) in extra_headers {
            builder = builder.header(k, v);
        }
        let req = builder.body(axum::body::Body::from(body)).unwrap();
        let resp = app.call(req).await.unwrap();
        let status = resp.status();
        let hdrs = resp.headers().clone();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes().to_vec();
        (status, hdrs, bytes)
    }

    #[tokio::test]
    async fn oauth_sso_flow_and_cross_node_cookie() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let idp_port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = listener.accept().await else { break };
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let n = s.read(&mut buf).await.unwrap_or(0);
                    let req_str = String::from_utf8_lossy(&buf[..n]);
                    let resp = if req_str.starts_with("POST /token") {
                        let body = r#"{"access_token":"tok123","token_type":"Bearer"}"#;
                        format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
                    } else if req_str.starts_with("GET /userinfo") {
                        let body = r#"{"sub":"u1","email":"sso@example.com"}"#;
                        format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
                    } else {
                        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
                    };
                    let _ = s.write_all(resp.as_bytes()).await;
                });
            }
        });

        let dir_a = std::env::temp_dir().join(format!("fucf-oauth-a-{}", uuid::Uuid::new_v4().simple()));
        let dir_b = std::env::temp_dir().join(format!("fucf-oauth-b-{}", uuid::Uuid::new_v4().simple()));
        let st_a = make_test_state(&dir_a, crate::sync::NodeRole::Peer);
        let st_b = make_test_state(&dir_b, crate::sync::NodeRole::Peer);
        let mut app_a = router(st_a.clone());
        let mut app_b = router(st_b.clone());

        let cfg = serde_json::to_vec(&json!({
            "enabled": true,
            "issuer_url": format!("http://127.0.0.1:{idp_port}"),
            "client_id": "panel-cid",
            "client_secret": "panel-sec",
            "auto_provision": true,
            "default_role": "editor",
        })).unwrap();
        let (sc, b) = call(&mut app_a, "PUT", "/client/v4/oauth/config", cfg).await;
        assert_eq!(sc, StatusCode::OK);
        assert_eq!(serde_json::from_slice::<Value>(&b).unwrap()["result"]["client_secret"], "***");

        // Initiate /login on Node A (creates ClusterSecret if not yet set)
        let (sc, hdrs, _) = call_raw(&mut app_a, "GET", "/client/v4/auth/oauth/login", vec![("host", "127.0.0.1:8080")], vec![]).await;
        assert_eq!(sc, StatusCode::FOUND);

        // Replicate accounts (ClusterSecret + OAuthConfig) from A to B
        let acc_delta = st_a.accounts.export_since(0, None).unwrap();
        let clk_b = st_b.store.clock();
        assert!(st_b.accounts.merge_delta(&acc_delta, &clk_b).unwrap());
        let loc = hdrs.get(header::LOCATION).unwrap().to_str().unwrap().to_string();
        assert!(loc.contains("code_challenge_method=S256"), "{loc}");
        let state_param = loc.split("state=").nth(1).unwrap().split('&').next().unwrap().to_string();
        let cookie_hdr = hdrs.get(header::SET_COOKIE).unwrap().to_str().unwrap().split(';').next().unwrap().to_string();

        // Complete /callback on Node B (stateless cross-node cookie!)
        let cb_uri = format!("/client/v4/auth/oauth/callback?code=authcode1&state={state_param}");
        let (sc, hdrs, _) = call_raw(
            &mut app_b,
            "GET",
            &cb_uri,
            vec![("host", "127.0.0.1:8080"), ("cookie", &cookie_hdr)],
            vec![],
        ).await;
        assert_eq!(sc, StatusCode::FOUND);
        let redir = hdrs.get(header::LOCATION).unwrap().to_str().unwrap().to_string();
        assert!(redir.starts_with("/#/?oauth_token="), "expected oauth_token redirect, got {redir}");
        let tok_raw = redir.strip_prefix("/#/?oauth_token=").unwrap();
        let tok = percent_encoding::percent_decode_str(tok_raw).decode_utf8_lossy().to_string();
        let (sc, _, me_body) = call_raw(&mut app_b, "GET", "/client/v4/account", vec![("authorization", &format!("Bearer {tok}"))], vec![]).await;
        assert_eq!(sc, StatusCode::OK);
        let me: Value = serde_json::from_slice(&me_body).unwrap();
        assert_eq!(me["result"]["email"], "sso@example.com");
        assert_eq!(me["result"]["role"], "editor");

        let _ = std::fs::remove_dir_all(dir_a);
        let _ = std::fs::remove_dir_all(dir_b);
    }

    /// A node without peers of its own (the hub the others pull from) still
    /// serves and accepts Workers KV and D1.
    #[tokio::test]
    async fn kv_and_d1_replicate_through_a_hub_without_peers() {
        let (dir_a, dir_b) = (
            std::env::temp_dir().join(format!("fucf-api-hub-a-{}", uuid::Uuid::new_v4().simple())),
            std::env::temp_dir().join(format!("fucf-api-hub-b-{}", uuid::Uuid::new_v4().simple())),
        );
        let (a, b) = (make_test_state(&dir_a, crate::sync::NodeRole::Peer), make_test_state(&dir_b, crate::sync::NodeRole::Peer));
        assert!(a.sync.is_none() && b.sync.is_none());
        let (mut app_a, mut app_b) = (router(a.clone()), router(b.clone()));
        let (sc, body) = call(&mut app_a, "POST", "/client/v4/kv/namespaces", br#"{"title":"AUTH_KV"}"#.to_vec()).await;
        assert_eq!(sc, StatusCode::OK);
        let ns = serde_json::from_slice::<Value>(&body).unwrap()["result"]["id"].as_str().unwrap().to_string();
        let (sc, _) = call(&mut app_a, "PUT", &format!("/client/v4/kv/namespaces/{ns}/values/k"), b"v".to_vec()).await;
        assert_eq!(sc, StatusCode::OK);
        let (sc, _) = call(&mut app_a, "POST", "/client/v4/d1/database", br#"{"name":"auth"}"#.to_vec()).await;
        assert_eq!(sc, StatusCode::OK);

        let (sc, _, body) = call_raw(
            &mut app_a,
            "GET",
            "/client/v4/replication/sync?since=0&since_accounts=0&domains=%7B%7D",
            vec![("authorization", "Bearer test-token")],
            vec![],
        )
        .await;
        assert_eq!(sc, StatusCode::OK);
        let pulled: Value = serde_json::from_slice(&body).unwrap();
        let domains = pulled["result"]["domains"].as_array().cloned().unwrap_or_default();
        assert_eq!(domains.len(), 2, "both KV and D1 are served: {pulled}");

        let push = serde_json::to_vec(&json!({ "node": "a", "role": "peer", "domains": domains })).unwrap();
        let (sc, _, body) = call_raw(
            &mut app_b,
            "POST",
            "/client/v4/replication/sync",
            vec![("authorization", "Bearer test-token"), ("content-type", "application/json")],
            push,
        )
        .await;
        assert_eq!(sc, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        let (_, body) = call(&mut app_b, "GET", "/client/v4/kv/namespaces", vec![]).await;
        assert!(String::from_utf8_lossy(&body).contains("AUTH_KV"), "{}", String::from_utf8_lossy(&body));
        let (_, body) = call(&mut app_b, "GET", &format!("/client/v4/kv/namespaces/{ns}/values/k"), vec![]).await;
        assert_eq!(body, b"v");
        let (_, body) = call(&mut app_b, "GET", "/client/v4/d1/database", vec![]).await;
        assert!(String::from_utf8_lossy(&body).contains("\"auth\""), "{}", String::from_utf8_lossy(&body));
        let _ = std::fs::remove_dir_all(dir_a);
        let _ = std::fs::remove_dir_all(dir_b);
    }

    #[tokio::test]
    async fn accelerate_sync_secret_and_write_isolation() {
        let dir = std::env::temp_dir().join(format!("fucf-api-iso-{}", uuid::Uuid::new_v4().simple()));
        let st = make_test_state(&dir, crate::sync::NodeRole::Peer);
        st.accounts.create_user("admin@example.com", Role::Admin, Some("strong-pass-123"), "admin@example.com", &Client::default()).unwrap();
        let mut app = router(st.clone());

        // Accelerate pull omits accounts_delta
        let (sc, _, b) = call_raw(
            &mut app,
            "GET",
            "/client/v4/replication/sync?since=0&since_accounts=0",
            vec![("authorization", "Bearer test-token"), ("x-fucf-node-role", "accelerate")],
            vec![],
        ).await;
        assert_eq!(sc, StatusCode::OK);
        let v: Value = serde_json::from_slice(&b).unwrap();
        assert!(v["result"]["accounts"].is_null(), "accelerate pull must omit accounts_delta");
        assert!(!v["result"]["config"].is_null(), "accelerate pull keeps config");

        // Accelerate push with config/accounts/domains is rejected with 403
        let push_body = serde_json::to_vec(&json!({
            "node": "accel-1",
            "role": "accelerate",
            "config": st.store.export_since_async(0, None).await.unwrap(),
        })).unwrap();
        let (sc, _, _) = call_raw(
            &mut app,
            "POST",
            "/client/v4/replication/sync",
            vec![("authorization", "Bearer test-token"), ("x-fucf-node-role", "accelerate"), ("content-type", "application/json")],
            push_body,
        ).await;
        assert_eq!(sc, StatusCode::FORBIDDEN);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn rulesets_answer_on_cloudflare_paths_and_tokens_need_the_phase_permission() {
        let dir = std::env::temp_dir().join(format!("fucf-api-rulesets-{}", uuid::Uuid::new_v4().simple()));
        let st = make_test_state(&dir, crate::sync::NodeRole::Peer);
        st.accounts.create_user("admin@example.com", Role::Admin, Some("strong-pass-123"), "admin@example.com", &Client::default()).unwrap();
        let session = match st.accounts.login("admin@example.com", "strong-pass-123", &Client::default()).unwrap() {
            Login::Session(token, _) => token,
            _ => panic!("expected signed in"),
        };
        let zone = st.store.create_zone("example.com").unwrap();
        let other = st.store.create_zone("example.net").unwrap();
        let mut app = router(st.clone());
        let json_of = |b: &[u8]| serde_json::from_slice::<Value>(b).unwrap();
        let as_session = format!("Bearer {session}");
        let z = zone.id.clone();
        let base = format!("/client/v4/zones/{z}/rulesets");

        // the fleet's own token can do everything
        let fw = json!({ "phase": "http_request_firewall_custom", "kind": "zone", "name": "default",
            "rules": [{ "action": "block", "expression": "ip.src eq 192.0.2.1" }] });
        let (sc, b) = call(&mut app, "POST", &base, fw.to_string().into_bytes()).await;
        assert_eq!(sc, StatusCode::OK, "{}", String::from_utf8_lossy(&b));
        let fw_id = json_of(&b)["result"]["id"].as_str().unwrap().to_string();
        let rule_id = json_of(&b)["result"]["rules"][0]["id"].as_str().unwrap().to_string();
        assert_eq!(st.store.items::<FirewallRule>(&z).unwrap()[0].meta.id, rule_id);
        let (sc, b) = call(&mut app, "GET", &base, vec![]).await;
        assert_eq!(sc, StatusCode::OK);
        assert_eq!(json_of(&b)["result"][0]["id"], json!(fw_id));
        let (sc, b) = call(&mut app, "GET", &format!("{base}/phases/http_request_firewall_custom/entrypoint"), vec![]).await;
        assert_eq!((sc, json_of(&b)["result"]["id"].clone()), (StatusCode::OK, json!(fw_id)));
        let (sc, b) = call(&mut app, "PATCH", &format!("{base}/{fw_id}/rules/{rule_id}"), br#"{"action":"log"}"#.to_vec()).await;
        assert_eq!((sc, json_of(&b)["result"]["rules"][0]["action"].clone()), (StatusCode::OK, json!("log")));
        let (sc, b) = call(&mut app, "GET", &format!("{base}/phases/http_request_firewall_managed/entrypoint"), vec![]).await;
        assert_eq!(sc, StatusCode::BAD_REQUEST, "{}", String::from_utf8_lossy(&b));
        let (sc, _) = call(&mut app, "GET", &format!("/client/v4/zones/{}/rulesets/{fw_id}", other.id), vec![]).await;
        assert_eq!(sc, StatusCode::NOT_FOUND, "a ruleset id belongs to one zone");
        let (sc, b) = call(&mut app, "PUT", &format!("{base}/{fw_id}"), br#"{"rules":[{"action":"nonsense","expression":"true"}]}"#.to_vec()).await;
        assert_eq!(sc, StatusCode::BAD_REQUEST);
        assert!(json_of(&b)["errors"][0]["message"].as_str().unwrap().contains("rules[0].action"));
        let (sc, _) = call(&mut app, "PUT", &format!("{base}/{fw_id}"), b"not json".to_vec()).await;
        assert_eq!(sc, StatusCode::BAD_REQUEST);

        // a token for the firewall of this zone only
        let spec = json!({
            "name": "firewall only",
            "policies": [{
                "effect": "allow",
                "resources": { format!("com.cloudflare.api.account.zone.{z}"): "*" },
                "permission_groups": [{ "name": "Firewall Services Write" }],
            }],
        });
        let (sc, _, b) = call_raw(&mut app, "POST", "/client/v4/user/tokens", vec![("authorization", &as_session), ("content-type", "application/json")], spec.to_string().into_bytes()).await;
        assert_eq!(sc, StatusCode::OK, "{}", String::from_utf8_lossy(&b));
        let bearer = format!("Bearer {}", json_of(&b)["result"]["value"].as_str().unwrap());
        let auth = || vec![("authorization", bearer.as_str()), ("content-type", "application/json")];
        let transform = json!({ "phase": "http_request_late_transform",
            "rules": [{ "action": "rewrite", "expression": "true", "action_parameters": { "headers": { "x-a": { "operation": "set", "value": "1" } } } }] });

        let (sc, _, _) = call_raw(&mut app, "GET", &base, auth(), vec![]).await;
        assert_eq!(sc, StatusCode::OK);
        let (sc, _, _) = call_raw(&mut app, "DELETE", &format!("{base}/{fw_id}/rules/{rule_id}"), auth(), vec![]).await;
        assert_eq!(sc, StatusCode::OK);
        let (sc, _, _) = call_raw(&mut app, "POST", &base, auth(), transform.to_string().into_bytes()).await;
        assert_eq!(sc, StatusCode::FORBIDDEN, "creating a transform ruleset needs the transform permission too");
        let (sc, _, _) = call_raw(&mut app, "PUT", &format!("{base}/phases/http_request_late_transform/entrypoint"), auth(), json!({ "rules": [] }).to_string().into_bytes()).await;
        assert_eq!(sc, StatusCode::FORBIDDEN);
        let late = crate::rulesets::ruleset_id(&z, "http_request_late_transform");
        let (sc, _, _) = call_raw(&mut app, "GET", &format!("{base}/{late}"), auth(), vec![]).await;
        assert_eq!(sc, StatusCode::FORBIDDEN, "by id too");
        let (sc, _, _) = call_raw(&mut app, "GET", &format!("/client/v4/zones/{}/rulesets", other.id), auth(), vec![]).await;
        assert_eq!(sc, StatusCode::FORBIDDEN, "another zone");
        assert!(st.store.items::<TransformRule>(&z).unwrap().is_empty());

        // a token for transform rules only: its phase yes, creating through the firewall-only path no
        let spec = json!({
            "name": "transform only",
            "policies": [{
                "effect": "allow",
                "resources": { format!("com.cloudflare.api.account.zone.{z}"): "*" },
                "permission_groups": [{ "name": "Transform Rules Write" }],
            }],
        });
        let (sc, _, b) = call_raw(&mut app, "POST", "/client/v4/user/tokens", vec![("authorization", &as_session), ("content-type", "application/json")], spec.to_string().into_bytes()).await;
        assert_eq!(sc, StatusCode::OK);
        let bearer2 = format!("Bearer {}", json_of(&b)["result"]["value"].as_str().unwrap());
        let auth2 = || vec![("authorization", bearer2.as_str()), ("content-type", "application/json")];
        let (sc, _, _) = call_raw(&mut app, "POST", &base, auth2(), transform.to_string().into_bytes()).await;
        assert_eq!(sc, StatusCode::FORBIDDEN);
        let (sc, _, b) = call_raw(&mut app, "PUT", &format!("{base}/phases/http_request_late_transform/entrypoint"), auth2(), transform.to_string().into_bytes()).await;
        assert_eq!(sc, StatusCode::OK, "{}", String::from_utf8_lossy(&b));
        let (sc, _, _) = call_raw(&mut app, "GET", &format!("{base}/{fw_id}"), auth2(), vec![]).await;
        assert_eq!(sc, StatusCode::FORBIDDEN);
        assert_eq!(st.store.items::<TransformRule>(&z).unwrap().len(), 1);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn waiting_rooms_are_managed_per_zone_and_need_their_own_permission() {
        let dir = std::env::temp_dir().join(format!("fucf-api-waiting-{}", uuid::Uuid::new_v4().simple()));
        let st = make_test_state(&dir, crate::sync::NodeRole::Peer);
        st.accounts.create_user("admin@example.com", Role::Admin, Some("strong-pass-123"), "admin@example.com", &Client::default()).unwrap();
        st.accounts.create_user("viewer@example.com", Role::Viewer, Some("strong-pass-123"), "viewer@example.com", &Client::default()).unwrap();
        let session = |email: &str| match st.accounts.login(email, "strong-pass-123", &Client::default()).unwrap() {
            Login::Session(token, _) => format!("Bearer {token}"),
            _ => panic!("expected signed in"),
        };
        let (admin, viewer) = (session("admin@example.com"), session("viewer@example.com"));
        let zone = st.store.create_zone("example.com").unwrap();
        let other = st.store.create_zone("example.net").unwrap();
        let z = zone.id.clone();
        let mut app = router(st.clone());
        let json_of = |b: &[u8]| serde_json::from_slice::<Value>(b).unwrap();
        let rooms = format!("/client/v4/zones/{z}/waiting_rooms");
        let room = json!({ "name": "shop", "host": "www.example.com", "path_prefix": "/shop", "total_active_users": 100, "new_users_per_minute": 20, "session_minutes": 10 });

        let (sc, b) = call(&mut app, "POST", &rooms, room.to_string().into_bytes()).await;
        assert_eq!(sc, StatusCode::OK, "{}", String::from_utf8_lossy(&b));
        let r = json_of(&b)["result"].clone();
        let id = r["id"].as_str().unwrap().to_string();
        assert_eq!((r["zone_id"].clone(), r["enabled"].clone(), r["session_minutes"].clone()), (json!(z), json!(true), json!(10)));
        assert!(r.get("sync").is_none());
        let (sc, b) = call(&mut app, "POST", &rooms, room.to_string().into_bytes()).await;
        assert_eq!(sc, StatusCode::CONFLICT, "one enabled room per host and path: {}", String::from_utf8_lossy(&b));
        for bad in [
            b"not json".to_vec(),
            json!({ "name": "x", "host": "www.example.net", "total_active_users": 1, "new_users_per_minute": 1 }).to_string().into_bytes(),
            json!({ "name": "x", "host": "example.com", "path_prefix": "x", "total_active_users": 1, "new_users_per_minute": 1 }).to_string().into_bytes(),
            json!({ "name": "x", "host": "example.com", "total_active_users": 1, "new_users_per_minute": 2 }).to_string().into_bytes(),
        ] {
            let (sc, b) = call(&mut app, "POST", &rooms, bad).await;
            assert_eq!(sc, StatusCode::BAD_REQUEST, "{}", String::from_utf8_lossy(&b));
        }
        let (_, b) = call(&mut app, "GET", &rooms, vec![]).await;
        assert_eq!(json_of(&b)["result"].as_array().unwrap().len(), 1);
        let (sc, b) = call(&mut app, "PATCH", &format!("{rooms}/{id}"), br#"{"enabled":false}"#.to_vec()).await;
        assert_eq!(sc, StatusCode::OK);
        assert_eq!((json_of(&b)["result"]["enabled"].clone(), json_of(&b)["result"]["path_prefix"].clone()), (json!(false), json!("/shop")));
        assert!(st.store.snapshot().zones["example.com"].waiting_rooms.is_empty(), "a disabled room is not served");
        let (sc, _) = call(&mut app, "PUT", &format!("{rooms}/{id}"), json!({ "name": "only a name" }).to_string().into_bytes()).await;
        assert_eq!(sc, StatusCode::BAD_REQUEST, "a replace needs the limits again");
        let (sc, _) = call(&mut app, "GET", &format!("/client/v4/zones/{}/waiting_rooms/{id}", other.id), vec![]).await;
        assert_eq!(sc, StatusCode::NOT_FOUND, "a room belongs to one zone");
        let (sc, _) = call(&mut app, "DELETE", &format!("/client/v4/zones/{}/waiting_rooms/{id}", other.id), vec![]).await;
        assert_eq!(sc, StatusCode::NOT_FOUND);
        let (sc, _) = call(&mut app, "GET", &format!("{rooms}/no-such-room"), vec![]).await;
        assert_eq!(sc, StatusCode::NOT_FOUND);
        let (sc, _) = call(&mut app, "GET", "/client/v4/zones/no-such-zone/waiting_rooms", vec![]).await;
        assert_eq!(sc, StatusCode::NOT_FOUND);

        // panel roles: a viewer reads, does not write
        give(&st, &z, "viewer@example.com").await;
        let h = vec![("authorization", viewer.as_str()), ("content-type", "application/json")];
        let (sc, _, _) = call_raw(&mut app, "GET", &rooms, h.clone(), vec![]).await;
        assert_eq!(sc, StatusCode::OK);
        let (sc, _, _) = call_raw(&mut app, "DELETE", &format!("{rooms}/{id}"), h, vec![]).await;
        assert_eq!(sc, StatusCode::FORBIDDEN);

        // tokens: neither firewall nor zone settings will do; reading is not writing; one zone is not another
        let mut token = async |group: &str| {
            let spec = json!({
                "name": group,
                "policies": [{ "effect": "allow", "resources": { format!("com.cloudflare.api.account.zone.{z}"): "*" }, "permission_groups": [{ "name": group }] }],
            });
            let h = vec![("authorization", admin.as_str()), ("content-type", "application/json")];
            let (sc, _, b) = call_raw(&mut app, "POST", "/client/v4/user/tokens", h, spec.to_string().into_bytes()).await;
            assert_eq!(sc, StatusCode::OK, "{}", String::from_utf8_lossy(&b));
            format!("Bearer {}", json_of(&b)["result"]["value"].as_str().unwrap())
        };
        let firewall = token("Firewall Services Write").await;
        let settings = token("Zone Settings Write").await;
        let read = token("Waiting Rooms Read").await;
        let write = token("Waiting Rooms Write").await;
        let mut as_token = async |bearer: &str, method: &str, path: &str, body: Vec<u8>| {
            call_raw(&mut app, method, path, vec![("authorization", bearer), ("content-type", "application/json")], body).await.0
        };
        let new_room = json!({ "name": "blog", "host": "example.com", "path_prefix": "/blog", "total_active_users": 5, "new_users_per_minute": 5 }).to_string();
        for bearer in [&firewall, &settings] {
            assert_eq!(as_token(bearer, "GET", &rooms, vec![]).await, StatusCode::FORBIDDEN);
            assert_eq!(as_token(bearer, "POST", &rooms, new_room.clone().into_bytes()).await, StatusCode::FORBIDDEN);
        }
        assert_eq!(as_token(&read, "GET", &rooms, vec![]).await, StatusCode::OK);
        assert_eq!(as_token(&read, "GET", &format!("{rooms}/{id}"), vec![]).await, StatusCode::OK);
        assert_eq!(as_token(&read, "POST", &rooms, new_room.clone().into_bytes()).await, StatusCode::FORBIDDEN);
        assert_eq!(as_token(&read, "PATCH", &format!("{rooms}/{id}"), br#"{"enabled":true}"#.to_vec()).await, StatusCode::FORBIDDEN);
        assert_eq!(as_token(&read, "DELETE", &format!("{rooms}/{id}"), vec![]).await, StatusCode::FORBIDDEN);
        assert_eq!(as_token(&write, "GET", &format!("/client/v4/zones/{}/waiting_rooms", other.id), vec![]).await, StatusCode::FORBIDDEN, "another zone");
        assert_eq!(as_token(&write, "POST", &rooms, new_room.clone().into_bytes()).await, StatusCode::OK);
        assert_eq!(as_token(&write, "DELETE", &format!("{rooms}/{id}"), vec![]).await, StatusCode::OK);
        assert_eq!(st.store.items::<crate::edge::waiting::WaitingRoom>(&z).unwrap().len(), 1);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn custom_hostnames_belong_to_one_zone_of_one_user_and_need_the_ssl_permission() {
        let dir = std::env::temp_dir().join(format!("fucf-api-custom-hosts-{}", uuid::Uuid::new_v4().simple()));
        let st = make_test_state(&dir, crate::sync::NodeRole::Peer);
        for (email, role) in [("admin@example.com", Role::Admin), ("alice@example.com", Role::Editor), ("bob@example.com", Role::Editor), ("viewer@example.com", Role::Viewer)] {
            st.accounts.create_user(email, role, Some("strong-pass-123"), email, &Client::default()).unwrap();
        }
        let session = |email: &str| match st.accounts.login(email, "strong-pass-123", &Client::default()).unwrap() {
            Login::Session(token, _) => format!("Bearer {token}"),
            _ => panic!("expected signed in"),
        };
        let mut app = router(st.clone());
        let json_of = |b: &[u8]| serde_json::from_slice::<Value>(b).unwrap();
        let alice_zone = st.store.create_zone("example.com").unwrap().id;
        let bob_zone = st.store.create_zone("example.org").unwrap().id;
        let partial = st.store.create_zone_as("partial.example.net", "partial").unwrap().id;
        give(&st, &alice_zone, "alice@example.com").await;
        give(&st, &bob_zone, "bob@example.com").await;
        let (alice, bob, admin, viewer) = (session("alice@example.com"), session("bob@example.com"), session("admin@example.com"), session("viewer@example.com"));
        let mut ask = async |bearer: &str, method: &str, path: &str, body: Value| {
            let body = if body.is_null() { vec![] } else { body.to_string().into_bytes() };
            let (sc, _, b) = call_raw(&mut app, method, &format!("/client/v4{path}"), vec![("authorization", bearer), ("content-type", "application/json")], body).await;
            (sc, b)
        };
        let hosts = format!("/zones/{alice_zone}/custom_hostnames");

        let (sc, b) = ask(&alice, "POST", &hosts, json!({ "hostname": "Shop.Example.Info", "status": "active", "certificate": "x" })).await;
        assert_eq!(sc, StatusCode::OK, "{}", String::from_utf8_lossy(&b));
        let h = json_of(&b)["result"].clone();
        let id = h["id"].as_str().unwrap().to_string();
        assert_eq!((h["hostname"].clone(), h["status"].clone(), h.get("certificate")), (json!("shop.example.info"), json!("pending"), None));
        let token = h["verify_txt"].as_str().unwrap();
        assert_eq!(h["dcv_delegation"], json!({ "type": "CNAME", "name": "_acme-challenge.shop.example.info", "content": format!("_acme-challenge.{token}.example.com") }));
        assert!(h.get("private_key").is_none() && h.get("sync").is_none());

        // names: one owner across zones and users, no zone's, nothing that is no public host name
        for (bearer, path, name, want) in [
            (&bob, format!("/zones/{bob_zone}/custom_hostnames"), "shop.example.info", StatusCode::CONFLICT),
            (&alice, hosts.clone(), "www.example.org", StatusCode::CONFLICT),
            (&alice, hosts.clone(), "a.partial.example.net", StatusCode::CONFLICT),
            (&alice, hosts.clone(), "example.net", StatusCode::CONFLICT),
            (&alice, hosts.clone(), "198.51.100.7", StatusCode::BAD_REQUEST),
            (&alice, hosts.clone(), "*.example.info", StatusCode::BAD_REQUEST),
            (&alice, hosts.clone(), "shop.test", StatusCode::BAD_REQUEST),
            (&admin, format!("/zones/{partial}/custom_hostnames"), "p.example.info", StatusCode::BAD_REQUEST),
        ] {
            let (sc, b) = ask(bearer, "POST", &path, json!({ "hostname": name })).await;
            assert_eq!(sc, want, "{name}: {}", String::from_utf8_lossy(&b));
        }
        let (sc, _) = ask(&alice, "POST", &hosts, Value::Null).await;
        assert_eq!(sc, StatusCode::BAD_REQUEST, "no body");

        // PATCH changes the origin only; there is no PUT
        let (sc, b) = ask(&alice, "PATCH", &format!("{hosts}/{id}"), json!({ "custom_origin_server": "www.example.com", "status": "active", "verify_txt": "mine" })).await;
        assert_eq!(sc, StatusCode::OK, "{}", String::from_utf8_lossy(&b));
        assert_eq!((json_of(&b)["result"]["cname_target"].clone(), json_of(&b)["result"]["status"].clone(), json_of(&b)["result"]["verify_txt"].clone()), (json!("www.example.com"), json!("pending"), json!(token)));
        let (sc, _) = ask(&alice, "PATCH", &format!("{hosts}/{id}"), json!({ "hostname": "other.example.info" })).await;
        assert_eq!(sc, StatusCode::BAD_REQUEST);
        let (sc, _) = ask(&alice, "PUT", &format!("{hosts}/{id}"), json!({ "hostname": "shop.example.info" })).await;
        assert_eq!(sc, StatusCode::METHOD_NOT_ALLOWED);
        let (sc, b) = ask(&alice, "GET", &hosts, Value::Null).await;
        assert_eq!((sc, json_of(&b)["result"].as_array().unwrap().len()), (StatusCode::OK, 1));

        // another user's zone is not there for them, under any id
        let (sc, _) = ask(&bob, "GET", &hosts, Value::Null).await;
        assert_eq!(sc, StatusCode::NOT_FOUND);
        for (method, path) in [("GET", format!("{hosts}/{id}")), ("PATCH", format!("{hosts}/{id}")), ("DELETE", format!("{hosts}/{id}")), ("POST", hosts.clone())] {
            let (sc, _) = ask(&bob, method, &path, json!({ "hostname": "bob.example.info" })).await;
            assert_eq!(sc, StatusCode::NOT_FOUND, "{method} {path}");
        }
        for (method, path) in [("GET", format!("/zones/{bob_zone}/custom_hostnames/{id}")), ("DELETE", format!("/zones/{bob_zone}/custom_hostnames/{id}"))] {
            let (sc, _) = ask(&bob, method, &path, Value::Null).await;
            assert_eq!(sc, StatusCode::NOT_FOUND, "an id of another zone in one's own: {method}");
        }

        // a viewer of the zone reads and does not write
        give(&st, &alice_zone, "viewer@example.com").await;
        let (sc, _) = ask(&viewer, "GET", &hosts, Value::Null).await;
        assert_eq!(sc, StatusCode::OK);
        for (method, path) in [("POST", hosts.clone()), ("PATCH", format!("{hosts}/{id}")), ("DELETE", format!("{hosts}/{id}"))] {
            let (sc, _) = ask(&viewer, method, &path, json!({ "hostname": "v.example.info" })).await;
            assert_eq!(sc, StatusCode::FORBIDDEN, "{method}");
        }

        // tokens: the SSL permission, read is not write
        let mut token = async |group: &str| {
            let spec = json!({
                "name": group,
                "policies": [{ "effect": "allow", "resources": { format!("com.cloudflare.api.account.zone.{alice_zone}"): "*" }, "permission_groups": [{ "name": group }] }],
            });
            let (sc, b) = ask(&admin, "POST", "/user/tokens", spec).await;
            assert_eq!(sc, StatusCode::OK, "{}", String::from_utf8_lossy(&b));
            format!("Bearer {}", json_of(&b)["result"]["value"].as_str().unwrap())
        };
        let dns = token("DNS Write").await;
        let read = token("SSL and Certificates Read").await;
        let write = token("SSL and Certificates Write").await;
        let new = json!({ "hostname": "api.example.info" });
        assert_eq!(ask(&dns, "GET", &hosts, Value::Null).await.0, StatusCode::FORBIDDEN);
        assert_eq!(ask(&read, "GET", &hosts, Value::Null).await.0, StatusCode::OK);
        assert_eq!(ask(&read, "POST", &hosts, new.clone()).await.0, StatusCode::FORBIDDEN);
        assert_eq!(ask(&write, "GET", &format!("/zones/{bob_zone}/custom_hostnames"), Value::Null).await.0, StatusCode::FORBIDDEN, "another zone");
        assert_eq!(ask(&write, "POST", &hosts, new).await.0, StatusCode::OK);
        assert_eq!(ask(&write, "DELETE", &format!("{hosts}/{id}"), Value::Null).await.0, StatusCode::OK);
        assert_eq!(st.store.items::<crate::custom_hostnames::CustomHostname>(&alice_zone).unwrap().len(), 1);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn the_request_log_answers_per_zone_and_needs_the_logs_permission() {
        use crate::edge::reqlog::sample;
        let dir = std::env::temp_dir().join(format!("fucf-api-reqlog-{}", uuid::Uuid::new_v4().simple()));
        let st = make_test_state(&dir, crate::sync::NodeRole::Peer);
        st.accounts.create_user("admin@example.com", Role::Admin, Some("strong-pass-123"), "admin@example.com", &Client::default()).unwrap();
        st.accounts.create_user("editor@example.com", Role::Editor, Some("strong-pass-123"), "editor@example.com", &Client::default()).unwrap();
        st.accounts.create_user("viewer@example.com", Role::Viewer, Some("strong-pass-123"), "viewer@example.com", &Client::default()).unwrap();
        let session = |email: &str| match st.accounts.login(email, "strong-pass-123", &Client::default()).unwrap() {
            Login::Session(token, _) => format!("Bearer {token}"),
            _ => panic!("expected signed in"),
        };
        let (admin, editor, viewer) = (session("admin@example.com"), session("editor@example.com"), session("viewer@example.com"));
        let zone = st.store.create_zone("example.com").unwrap();
        let other = st.store.create_zone("example.net").unwrap();
        let z = zone.id.clone();
        st.edge.reqlog.push(sample(&z, 404, "/a"));
        st.edge.reqlog.push(sample(&other.id, 500, "/b"));
        st.edge.reqlog.push(sample(&z, 200, "/c"));
        let mut app = router(st.clone());
        let json_of = |b: &[u8]| serde_json::from_slice::<Value>(b).unwrap();
        let logs = format!("/client/v4/zones/{z}/logs/requests");

        let (sc, b) = call(&mut app, "GET", &logs, vec![]).await;
        assert_eq!(sc, StatusCode::OK, "{}", String::from_utf8_lossy(&b));
        let r = &json_of(&b)["result"];
        assert_eq!(r["entries"].as_array().unwrap().iter().map(|e| e["path"].clone()).collect::<Vec<_>>(), vec![json!("/a"), json!("/c")], "only this zone");
        assert_eq!((r["cursor"].clone(), r["gap"].clone()), (json!(3), json!(false)));
        assert!(r["node"].is_string());
        assert_eq!(r["entries"][0]["client_ip"], "192.0.2.10");
        let (_, b) = call(&mut app, "GET", &format!("{logs}?status=4xx"), vec![]).await;
        assert_eq!(json_of(&b)["result"]["entries"].as_array().unwrap().len(), 1);
        let (_, b) = call(&mut app, "GET", &format!("{logs}?since=1&path=/c"), vec![]).await;
        assert_eq!(json_of(&b)["result"]["entries"][0]["seq"], 3);
        for since in ["3", "99"] {
            let (sc, b) = call(&mut app, "GET", &format!("{logs}?since={since}"), vec![]).await;
            assert_eq!(sc, StatusCode::OK);
            assert_eq!((json_of(&b)["result"]["entries"].as_array().unwrap().len(), json_of(&b)["result"]["cursor"].clone()), (0, json!(3)), "since={since}");
        }
        for bad in ["limit=0", "limit=1001", "status=abc", "status=", "since=-1", "since=x", "ip=nope", "path=c", "host=a%20b", "foo=1"] {
            let (sc, b) = call(&mut app, "GET", &format!("{logs}?{bad}"), vec![]).await;
            assert_eq!(sc, StatusCode::BAD_REQUEST, "{bad}: {}", String::from_utf8_lossy(&b));
        }
        let (sc, _) = call(&mut app, "GET", "/client/v4/zones/no-such-zone/logs/requests", vec![]).await;
        assert_eq!(sc, StatusCode::NOT_FOUND);

        // log jobs
        let jobs = format!("/client/v4/zones/{z}/logpush/jobs");
        let (sc, _) = call(&mut app, "POST", &jobs, json!({ "name": "j", "destination": "http://logs.example.com/in" }).to_string().into_bytes()).await;
        assert_eq!(sc, StatusCode::BAD_REQUEST, "plain http is refused");
        let (sc, _) = call(&mut app, "POST", &jobs, b"not json".to_vec()).await;
        assert_eq!(sc, StatusCode::BAD_REQUEST);
        let (sc, b) = call(&mut app, "POST", &jobs, json!({ "name": "errors", "destination": "https://logs.example.com/in", "status_min": 500 }).to_string().into_bytes()).await;
        assert_eq!(sc, StatusCode::OK, "{}", String::from_utf8_lossy(&b));
        let job_id = json_of(&b)["result"]["id"].as_str().unwrap().to_string();
        assert_eq!(json_of(&b)["result"]["zone_id"], json!(z));
        let (_, b) = call(&mut app, "GET", &jobs, vec![]).await;
        assert_eq!(json_of(&b)["result"].as_array().unwrap().len(), 1);
        let (sc, _) = call(&mut app, "GET", &format!("/client/v4/zones/{}/logpush/jobs/{job_id}", other.id), vec![]).await;
        assert_eq!(sc, StatusCode::NOT_FOUND, "a job belongs to one zone");
        let (sc, _) = call(&mut app, "PATCH", &format!("{jobs}/{job_id}"), br#"{"batch_seconds":1}"#.to_vec()).await;
        assert_eq!(sc, StatusCode::BAD_REQUEST);

        // panel roles: everyone who sees the zone reads the log, only admins send it elsewhere
        let with = |bearer: &str| vec![("authorization", bearer.to_string()), ("content-type", "application/json".to_string())];
        let new_job = json!({ "name": "x", "destination": "https://logs.example.com/x" }).to_string();
        for (bearer, email) in [(&viewer, "viewer@example.com"), (&editor, "editor@example.com")] {
            give(&st, &z, email).await;
            let h = with(bearer);
            let h: Vec<(&str, &str)> = h.iter().map(|(k, v)| (*k, v.as_str())).collect();
            let (sc, _, _) = call_raw(&mut app, "GET", &logs, h.clone(), vec![]).await;
            assert_eq!(sc, StatusCode::OK);
            let (sc, _, _) = call_raw(&mut app, "POST", &jobs, h.clone(), new_job.clone().into_bytes()).await;
            assert_eq!(sc, StatusCode::FORBIDDEN);
            let (sc, _, _) = call_raw(&mut app, "DELETE", &format!("{jobs}/{job_id}"), h, vec![]).await;
            assert_eq!(sc, StatusCode::FORBIDDEN);
        }

        // tokens: analytics is not enough, logs is per zone, writing needs Logs Write
        let mut token = async |group: &str| {
            let spec = json!({
                "name": group,
                "policies": [{ "effect": "allow", "resources": { format!("com.cloudflare.api.account.zone.{z}"): "*" }, "permission_groups": [{ "name": group }] }],
            });
            let h = vec![("authorization", admin.as_str()), ("content-type", "application/json")];
            let (sc, _, b) = call_raw(&mut app, "POST", "/client/v4/user/tokens", h, spec.to_string().into_bytes()).await;
            assert_eq!(sc, StatusCode::OK, "{}", String::from_utf8_lossy(&b));
            format!("Bearer {}", json_of(&b)["result"]["value"].as_str().unwrap())
        };
        let analytics = token("Analytics Read").await;
        let read = token("Logs Read").await;
        let write = token("Logs Write").await;
        let mut as_token = async |bearer: &str, method: &str, path: &str, body: Vec<u8>| {
            call_raw(&mut app, method, path, vec![("authorization", bearer), ("content-type", "application/json")], body).await.0
        };
        assert_eq!(as_token(&analytics, "GET", &logs, vec![]).await, StatusCode::FORBIDDEN, "visitor addresses need the logs permission");
        assert_eq!(as_token(&read, "GET", &logs, vec![]).await, StatusCode::OK);
        assert_eq!(as_token(&read, "GET", &jobs, vec![]).await, StatusCode::OK);
        assert_eq!(as_token(&read, "GET", &format!("/client/v4/zones/{}/logs/requests", other.id), vec![]).await, StatusCode::FORBIDDEN, "another zone");
        assert_eq!(as_token(&read, "POST", &jobs, new_job.clone().into_bytes()).await, StatusCode::FORBIDDEN);
        assert_eq!(as_token(&write, "POST", &jobs, new_job.clone().into_bytes()).await, StatusCode::OK);
        assert_eq!(as_token(&write, "DELETE", &format!("{jobs}/{job_id}"), vec![]).await, StatusCode::OK);
        assert_eq!(st.store.items::<crate::edge::reqlog::LogJob>(&z).unwrap().len(), 1);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn cloudflare_style_tokens_keys_and_dns() {
        let dir = std::env::temp_dir().join(format!("fucf-api-tokens-{}", uuid::Uuid::new_v4().simple()));
        let st = make_test_state(&dir, crate::sync::NodeRole::Peer);
        st.accounts.create_user("admin@example.com", Role::Admin, Some("strong-pass-123"), "admin@example.com", &Client::default()).unwrap();
        let session = match st.accounts.login("admin@example.com", "strong-pass-123", &Client::default()).unwrap() {
            Login::Session(token, _) => token,
            _ => panic!("expected signed in"),
        };
        let one = st.store.create_zone("example.com").unwrap();
        let other = st.store.create_zone("example.org").unwrap();
        let mut app = router(st.clone());
        let json_of = |b: &[u8]| serde_json::from_slice::<Value>(b).unwrap();
        let as_session = format!("Bearer {session}");

        // a token for DNS on one zone only
        let spec = json!({
            "name": "certbot",
            "policies": [{
                "effect": "allow",
                "resources": { format!("com.cloudflare.api.account.zone.{}", one.id): "*" },
                "permission_groups": [{ "name": "Zone Read" }, { "id": "4755a26eedb94da69e1066d98aa820be" }],
            }],
        });
        let (sc, _, b) = call_raw(
            &mut app,
            "POST",
            "/client/v4/user/tokens",
            vec![("authorization", &as_session), ("content-type", "application/json")],
            spec.to_string().into_bytes(),
        )
        .await;
        assert_eq!(sc, StatusCode::OK, "{}", String::from_utf8_lossy(&b));
        let created = json_of(&b)["result"].clone();
        let value = created["value"].as_str().unwrap().to_string();
        let token_id = created["id"].as_str().unwrap().to_string();
        let bearer = format!("Bearer {value}");
        let auth = || vec![("authorization", bearer.as_str()), ("content-type", "application/json")];

        let (sc, _, b) = call_raw(&mut app, "GET", "/client/v4/user/tokens/verify", auth(), vec![]).await;
        assert_eq!((sc, json_of(&b)["result"]["id"].as_str()), (StatusCode::OK, Some(token_id.as_str())));
        let (sc, _, b) = call_raw(&mut app, "GET", "/client/v4/zones", auth(), vec![]).await;
        assert_eq!(sc, StatusCode::OK);
        let zones = json_of(&b)["result"].clone();
        assert_eq!(zones.as_array().unwrap().len(), 1, "only the zone the token names: {zones}");
        assert_eq!(zones[0]["account"]["id"], crate::tokens::account_id());

        let rec = json!({ "type": "TXT", "name": "_acme-challenge", "content": "\"abc\"", "ttl": 120 });
        let uri = format!("/client/v4/zones/{}/dns_records", one.id);
        let (sc, _, b) = call_raw(&mut app, "POST", &uri, auth(), rec.to_string().into_bytes()).await;
        assert_eq!(sc, StatusCode::OK, "{}", String::from_utf8_lossy(&b));
        let other_uri = format!("/client/v4/zones/{}/dns_records", other.id);
        let (sc, _, _) = call_raw(&mut app, "POST", &other_uri, auth(), rec.to_string().into_bytes()).await;
        assert_eq!(sc, StatusCode::FORBIDDEN, "not on another zone");
        let (sc, _, _) = call_raw(&mut app, "POST", &format!("/client/v4/zones/{}/purge_cache", one.id), auth(), b"{}".to_vec()).await;
        assert_eq!(sc, StatusCode::FORBIDDEN, "no cache purge in the token");
        let (sc, _, _) = call_raw(&mut app, "GET", "/client/v4/users", auth(), vec![]).await;
        assert_eq!(sc, StatusCode::FORBIDDEN, "users are never for tokens");
        let (sc, _, _) = call_raw(&mut app, "POST", "/client/v4/account/password", auth(), b"{}".to_vec()).await;
        assert_eq!(sc, StatusCode::FORBIDDEN);

        // proxied, with an own origin port, and SRV through `data`
        let proxied = json!({ "type": "A", "name": "www", "content": "192.0.2.10", "proxied": true, "origin": { "port": 8443, "scheme": "https" } });
        let (sc, _, b) = call_raw(&mut app, "POST", &uri, auth(), proxied.to_string().into_bytes()).await;
        assert_eq!(sc, StatusCode::OK, "{}", String::from_utf8_lossy(&b));
        let www = json_of(&b)["result"].clone();
        assert_eq!((www["proxied"].as_bool(), www["origin"]["port"].as_u64()), (Some(true), Some(8443)));
        let srv = json!({ "type": "SRV", "name": "_sip._tcp", "data": { "priority": 10, "weight": 5, "port": 5060, "target": "sip.example.com" } });
        let (sc, _, b) = call_raw(&mut app, "POST", &uri, auth(), srv.to_string().into_bytes()).await;
        assert_eq!(sc, StatusCode::OK, "{}", String::from_utf8_lossy(&b));
        assert_eq!(json_of(&b)["result"]["priority"], 10);

        // filters
        let (_, _, b) = call_raw(&mut app, "GET", &format!("{uri}?name.startswith=www&proxied=true"), auth(), vec![]).await;
        assert_eq!(json_of(&b)["result"].as_array().unwrap().len(), 1);
        let (_, _, b) = call_raw(&mut app, "GET", &format!("{uri}?type=TXT&type=A&match=any&name.contains=acme"), auth(), vec![]).await;
        assert!(!json_of(&b)["result"].as_array().unwrap().is_empty());
        let (_, _, b) = call_raw(&mut app, "GET", &format!("{uri}?order=type&direction=desc"), auth(), vec![]).await;
        assert_eq!(json_of(&b)["result"][0]["type"], "TXT");

        // batch: drop the TXT, move www, add one
        let txt_id = {
            let (_, _, b) = call_raw(&mut app, "GET", &format!("{uri}?type=TXT"), auth(), vec![]).await;
            json_of(&b)["result"][0]["id"].as_str().unwrap().to_string()
        };
        let batch = json!({
            "deletes": [{ "id": txt_id }],
            "patches": [{ "id": www["id"], "content": "192.0.2.11" }],
            "posts": [{ "type": "AAAA", "name": "v6", "content": "2001:db8::1" }],
        });
        let (sc, _, b) = call_raw(&mut app, "POST", &format!("{uri}/batch"), auth(), batch.to_string().into_bytes()).await;
        assert_eq!(sc, StatusCode::OK, "{}", String::from_utf8_lossy(&b));
        let done = json_of(&b)["result"].clone();
        assert_eq!((done["deletes"].as_array().unwrap().len(), done["patches"][0]["content"].as_str(), done["posts"].as_array().unwrap().len()), (1, Some("192.0.2.11"), 1));
        let (sc, _, b) = call_raw(&mut app, "POST", &format!("{uri}/batch"), auth(), json!({ "deletes": [{ "id": "nope" }] }).to_string().into_bytes()).await;
        assert_eq!(sc, StatusCode::BAD_REQUEST, "{}", String::from_utf8_lossy(&b));

        // export, and import into the other zone (as the admin's session)
        let (sc, _, b) = call_raw(&mut app, "GET", &format!("{uri}/export"), auth(), vec![]).await;
        let file = String::from_utf8(b).unwrap();
        assert_eq!(sc, StatusCode::OK);
        assert!(file.contains("www.example.com.\t300\tIN\tA\t192.0.2.11 ; cf_tags=cf-proxied:true"), "{file}");
        assert!(file.contains("_sip._tcp.example.com.\t300\tIN\tSRV\t10 5 5060 sip.example.com."), "{file}");
        let imported = "$ORIGIN example.org.\n$TTL 3600\n@ IN SOA ns1 hostmaster ( 1 ; serial\n 7200 3600 1209600 300 )\nwww 300 IN A 192.0.2.20 ; cf_tags=cf-proxied:true\n  IN TXT \"a;b\" ; note\nmail IN MX 10 mx.example.net.\nx IN LOC 1 2 3\n";
        let multipart = format!("--XyZ\r\nContent-Disposition: form-data; name=\"file\"; filename=\"z.txt\"\r\nContent-Type: text/plain\r\n\r\n{imported}\r\n--XyZ--\r\n");
        let (sc, _, b) = call_raw(
            &mut app,
            "POST",
            &format!("{other_uri}/import"),
            vec![("authorization", &as_session), ("content-type", "multipart/form-data; boundary=XyZ")],
            multipart.into_bytes(),
        )
        .await;
        assert_eq!(sc, StatusCode::OK, "{}", String::from_utf8_lossy(&b));
        let res = json_of(&b);
        assert_eq!((res["result"]["recs_added"].as_u64(), res["result"]["total_records_parsed"].as_u64()), (Some(3), Some(4)), "{res}");
        let (_, recs) = st.store.list_records(&other.id).unwrap();
        let www_org = recs.iter().find(|r| r.name == "www.example.org").unwrap();
        assert!(www_org.proxied && www_org.ttl == 300);
        let txt = recs.iter().find(|r| r.rtype == "TXT").unwrap();
        assert_eq!((txt.name.as_str(), txt.ttl, txt.comment.as_deref()), ("www.example.org", 3600, Some("note")));
        assert!(txt.content.contains("a;b"));

        // Cloudflare's account paths, and the account itself
        let (sc, _, b) = call_raw(&mut app, "GET", "/client/v4/accounts", auth(), vec![]).await;
        assert_eq!((sc, json_of(&b)["result"][0]["id"].as_str()), (StatusCode::OK, Some(crate::tokens::account_id())));
        let kv = format!("/client/v4/accounts/{}/storage/kv/namespaces", crate::tokens::account_id());
        let (sc, _, _) = call_raw(&mut app, "GET", &kv, auth(), vec![]).await;
        assert_eq!(sc, StatusCode::FORBIDDEN, "no KV in the token");
        let (sc, _, b) = call_raw(&mut app, "GET", &kv, vec![("authorization", &as_session)], vec![]).await;
        assert_eq!(sc, StatusCode::OK, "{}", String::from_utf8_lossy(&b));
        let (sc, _, _) = call_raw(&mut app, "GET", "/client/v4/accounts/0000/storage/kv/namespaces", vec![("authorization", &as_session)], vec![]).await;
        assert_eq!(sc, StatusCode::NOT_FOUND);
        let (sc, _, b) = call_raw(&mut app, "GET", "/client/v4/user/tokens/permission_groups", vec![("authorization", &as_session)], vec![]).await;
        assert!(sc == StatusCode::OK && json_of(&b)["result"].as_array().unwrap().iter().any(|g| g["name"] == "DNS Write"));

        // roll: the old value stops working; deleting ends it
        let (sc, _, b) = call_raw(&mut app, "PUT", &format!("/client/v4/user/tokens/{token_id}/value"), vec![("authorization", &as_session)], vec![]).await;
        assert_eq!(sc, StatusCode::OK);
        let rolled = format!("Bearer {}", json_of(&b)["result"].as_str().unwrap());
        let (sc, _, _) = call_raw(&mut app, "GET", "/client/v4/user/tokens/verify", auth(), vec![]).await;
        assert_eq!(sc, StatusCode::UNAUTHORIZED);
        let (sc, _, _) = call_raw(&mut app, "GET", "/client/v4/user/tokens/verify", vec![("authorization", &rolled)], vec![]).await;
        assert_eq!(sc, StatusCode::OK);
        let (sc, _, _) = call_raw(&mut app, "DELETE", &format!("/client/v4/user/tokens/{token_id}"), vec![("authorization", &as_session)], vec![]).await;
        assert_eq!(sc, StatusCode::OK);
        let (sc, _, _) = call_raw(&mut app, "GET", "/client/v4/user/tokens/verify", vec![("authorization", &rolled)], vec![]).await;
        assert_eq!(sc, StatusCode::UNAUTHORIZED);

        // the Global API Key: what the owner may do, but not the owner's credentials
        let (sc, _, b) = call_raw(
            &mut app,
            "POST",
            "/client/v4/account/api_key",
            vec![("authorization", &as_session), ("content-type", "application/json")],
            br#"{"password":"strong-pass-123"}"#.to_vec(),
        )
        .await;
        assert_eq!(sc, StatusCode::OK, "{}", String::from_utf8_lossy(&b));
        let key = json_of(&b)["result"]["api_key"].as_str().unwrap().to_string();
        let by_key = vec![("x-auth-email", "admin@example.com"), ("x-auth-key", key.as_str())];
        let (sc, _, _) = call_raw(&mut app, "GET", &format!("/client/v4/zones/{}/dns_records", other.id), by_key.clone(), vec![]).await;
        assert_eq!(sc, StatusCode::OK);
        let (sc, _, _) = call_raw(&mut app, "GET", "/client/v4/account", by_key.clone(), vec![]).await;
        assert_eq!(sc, StatusCode::FORBIDDEN);
        let (sc, _, _) = call_raw(&mut app, "GET", "/client/v4/zones", vec![("x-auth-email", "admin@example.com"), ("x-auth-key", "wrong")], vec![]).await;
        assert_eq!(sc, StatusCode::UNAUTHORIZED);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn viewer_redaction_for_workers_and_kv() {
        let dir = std::env::temp_dir().join(format!("fucf-api-viewer-{}", uuid::Uuid::new_v4().simple()));
        let st = make_test_state(&dir, crate::sync::NodeRole::Peer);
        st.accounts.create_user("admin@example.com", Role::Admin, Some("strong-pass-123"), "admin@example.com", &Client::default()).unwrap();
        st.accounts.create_user("view@example.com", Role::Viewer, Some("viewer-pass-123"), "admin@example.com", &Client::default()).unwrap();
        let viewer_tok = match st.accounts.login("view@example.com", "viewer-pass-123", &Client::default()).unwrap() {
            Login::Session(token, _) => token,
            _ => panic!("expected signed in"),
        };
        let mut app = router(st.clone());

        let (sc, _) = call(&mut app, "PUT", "/client/v4/workers/scripts/secw", b"export default { fetch() { return new Response('ok'); } }".to_vec()).await;
        assert_eq!(sc, StatusCode::OK);
        let (sc, _) = call(&mut app, "PATCH", "/client/v4/workers/scripts/secw/settings", br#"{"vars":{"API_KEY":"supersecret"}}"#.to_vec()).await;
        assert_eq!(sc, StatusCode::OK);
        let (sc, b) = call(&mut app, "POST", "/client/v4/kv/namespaces", br#"{"title":"secns"}"#.to_vec()).await;
        assert_eq!(sc, StatusCode::OK);
        let ns_id = serde_json::from_slice::<Value>(&b).unwrap()["result"]["id"].as_str().unwrap().to_string();
        let (sc, _) = call(&mut app, "PUT", &format!("/client/v4/kv/namespaces/{ns_id}/values/tok"), b"secretval".to_vec()).await;
        assert_eq!(sc, StatusCode::OK);

        let auth_hdr = format!("Bearer {viewer_tok}");
        let (sc, _, _) = call_raw(
            &mut app,
            "POST",
            "/client/v4/account/password",
            vec![("authorization", &auth_hdr), ("content-type", "application/json")],
            br#"{"current":"viewer-pass-123","new":"viewer-pass-456"}"#.to_vec(),
        ).await;
        assert_eq!(sc, StatusCode::OK);

        let (sc, _, _) = call_raw(&mut app, "GET", "/client/v4/workers/scripts/secw", vec![("authorization", &auth_hdr)], vec![]).await;
        assert_eq!(sc, StatusCode::FORBIDDEN);

        let (sc, _, _) = call_raw(&mut app, "GET", &format!("/client/v4/kv/namespaces/{ns_id}/values/tok"), vec![("authorization", &auth_hdr)], vec![]).await;
        assert_eq!(sc, StatusCode::FORBIDDEN);

        let (sc, _, b) = call_raw(&mut app, "GET", "/client/v4/workers/scripts/secw/settings", vec![("authorization", &auth_hdr)], vec![]).await;
        assert_eq!(sc, StatusCode::OK);
        let settings: Value = serde_json::from_slice(&b).unwrap();
        assert_eq!(settings["result"]["vars"]["API_KEY"], "***");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn alert_channels_through_the_api_keep_their_secrets_and_their_permissions() {
        let dir = std::env::temp_dir().join(format!("fucf-api-alerts-{}", uuid::Uuid::new_v4().simple()));
        let st = make_test_state(&dir, crate::sync::NodeRole::Peer);
        st.accounts.create_user("admin@example.com", Role::Admin, Some("strong-pass-123"), "admin@example.com", &Client::default()).unwrap();
        // (each made in their own name: no password change pending)
        st.accounts.create_user("edit@example.com", Role::Editor, Some("editor-pass-123"), "edit@example.com", &Client::default()).unwrap();
        st.accounts.create_user("view@example.com", Role::Viewer, Some("viewer-pass-123"), "view@example.com", &Client::default()).unwrap();
        let session = |email: &str, password: &str| match st.accounts.login(email, password, &Client::default()).unwrap() {
            Login::Session(token, _) => format!("Bearer {token}"),
            _ => panic!("expected signed in"),
        };
        let admin = session("admin@example.com", "strong-pass-123");
        let editor = session("edit@example.com", "editor-pass-123");
        let viewer = session("view@example.com", "viewer-pass-123");
        let mut app = router(st.clone());
        let json_of = |b: &[u8]| serde_json::from_slice::<Value>(b).unwrap();
        let as_who = |auth: &str| -> Vec<(&'static str, String)> { vec![("authorization", auth.to_string()), ("content-type", "application/json".to_string())] };
        let bot = format!("{}:{}", 12345, "test-token-".repeat(3));
        let base = "/client/v4/alerts/channels";

        let hook = json!({ "name": "ops", "kind": "webhook", "url": "https://hooks.example.com/services/test-secret", "events": ["node_offline", "under_attack"] });
        let (sc, b) = call(&mut app, "POST", base, hook.to_string().into_bytes()).await;
        assert_eq!(sc, StatusCode::OK, "{}", String::from_utf8_lossy(&b));
        assert!(!String::from_utf8_lossy(&b).contains("test-secret"));
        let hook_id = json_of(&b)["result"]["id"].as_str().unwrap().to_string();
        let tg = json!({ "name": "chat", "kind": "telegram", "bot_token": bot, "chat_id": "-1001234", "events": ["traffic_limit"] });
        let (sc, b) = call(&mut app, "POST", base, tg.to_string().into_bytes()).await;
        assert_eq!(sc, StatusCode::OK, "{}", String::from_utf8_lossy(&b));
        assert_eq!(json_of(&b)["result"]["bot_token"], "***");
        let tg_id = json_of(&b)["result"]["id"].as_str().unwrap().to_string();

        // nothing that answers shows a secret
        for path in [base.to_string(), format!("{base}/{hook_id}"), format!("{base}/{tg_id}")] {
            let (sc, b) = call(&mut app, "GET", &path, vec![]).await;
            let text = String::from_utf8_lossy(&b).to_string();
            assert_eq!(sc, StatusCode::OK);
            assert!(!text.contains("test-secret") && !text.contains("test-token") && !text.contains("\"sync\""), "{text}");
        }
        // what was shown, sent back whole with a change, keeps the secret
        let (_, b) = call(&mut app, "GET", &format!("{base}/{hook_id}"), vec![]).await;
        let mut shown = json_of(&b)["result"].clone();
        shown["name"] = json!("ops renamed");
        let (sc, b) = call(&mut app, "PUT", &format!("{base}/{hook_id}"), shown.to_string().into_bytes()).await;
        assert_eq!((sc, json_of(&b)["result"]["name"].clone()), (StatusCode::OK, json!("ops renamed")));
        assert_eq!(st.store.get_alert_channel(&hook_id).unwrap().url, "https://hooks.example.com/services/test-secret");
        let (sc, _) = call(&mut app, "PATCH", &format!("{base}/{tg_id}"), br#"{"bot_token":"***","chat_id":"@example_alerts"}"#.to_vec()).await;
        assert_eq!(sc, StatusCode::OK);
        let kept = st.store.get_alert_channel(&tg_id).unwrap();
        assert_eq!((kept.bot_token.as_str(), kept.chat_id.as_str()), (bot.as_str(), "@example_alerts"));

        // refused, and nothing changes
        for (method, path, body) in [
            ("POST", base.to_string(), json!({ "name": "x", "kind": "webhook", "url": "http://hooks.example.com/x", "events": ["node_offline"] })),
            ("POST", base.to_string(), json!({ "name": "x", "kind": "webhook", "url": "https://hooks.example.com/x", "events": [] })),
            ("POST", base.to_string(), json!({ "name": "x", "kind": "sms", "events": ["node_offline"] })),
            ("POST", base.to_string(), json!({ "name": "x", "kind": "telegram", "bot_token": "***", "chat_id": "42", "events": ["node_offline"] })),
            ("PUT", format!("{base}/{hook_id}"), json!({ "url": "https://hooks.example.net/***" })),
            ("PATCH", format!("{base}/{hook_id}"), json!({ "events": ["node_offline", "nope"] })),
        ] {
            let (sc, b) = call(&mut app, method, &path, body.to_string().into_bytes()).await;
            assert_eq!(sc, StatusCode::BAD_REQUEST, "{method} {path} {body}: {}", String::from_utf8_lossy(&b));
        }
        let (sc, _) = call(&mut app, "POST", base, b"not json".to_vec()).await;
        assert_eq!(sc, StatusCode::BAD_REQUEST);
        assert_eq!(st.store.list_alert_channels().len(), 2);
        assert_eq!(st.store.get_alert_channel(&hook_id).unwrap().events, vec!["node_offline", "under_attack"]);
        for (method, path) in [("GET", format!("{base}/no-such-id")), ("PUT", format!("{base}/no-such-id")), ("DELETE", format!("{base}/no-such-id")), ("POST", format!("{base}/no-such-id/test"))] {
            let (sc, _) = call(&mut app, method, &path, br#"{"name":"x"}"#.to_vec()).await;
            assert_eq!(sc, StatusCode::NOT_FOUND, "{method} {path}");
        }

        // this test starts no checks: the route answers all the same
        let (sc, b) = call(&mut app, "GET", "/client/v4/alerts/active", vec![]).await;
        assert_eq!(sc, StatusCode::OK);
        assert!(json_of(&b)["result"]["alerts"].is_array());

        // roles: viewers and editors read, only administrators change or test
        for who in [&viewer, &editor] {
            let h = as_who(who);
            let (sc, _, b) = call_raw(&mut app, "GET", base, h.iter().map(|(k, v)| (*k, v.as_str())).collect(), vec![]).await;
            assert_eq!(sc, StatusCode::OK);
            assert!(!String::from_utf8_lossy(&b).contains("test-secret"));
            for (method, path) in [("POST", base.to_string()), ("PATCH", format!("{base}/{hook_id}")), ("DELETE", format!("{base}/{hook_id}")), ("POST", format!("{base}/{hook_id}/test"))] {
                let (sc, _, _) = call_raw(&mut app, method, &path, h.iter().map(|(k, v)| (*k, v.as_str())).collect(), hook.to_string().into_bytes()).await;
                assert_eq!(sc, StatusCode::FORBIDDEN, "{method} {path}");
            }
        }
        assert_eq!(st.store.list_alert_channels().len(), 2);

        // tokens: a fleet token is not enough; Notifications Read reads, Write changes
        let token_with = |group: &str| {
            json!({
                "name": group,
                "policies": [{ "effect": "allow", "resources": { format!("com.cloudflare.api.account.{}", crate::tokens::account_id()): "*" }, "permission_groups": [{ "name": group }] }],
            })
        };
        let mut bearer = HashMap::new();
        for group in ["Fleet Write", "Notifications Read", "Notifications Write"] {
            let h = as_who(&admin);
            let (sc, _, b) = call_raw(&mut app, "POST", "/client/v4/user/tokens", h.iter().map(|(k, v)| (*k, v.as_str())).collect(), token_with(group).to_string().into_bytes()).await;
            assert_eq!(sc, StatusCode::OK, "{}", String::from_utf8_lossy(&b));
            bearer.insert(group, format!("Bearer {}", json_of(&b)["result"]["value"].as_str().unwrap()));
        }
        let expect = [
            ("Fleet Write", "GET", base.to_string(), StatusCode::FORBIDDEN),
            ("Notifications Read", "GET", "/client/v4/alerts/active".to_string(), StatusCode::OK),
            ("Notifications Read", "GET", base.to_string(), StatusCode::OK),
            ("Notifications Read", "DELETE", format!("{base}/{tg_id}"), StatusCode::FORBIDDEN),
            ("Notifications Write", "DELETE", format!("{base}/{tg_id}"), StatusCode::OK),
        ];
        for (group, method, path, status) in expect {
            let h = as_who(&bearer[group]);
            let (sc, _, b) = call_raw(&mut app, method, &path, h.iter().map(|(k, v)| (*k, v.as_str())).collect(), vec![]).await;
            assert_eq!(sc, status, "{group}: {method} {path}");
            assert!(!String::from_utf8_lossy(&b).contains("test-secret"));
        }
        assert!(st.store.get_alert_channel(&tg_id).is_none());

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn challenge_widgets_show_their_secret_once_and_only_administrators_change_them() {
        let dir = std::env::temp_dir().join(format!("fucf-api-widgets-{}", uuid::Uuid::new_v4().simple()));
        let st = make_test_state(&dir, crate::sync::NodeRole::Peer);
        st.accounts.create_user("admin@example.com", Role::Admin, Some("strong-pass-123"), "admin@example.com", &Client::default()).unwrap();
        st.accounts.create_user("edit@example.com", Role::Editor, Some("editor-pass-123"), "edit@example.com", &Client::default()).unwrap();
        st.accounts.create_user("view@example.com", Role::Viewer, Some("viewer-pass-123"), "view@example.com", &Client::default()).unwrap();
        let session = |email: &str, password: &str| match st.accounts.login(email, password, &Client::default()).unwrap() {
            Login::Session(token, _) => format!("Bearer {token}"),
            _ => panic!("expected signed in"),
        };
        let admin = session("admin@example.com", "strong-pass-123");
        let editor = session("edit@example.com", "editor-pass-123");
        let viewer = session("view@example.com", "viewer-pass-123");
        let mut app = router(st.clone());
        let json_of = |b: &[u8]| serde_json::from_slice::<Value>(b).unwrap();
        let as_who = |auth: &str| -> Vec<(&'static str, String)> { vec![("authorization", auth.to_string()), ("content-type", "application/json".to_string())] };
        let base = format!("/client/v4/accounts/{}/challenges/widgets", crate::tokens::account_id());

        // made: the answer holds the secret, the store only its digest
        let widget = json!({ "name": "sign-up form", "domains": ["Shop.Example.com", "www.example.net"], "mode": "managed" });
        let (sc, b) = call(&mut app, "POST", &base, widget.to_string().into_bytes()).await;
        assert_eq!(sc, StatusCode::OK, "{}", String::from_utf8_lossy(&b));
        let made = json_of(&b)["result"].clone();
        let sitekey = made["sitekey"].as_str().unwrap().to_string();
        let secret = made["secret"].as_str().unwrap().to_string();
        assert_eq!(made["id"], json!(sitekey));
        assert_eq!(made["domains"], json!(["shop.example.com", "www.example.net"]));
        assert!(secret.starts_with("fcfws_") && secret.len() == 6 + 64);
        let kept = st.store.get_challenge_widget(&sitekey).unwrap();
        assert_eq!(kept.secret_sha256, crate::release::sha256_hex(secret.as_bytes()));
        assert!(!serde_json::to_string(&kept).unwrap().contains(&secret));

        // read back in every way: no secret, no digest, no sync data
        let shown_nowhere = |text: &str| !text.contains(&secret) && !text.contains(&kept.secret_sha256) && !text.contains("secret") && !text.contains("\"sync\"");
        for path in [base.clone(), format!("{base}/{sitekey}"), "/client/v4/challenges/widgets".to_string()] {
            let (sc, b) = call(&mut app, "GET", &path, vec![]).await;
            let text = String::from_utf8_lossy(&b).to_string();
            assert_eq!(sc, StatusCode::OK, "{path}");
            assert!(shown_nowhere(&text), "{path}: {text}");
        }
        // changed: the secret stays, and is not shown
        let (sc, b) = call(&mut app, "PUT", &format!("{base}/{sitekey}"), json!({ "name": "renamed", "sitekey": sitekey }).to_string().into_bytes()).await;
        assert_eq!(sc, StatusCode::OK, "{}", String::from_utf8_lossy(&b));
        assert!(shown_nowhere(&String::from_utf8_lossy(&b)));
        assert_eq!(st.store.get_challenge_widget(&sitekey).unwrap().secret_sha256, kept.secret_sha256);

        // rotated: a new secret, once; the old digest is gone
        let (sc, b) = call(&mut app, "POST", &format!("{base}/{sitekey}/rotate_secret"), br#"{"invalidate_immediately":true}"#.to_vec()).await;
        assert_eq!(sc, StatusCode::OK, "{}", String::from_utf8_lossy(&b));
        let rotated = json_of(&b)["result"]["secret"].as_str().unwrap().to_string();
        assert_ne!(rotated, secret);
        assert_eq!(st.store.get_challenge_widget(&sitekey).unwrap().secret_sha256, crate::release::sha256_hex(rotated.as_bytes()));
        let (sc, _) = call(&mut app, "POST", &format!("{base}/{sitekey}/rotate_secret"), vec![]).await;
        assert_eq!(sc, StatusCode::OK);
        let (_, b) = call(&mut app, "GET", &base, vec![]).await;
        assert!(!String::from_utf8_lossy(&b).contains(&rotated));

        // refused, and nothing changes
        let before = st.store.get_challenge_widget(&sitekey).unwrap();
        for (method, path, body) in [
            ("POST", base.clone(), json!({ "name": "x", "domains": [] })),
            ("POST", base.clone(), json!({ "name": "x", "domains": ["*.example.com"] })),
            ("POST", base.clone(), json!({ "name": "x", "domains": ["192.0.2.1"] })),
            ("POST", base.clone(), json!({ "name": "x", "domains": ["example.com"], "mode": "invisible" })),
            ("POST", base.clone(), json!({ "name": "x", "domains": ["example.com"], "secret": "test-secret" })),
            ("POST", base.clone(), json!({ "name": "x", "domains": ["example.com"], "sitekey": "0123456789abcdef0123456789abcdef" })),
            ("POST", base.clone(), json!({ "name": "", "domains": ["example.com"] })),
            ("POST", base.clone(), json!(["not", "an", "object"])),
            ("PATCH", format!("{base}/{sitekey}"), json!({ "secret_sha256": "00".repeat(32) })),
            ("PATCH", format!("{base}/{sitekey}"), json!({ "sitekey": "0123456789abcdef0123456789abcdef" })),
            ("PATCH", format!("{base}/{sitekey}"), json!({ "clearance_level": "managed" })),
            ("POST", format!("{base}/{sitekey}/rotate_secret"), json!({ "invalidate_immediately": false })),
            ("POST", format!("{base}/{sitekey}/rotate_secret"), json!({ "keep_old": true })),
        ] {
            let (sc, b) = call(&mut app, method, &path, body.to_string().into_bytes()).await;
            assert_eq!(sc, StatusCode::BAD_REQUEST, "{method} {path} {body}: {}", String::from_utf8_lossy(&b));
        }
        let (sc, _) = call(&mut app, "POST", &base, b"not json".to_vec()).await;
        assert_eq!(sc, StatusCode::BAD_REQUEST);
        let after = st.store.get_challenge_widget(&sitekey).unwrap();
        assert_eq!((&after.secret_sha256, &after.domains, st.store.list_challenge_widgets().len()), (&before.secret_sha256, &before.domains, 1));
        for (method, path) in [
            ("GET", format!("{base}/0123456789abcdef0123456789abcdef")),
            ("PUT", format!("{base}/0123456789abcdef0123456789abcdef")),
            ("DELETE", format!("{base}/0123456789abcdef0123456789abcdef")),
            ("POST", format!("{base}/0123456789abcdef0123456789abcdef/rotate_secret")),
        ] {
            let (sc, _) = call(&mut app, method, &path, br#"{"name":"x"}"#.to_vec()).await;
            assert_eq!(sc, StatusCode::NOT_FOUND, "{method} {path}");
        }

        // roles: viewers and editors read, only administrators change, rotate or delete
        for who in [&viewer, &editor] {
            let h = as_who(who);
            let (sc, _, b) = call_raw(&mut app, "GET", &base, h.iter().map(|(k, v)| (*k, v.as_str())).collect(), vec![]).await;
            assert_eq!(sc, StatusCode::OK);
            assert!(String::from_utf8_lossy(&b).contains(&sitekey));
            for (method, path) in [("POST", base.clone()), ("PATCH", format!("{base}/{sitekey}")), ("POST", format!("{base}/{sitekey}/rotate_secret")), ("DELETE", format!("{base}/{sitekey}"))] {
                let (sc, _, b) = call_raw(&mut app, method, &path, h.iter().map(|(k, v)| (*k, v.as_str())).collect(), widget.to_string().into_bytes()).await;
                assert_eq!(sc, StatusCode::FORBIDDEN, "{method} {path}");
                assert!(!String::from_utf8_lossy(&b).contains("fcfws_"));
            }
        }
        assert_eq!(st.store.get_challenge_widget(&sitekey).unwrap().secret_sha256, after.secret_sha256);
        assert_eq!(st.store.list_challenge_widgets().len(), 1);

        // tokens: a fleet token is not enough; Turnstile Sites Read reads, Write changes
        let token_with = |group: &str| {
            json!({
                "name": group,
                "policies": [{ "effect": "allow", "resources": { format!("com.cloudflare.api.account.{}", crate::tokens::account_id()): "*" }, "permission_groups": [{ "name": group }] }],
            })
        };
        let mut bearer = HashMap::new();
        for group in ["Fleet Write", "Turnstile Sites Read", "Turnstile Sites Write"] {
            let h = as_who(&admin);
            let (sc, _, b) = call_raw(&mut app, "POST", "/client/v4/user/tokens", h.iter().map(|(k, v)| (*k, v.as_str())).collect(), token_with(group).to_string().into_bytes()).await;
            assert_eq!(sc, StatusCode::OK, "{}", String::from_utf8_lossy(&b));
            bearer.insert(group, format!("Bearer {}", json_of(&b)["result"]["value"].as_str().unwrap()));
        }
        let expect = [
            ("Fleet Write", "GET", base.clone(), StatusCode::FORBIDDEN),
            ("Fleet Write", "POST", format!("{base}/{sitekey}/rotate_secret"), StatusCode::FORBIDDEN),
            ("Turnstile Sites Read", "GET", format!("{base}/{sitekey}"), StatusCode::OK),
            ("Turnstile Sites Read", "POST", format!("{base}/{sitekey}/rotate_secret"), StatusCode::FORBIDDEN),
            ("Turnstile Sites Read", "DELETE", format!("{base}/{sitekey}"), StatusCode::FORBIDDEN),
            ("Turnstile Sites Write", "DELETE", format!("{base}/{sitekey}"), StatusCode::OK),
        ];
        for (group, method, path, status) in expect {
            let h = as_who(&bearer[group]);
            let (sc, _, b) = call_raw(&mut app, method, &path, h.iter().map(|(k, v)| (*k, v.as_str())).collect(), vec![]).await;
            assert_eq!(sc, status, "{group}: {method} {path}");
            assert!(!String::from_utf8_lossy(&b).contains("fcfws_"));
        }
        assert!(st.store.get_challenge_widget(&sitekey).is_none());

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn oauth_redirect_uri_prefers_panel_host() {
        let mut cfg = crate::auth::OAuthConfig::default();
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(header::HOST, "evil.example".parse().unwrap());
        headers.insert("x-forwarded-proto", "http".parse().unwrap());

        // When panel_host is configured and redirect_base_url is empty, Host / X-Forwarded-Proto are ignored.
        let (uri, secure) = oauth_redirect_uri(&cfg, &headers, Some("dashboard.fucloudflare.com"));
        assert_eq!(uri, "https://dashboard.fucloudflare.com/client/v4/auth/oauth/callback");
        assert!(secure);

        // Explicit redirect_base_url takes precedence over panel_host.
        cfg.redirect_base_url = "https://auth.example.com/".into();
        let (uri, secure) = oauth_redirect_uri(&cfg, &headers, Some("dashboard.fucloudflare.com"));
        assert_eq!(uri, "https://auth.example.com/client/v4/auth/oauth/callback");
        assert!(secure);
    }

    #[tokio::test]
    async fn ip_lists_answer_on_cloudflare_account_paths_and_tokens_need_the_lists_permission() {
        let dir = std::env::temp_dir().join(format!("fucf-api-lists-{}", uuid::Uuid::new_v4().simple()));
        let st = make_test_state(&dir, crate::sync::NodeRole::Peer);
        st.accounts.create_user("admin@example.com", Role::Admin, Some("strong-pass-123"), "admin@example.com", &Client::default()).unwrap();
        let session = match st.accounts.login("admin@example.com", "strong-pass-123", &Client::default()).unwrap() {
            Login::Session(token, _) => token,
            _ => panic!("expected signed in"),
        };
        let zone = st.store.create_zone("example.com").unwrap();
        let mut app = router(st.clone());
        let json_of = |b: &[u8]| serde_json::from_slice::<Value>(b).unwrap();
        let as_session = format!("Bearer {session}");
        let base = format!("/client/v4/accounts/{}/rules/lists", crate::tokens::account_id());

        // the fleet's own token, on Cloudflare's account path
        let (sc, b) = call(&mut app, "POST", &base, br#"{"name":"office","kind":"ip","description":"the office"}"#.to_vec()).await;
        assert_eq!(sc, StatusCode::OK, "{}", String::from_utf8_lossy(&b));
        let id = json_of(&b)["result"]["id"].as_str().unwrap().to_string();
        let (sc, b) = call(&mut app, "POST", &format!("{base}/{id}/items"), br#"[{"ip":"192.0.2.0/24","comment":"desks"},{"ip":"2001:db8::1"}]"#.to_vec()).await;
        assert_eq!(sc, StatusCode::OK, "{}", String::from_utf8_lossy(&b));
        let op = json_of(&b)["result"]["operation_id"].as_str().unwrap().to_string();
        let (sc, b) = call(&mut app, "GET", &format!("{base}/bulk_operations/{op}"), vec![]).await;
        assert_eq!((sc, json_of(&b)["result"]["status"].clone()), (StatusCode::OK, json!("completed")));
        let (sc, _) = call(&mut app, "GET", &format!("{base}/bulk_operations/nope"), vec![]).await;
        assert_eq!(sc, StatusCode::NOT_FOUND);
        let (sc, b) = call(&mut app, "GET", &format!("/client/v4/rules/lists/{id}/items"), vec![]).await;
        assert_eq!(sc, StatusCode::OK);
        let items = json_of(&b)["result"].clone();
        assert_eq!(items.as_array().unwrap().len(), 2);
        let item_id = items[1]["id"].as_str().unwrap().to_string();
        let (sc, b) = call(&mut app, "GET", &format!("{base}/{id}/items/{item_id}"), vec![]).await;
        assert_eq!((sc, json_of(&b)["result"]["ip"].clone()), (StatusCode::OK, json!("2001:db8::1")));
        let (sc, b) = call(&mut app, "POST", &format!("{base}/{id}/items"), br#"[{"ip":"192.0.2.1/24"}]"#.to_vec()).await;
        assert_eq!(sc, StatusCode::BAD_REQUEST, "{}", String::from_utf8_lossy(&b));
        let (sc, _) = call(&mut app, "POST", &format!("{base}/{id}/items"), b"not json".to_vec()).await;
        assert_eq!(sc, StatusCode::BAD_REQUEST);
        let (sc, _) = call(&mut app, "GET", "/client/v4/accounts/0000/rules/lists", vec![]).await;
        assert_eq!(sc, StatusCode::NOT_FOUND, "another account");
        let (sc, _) = call(&mut app, "GET", &format!("{base}/nope/items"), vec![]).await;
        assert_eq!(sc, StatusCode::NOT_FOUND);
        // the other account paths with an id in them get theirs, too
        let (_, b) = call(&mut app, "POST", "/client/v4/kv/namespaces", br#"{"title":"sessions"}"#.to_vec()).await;
        let ns = json_of(&b)["result"]["id"].as_str().unwrap().to_string();
        let kv = format!("/client/v4/accounts/{}/storage/kv/namespaces/{ns}", crate::tokens::account_id());
        let (sc, b) = call(&mut app, "GET", &kv, vec![]).await;
        assert_eq!((sc, json_of(&b)["result"]["title"].clone()), (StatusCode::OK, json!("sessions")), "{}", String::from_utf8_lossy(&b));

        // a rule uses it: the edge follows the list, and the list cannot be deleted
        let rule = json!({ "expression": "ip.src in $office", "action": "block" });
        let (sc, b) = call(&mut app, "POST", &format!("/client/v4/zones/{}/firewall/rules", zone.id), rule.to_string().into_bytes()).await;
        assert_eq!(sc, StatusCode::OK, "{}", String::from_utf8_lossy(&b));
        let rule_id = json_of(&b)["result"]["id"].as_str().unwrap().to_string();
        let (sc, b) = call(&mut app, "POST", &format!("/client/v4/zones/{}/firewall/rules", zone.id), br#"{"expression":"ip.src in $absent","action":"block"}"#.to_vec()).await;
        assert_eq!(sc, StatusCode::BAD_REQUEST, "{}", String::from_utf8_lossy(&b));
        let (sc, b) = call(&mut app, "DELETE", &format!("{base}/{id}"), vec![]).await;
        assert_eq!(sc, StatusCode::CONFLICT);
        let err = json_of(&b);
        assert_eq!(err["success"], json!(false));
        assert!(err["errors"][0]["message"].as_str().unwrap().contains(&rule_id), "{err}");
        let (sc, _) = call(&mut app, "PUT", &format!("{base}/{id}"), br#"{"name":"moved"}"#.to_vec()).await;
        assert_eq!(sc, StatusCode::CONFLICT, "a rename would leave the rule behind");
        let (sc, b) = call(&mut app, "GET", &base, vec![]).await;
        assert_eq!((sc, json_of(&b)["result"][0]["num_referencing_filters"].clone()), (StatusCode::OK, json!(1)));

        // tokens: read only, zone only
        let token = |groups: Value, resources: Value| json!({ "name": "lists", "policies": [{ "effect": "allow", "resources": resources, "permission_groups": groups }] });
        let account = json!({ format!("com.cloudflare.api.account.{}", crate::tokens::account_id()): "*" });
        let mut bearers = vec![];
        for spec in [
            token(json!([{ "name": "Account Filter Lists Read" }]), account.clone()),
            token(json!([{ "name": "Firewall Services Write" }, { "name": "Zone Write" }]), json!({ format!("com.cloudflare.api.account.zone.{}", zone.id): "*" })),
            token(json!([{ "name": "Account Filter Lists Write" }]), account),
        ] {
            let (sc, _, b) = call_raw(&mut app, "POST", "/client/v4/user/tokens", vec![("authorization", &as_session), ("content-type", "application/json")], spec.to_string().into_bytes()).await;
            assert_eq!(sc, StatusCode::OK, "{}", String::from_utf8_lossy(&b));
            bearers.push(format!("Bearer {}", json_of(&b)["result"]["value"].as_str().unwrap()));
        }
        let (read, zone_only, write) = (&bearers[0], &bearers[1], &bearers[2]);
        let items_uri = format!("{base}/{id}/items");
        let add = br#"[{"ip":"203.0.113.9"}]"#.to_vec();
        let (sc, _, _) = call_raw(&mut app, "GET", &items_uri, vec![("authorization", read)], vec![]).await;
        assert_eq!(sc, StatusCode::OK);
        let (sc, _, _) = call_raw(&mut app, "POST", &items_uri, vec![("authorization", read)], add.clone()).await;
        assert_eq!(sc, StatusCode::FORBIDDEN, "read only");
        let (sc, _, _) = call_raw(&mut app, "POST", &base, vec![("authorization", read)], br#"{"name":"x"}"#.to_vec()).await;
        assert_eq!(sc, StatusCode::FORBIDDEN);
        for (method, uri) in [("GET", base.as_str()), ("GET", items_uri.as_str()), ("POST", items_uri.as_str())] {
            let (sc, _, _) = call_raw(&mut app, method, uri, vec![("authorization", zone_only)], add.clone()).await;
            assert_eq!(sc, StatusCode::FORBIDDEN, "a zone token: {method} {uri}");
        }
        let (sc, _, _) = call_raw(&mut app, "GET", &format!("/client/v4/zones/{}/firewall/rules", zone.id), vec![("authorization", zone_only)], vec![]).await;
        assert_eq!(sc, StatusCode::OK, "the zone token itself works");
        let (sc, _, b) = call_raw(&mut app, "POST", &items_uri, vec![("authorization", write), ("content-type", "application/json")], add).await;
        assert_eq!(sc, StatusCode::OK, "{}", String::from_utf8_lossy(&b));

        // the rule lets go; delete takes Cloudflare's body
        let (sc, _) = call(&mut app, "DELETE", &format!("/client/v4/zones/{}/firewall/rules/{rule_id}", zone.id), vec![]).await;
        assert_eq!(sc, StatusCode::OK);
        let (sc, _) = call(&mut app, "DELETE", &items_uri, vec![]).await;
        assert_eq!(sc, StatusCode::BAD_REQUEST, "a delete names the items");
        let del = json!({ "items": [{ "id": item_id }] });
        let (sc, b) = call(&mut app, "DELETE", &items_uri, del.to_string().into_bytes()).await;
        assert_eq!(sc, StatusCode::OK, "{}", String::from_utf8_lossy(&b));
        let (sc, b) = call(&mut app, "PUT", &items_uri, b"[]".to_vec()).await;
        assert_eq!(sc, StatusCode::OK, "{}", String::from_utf8_lossy(&b));
        let (sc, b) = call(&mut app, "PATCH", &format!("{base}/{id}"), br#"{"name":"moved"}"#.to_vec()).await;
        assert_eq!((sc, json_of(&b)["result"]["name"].clone()), (StatusCode::OK, json!("moved")));
        let (sc, _) = call(&mut app, "DELETE", &format!("{base}/{id}"), vec![]).await;
        assert_eq!(sc, StatusCode::OK);
        let (sc, _) = call(&mut app, "GET", &format!("{base}/{id}"), vec![]).await;
        assert_eq!(sc, StatusCode::NOT_FOUND);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn a_zone_makes_one_origin_ca_signs_with_it_and_never_answers_its_key() {
        let dir = std::env::temp_dir().join(format!("fucf-api-origin-ca-{}", uuid::Uuid::new_v4().simple()));
        let st = make_test_state(&dir, crate::sync::NodeRole::Peer);
        for (email, role) in [("admin@example.com", Role::Admin), ("editor@example.com", Role::Editor), ("other@example.com", Role::Editor), ("viewer@example.com", Role::Viewer)] {
            st.accounts.create_user(email, role, Some("strong-pass-123"), email, &Client::default()).unwrap();
        }
        let session = |email: &str| match st.accounts.login(email, "strong-pass-123", &Client::default()).unwrap() {
            Login::Session(token, _) => format!("Bearer {token}"),
            _ => panic!("expected signed in"),
        };
        let (admin, editor, other, viewer) = (session("admin@example.com"), session("editor@example.com"), session("other@example.com"), session("viewer@example.com"));
        let zone = st.store.create_zone("example.com").unwrap();
        let z = zone.id.clone();
        give(&st, &z, "editor@example.com").await;
        let mut app = router(st.clone());
        let json_of = |b: &[u8]| serde_json::from_slice::<Value>(b).unwrap();
        let ca = format!("/client/v4/zones/{z}/origin_ca");
        let sign = format!("{ca}/sign");
        let stored = || st.store.get_zone(&z).unwrap().origin_ca;
        // the CA's key: neither its PEM nor any part of it in an answer
        let leaks = |b: &[u8], key: &str| {
            let text = String::from_utf8_lossy(b);
            let middle: String = key.lines().filter(|l| !l.starts_with("-----")).collect::<String>().chars().skip(20).take(40).collect();
            text.contains(&middle) || text.contains(&key.replace('\n', "\\n"))
        };
        let mut as_user = async |bearer: &str, method: &str, path: &str, body: Value| {
            let h = vec![("authorization", bearer), ("content-type", "application/json")];
            let (sc, _, b) = call_raw(&mut app, method, path, h, if body.is_null() { vec![] } else { body.to_string().into_bytes() }).await;
            (sc, b)
        };

        // none yet; the zone's owner makes it, once
        let (sc, b) = as_user(&editor, "GET", &ca, Value::Null).await;
        assert_eq!((sc, json_of(&b)["result"].clone()), (StatusCode::OK, json!({ "present": false })));
        let (sc, b) = as_user(&editor, "POST", &sign, json!({ "hostnames": ["example.com"], "days": 30 })).await;
        assert_eq!(sc, StatusCode::BAD_REQUEST, "no CA to sign with: {}", String::from_utf8_lossy(&b));
        let (sc, b) = as_user(&editor, "POST", &ca, Value::Null).await;
        assert_eq!(sc, StatusCode::OK, "{}", String::from_utf8_lossy(&b));
        let key = stored().unwrap().private_key;
        assert!(!leaks(&b, &key));
        let made = json_of(&b)["result"].clone();
        assert_eq!((made["present"].clone(), made["certificate"].clone()), (json!(true), json!(stored().unwrap().certificate)));
        assert!(made["expires_on"].is_string() && made.get("private_key").is_none(), "{made}");
        let (sc, b) = as_user(&editor, "POST", &ca, Value::Null).await;
        assert_eq!(sc, StatusCode::CONFLICT, "{}", String::from_utf8_lossy(&b));
        assert_eq!(stored().unwrap().private_key, key, "the refused second one changed nothing");
        // nothing that shows the zone shows the key
        for path in [ca.clone(), format!("/client/v4/zones/{z}"), format!("/client/v4/zones/{z}/settings"), "/client/v4/zones".to_string()] {
            let (sc, b) = as_user(&admin, "GET", &path, Value::Null).await;
            assert!(sc == StatusCode::OK && !leaks(&b, &key), "{path}: {}", String::from_utf8_lossy(&b));
        }

        // signing: a certificate and its key, for names of the zone, for a bounded time
        let (sc, b) = as_user(&editor, "POST", &sign, json!({ "hostnames": ["example.com", "*.example.com"], "days": 365 })).await;
        assert_eq!(sc, StatusCode::OK, "{}", String::from_utf8_lossy(&b));
        assert!(!leaks(&b, &key));
        let signed = json_of(&b)["result"].clone();
        assert!(crate::edge::tls::parse_cert(signed["certificate"].as_str().unwrap(), signed["private_key"].as_str().unwrap()).is_ok(), "{signed}");
        assert_eq!((signed["hostnames"].clone(), signed["ca_certificate"].clone()), (json!(["example.com", "*.example.com"]), made["certificate"].clone()));
        let (sc, _) = as_user(&editor, "POST", &sign, json!({ "names": ["origin.example.com"], "requested_validity": 5475 })).await;
        assert_eq!(sc, StatusCode::OK, "Cloudflare's field names");
        for body in [
            json!({ "hostnames": ["example.net"], "days": 30 }),
            json!({ "hostnames": ["www.example.com", "evil.example.org"], "days": 30 }),
            json!({ "hostnames": [], "days": 30 }),
            json!({ "hostnames": ["example.com"], "days": 0 }),
            json!({ "hostnames": ["example.com"], "days": 5476 }),
            json!({ "hostnames": ["example.com"] }),
            json!({ "hostnames": ["example.com"], "days": 30, "ca_private_key": "x" }),
            json!("example.com"),
        ] {
            let (sc, b) = as_user(&editor, "POST", &sign, body.clone()).await;
            assert_eq!(sc, StatusCode::BAD_REQUEST, "{body}: {}", String::from_utf8_lossy(&b));
            assert!(!leaks(&b, &key));
        }

        // who may: a viewer reads, other users see no such zone, tokens need the SSL permission
        let (sc, _) = as_user(&viewer, "GET", &ca, Value::Null).await;
        assert_eq!(sc, StatusCode::NOT_FOUND, "a viewer sees only zones given to them");
        give(&st, &z, "viewer@example.com").await;
        let (sc, _) = as_user(&viewer, "GET", &ca, Value::Null).await;
        assert_eq!(sc, StatusCode::OK);
        for (method, path) in [("POST", &sign), ("POST", &ca), ("DELETE", &ca)] {
            let (sc, _) = as_user(&viewer, method, path, json!({ "hostnames": ["example.com"], "days": 1 })).await;
            assert_eq!(sc, StatusCode::FORBIDDEN, "{method} {path}");
        }
        give(&st, &z, "editor@example.com").await;
        for (method, path) in [("GET", &ca), ("POST", &sign), ("DELETE", &ca)] {
            let (sc, _) = as_user(&other, method, path, json!({ "hostnames": ["example.com"], "days": 1 })).await;
            assert_eq!(sc, StatusCode::NOT_FOUND, "another user's zone: {method} {path}");
        }
        let (sc, _) = as_user(&admin, "POST", "/client/v4/zones/0123456789abcdef0123456789abcdef/origin_ca", Value::Null).await;
        assert_eq!(sc, StatusCode::NOT_FOUND);
        let mut token = async |group: &str| {
            let spec = json!({
                "name": group,
                "policies": [{ "effect": "allow", "resources": { format!("com.cloudflare.api.account.zone.{z}"): "*" }, "permission_groups": [{ "name": group }] }],
            });
            let (sc, b) = as_user(&admin, "POST", "/client/v4/user/tokens", spec).await;
            assert_eq!(sc, StatusCode::OK, "{}", String::from_utf8_lossy(&b));
            format!("Bearer {}", json_of(&b)["result"]["value"].as_str().unwrap())
        };
        let (settings, read, write) = (token("Zone Settings Write").await, token("SSL and Certificates Read").await, token("SSL and Certificates Write").await);
        let ask = json!({ "hostnames": ["example.com"], "days": 1 });
        assert_eq!(as_user(&settings, "GET", &ca, Value::Null).await.0, StatusCode::FORBIDDEN);
        assert_eq!(as_user(&settings, "POST", &sign, ask.clone()).await.0, StatusCode::FORBIDDEN);
        assert_eq!(as_user(&read, "GET", &ca, Value::Null).await.0, StatusCode::OK);
        assert_eq!(as_user(&read, "POST", &sign, ask.clone()).await.0, StatusCode::FORBIDDEN);
        assert_eq!(as_user(&write, "POST", &sign, ask.clone()).await.0, StatusCode::OK);

        // rotation: remove it, make another; the first one is gone for good
        let (sc, _) = as_user(&editor, "DELETE", &ca, Value::Null).await;
        assert_eq!(sc, StatusCode::OK);
        assert!(stored().is_none());
        assert_eq!(as_user(&editor, "DELETE", &ca, Value::Null).await.0, StatusCode::NOT_FOUND);
        assert_eq!(as_user(&editor, "POST", &ca, Value::Null).await.0, StatusCode::OK);
        assert_ne!(stored().unwrap().private_key, key);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn email_settings_take_a_dkim_key_but_never_answer_it() {
        let dir = std::env::temp_dir().join(format!("fucf-api-dkim-{}", uuid::Uuid::new_v4().simple()));
        let st = make_test_state(&dir, crate::sync::NodeRole::Peer);
        st.accounts.create_user("admin@example.com", Role::Admin, Some("strong-pass-123"), "admin@example.com", &Client::default()).unwrap();
        st.accounts.create_user("view@example.com", Role::Viewer, Some("viewer-pass-123"), "admin@example.com", &Client::default()).unwrap();
        let session = |email: &str, password: &str| match st.accounts.login(email, password, &Client::default()).unwrap() {
            Login::Session(token, _) => format!("Bearer {token}"),
            _ => panic!("expected signed in"),
        };
        let (as_admin, as_viewer) = (session("admin@example.com", "strong-pass-123"), session("view@example.com", "viewer-pass-123"));
        let zone = st.store.create_zone("example.com").unwrap();
        let mut app = router(st.clone());
        let json_of = |b: &[u8]| serde_json::from_slice::<Value>(b).unwrap();
        let email = format!("/client/v4/zones/{}/email", zone.id);
        let pem = crate::dkim::test_keys::rsa_2048();
        let secret_part = crate::dkim::test_keys::rsa_2048_b64()[300..340].to_string();
        let leaks = |b: &[u8]| {
            let text = String::from_utf8_lossy(b);
            text.contains(&secret_part) || text.contains("KEY-----") || text.contains("private_key\":\"")
        };

        let (sc, b) = call(&mut app, "GET", &email, vec![]).await;
        assert_eq!(sc, StatusCode::OK);
        let v = json_of(&b)["result"].clone();
        assert_eq!((v["dkim_selector"].clone(), v["has_dkim_private_key"].clone(), v["dkim_record"].clone()), (Value::Null, json!(false), Value::Null));

        let (sc, b) = call(&mut app, "PATCH", &email, json!({ "dkim_selector": "fucf", "dkim_private_key": pem }).to_string().into_bytes()).await;
        assert_eq!(sc, StatusCode::OK, "{}", String::from_utf8_lossy(&b));
        assert!(!leaks(&b), "{}", String::from_utf8_lossy(&b));
        let v = json_of(&b)["result"].clone();
        let record = json!({ "type": "TXT", "name": "fucf._domainkey.example.com", "content": format!("v=DKIM1; k=rsa; p={}", crate::dkim::test_keys::RSA_2048_SPKI) });
        assert_eq!((v["dkim_selector"].clone(), v["has_dkim_private_key"].clone(), v["dkim_key_bits"].clone()), (json!("fucf"), json!(true), json!(2048)));
        assert_eq!((v["dkim_record"].clone(), v["dkim_published"].clone()), (record.clone(), json!(false)));
        assert!(v["needed_records"].as_array().unwrap().contains(&record), "{v}");
        assert!(v.get("rules").is_some() && v.get("enabled").is_some(), "the same answer as GET");
        // nothing else that shows the zone shows the key
        for path in [format!("/client/v4/zones/{}", zone.id), format!("/client/v4/zones/{}/settings", zone.id), "/client/v4/zones".to_string(), email.clone()] {
            let (sc, b) = call(&mut app, "GET", &path, vec![]).await;
            assert!(sc == StatusCode::OK && !leaks(&b), "{path}: {}", String::from_utf8_lossy(&b));
        }

        // the answer sent back as it is keeps the key; refused input changes nothing
        call(&mut app, "PATCH", &email, v.to_string().into_bytes()).await;
        let stored = || st.store.get_zone(&zone.id).unwrap().email_dkim;
        assert_eq!(stored().map(|k| k.private_key), Some(pem.clone()));
        for (body, status) in [
            (json!({ "dkim_selector": "fucf", "dkim_private_key": "***" }).to_string(), StatusCode::BAD_REQUEST),
            (json!({ "dkim_selector": "under_score" }).to_string(), StatusCode::BAD_REQUEST),
            (json!({ "dkim_selector": "fucf", "dkim_private_key": crate::dkim::test_keys::rsa_1024() }).to_string(), StatusCode::BAD_REQUEST),
            ("not json".to_string(), StatusCode::BAD_REQUEST),
        ] {
            let (sc, b) = call(&mut app, "PATCH", &email, body.clone().into_bytes()).await;
            assert_eq!(sc, status, "{body}: {}", String::from_utf8_lossy(&b));
            assert!(!leaks(&b));
            assert_eq!(stored().map(|k| (k.selector, k.private_key)), Some(("fucf".to_string(), pem.clone())), "{body}");
        }
        let (sc, _) = call(&mut app, "PATCH", "/client/v4/zones/0123456789abcdef0123456789abcdef/email", json!({ "dkim_selector": "fucf" }).to_string().into_bytes()).await;
        assert_eq!(sc, StatusCode::NOT_FOUND);

        // once the record is there, it is no longer asked for
        let (sc, b) = call(&mut app, "POST", &format!("/client/v4/zones/{}/dns_records", zone.id), record.to_string().into_bytes()).await;
        assert_eq!(sc, StatusCode::OK, "{}", String::from_utf8_lossy(&b));
        let (_, b) = call(&mut app, "GET", &email, vec![]).await;
        let v = json_of(&b)["result"].clone();
        assert_eq!(v["dkim_published"], json!(true));
        assert!(!v["needed_records"].as_array().unwrap().iter().any(|r| r["name"] == record["name"]), "{v}");

        // viewers read, but do not change (once past their first password)
        give(&st, &zone.id, "view@example.com").await;
        let first = br#"{"current":"viewer-pass-123","new":"viewer-pass-456"}"#.to_vec();
        let (sc, _, _) = call_raw(&mut app, "POST", "/client/v4/account/password", vec![("authorization", &as_viewer), ("content-type", "application/json")], first).await;
        assert_eq!(sc, StatusCode::OK);
        let (sc, _, b) = call_raw(&mut app, "GET", &email, vec![("authorization", &as_viewer)], vec![]).await;
        assert!(sc == StatusCode::OK && !leaks(&b), "{sc}");
        let (sc, _, _) = call_raw(&mut app, "PATCH", &email, vec![("authorization", &as_viewer), ("content-type", "application/json")], br#"{"dkim_selector":null}"#.to_vec()).await;
        assert_eq!(sc, StatusCode::FORBIDDEN);
        assert!(stored().is_some());

        // tokens: e-mail routing read sees it, write changes it, others neither
        let token = |group: &str| {
            let spec = json!({ "name": group, "policies": [{ "effect": "allow",
                "resources": { format!("com.cloudflare.api.account.zone.{}", zone.id): "*" }, "permission_groups": [{ "name": group }] }] });
            (spec.to_string().into_bytes(), group.to_string())
        };
        let mut bearer = HashMap::new();
        for group in ["Email Routing Rules Read", "Email Routing Rules Write", "DNS Write"] {
            let (spec, name) = token(group);
            let (sc, _, b) = call_raw(&mut app, "POST", "/client/v4/user/tokens", vec![("authorization", &as_admin), ("content-type", "application/json")], spec).await;
            assert_eq!(sc, StatusCode::OK, "{}", String::from_utf8_lossy(&b));
            bearer.insert(name, format!("Bearer {}", json_of(&b)["result"]["value"].as_str().unwrap()));
        }
        let with = |group: &str| vec![("authorization", bearer[group].as_str()), ("content-type", "application/json")];
        let remove = br#"{"dkim_selector":""}"#.to_vec();
        let (sc, _, b) = call_raw(&mut app, "GET", &email, with("Email Routing Rules Read"), vec![]).await;
        assert!(sc == StatusCode::OK && !leaks(&b));
        let (sc, _, _) = call_raw(&mut app, "PATCH", &email, with("Email Routing Rules Read"), remove.clone()).await;
        assert_eq!(sc, StatusCode::FORBIDDEN);
        let (sc, _, _) = call_raw(&mut app, "GET", &email, with("DNS Write"), vec![]).await;
        assert_eq!(sc, StatusCode::FORBIDDEN);
        let (sc, _, _) = call_raw(&mut app, "PATCH", &email, with("DNS Write"), remove.clone()).await;
        assert_eq!(sc, StatusCode::FORBIDDEN);
        assert!(stored().is_some());
        let (sc, _, b) = call_raw(&mut app, "PATCH", &email, with("Email Routing Rules Write"), remove).await;
        assert_eq!(sc, StatusCode::OK, "{}", String::from_utf8_lossy(&b));
        assert_eq!(json_of(&b)["result"]["has_dkim_private_key"], json!(false));
        assert!(stored().is_none());

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn users_see_and_change_only_their_own_zones_and_administrators_see_all() {
        let dir = std::env::temp_dir().join(format!("fucf-api-tenancy-{}", uuid::Uuid::new_v4().simple()));
        let st = make_test_state(&dir, crate::sync::NodeRole::Peer);
        let mut app = router(st.clone());
        let json_of = |b: &[u8]| serde_json::from_slice::<Value>(b).unwrap();
        // two editors, each past their first password
        let mut sessions = HashMap::new();
        for who in ["alice", "bob"] {
            let email = format!("{who}@example.com");
            st.accounts.create_user(&email, Role::Editor, Some("first-pass-123"), "admin@example.com", &Client::default()).unwrap();
            let Login::Session(token, _) = st.accounts.login(&email, "first-pass-123", &Client::default()).unwrap() else { panic!("expected signed in") };
            let bearer = format!("Bearer {token}");
            let (sc, _, _) = call_raw(&mut app, "POST", "/client/v4/account/password", vec![("authorization", &bearer), ("content-type", "application/json")],
                br#"{"current":"first-pass-123","new":"second-pass-456"}"#.to_vec()).await;
            assert_eq!(sc, StatusCode::OK);
            sessions.insert(who, bearer);
        }
        let as_user = |who: &str| vec![("authorization", sessions[who].as_str()), ("content-type", "application/json")];
        let mut users_app = app.clone();
        let mut ask = async move |who: &str, method: &str, path: &str, body: Value| {
            let body = if body.is_null() { vec![] } else { body.to_string().into_bytes() };
            let (sc, _, b) = call_raw(&mut users_app, method, &format!("/client/v4{path}"), as_user(who), body).await;
            (sc, b)
        };

        let (sc, b) = ask("alice", "POST", "/zones", json!({ "name": "alice.example.com" })).await;
        assert_eq!(sc, StatusCode::OK, "{}", String::from_utf8_lossy(&b));
        let mine = json_of(&b)["result"]["id"].as_str().unwrap().to_string();
        let alice_id = st.accounts.users().iter().find(|u| u["email"] == "alice@example.com").unwrap()["id"].clone();
        assert_eq!(json_of(&b)["result"]["owner"]["id"], alice_id);
        let (_, b) = ask("bob", "POST", "/zones", json!({ "name": "bob.example.net" })).await;
        let theirs = json_of(&b)["result"]["id"].as_str().unwrap().to_string();
        let unowned = st.store.create_zone("old.example.org").unwrap().id;

        // the list: each their own, the fleet's token (an administrator) all three
        let names = |b: &[u8]| json_of(b)["result"].as_array().unwrap().iter().map(|z| z["name"].as_str().unwrap().to_string()).collect::<Vec<_>>();
        let (_, b) = ask("alice", "GET", "/zones", Value::Null).await;
        assert_eq!(names(&b), ["alice.example.com"]);
        let (_, b) = ask("bob", "GET", "/zones?name=alice.example.com", Value::Null).await;
        assert!(names(&b).is_empty(), "not even by name");
        let (_, b) = call(&mut app, "GET", "/client/v4/zones", vec![]).await;
        assert_eq!(names(&b).len(), 3);

        // every kind of zone path answers another user's zone as if it were not there
        let reads = ["", "/dns_records", "/dns_records/export", "/settings", "/settings/ssl", "/dnssec", "/rulesets", "/firewall/rules", "/rate_limits",
            "/cache_rules", "/workers/routes", "/email", "/email/rules", "/waiting_rooms", "/ssl/certificate_packs", "/custom_certificates", "/custom_hostnames",
            "/security/events", "/logs/requests"];
        for path in reads {
            for zone in [&theirs, &unowned] {
                let (sc, b) = ask("alice", "GET", &format!("/zones/{zone}{path}"), Value::Null).await;
                assert_eq!((sc, json_of(&b)["errors"][0]["code"].clone()), (StatusCode::NOT_FOUND, json!(1001)), "{path}");
            }
            let (sc, b) = ask("alice", "GET", &format!("/zones/{mine}{path}"), Value::Null).await;
            assert!(sc != StatusCode::NOT_FOUND && sc != StatusCode::FORBIDDEN, "{path}: {sc} {}", String::from_utf8_lossy(&b));
        }
        let writes = [
            ("POST", "/dns_records", json!({ "type": "A", "name": "www", "content": "192.0.2.1" })),
            ("PATCH", "/settings/ssl", json!({ "value": "full" })),
            ("POST", "/firewall/rules", json!({ "description": "x", "expression": "ip.src eq 192.0.2.1", "action": "block" })),
            ("PUT", "/rulesets/phases/http_request_firewall_custom/entrypoint", json!({ "rules": [] })),
            ("POST", "/purge_cache", json!({ "purge_everything": true })),
            ("PATCH", "/email", json!({ "dkim_selector": null })),
            ("PATCH", "", json!({ "paused": true })),
            ("DELETE", "", Value::Null),
        ];
        for (method, path, body) in &writes {
            let (sc, _) = ask("alice", method, &format!("/zones/{theirs}{path}"), body.clone()).await;
            assert_eq!(sc, StatusCode::NOT_FOUND, "{method} {path}");
        }
        // the router decodes the id for the handler, so an encoded one is the same zone
        let encoded: String = theirs.bytes().map(|b| format!("%{b:02X}")).collect();
        let (sc, _) = ask("alice", "GET", &format!("/zones/{encoded}/dns_records"), Value::Null).await;
        assert_eq!(sc, StatusCode::NOT_FOUND);
        let (sc, _) = ask("alice", "PATCH", &format!("/zones/{encoded}"), json!({ "paused": true })).await;
        assert_eq!(sc, StatusCode::NOT_FOUND);
        let own: String = mine.bytes().map(|b| format!("%{b:02X}")).collect();
        let (sc, _) = ask("alice", "GET", &format!("/zones/{own}/dns_records"), Value::Null).await;
        assert_eq!(sc, StatusCode::OK, "the router does decode it");
        let bob_zone = st.store.get_zone(&theirs).unwrap();
        assert!(!bob_zone.paused && st.store.list_records(&theirs).unwrap().1.is_empty(), "nothing of bob's changed");
        let (sc, b) = ask("alice", "POST", &format!("/zones/{mine}/dns_records"), writes[0].2.clone()).await;
        assert_eq!(sc, StatusCode::OK, "{}", String::from_utf8_lossy(&b));

        // a zone inside another user's is refused; owners are the administrators' to change
        let (sc, b) = ask("alice", "POST", "/zones", json!({ "name": "shop.bob.example.net" })).await;
        assert_eq!(sc, StatusCode::CONFLICT, "{}", String::from_utf8_lossy(&b));
        let (sc, _) = ask("alice", "POST", "/zones", json!({ "name": "example.org" })).await;
        assert_eq!(sc, StatusCode::CONFLICT, "above the administrators' zone");
        let (sc, _) = ask("alice", "POST", "/zones", json!({ "name": "new.example.com", "owner": null })).await;
        assert_eq!(sc, StatusCode::BAD_REQUEST);
        let (sc, _) = ask("alice", "PATCH", &format!("/zones/{mine}"), json!({ "owner": null })).await;
        assert_eq!(sc, StatusCode::FORBIDDEN);
        assert!(st.store.get_zone(&mine).unwrap().owner.is_some());

        // account-level objects: they read, administrators change
        let (sc, _) = ask("alice", "GET", "/kv/namespaces", Value::Null).await;
        assert_eq!(sc, StatusCode::OK);
        for (method, path) in [("POST", "/kv/namespaces"), ("POST", "/d1/database"), ("POST", "/rules/lists"), ("PUT", "/workers/scripts/w")] {
            let (sc, b) = ask("alice", method, path, json!({ "title": "x", "name": "x", "kind": "ip" })).await;
            assert_eq!(sc, StatusCode::FORBIDDEN, "{method} {path}: {}", String::from_utf8_lossy(&b));
        }

        // Workers run the administrators' code: no routes or e-mail rules to them from users
        let (sc, _) = ask("alice", "POST", &format!("/zones/{mine}/workers/routes"), json!({ "pattern": "alice.example.com/*", "script": "w" })).await;
        assert_eq!(sc, StatusCode::FORBIDDEN);
        let rules = format!("/zones/{mine}/email/rules");
        let (sc, _) = ask("alice", "POST", &rules, json!({ "address": "hi", "action": "worker", "worker": "w" })).await;
        assert_eq!(sc, StatusCode::FORBIDDEN);
        let (sc, b) = ask("alice", "POST", &rules, json!({ "address": "hi", "action": "forward", "destinations": ["owner@example.net"] })).await;
        assert_eq!(sc, StatusCode::OK, "{}", String::from_utf8_lossy(&b));
        let rule = json_of(&b)["result"]["id"].as_str().unwrap().to_string();
        let (sc, _) = ask("alice", "PATCH", &format!("{rules}/{rule}"), json!({ "worker": "w" })).await;
        assert_eq!(sc, StatusCode::FORBIDDEN, "nor turned into one");
        let (sc, _) = ask("alice", "PATCH", &format!("{rules}/{rule}"), json!({ "description": "mine" })).await;
        assert_eq!(sc, StatusCode::OK);

        // analytics count only the zones one sees
        let (_, b) = ask("alice", "GET", "/analytics", Value::Null).await;
        let zones = json_of(&b)["result"]["zones"].as_object().unwrap().keys().cloned().collect::<Vec<_>>();
        assert_eq!(zones, [mine.clone()]);

        // a token reaches no further than its user, even one for every zone
        let spec = json!({ "name": "all", "policies": [{ "effect": "allow", "resources": { "com.cloudflare.api.account.zone.*": "*" },
            "permission_groups": [{ "name": "Zone Read" }, { "name": "DNS Write" }] }] });
        let (sc, b) = ask("alice", "POST", "/user/tokens", spec).await;
        assert_eq!(sc, StatusCode::OK, "{}", String::from_utf8_lossy(&b));
        let bearer = format!("Bearer {}", json_of(&b)["result"]["value"].as_str().unwrap());
        let with = vec![("authorization", bearer.as_str()), ("content-type", "application/json")];
        let (_, _, b) = call_raw(&mut app, "GET", "/client/v4/zones", with.clone(), vec![]).await;
        assert_eq!(names(&b), ["alice.example.com"]);
        let (sc, _, _) = call_raw(&mut app, "GET", &format!("/client/v4/zones/{theirs}/dns_records"), with.clone(), vec![]).await;
        assert_eq!(sc, StatusCode::NOT_FOUND);
        let (sc, _, _) = call_raw(&mut app, "POST", &format!("/client/v4/zones/{theirs}/dns_records"), with.clone(), writes[0].2.to_string().into_bytes()).await;
        assert_eq!(sc, StatusCode::NOT_FOUND);
        let (sc, _, _) = call_raw(&mut app, "GET", &format!("/client/v4/zones/{mine}/dns_records"), with.clone(), vec![]).await;
        assert_eq!(sc, StatusCode::OK);

        // an administrator gives bob's zone to alice, then to nobody
        for bad_owner in [json!("0123456789abcdef0123456789abcdef"), json!(7), json!({ "id": 7 })] {
            let (sc, _) = call(&mut app, "PATCH", &format!("/client/v4/zones/{theirs}"), json!({ "owner": bad_owner, "paused": true }).to_string().into_bytes()).await;
            assert_eq!(sc, StatusCode::BAD_REQUEST, "{bad_owner}");
            assert!(!st.store.get_zone(&theirs).unwrap().paused, "a refused owner changes nothing else");
        }
        let (sc, b) = call(&mut app, "PATCH", &format!("/client/v4/zones/{theirs}"), json!({ "owner": { "id": alice_id } }).to_string().into_bytes()).await;
        assert_eq!((sc, json_of(&b)["result"]["owner"]["id"].clone()), (StatusCode::OK, alice_id.clone()));
        let (sc, _) = ask("alice", "GET", &format!("/zones/{theirs}/dns_records"), Value::Null).await;
        assert_eq!(sc, StatusCode::OK);
        let (sc, _) = ask("bob", "GET", &format!("/zones/{theirs}"), Value::Null).await;
        assert_eq!(sc, StatusCode::NOT_FOUND, "bob gave it up");
        let (sc, b) = call(&mut app, "PATCH", &format!("/client/v4/zones/{theirs}"), json!({ "owner": null }).to_string().into_bytes()).await;
        assert_eq!((sc, json_of(&b)["result"]["owner"]["id"].clone()), (StatusCode::OK, Value::Null));
        let (sc, _) = ask("alice", "GET", &format!("/zones/{theirs}"), Value::Null).await;
        assert_eq!(sc, StatusCode::NOT_FOUND);

        let _ = std::fs::remove_dir_all(dir);
    }
}
