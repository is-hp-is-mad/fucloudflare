//! Workers: user JavaScript executed at the edge (Boa engine).
//!
//! Each request gets a fresh JS context on a blocking thread. The Fetch API
//! lives in `prelude.js`; this module provides the host functions under it
//! and converts between HTTP and the JSON the prelude speaks.
//!
//! Scripts use the Cloudflare shapes:
//! `export default { async fetch(request, env, ctx) { ... } }` or
//! `addEventListener("fetch", event => event.respondWith(...))`.

pub mod cron;
pub mod crypto;
pub mod db;
pub mod kv;

use crate::edge::{full, Body, Edge, EdgeError, WORKER_BODY_LIMIT};
use crate::expr::ReqInfo;
use crate::items::WorkerScript;
use crate::store::Snapshot;
use boa_engine::property::Attribute;
use boa_engine::{js_string, Context, JsError, JsNativeError, JsResult, JsString, JsValue, NativeFunction, Script, Source};
use bytes::Bytes;
use hyper::header::{HeaderName, HeaderValue};
use hyper::{Response, StatusCode};
use serde::Deserialize;
use std::cell::RefCell;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

const PRELUDE: &str = include_str!("prelude.js");
const WALL_LIMIT: Duration = Duration::from_secs(30);
const LOOP_LIMIT: u64 = 20_000_000;
const MAX_SUBREQUESTS: u32 = 50;
const MAX_CONCURRENT_WORKERS: usize = 16;

static WORKER_SLOTS: std::sync::LazyLock<tokio::sync::Semaphore> =
    std::sync::LazyLock::new(|| tokio::sync::Semaphore::new(MAX_CONCURRENT_WORKERS));

/// Per-invocation state reachable from the host functions. A worker runs
/// start-to-finish on one blocking thread, so a thread-local is enough.
struct State {
    edge: Arc<Edge>,
    snap: Arc<Snapshot>,
    info: ReqInfo,
    name: String,
    runtime: tokio::runtime::Handle,
    /// Byte buffers referenced from JS by index; 0 is the request body.
    bodies: Vec<Bytes>,
    subrequests: u32,
    kv: Option<Arc<kv::KvStore>>,
    d1: Option<Arc<db::D1Store>>,
    allowed_kv: HashSet<String>,
    allowed_d1: HashSet<String>,
}

thread_local! {
    static STATE: RefCell<Option<State>> = const { RefCell::new(None) };
}

fn throw(msg: impl Into<String>) -> JsError {
    JsNativeError::typ().with_message(msg.into()).into()
}

fn arg_string(args: &[JsValue], ctx: &mut Context) -> JsResult<String> {
    Ok(args.first().cloned().unwrap_or_default().to_string(ctx)?.to_std_string_lossy())
}

#[derive(Deserialize)]
struct FetchCall {
    method: String,
    url: String,
    headers: Vec<(String, String)>,
    body: Option<String>,
    #[serde(rename = "bodyId")]
    body_id: Option<usize>,
}

fn host_fetch(_: &JsValue, args: &[JsValue], ctx: &mut Context) -> JsResult<JsValue> {
    let call: FetchCall = serde_json::from_str(&arg_string(args, ctx)?).map_err(|e| throw(e.to_string()))?;
    let (edge, snap, info, runtime, body) = STATE.with_borrow_mut(|s| {
        let s = s.as_mut().ok_or_else(|| throw("no worker state"))?;
        s.subrequests += 1;
        if s.subrequests > MAX_SUBREQUESTS {
            return Err(throw("too many subrequests"));
        }
        let body = match (call.body, call.body_id) {
            (Some(text), _) => Bytes::from(text),
            (None, Some(id)) => s.bodies.get(id).cloned().unwrap_or_default(),
            (None, None) => Bytes::new(),
        };
        Ok((s.edge.clone(), s.snap.clone(), s.info.clone(), s.runtime.clone(), body))
    })?;
    let result = runtime.block_on(edge.subrequest(&snap, &info, &call.method, &call.url, call.headers, body));
    let (status, headers, data) = result.map_err(throw)?;
    let id = STATE.with_borrow_mut(|s| {
        let bodies = &mut s.as_mut().expect("worker state").bodies;
        bodies.push(data);
        bodies.len() - 1
    });
    let out = serde_json::json!({ "status": status, "headers": headers, "bodyId": id });
    Ok(JsString::from(out.to_string()).into())
}

fn host_body_text(_: &JsValue, args: &[JsValue], ctx: &mut Context) -> JsResult<JsValue> {
    let id = args.first().cloned().unwrap_or_default().to_u32(ctx)? as usize;
    let text = STATE.with_borrow(|s| {
        s.as_ref().and_then(|s| s.bodies.get(id)).map(|b| String::from_utf8_lossy(b).into_owned())
    });
    Ok(JsString::from(text.ok_or_else(|| throw("unknown body"))?).into())
}

fn host_log(_: &JsValue, args: &[JsValue], ctx: &mut Context) -> JsResult<JsValue> {
    let msg: String = arg_string(args, ctx)?.chars().take(2048).collect();
    let name = STATE.with_borrow(|s| s.as_ref().map(|s| s.name.clone()).unwrap_or_default());
    tracing::info!(worker = %name, "{msg}");
    Ok(JsValue::undefined())
}

fn with_kv(
    args: &[JsValue],
    ctx: &mut Context,
    f: impl FnOnce(&Arc<kv::KvStore>, &tokio::runtime::Handle, &str) -> Result<String, String>,
) -> JsResult<JsValue> {
    let arg = arg_string(args, ctx)?;
    let parsed: serde_json::Value = serde_json::from_str(&arg).map_err(|e| throw(e.to_string()))?;
    let ns_id = parsed
        .get("ns_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| throw("missing ns_id"))?;
    let (kv, rt) = STATE.with_borrow(|s| {
        let s = s.as_ref().ok_or_else(|| throw("no worker state"))?;
        if !s.allowed_kv.contains(ns_id) {
            return Err(throw("unauthorized KV namespace binding"));
        }
        let kv = s.kv.clone().ok_or_else(|| throw("KV store not configured"))?;
        Ok::<_, JsError>((kv, s.runtime.clone()))
    })?;
    let out = f(&kv, &rt, &arg).map_err(throw)?;
    Ok(JsString::from(out).into())
}

fn with_d1(
    args: &[JsValue],
    ctx: &mut Context,
    f: impl FnOnce(&Arc<db::D1Store>, &tokio::runtime::Handle, &str) -> Result<String, String>,
) -> JsResult<JsValue> {
    let arg = arg_string(args, ctx)?;
    let parsed: serde_json::Value = serde_json::from_str(&arg).map_err(|e| throw(e.to_string()))?;
    let db_id = parsed
        .get("db_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| throw("missing db_id"))?;
    let (d1, rt) = STATE.with_borrow(|s| {
        let s = s.as_ref().ok_or_else(|| throw("no worker state"))?;
        if !s.allowed_d1.contains(db_id) {
            return Err(throw("unauthorized D1 database binding"));
        }
        let d1 = s.d1.clone().ok_or_else(|| throw("D1 store not configured"))?;
        Ok::<_, JsError>((d1, s.runtime.clone()))
    })?;
    let out = f(&d1, &rt, &arg).map_err(throw)?;
    Ok(JsString::from(out).into())
}

fn host_kv_get(_: &JsValue, args: &[JsValue], ctx: &mut Context) -> JsResult<JsValue> {
    with_kv(args, ctx, kv::host_kv_get)
}
fn host_kv_put(_: &JsValue, args: &[JsValue], ctx: &mut Context) -> JsResult<JsValue> {
    with_kv(args, ctx, kv::host_kv_put)
}
fn host_kv_delete(_: &JsValue, args: &[JsValue], ctx: &mut Context) -> JsResult<JsValue> {
    with_kv(args, ctx, kv::host_kv_delete)
}
fn host_kv_list(_: &JsValue, args: &[JsValue], ctx: &mut Context) -> JsResult<JsValue> {
    with_kv(args, ctx, kv::host_kv_list)
}

fn host_d1_query(_: &JsValue, args: &[JsValue], ctx: &mut Context) -> JsResult<JsValue> {
    with_d1(args, ctx, db::host_d1_query)
}
fn host_d1_batch(_: &JsValue, args: &[JsValue], ctx: &mut Context) -> JsResult<JsValue> {
    with_d1(args, ctx, db::host_d1_batch)
}
fn host_d1_exec(_: &JsValue, args: &[JsValue], ctx: &mut Context) -> JsResult<JsValue> {
    with_d1(args, ctx, db::host_d1_exec)
}

fn register_natives(ctx: &mut Context) -> Result<(), String> {
    let natives: [(JsString, usize, fn(&JsValue, &[JsValue], &mut Context) -> JsResult<JsValue>); 18] = [
        (js_string!("__fetch"), 1, host_fetch),
        (js_string!("__bodyText"), 1, host_body_text),
        (js_string!("__log"), 1, host_log),
        (js_string!("__cryptoRandom"), 1, crypto::host_crypto_random),
        (js_string!("__cryptoDigest"), 2, crypto::host_crypto_digest),
        (js_string!("__cryptoSign"), 1, crypto::host_crypto_sign),
        (js_string!("__cryptoVerify"), 1, crypto::host_crypto_verify),
        (js_string!("__cryptoEncrypt"), 1, crypto::host_crypto_encrypt),
        (js_string!("__cryptoDecrypt"), 1, crypto::host_crypto_decrypt),
        (js_string!("__cryptoGenerateEc"), 1, crypto::host_crypto_generate_ec),
        (js_string!("__cryptoDeriveBits"), 1, crypto::host_crypto_derive_bits),
        (js_string!("__kvGet"), 1, host_kv_get),
        (js_string!("__kvPut"), 1, host_kv_put),
        (js_string!("__kvDelete"), 1, host_kv_delete),
        (js_string!("__kvList"), 1, host_kv_list),
        (js_string!("__d1Query"), 1, host_d1_query),
        (js_string!("__d1Batch"), 1, host_d1_batch),
        (js_string!("__d1Exec"), 1, host_d1_exec),
    ];
    for (name, len, f) in natives {
        ctx.register_global_callable(name, len, NativeFunction::from_fn_ptr(f))
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn env_json(script: &WorkerScript) -> String {
    serde_json::json!({
        "__vars": script.vars,
        "__kv": script.kv_bindings,
        "__d1": script.d1_bindings,
    })
    .to_string()
}

/// `export default X` -> a global assignment, so module-style scripts run as
/// classic scripts (single-file workers only; other imports/exports fail).
fn transform(src: &str) -> String {
    static EXPORT: std::sync::LazyLock<regex::Regex> =
        std::sync::LazyLock::new(|| regex::Regex::new(r"(?m)^(\s*)export\s+default\s+").expect("regex"));
    EXPORT.replace(src, "${1}globalThis.__default = ").into_owned()
}

fn describe(e: JsError, ctx: &mut Context) -> String {
    match e.try_native(ctx) {
        Ok(native) => native.to_string(),
        Err(_) => e.to_string(),
    }
}

/// Reject scripts that do not parse, at upload time.
pub fn check_syntax(src: &str) -> Result<(), String> {
    let mut ctx = Context::default();
    let code = transform(src);
    Script::parse(Source::from_bytes(&code), None, &mut ctx)
        .map(|_| ())
        .map_err(|e| format!("script does not parse: {}", describe(e, &mut ctx)))
}

#[derive(Deserialize)]
struct Output {
    status: u16,
    headers: Vec<(String, String)>,
    body: Option<String>,
    #[serde(rename = "bodyId")]
    body_id: Option<usize>,
}

fn global_string(ctx: &mut Context, name: JsString) -> Option<String> {
    let v = ctx.global_object().get(name, ctx).ok()?;
    v.as_string().map(|s| s.to_std_string_lossy())
}

/// Run the script for one request; blocking.
fn execute(script: &WorkerScript, request: String) -> Result<(Output, Bytes), String> {
    let mut ctx = Context::default();
    ctx.runtime_limits_mut().set_loop_iteration_limit(LOOP_LIMIT);
    ctx.runtime_limits_mut().set_recursion_limit(400);

    register_natives(&mut ctx)?;
    ctx.eval(Source::from_bytes(PRELUDE)).map_err(|e| format!("prelude: {}", describe(e, &mut ctx)))?;

    let env = env_json(script);
    for (name, value) in [(js_string!("__req"), request), (js_string!("__env"), env)] {
        ctx.register_global_property(name, JsString::from(value), Attribute::all()).map_err(|e| e.to_string())?;
    }

    let code = transform(&script.script);
    ctx.eval(Source::from_bytes(&code)).map_err(|e| describe(e, &mut ctx))?;
    ctx.eval(Source::from_bytes("__run(__req, __env)")).map_err(|e| describe(e, &mut ctx))?;
    ctx.run_jobs().map_err(|e| describe(e, &mut ctx))?;

    if let Some(err) = global_string(&mut ctx, js_string!("__err")) {
        return Err(err);
    }
    let out = global_string(&mut ctx, js_string!("__out")).ok_or("the fetch handler never settled")?;
    let out: Output = serde_json::from_str(&out).map_err(|e| e.to_string())?;
    let body = match (&out.body, out.body_id) {
        (Some(text), _) => Bytes::from(text.clone()),
        (None, Some(id)) => STATE.with_borrow(|s| s.as_ref().and_then(|s| s.bodies.get(id).cloned())).unwrap_or_default(),
        (None, None) => Bytes::new(),
    };
    Ok((out, body))
}

pub async fn run(
    edge: Arc<Edge>,
    snap: Arc<Snapshot>,
    script: Arc<WorkerScript>,
    info: ReqInfo,
    body: Bytes,
) -> Result<Response<Body>, EdgeError> {
    let request = serde_json::json!({
        "url": format!("{}://{}{}", if info.ssl { "https" } else { "http" }, info.host, info.uri()),
        "method": info.method,
        "headers": info.headers,
        "hasBody": !body.is_empty(),
        "cf": { "clientIp": info.ip.map(|i| i.to_string()) },
    })
    .to_string();
    let name = script.name.clone();
    let kv = edge.kv.get().cloned();
    let d1 = edge.d1.get().cloned();
    let state = State {
        edge,
        snap,
        info,
        name: name.clone(),
        runtime: tokio::runtime::Handle::current(),
        bodies: vec![body],
        subrequests: 0,
        kv,
        d1,
        allowed_kv: script.kv_bindings.values().cloned().collect(),
        allowed_d1: script.d1_bindings.values().cloned().collect(),
    };

    let slot = tokio::time::timeout(Duration::from_secs(5), WORKER_SLOTS.acquire())
        .await
        .map_err(|_| EdgeError::new(503, "Worker busy", "too many concurrent worker executions"))?
        .map_err(|_| EdgeError::new(503, "Worker unavailable", "worker runtime shutting down"))?;
    let task = tokio::task::spawn_blocking(move || {
        let _slot = slot;
        STATE.set(Some(state));
        let result = execute(&script, request);
        STATE.set(None);
        result
    });
    let failed = |why: String| {
        tracing::warn!(worker = %name, "worker failed: {why}");
        EdgeError::new(500, "Worker threw exception", "the worker script for this route failed")
    };
    let (out, body) = match tokio::time::timeout(WALL_LIMIT, task).await {
        Err(_) => return Err(failed("exceeded the time limit".into())),
        Ok(Err(join)) => return Err(failed(format!("crashed: {join}"))),
        Ok(Ok(Err(e))) => return Err(failed(e)),
        Ok(Ok(Ok(x))) => x,
    };
    if body.len() > WORKER_BODY_LIMIT {
        return Err(failed("response body too large".into()));
    }

    let mut resp = Response::new(full(body));
    *resp.status_mut() = StatusCode::from_u16(out.status).map_err(|_| failed("invalid status".into()))?;
    for (n, v) in &out.headers {
        // length and framing are recomputed for the body we actually send
        if matches!(n.to_ascii_lowercase().as_str(), "content-length" | "transfer-encoding" | "connection") {
            continue;
        }
        if let (Ok(n), Ok(v)) = (HeaderName::from_bytes(n.as_bytes()), HeaderValue::from_str(v)) {
            resp.headers_mut().append(n, v);
        }
    }
    Ok(resp)
}

/// Outcome of an Email Routing Worker (`export default { async email(message, env, ctx) }`).
#[derive(Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct EmailOutcome {
    pub reject: Option<String>,
    pub forwards: Vec<String>,
}

/// Parse RFC 5322 header lines (up to the first blank line) into `(name, value)` pairs.
fn parse_email_headers(raw: &[u8]) -> Vec<(String, String)> {
    let text = String::from_utf8_lossy(raw);
    let head = text.split("\r\n\r\n").next().or_else(|| text.split("\n\n").next()).unwrap_or("");
    let mut out: Vec<(String, String)> = Vec::new();
    for line in head.lines() {
        let line = line.trim_end_matches('\r');
        if line.starts_with([' ', '\t']) {
            if let Some(last) = out.last_mut() {
                last.1.push(' ');
                last.1.push_str(line.trim());
            }
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            let name = k.trim();
            if !name.is_empty() {
                out.push((name.to_string(), v.trim().to_string()));
            }
        }
    }
    out
}

fn execute_email(script: &WorkerScript, msg_json: String) -> Result<EmailOutcome, String> {
    let mut ctx = Context::default();
    ctx.runtime_limits_mut().set_loop_iteration_limit(LOOP_LIMIT);
    ctx.runtime_limits_mut().set_recursion_limit(400);

    register_natives(&mut ctx)?;
    ctx.eval(Source::from_bytes(PRELUDE)).map_err(|e| format!("prelude: {}", describe(e, &mut ctx)))?;

    let env = env_json(script);
    for (name, value) in [(js_string!("__msg"), msg_json), (js_string!("__env"), env)] {
        ctx.register_global_property(name, JsString::from(value), Attribute::all()).map_err(|e| e.to_string())?;
    }

    let code = transform(&script.script);
    ctx.eval(Source::from_bytes(&code)).map_err(|e| describe(e, &mut ctx))?;
    ctx.eval(Source::from_bytes("__runEmail(__msg, __env)")).map_err(|e| describe(e, &mut ctx))?;
    ctx.run_jobs().map_err(|e| describe(e, &mut ctx))?;

    if let Some(err) = global_string(&mut ctx, js_string!("__err")) {
        return Err(err);
    }
    let out = global_string(&mut ctx, js_string!("__out")).ok_or("the email handler never settled")?;
    serde_json::from_str(&out).map_err(|e| e.to_string())
}

pub async fn run_email(
    edge: Arc<Edge>,
    snap: Arc<Snapshot>,
    script: Arc<WorkerScript>,
    from: &str,
    to: &str,
    raw: Bytes,
) -> Result<EmailOutcome, String> {
    let headers = parse_email_headers(&raw);
    let msg_json = serde_json::json!({
        "from": from,
        "to": to,
        "headers": headers,
        "rawSize": raw.len(),
    })
    .to_string();
    let name = script.name.clone();
    let kv = edge.kv.get().cloned();
    let d1 = edge.d1.get().cloned();
    let state = State {
        edge,
        snap,
        info: ReqInfo::default(),
        name: name.clone(),
        runtime: tokio::runtime::Handle::current(),
        bodies: vec![raw],
        subrequests: 0,
        kv,
        d1,
        allowed_kv: script.kv_bindings.values().cloned().collect(),
        allowed_d1: script.d1_bindings.values().cloned().collect(),
    };

    let slot = tokio::time::timeout(Duration::from_secs(5), WORKER_SLOTS.acquire())
        .await
        .map_err(|_| "too many concurrent worker executions".to_string())?
        .map_err(|_| "worker runtime shutting down".to_string())?;
    let task = tokio::task::spawn_blocking(move || {
        let _slot = slot;
        STATE.set(Some(state));
        let result = execute_email(&script, msg_json);
        STATE.set(None);
        result
    });
    match tokio::time::timeout(WALL_LIMIT, task).await {
        Err(_) => Err("email worker exceeded the time limit".into()),
        Ok(Err(join)) => Err(format!("email worker crashed: {join}")),
        Ok(Ok(res)) => res,
    }
}

fn execute_scheduled(script: &WorkerScript, ctrl_json: String) -> Result<(), String> {
    let mut ctx = Context::default();
    ctx.runtime_limits_mut().set_loop_iteration_limit(LOOP_LIMIT);
    ctx.runtime_limits_mut().set_recursion_limit(400);

    register_natives(&mut ctx)?;
    ctx.eval(Source::from_bytes(PRELUDE)).map_err(|e| format!("prelude: {}", describe(e, &mut ctx)))?;

    let env = env_json(script);
    for (name, value) in [(js_string!("__ctrl"), ctrl_json), (js_string!("__env"), env)] {
        ctx.register_global_property(name, JsString::from(value), Attribute::all()).map_err(|e| e.to_string())?;
    }

    let code = transform(&script.script);
    ctx.eval(Source::from_bytes(&code)).map_err(|e| describe(e, &mut ctx))?;
    ctx.eval(Source::from_bytes("__runScheduled(__ctrl, __env)")).map_err(|e| describe(e, &mut ctx))?;
    ctx.run_jobs().map_err(|e| describe(e, &mut ctx))?;

    if let Some(err) = global_string(&mut ctx, js_string!("__err")) {
        return Err(err);
    }
    let _ = global_string(&mut ctx, js_string!("__out")).ok_or("the scheduled handler never settled")?;
    Ok(())
}

pub async fn run_scheduled(
    edge: Arc<Edge>,
    snap: Arc<Snapshot>,
    script: Arc<WorkerScript>,
    cron: &str,
    scheduled_ms: u64,
) -> Result<(), String> {
    let ctrl_json = serde_json::json!({
        "cron": cron,
        "scheduledTime": scheduled_ms,
    })
    .to_string();
    let name = script.name.clone();
    let kv = edge.kv.get().cloned();
    let d1 = edge.d1.get().cloned();
    let state = State {
        edge,
        snap,
        info: ReqInfo::default(),
        name,
        runtime: tokio::runtime::Handle::current(),
        bodies: Vec::new(),
        subrequests: 0,
        kv,
        d1,
        allowed_kv: script.kv_bindings.values().cloned().collect(),
        allowed_d1: script.d1_bindings.values().cloned().collect(),
    };

    let slot = tokio::time::timeout(Duration::from_secs(5), WORKER_SLOTS.acquire())
        .await
        .map_err(|_| "too many concurrent worker executions".to_string())?
        .map_err(|_| "worker runtime shutting down".to_string())?;
    let task = tokio::task::spawn_blocking(move || {
        let _slot = slot;
        STATE.set(Some(state));
        let result = execute_scheduled(&script, ctrl_json);
        STATE.set(None);
        result
    });
    match tokio::time::timeout(WALL_LIMIT, task).await {
        Err(_) => Err("scheduled worker exceeded the time limit".into()),
        Ok(Err(join)) => Err(format!("scheduled worker crashed: {join}")),
        Ok(Ok(res)) => res,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syntax_check_and_transform() {
        assert!(check_syntax("export default { async fetch(request) { return new Response('hi'); } }").is_ok());
        assert!(check_syntax("addEventListener('fetch', e => e.respondWith(new Response('x')))").is_ok());
        assert!(check_syntax("export default { fetch( { ").is_err());
        assert_eq!(transform("  export default {}"), "  globalThis.__default = {}");
    }

    #[test]
    fn email_worker_forwards_and_rejects() {
        let raw = b"From: Alice <a@ex.com>\r\nSubject: Hello\r\n\r\nBody text".to_vec();
        let headers = parse_email_headers(&raw);
        assert!(headers.iter().any(|(k, v)| k.eq_ignore_ascii_case("subject") && v == "Hello"));

        let script = WorkerScript {
            name: "mail-router".into(),
            script: r#"
                export default {
                    async email(message, env, ctx) {
                        const subj = message.headers.get("subject");
                        if (subj === "SPAM") {
                            message.setReject("spam blocked");
                            return;
                        }
                        const body = await new Response(message.raw).text();
                        if (body.includes("Body")) {
                            await message.forward(env.DEST);
                        }
                    }
                }
            "#.into(),
            vars: std::collections::BTreeMap::from([("DEST".into(), "dest@other.example".into())]),
            kv_bindings: Default::default(),
            d1_bindings: Default::default(),
            crons: Vec::new(),
            created_on: String::new(),
            modified_on: String::new(),
            sync: Default::default(),
        };
        let dir = std::env::temp_dir().join(format!("fucf-ew-{}", uuid::Uuid::new_v4().simple()));
        let store = Arc::new(crate::store::Store::open(&dir.join("s.json"), vec![]).unwrap());
        let edge = Arc::new(Edge::new(store.clone(), Arc::new(crate::edge::cache::Cache::new(1 << 20)), Arc::new(crate::edge::waf::Waf::new()), vec![]).unwrap());
        let rt = tokio::runtime::Runtime::new().unwrap();
        let out = rt.block_on(run_email(edge.clone(), store.snapshot(), Arc::new(script.clone()), "a@ex.com", "hi@fucloudflare.com", Bytes::from(raw))).unwrap();
        assert_eq!(out, EmailOutcome { reject: None, forwards: vec!["dest@other.example".into()] });

        let spam = b"Subject: SPAM\r\n\r\nbuy now".to_vec();
        let out2 = rt.block_on(run_email(edge, store.snapshot(), Arc::new(script), "s@ex.com", "hi@fucloudflare.com", Bytes::from(spam))).unwrap();
        assert_eq!(out2.reject.as_deref(), Some("spam blocked"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn worker_kv_d1_cron_and_webcrypto_integration() {
        let dir = std::env::temp_dir().join(format!("fucf-w2-{}", uuid::Uuid::new_v4().simple()));
        let store = Arc::new(crate::store::Store::open(&dir.join("s.json"), vec![]).unwrap());
        let kv_store = kv::KvStore::open(dir.join("kv"), store.clock(), "au".into()).unwrap();
        let d1_store = db::D1Store::open(dir.join("d1"), store.clock(), "au".into()).unwrap();
        let ns = kv_store.create_namespace("ns1").unwrap();
        let d1 = d1_store.create_database("db1").unwrap();

        let edge_val = Edge::new(
            store.clone(),
            Arc::new(crate::edge::cache::Cache::new(1 << 20)),
            Arc::new(crate::edge::waf::Waf::new()),
            vec![],
        )
        .unwrap();
        let _ = edge_val.kv.set(kv_store.clone());
        let _ = edge_val.d1.set(d1_store.clone());
        let edge = Arc::new(edge_val);

        let script = WorkerScript {
            name: "m2-worker".into(),
            script: r#"
                export default {
                    async fetch(request, env, ctx) {
                        const u = new URL(request.url);
                        if (u.pathname === "/redir") {
                            return Response.redirect("https://example.com/next", 301);
                        }

                        // KV test
                        await env.KV.put("k1", JSON.stringify({ hello: "world" }), { metadata: { v: 1 } });
                        await env.KV.put("k2", "two");
                        const m = await env.KV.get(["k1", "k2"], { type: "text" });
                        const wm = await env.KV.getWithMetadata("k1", "json");
                        const lst = await env.KV.list({ prefix: "k" });
                        const st = await env.KV.get("k2", "stream");
                        const rdr = st.getReader();
                        const ch1 = await rdr.read();
                        const ch2 = await rdr.read();
                        const streamText = (!ch1.done && ch2.done) ? new TextDecoder().decode(ch1.value) : "bad";

                        // D1 test
                        await env.DB.exec("CREATE TABLE IF NOT EXISTS items (id INTEGER PRIMARY KEY, val TEXT);");
                        await env.DB.prepare("INSERT INTO items (id, val) VALUES (?, ?)").bind(1, "ok").run();
                        let undErr = false;
                        try { env.DB.prepare("SELECT ?").bind(undefined); } catch (e) { undErr = String(e).includes("D1_TYPE_ERROR"); }
                        const row = await env.DB.prepare("SELECT val FROM items WHERE id = ?").bind(1).first("val");

                        // WebCrypto + TextEncoder/TextDecoder + Map
                        const enc = new TextEncoder();
                        const dec = new TextDecoder();
                        const bytes = enc.encode("hello-fucf");
                        const sha = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));

                        const hKey = await crypto.subtle.importKey("raw", enc.encode("secret"), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
                        const hSig = await crypto.subtle.sign("HMAC", hKey, bytes);
                        const hOk = await crypto.subtle.verify("HMAC", hKey, hSig, bytes);

                        const ec = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
                        const eSig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, ec.privateKey, bytes);
                        const eOk = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, ec.publicKey, eSig, bytes);

                        const aes = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
                        const iv = crypto.getRandomValues(new Uint8Array(12));
                        const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: enc.encode("aad") }, aes, bytes);
                        const pt = dec.decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv, additionalData: enc.encode("aad") }, aes, ct));

                        const uuid = crypto.randomUUID();
                        return Response.json({
                            kvMapSize: m.size,
                            kvMeta: wm.metadata.v,
                            kvListLen: lst.keys.length,
                            kvStreamText: streamText,
                            d1Row: row,
                            d1UndefinedErr: undErr,
                            shaLen: sha.length,
                            hmacOk: hOk,
                            ecdsaOk: eOk,
                            aesRoundTrip: pt,
                            uuidLen: uuid.length,
                        });
                    },
                    async scheduled(controller, env, ctx) {
                        controller.noRetry();
                        ctx.waitUntil(env.KV.put("cron_last", controller.cron + "@" + controller.scheduledTime));
                    }
                }
            "#.into(),
            vars: Default::default(),
            kv_bindings: std::collections::BTreeMap::from([("KV".into(), ns.id.clone())]),
            d1_bindings: std::collections::BTreeMap::from([("DB".into(), d1.id.clone())]),
            crons: vec!["*/5 * * * *".into()],
            created_on: String::new(),
            modified_on: String::new(),
            sync: Default::default(),
        };

        let rt = tokio::runtime::Runtime::new().unwrap();
        let info = ReqInfo {
            method: "GET".into(),
            host: "test.example".into(),
            path: "/test".into(),
            ssl: true,
            ..Default::default()
        };
        let resp = rt.block_on(run(edge.clone(), store.snapshot(), Arc::new(script.clone()), info, Bytes::new())).unwrap();
        assert_eq!(resp.status(), 200);
        let body_bytes = rt.block_on(http_body_util::BodyExt::collect(resp.into_body())).unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(v["kvMapSize"], 2);
        assert_eq!(v["kvMeta"], 1);
        assert_eq!(v["kvListLen"], 2);
        assert_eq!(v["kvStreamText"], "two");
        assert_eq!(v["d1Row"], "ok");
        assert_eq!(v["d1UndefinedErr"], true);
        assert_eq!(v["shaLen"], 32);
        assert_eq!(v["hmacOk"], true);
        assert_eq!(v["ecdsaOk"], true);
        assert_eq!(v["aesRoundTrip"], "hello-fucf");
        assert_eq!(v["uuidLen"], 36);

        // Redirect test
        let info_r = ReqInfo {
            method: "GET".into(),
            host: "test.example".into(),
            path: "/redir".into(),
            ssl: true,
            ..Default::default()
        };
        let resp_r = rt.block_on(run(edge.clone(), store.snapshot(), Arc::new(script.clone()), info_r, Bytes::new())).unwrap();
        assert_eq!(resp_r.status(), 301);
        assert_eq!(resp_r.headers().get("location").unwrap(), "https://example.com/next");

        // Scheduled cron execution test
        rt.block_on(run_scheduled(edge, store.snapshot(), Arc::new(script), "*/5 * * * *", 1700000000000)).unwrap();
        let cron_val = kv_store.get_with_metadata(&ns.id, "cron_last").unwrap().unwrap();
        assert_eq!(cron_val.0.as_ref(), b"*/5 * * * *@1700000000000");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn webcrypto_rsa_pkcs1_v1_5_sign_and_verify() {
        let dir = std::env::temp_dir().join(format!("fucf-rsa-{}", uuid::Uuid::new_v4().simple()));
        let store = Arc::new(crate::store::Store::open(&dir.join("s.json"), vec![]).unwrap());
        let edge = Arc::new(Edge::new(
            store.clone(),
            Arc::new(crate::edge::cache::Cache::new(1 << 20)),
            Arc::new(crate::edge::waf::Waf::new()),
            vec![],
        ).unwrap());
        let pkcs8_b64 = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCm7Bz6h24lK4NcqPbzbSGty7tHeaGKRMO1Zwuf9Z9hkR2fQbYZvpS7ehvbnd9k3eLyYRiu1YG7E9yefj44omWpTGfxzdHMQIAD0ZRjScCUmc8OcQ2rQ3rHZasUv+i9koBw63H/2jEMq7TmmARwlcTJLy5/mNvRmBxG2FTA8rXWVm1TZlRsZlVnR0mzr66wFPncqtk3IDmG0CYcghb5Xnz2jC9eajyhQumymZO9EVvIgPwMX8oGBoXSTMKwbWTgV+OsbblljPFzegCmipZMnRcyF4se8fxN/tH3ufdbonNa0+2YLteTheZzBNPdx65GTHXLBDfG3qqEVUCw8ci74rg/AgMBAAECggEATshG3xmXa1SvscaPk5Gw4Rm0gQYPr7ZH1nDVpEAl4sM+g2FcxKbWBOwbhNpsyusMx4/7Od1MVxMHQAjebhV7vN1ye8ZEHE5e/S5oBjqTea9kcfD63hfBtaWvCuKOwxaHp4QAcJy3JL9P6Lvb8JVHZRrvK8rmCPTtd6R3z/9dwlSRb7a31QBGEkuba3UlwKoeDKK2oC3vwZJ5TXJGx1zQ2I5d4nAIOG5Q70/GOHdWPlaMYv0GI7zKgYnJw2btUVfJ4I/0TSj3YV+y3oltOLrmesCEtfcclgJQbG/AYsyh4uJnqDATvqH0fucErzmd9CrxJRSZ/mLLIXmjG4yZ1Qoe9QKBgQDhrDkL38QX1tbz/ScZCWirWyO2xSk+mnuZDnBUqKupGyTxteyENLGTmN9CKqefM8+I3yKwyYH/DE2k3Qx8NqpSh8NujDesCebXEsYo8bqskd03uFRZFVy7BrmVHw5uw9AC+kXuxktHTmJmxsQASri7K1VA9TaHTjyIeFXKCLELKwKBgQC9WrXcAM/qxWoNIP3gE+WtM6/E74mGo+1FfGFNG8ddFYwKyggdw6J4MJKstYmS9BaPbHEX/RepVB+5DA/Me9WbK9eaNs7iLzSJb6WXaxSLbY5OZd5EZvX7wXLBkT/QEnmyaD+Fn9kc3LExzvqIY6DT79JDHViF5XU1CQbhf/WtPQKBgQCuGa/o+TjPK2+pzCPdrOSTTjy/RFwNcCDqc7k1lurYC5j04OUXGY/lzopvAXlP2SjC72JUASHJIjTEe8SmD4ZXJWYgYwyQLRNp2ZIHBHZ/rAh+dDaeg1yG7Sk/YjZAPdC8e1h4XYK2AELqB24uy3a47zVWZ9cpi7Inlq6YrxvnAQKBgFn0Y/zWLfAcRNtj1vfCvBPiQBhQq4bZDXk7M4ZMMhPYjqT5gY2SSPbMLIH75BV5+9W68KcyxzDcFA322vKLydhjpZNPgk0Vm+HGtmYOqr3qF/bKkiLwvt8Q8ZFfjW8tt763o6W5YI1DkrJU39Q3cEn+3maf5FQHw/ykAy7ReUcJAoGAT0gHWzQ6eeSHqPOaBoj9geCYJIEW9+4hLUc+56Z5cpa2egm15VoIRCWcwDwflVPtJoRdgyGTYHWwYjmufixkqgFpYAh/XKrel2UCDyQWS6g4ktYH29YwRD3ClFr62dURJS8h+8zTdcBCqqjPC7i5hp6DwqkL1c6As+R12zDv6Oo=";
        let spki_b64 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApuwc+oduJSuDXKj2820hrcu7R3mhikTDtWcLn/WfYZEdn0G2Gb6Uu3ob253fZN3i8mEYrtWBuxPcnn4+OKJlqUxn8c3RzECAA9GUY0nAlJnPDnENq0N6x2WrFL/ovZKAcOtx/9oxDKu05pgEcJXEyS8uf5jb0ZgcRthUwPK11lZtU2ZUbGZVZ0dJs6+usBT53KrZNyA5htAmHIIW+V589owvXmo8oULpspmTvRFbyID8DF/KBgaF0kzCsG1k4FfjrG25ZYzxc3oApoqWTJ0XMheLHvH8Tf7R97n3W6JzWtPtmC7Xk4XmcwTT3ceuRkx1ywQ3xt6qhFVAsPHIu+K4PwIDAQAB";
        let script = WorkerScript {
            name: "rsa-test".into(),
            script: r#"
                export default {
                    async fetch(req, env) {
                        const dec = (b64) => Uint8Array.from(atob(b64), c => c.charCodeAt(0));
                        const priv = await crypto.subtle.importKey("pkcs8", dec(env.PKCS8), { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
                        const pub = await crypto.subtle.importKey("spki", dec(env.SPKI), { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
                        const msg = new TextEncoder().encode("rsa-payload");
                        const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", priv, msg);
                        const ok = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", pub, sig, msg);
                        const bad = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", pub, sig, new TextEncoder().encode("tampered"));
                        return Response.json({ ok, bad });
                    }
                }
            "#.into(),
            vars: std::collections::BTreeMap::from([
                ("PKCS8".into(), pkcs8_b64.into()),
                ("SPKI".into(), spki_b64.into()),
            ]),
            kv_bindings: Default::default(),
            d1_bindings: Default::default(),
            crons: Vec::new(),
            created_on: String::new(),
            modified_on: String::new(),
            sync: Default::default(),
        };
        let rt = tokio::runtime::Runtime::new().unwrap();
        let info = ReqInfo { method: "GET".into(), host: "t.example".into(), path: "/".into(), ssl: true, ..Default::default() };
        let resp = rt.block_on(run(edge, store.snapshot(), Arc::new(script), info, Bytes::new())).unwrap();
        let body = rt.block_on(http_body_util::BodyExt::collect(resp.into_body())).unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["ok"], true);
        assert_eq!(v["bad"], false);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn cross_worker_kv_d1_isolation_and_pbkdf2() {
        let dir = std::env::temp_dir().join(format!("fucf-wk-iso-{}", uuid::Uuid::new_v4().simple()));
        let store = Arc::new(crate::store::Store::open(&dir.join("cfg.json"), vec![]).unwrap());
        let edge = Arc::new(Edge::new(store.clone(), Arc::new(crate::edge::cache::Cache::new(1 << 20)), Arc::new(crate::edge::waf::Waf::new()), vec![]).unwrap());
        let kv_store = kv::KvStore::open(dir.join("kv"), store.clock(), "au".into()).unwrap();
        let d1_store = db::D1Store::open(dir.join("d1"), store.clock(), "au".into()).unwrap();
        let ns_allowed = kv_store.create_namespace("allowed").unwrap();
        let ns_secret = kv_store.create_namespace("secret").unwrap();
        kv_store.put(&ns_secret.id, "k", b"topsecret", None, None, None).unwrap();
        let db_allowed = d1_store.create_database("allowed").unwrap();
        let db_secret = d1_store.create_database("secret").unwrap();
        d1_store.exec(&db_secret.id, "CREATE TABLE s (v TEXT); INSERT INTO s VALUES ('secret');").unwrap();
        let _ = edge.kv.set(kv_store);
        let _ = edge.d1.set(d1_store);

        let script = WorkerScript {
            name: "iso-test".into(),
            script: format!(
                r#"
                export default {{
                    async fetch(req, env) {{
                        let kvBlocked = false;
                        try {{
                            JSON.parse(__kvGet(JSON.stringify({{ ns_id: "{ns_secret}", key: "k", type: "text" }})));
                        }} catch (e) {{
                            kvBlocked = String(e).includes("unauthorized");
                        }}
                        let d1Blocked = false;
                        try {{
                            JSON.parse(__d1Query(JSON.stringify({{ db_id: "{db_secret}", sql: "SELECT * FROM s", params: [] }})));
                        }} catch (e) {{
                            d1Blocked = String(e).includes("unauthorized");
                        }}
                        const pw = new TextEncoder().encode("password");
                        const salt = new TextEncoder().encode("salt");
                        const baseKey = await crypto.subtle.importKey("raw", pw, "PBKDF2", false, ["deriveBits"]);
                        const bits = await crypto.subtle.deriveBits({{ name: "PBKDF2", salt, iterations: 1, hash: "SHA-256" }}, baseKey, 256);
                        const hex = Array.from(new Uint8Array(bits)).map(b => b.toString(16).padStart(2, "0")).join("");
                        return Response.json({{ kvBlocked, d1Blocked, hex }});
                    }}
                }}
                "#,
                ns_secret = ns_secret.id,
                db_secret = db_secret.id,
            ),
            vars: Default::default(),
            kv_bindings: std::collections::BTreeMap::from([("KV".into(), ns_allowed.id)]),
            d1_bindings: std::collections::BTreeMap::from([("DB".into(), db_allowed.id)]),
            crons: Vec::new(),
            created_on: String::new(),
            modified_on: String::new(),
            sync: Default::default(),
        };
        let rt = tokio::runtime::Runtime::new().unwrap();
        let info = ReqInfo { method: "GET".into(), host: "t.example".into(), path: "/".into(), ssl: true, ..Default::default() };
        let resp = rt.block_on(run(edge, store.snapshot(), Arc::new(script), info, Bytes::new())).unwrap();
        let body = rt.block_on(http_body_util::BodyExt::collect(resp.into_body())).unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["kvBlocked"], true, "unauthorized KV access must be blocked: {v}");
        assert_eq!(v["d1Blocked"], true, "unauthorized D1 access must be blocked: {v}");
        // RFC 6070 test vector 1: PBKDF2-HMAC-SHA256("password", "salt", 1, 32)
        assert_eq!(v["hex"], "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b");
        let _ = std::fs::remove_dir_all(dir);
    }
}
