//! The Workers API paths that `wrangler deploy` calls around the upload
//! itself, answered from what a Worker here is: a name, one script, plain
//! variables, KV / D1 bindings and cron triggers.
//!
//! What wrangler 4.155.0 asks, in order, for a Worker with no
//! environments, Durable Objects, queues, workflows, assets or containers:
//!
//! 1. `GET /workers/services/{name}` ([`service`]). Cloudflare's code
//!    10007 (or 10090) means "not there yet": the upload is then a first
//!    deploy. Of the answer it reads `default_environment.script.tag`,
//!    `.tags` and `.last_deployed_from` (`dash` would make it download the
//!    whole remote configuration to compare, `api` makes it warn that the
//!    upload replaces edits made through the API).
//! 2. `GET /workers/scripts/{name}/secrets`, only when the configuration has
//!    `vars` or bindings: secrets here are none, so the answer is `[]`.
//! 3. `GET /workers/subdomain`, only for a first deploy that wants
//!    `workers.dev` (which there is none of here: refused, see
//!    [`NO_WORKERS_DEV`]).
//! 4. `GET /workers/scripts/{name}/deployments`: `{"deployments": []}`, as
//!    nothing here keeps deployments.
//! 5. The upload: a first deploy `PUT`s `/workers/scripts/{name}` (see
//!    `workers::upload`); a Worker that is already there goes through the
//!    versions API instead (`POST .../versions`, then `POST .../deployments`
//!    and `PATCH .../script-settings`), which needs Worker versions kept
//!    apart from what runs. There are none here, so both are refused
//!    ([`NO_VERSIONS`]) and a second `wrangler deploy` stops there.
//! 6. `GET /workers/workers/{name}` ([`worker`]) for `subdomain.enabled`
//!    and `subdomain.previews_enabled`, then `POST
//!    /workers/scripts/{name}/subdomain` with the wanted values: both false
//!    is what there is and is answered as such, anything else refused.
//! 7. With `routes`: `PUT /workers/scripts/{name}/routes` ([`parse_routes`],
//!    [`route_ops`]) replaces the script's routes in whichever zones they
//!    are, made through the zone's own route objects.
//! 8. With `triggers.crons`: `PUT /workers/scripts/{name}/schedules`
//!    ([`parse_schedules`]), the same crons `PATCH .../settings` sets.

use crate::items::{in_zone, WorkerRoute, WorkerScript};
use crate::store::{ItemOp, StoreError, Zone};
use serde_json::{json, Value};
use std::collections::BTreeSet;

/// What a refused versions API call says. Its words are what a user of
/// `wrangler deploy` reads when a Worker already exists here.
pub const NO_VERSIONS: &str = "fucf keeps no Worker versions (versions, gradual deployments, rollbacks): \
     to replace a Worker that is already there, upload it with PUT /workers/scripts/{name}, \
     e.g. wrangler deploy --dry-run --outdir dist and curl";

/// What the workers.dev calls that ask for more than "off" say.
pub const NO_WORKERS_DEV: &str = "fucf has no workers.dev subdomain or preview URLs: \
     set workers_dev = false and preview_urls = false, and reach the Worker through routes";

/// At most this many routes in one `PUT .../routes`.
const MAX_ROUTES: usize = 100;

/// A stable 32 hex digit id for a script, which wrangler calls its tag (the
/// email routing rules it writes name their Worker by it). Nothing here
/// stores one, so it is made from the name: the same on every node, and the
/// same again for a script deleted and made anew under the same name.
pub fn tag(name: &str) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, format!("fucf worker script\0{name}").as_bytes());
    digest.as_ref()[..16].iter().map(|b| format!("{b:02x}")).collect()
}

/// A digest of the script's source, which changes whenever it does.
fn etag(w: &WorkerScript) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, w.script.as_bytes());
    digest.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

/// `GET /workers/services/{name}`: the service with its one environment.
/// `last_deployed_from` is `api`: this API is the only way in, and it does
/// not record whether wrangler, curl or the panel's editor used it, so
/// wrangler is told what is true of all three (whatever is there is
/// replaced by the upload) and warns before it does so.
pub fn service(w: &WorkerScript) -> Value {
    json!({
        "id": w.name,
        "default_environment": {
            "environment": "production",
            "created_on": w.created_on,
            "modified_on": w.modified_on,
            "script": {
                "id": w.name,
                "tag": tag(&w.name),
                "tags": [],
                "etag": etag(w),
                "last_deployed_from": "api",
                "created_on": w.created_on,
                "modified_on": w.modified_on,
            },
        },
        "environments": [{ "environment": "production", "created_on": w.created_on, "modified_on": w.modified_on }],
        "created_on": w.created_on,
        "modified_on": w.modified_on,
    })
}

/// `GET /workers/workers/{name}` (the newer Workers API, which wrangler asks
/// for the script's `workers.dev` state): there is no `workers.dev` here.
pub fn worker(w: &WorkerScript) -> Value {
    json!({
        "id": tag(&w.name),
        "name": w.name,
        "tags": [],
        "subdomain": subdomain(),
        "created_on": w.created_on,
        "updated_on": w.modified_on,
    })
}

/// A script's `workers.dev` state, which is always off.
pub fn subdomain() -> Value {
    json!({ "enabled": false, "previews_enabled": false })
}

/// The body of `POST /workers/scripts/{name}/subdomain`: `enabled` (and
/// `previews_enabled`, if there) must be false, which is all that can be had.
pub fn check_subdomain(body: &Value) -> Result<(), String> {
    let Value::Object(o) = body else { return Err("the body must be an object".into()) };
    let flag = |key: &str, required: bool| match o.get(key) {
        Some(Value::Bool(b)) => Ok(*b),
        None | Some(Value::Null) if !required => Ok(false),
        None | Some(Value::Null) => Err(format!("'{key}' is missing")),
        Some(_) => Err(format!("'{key}' must be true or false")),
    };
    if flag("enabled", true)? || flag("previews_enabled", false)? {
        return Err(NO_WORKERS_DEV.into());
    }
    Ok(())
}

/// `GET /workers/scripts/{name}/schedules`: the script's crons. Nothing
/// records when each was added, so each carries the script's own times.
pub fn schedules(w: &WorkerScript) -> Value {
    let list: Vec<Value> = w.crons.iter().map(|c| json!({ "cron": c, "created_on": w.created_on, "modified_on": w.modified_on })).collect();
    json!({ "schedules": list })
}

/// The body of `PUT /workers/scripts/{name}/schedules`, `[{"cron": "..."}]`:
/// the crons that replace the script's, each one checked. `[]` removes them
/// all; the same cron twice is refused rather than run twice.
pub fn parse_schedules(body: &Value) -> Result<Vec<String>, String> {
    let Value::Array(items) = body else { return Err("the body must be an array of {\"cron\": \"...\"}".into()) };
    let mut out: Vec<String> = Vec::new();
    for (i, item) in items.iter().enumerate() {
        let Some(cron) = item.get("cron").and_then(Value::as_str) else { return Err(format!("[{i}]: 'cron' must be a string")) };
        let cron = cron.trim().to_string();
        super::cron::CronExpr::parse(&cron).map_err(|e| format!("[{i}]: {e}"))?;
        if out.contains(&cron) {
            return Err(format!("[{i}]: the cron '{cron}' is given twice"));
        }
        out.push(cron);
    }
    Ok(out)
}

/// One route of a `PUT /workers/scripts/{name}/routes` body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteSpec {
    /// As stored ([`normalize_pattern`]).
    pub pattern: String,
    pub zone_id: Option<String>,
    pub zone_name: Option<String>,
}

/// A route pattern as `WorkerRoute::validate` stores it: no scheme, the host
/// in lower case, a path (`/` if none was given).
pub fn normalize_pattern(pattern: &str) -> String {
    let p = pattern.trim();
    // the scheme is case-insensitive like the host (RFC 3986 section 3.1)
    let p = ["https://", "http://"]
        .iter()
        .find(|s| p.get(..s.len()).is_some_and(|head| head.eq_ignore_ascii_case(s)))
        .map_or(p, |s| &p[s.len()..]);
    match p.find('/') {
        Some(i) => format!("{}{}", p[..i].to_ascii_lowercase(), &p[i..]),
        None => format!("{}/", p.to_ascii_lowercase()),
    }
}

/// The host part of a stored pattern without its wildcard (`*.example.com`
/// and `*example.com` are about `example.com`).
fn pattern_host(pattern: &str) -> &str {
    let host = pattern.split('/').next().unwrap_or_default();
    host.trim_start_matches("*.").trim_start_matches('*')
}

/// The body of `PUT /workers/scripts/{name}/routes`: an array of
/// `{"pattern", "zone_id"?, "zone_name"?}`, as wrangler sends it. Custom
/// domains (`custom_domain: true`) are another API and refused here, as is
/// a route naming another script, the same pattern twice, or more than
/// [`MAX_ROUTES`] routes.
pub fn parse_routes(name: &str, body: &Value) -> Result<Vec<RouteSpec>, String> {
    let Value::Array(items) = body else { return Err("the body must be an array of routes".into()) };
    if items.len() > MAX_ROUTES {
        return Err(format!("at most {MAX_ROUTES} routes at once"));
    }
    let mut out: Vec<RouteSpec> = Vec::new();
    for (i, item) in items.iter().enumerate() {
        let Value::Object(o) = item else { return Err(format!("[{i}]: a route must be an object")) };
        let text = |key: &str| match o.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(s)) if !s.trim().is_empty() => Ok(Some(s.trim().to_string())),
            Some(_) => Err(format!("[{i}]: '{key}' must be a non-empty string")),
        };
        let pattern = text("pattern")?.ok_or_else(|| format!("[{i}]: 'pattern' is missing"))?;
        if o.get("custom_domain").and_then(Value::as_bool) == Some(true) {
            return Err(format!("[{i}]: custom domains are not supported: route the Worker with a pattern of a zone here"));
        }
        if let Some(script) = text("script")? {
            if script != name {
                return Err(format!("[{i}]: the route names the script '{script}', not '{name}'"));
            }
        }
        let spec = RouteSpec {
            pattern: normalize_pattern(&pattern),
            zone_id: text("zone_id")?,
            zone_name: text("zone_name")?.map(|n| n.trim_end_matches('.').to_ascii_lowercase()),
        };
        if pattern_host(&spec.pattern).is_empty() {
            return Err(format!("[{i}]: the pattern '{pattern}' names no host"));
        }
        if out.iter().any(|o| o.pattern == spec.pattern) {
            return Err(format!("[{i}]: the pattern '{}' is given twice", spec.pattern));
        }
        out.push(spec);
    }
    Ok(out)
}

/// The zone a route goes into: the one it names by id or by name, or else
/// the closest zone its host is in (`a.b.example.com` goes into the zone
/// `b.example.com` rather than `example.com`, as requests for it do). The
/// pattern's host must be in that zone.
pub fn zone_for<'a>(spec: &RouteSpec, zones: &'a [Zone]) -> Result<&'a Zone, String> {
    let host = pattern_host(&spec.pattern);
    let zone = if let Some(id) = &spec.zone_id {
        let z = zones.iter().find(|z| &z.id == id).ok_or_else(|| format!("route '{}': there is no zone '{id}'", spec.pattern))?;
        if spec.zone_name.as_ref().is_some_and(|n| n != &z.name) {
            return Err(format!("route '{}': the zone '{id}' is not called '{}'", spec.pattern, spec.zone_name.as_deref().unwrap_or_default()));
        }
        z
    } else if let Some(name) = &spec.zone_name {
        zones.iter().find(|z| &z.name == name).ok_or_else(|| format!("route '{}': there is no zone '{name}'", spec.pattern))?
    } else {
        zones
            .iter()
            .filter(|z| in_zone(z, host))
            .max_by_key(|z| z.name.len())
            .ok_or_else(|| format!("route '{}': no zone here holds '{host}'", spec.pattern))?
    };
    if !in_zone(zone, host) {
        return Err(format!("route '{}': '{host}' is not in the zone {}", spec.pattern, zone.name));
    }
    Ok(zone)
}

/// What to do in one zone so that the routes of script `name` there are
/// exactly `wanted` (stored patterns): drop its others, keep those already
/// there, make the missing ones. A wanted pattern that is already some other
/// script's route (or one that switches Workers off) is a conflict, not
/// taken over.
pub fn route_ops(name: &str, wanted: &[String], current: &[WorkerRoute]) -> Result<Vec<ItemOp>, StoreError> {
    let wanted_set: BTreeSet<&str> = wanted.iter().map(String::as_str).collect();
    let mut ops: Vec<ItemOp> = current
        .iter()
        .filter(|r| r.script.as_deref() == Some(name) && !wanted_set.contains(r.pattern.as_str()))
        .map(|r| ItemOp::Delete(r.meta.id.clone()))
        .collect();
    for (i, pattern) in wanted.iter().enumerate() {
        match current.iter().find(|r| &r.pattern == pattern) {
            Some(r) if r.script.as_deref() == Some(name) => {}
            Some(r) => {
                let whose = r.script.as_deref().map(|s| format!("the Worker '{s}'")).unwrap_or_else(|| "a route that switches Workers off".into());
                return Err(StoreError::Conflict(format!("the route '{pattern}' is already {whose}'s: remove it first")));
            }
            None => ops.push(ItemOp::Save { id: None, body: json!({ "pattern": pattern, "script": name }), replace: true, at: format!("routes[{i}]") }),
        }
    }
    Ok(ops)
}

/// A route as `PUT .../routes` answers it.
pub fn route_view(r: &WorkerRoute, zone: &Zone) -> Value {
    json!({ "id": r.meta.id, "pattern": r.pattern, "script": r.script, "zone_id": zone.id, "zone_name": zone.name })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn script(name: &str, crons: &[&str]) -> WorkerScript {
        serde_json::from_value(json!({
            "name": name,
            "script": "export default { fetch() { return new Response('ok') } }",
            "crons": crons,
            "created_on": "2026-01-01T00:00:00Z",
            "modified_on": "2026-01-02T00:00:00Z",
        }))
        .unwrap()
    }

    fn route(id: &str, pattern: &str, script: Option<&str>) -> WorkerRoute {
        serde_json::from_value(json!({
            "id": id, "zone_id": "z1", "created_on": "", "modified_on": "", "pattern": pattern, "script": script,
        }))
        .unwrap()
    }

    /// Zones with these ids and names (only those two fields matter here).
    fn zones(list: &[(&str, &str)]) -> Vec<Zone> {
        let dir = std::env::temp_dir().join(format!("fucf-services-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir).unwrap();
        let model = crate::store::Store::open(&dir.join("store.json"), vec![]).unwrap().create_zone("example.com").unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        list.iter().map(|(id, name)| Zone { id: id.to_string(), name: name.to_string(), ..model.clone() }).collect()
    }

    #[test]
    fn a_tag_is_32_hex_digits_stable_for_a_name_and_different_for_another() {
        let t = tag("compat-worker");
        assert_eq!(t.len(), 32);
        assert!(t.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()), "{t}");
        assert_eq!(t, tag("compat-worker"));
        assert_ne!(t, tag("compat-worker2"));
        assert_ne!(tag(""), tag("a"));
    }

    #[test]
    fn the_service_has_the_fields_wrangler_reads() {
        let w = script("compat-worker", &[]);
        let s = service(&w);
        let script = &s["default_environment"]["script"];
        assert_eq!(script["tag"], json!(tag("compat-worker")));
        assert_eq!(script["tags"], json!([]));
        assert_eq!(script["last_deployed_from"], json!("api"));
        assert_eq!(s["default_environment"]["environment"], json!("production"));
        assert_eq!(s["id"], json!("compat-worker"));
        // the etag follows the source and nothing else
        let mut changed = w.clone();
        changed.script.push(' ');
        assert_ne!(script["etag"], service(&changed)["default_environment"]["script"]["etag"]);
        assert_eq!(script["etag"], service(&touched_later(&w))["default_environment"]["script"]["etag"]);
        // and it never carries the script itself
        assert!(!s.to_string().contains("new Response"), "{s}");
    }

    fn touched_later(w: &WorkerScript) -> WorkerScript {
        WorkerScript { modified_on: "2027-01-01T00:00:00Z".into(), ..w.clone() }
    }

    #[test]
    fn the_workers_view_says_workers_dev_is_off() {
        let v = worker(&script("w", &[]));
        assert_eq!(v["subdomain"], json!({ "enabled": false, "previews_enabled": false }));
        assert_eq!(v["name"], json!("w"));
    }

    #[test]
    fn only_switching_workers_dev_off_is_accepted() {
        assert!(check_subdomain(&json!({ "enabled": false, "previews_enabled": false })).is_ok());
        assert!(check_subdomain(&json!({ "enabled": false })).is_ok(), "wrangler leaves out an unset preview_urls");
        assert!(check_subdomain(&json!({ "enabled": false, "previews_enabled": null })).is_ok());
        assert_eq!(check_subdomain(&json!({ "enabled": true })).unwrap_err(), NO_WORKERS_DEV);
        assert_eq!(check_subdomain(&json!({ "enabled": false, "previews_enabled": true })).unwrap_err(), NO_WORKERS_DEV);
        for bad in [json!({}), json!({ "enabled": "false" }), json!({ "enabled": 0 }), json!([false]), json!(null), json!({ "enabled": false, "previews_enabled": "no" })] {
            let e = check_subdomain(&bad).unwrap_err();
            assert_ne!(e, NO_WORKERS_DEV, "{bad}");
        }
    }

    #[test]
    fn schedules_are_checked_crons_and_an_empty_list_removes_them() {
        assert_eq!(parse_schedules(&json!([{ "cron": "*/5 * * * *" }, { "cron": " 0 3 * * 1 " }])).unwrap(), vec!["*/5 * * * *", "0 3 * * 1"]);
        assert_eq!(parse_schedules(&json!([])).unwrap(), Vec::<String>::new());
        assert!(parse_schedules(&json!([{ "cron": "not a cron" }])).unwrap_err().starts_with("[0]: "));
        assert!(parse_schedules(&json!([{ "cron": "* * * * *" }, { "cron": "* * * * *" }])).unwrap_err().contains("twice"));
        for bad in [json!({ "cron": "* * * * *" }), json!([{ "schedule": "* * * * *" }]), json!([{ "cron": 5 }]), json!(["* * * * *"]), json!(null)] {
            assert!(parse_schedules(&bad).is_err(), "{bad}");
        }
        let v = schedules(&script("w", &["*/5 * * * *"]));
        assert_eq!(v["schedules"][0]["cron"], json!("*/5 * * * *"));
        assert_eq!(schedules(&script("w", &[]))["schedules"], json!([]));
    }

    #[test]
    fn patterns_are_stored_as_the_zone_routes_store_them() {
        assert_eq!(normalize_pattern(" https://Shop.Example.COM/Api/* "), "shop.example.com/Api/*");
        assert_eq!(normalize_pattern("http://example.com"), "example.com/");
        assert_eq!(normalize_pattern("*.Example.net/*"), "*.example.net/*");
        assert_eq!(pattern_host("*.example.net/*"), "example.net");
        assert_eq!(pattern_host("*example.net/x"), "example.net");
    }

    #[test]
    fn a_routes_body_is_checked_before_anything_is_written() {
        let ok = parse_routes("w", &json!([{ "pattern": "example.com/*" }, { "pattern": "api.example.net/*", "zone_name": "Example.net." }, { "pattern": "x.example.org/", "zone_id": "z9", "script": "w" }])).unwrap();
        assert_eq!(ok[1], RouteSpec { pattern: "api.example.net/*".into(), zone_id: None, zone_name: Some("example.net".into()) });
        assert_eq!(ok[2].zone_id.as_deref(), Some("z9"));
        assert!(parse_routes("w", &json!([])).unwrap().is_empty());
        let fails = |body: Value, needle: &str| {
            let e = parse_routes("w", &body).unwrap_err();
            assert!(e.contains(needle), "{body}: {e}");
        };
        fails(json!({ "pattern": "example.com/*" }), "array");
        fails(json!(["example.com/*"]), "object");
        fails(json!([{}]), "'pattern' is missing");
        fails(json!([{ "pattern": "" }]), "non-empty");
        fails(json!([{ "pattern": 7 }]), "non-empty");
        fails(json!([{ "pattern": "/*" }]), "names no host");
        fails(json!([{ "pattern": "*/*" }]), "names no host");
        fails(json!([{ "pattern": "shop.example.com", "custom_domain": true }]), "custom domains");
        fails(json!([{ "pattern": "example.com/*", "script": "other" }]), "'other'");
        fails(json!([{ "pattern": "example.com/*" }, { "pattern": "HTTPS://EXAMPLE.com/*" }]), "twice");
        fails(json!([{ "pattern": "example.com/*", "zone_id": 5 }]), "'zone_id'");
        let many: Vec<Value> = (0..=MAX_ROUTES).map(|i| json!({ "pattern": format!("h{i}.example.com/*") })).collect();
        fails(Value::Array(many), "at most");
        // custom_domain false is an ordinary route
        assert_eq!(parse_routes("w", &json!([{ "pattern": "example.com/*", "custom_domain": false }])).unwrap().len(), 1);
    }

    #[test]
    fn a_route_goes_into_the_closest_zone_or_the_one_it_names() {
        let zones = zones(&[("z1", "example.com"), ("z2", "shop.example.com"), ("z3", "example.net")]);
        let spec = |pattern: &str, id: Option<&str>, name: Option<&str>| RouteSpec { pattern: normalize_pattern(pattern), zone_id: id.map(Into::into), zone_name: name.map(Into::into) };
        assert_eq!(zone_for(&spec("www.example.com/*", None, None), &zones).unwrap().id, "z1");
        assert_eq!(zone_for(&spec("a.shop.example.com/*", None, None), &zones).unwrap().id, "z2");
        assert_eq!(zone_for(&spec("*.shop.example.com/*", None, None), &zones).unwrap().id, "z2");
        assert_eq!(zone_for(&spec("example.net/*", None, Some("example.net")), &zones).unwrap().id, "z3");
        assert_eq!(zone_for(&spec("shop.example.com/*", Some("z1"), None), &zones).unwrap().id, "z1", "a zone named by id is taken as named");
        // a zone that does not hold the host, or is not there, or two names that disagree
        assert!(zone_for(&spec("example.org/*", None, None), &zones).unwrap_err().contains("no zone"));
        assert!(zone_for(&spec("example.org/*", Some("z1"), None), &zones).unwrap_err().contains("not in the zone"));
        assert!(zone_for(&spec("example.com/*", Some("nope"), None), &zones).unwrap_err().contains("no zone 'nope'"));
        assert!(zone_for(&spec("example.com/*", None, Some("example.org")), &zones).unwrap_err().contains("no zone 'example.org'"));
        assert!(zone_for(&spec("example.com/*", Some("z1"), Some("example.net")), &zones).unwrap_err().contains("is not called"));
        assert!(zone_for(&spec("badexample.com/*", None, None), &zones).is_err(), "a name ending alike is not in the zone");
    }

    #[test]
    fn the_routes_of_a_script_are_replaced_without_touching_anyone_elses() {
        let current = vec![
            route("r1", "example.com/old/*", Some("w")),
            route("r2", "example.com/keep/*", Some("w")),
            route("r3", "example.com/theirs/*", Some("other")),
            route("r4", "example.com/off/*", None),
        ];
        let ops = route_ops("w", &["example.com/keep/*".into(), "example.com/new/*".into()], &current).unwrap();
        assert_eq!(ops.len(), 2);
        assert!(matches!(&ops[0], ItemOp::Delete(id) if id == "r1"));
        assert!(matches!(&ops[1], ItemOp::Save { id: None, body, replace: true, .. } if body == &json!({ "pattern": "example.com/new/*", "script": "w" })));
        // nothing wanted: all of the script's go, the others stay
        let ops = route_ops("w", &[], &current).unwrap();
        assert_eq!(ops.iter().filter(|o| matches!(o, ItemOp::Delete(_))).count(), 2);
        assert_eq!(ops.len(), 2);
        // already as wanted: nothing to do
        assert!(route_ops("w", &["example.com/old/*".into(), "example.com/keep/*".into()], &current).unwrap().is_empty());
        // another script's route, or one that switches Workers off, is not taken over
        assert!(matches!(route_ops("w", &["example.com/theirs/*".into()], &current), Err(StoreError::Conflict(m)) if m.contains("'other'")));
        assert!(matches!(route_ops("w", &["example.com/off/*".into()], &current), Err(StoreError::Conflict(m)) if m.contains("switches Workers off")));
    }
}
