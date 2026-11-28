//! Cloudflare's Rulesets API, laid over the rule types this server already
//! has, so that Terraform, cf-terraforming and scripts written for
//! Cloudflare can manage a zone's rules here too.
//!
//! Nothing new is stored. Each phase's entrypoint ruleset is a view of one
//! existing type (see [`kind_of`]); its id is derived from the zone and the
//! phase, and its rules' ids are the ids of the existing objects. A transform
//! rule can rewrite the path, request headers and response headers at once,
//! so it shows in up to three phases, and a change made through one phase
//! touches only that part of it.
//!
//! What a Cloudflare rule says and this server cannot do is rejected with a
//! 400 naming the field, never quietly dropped: a rule that silently did
//! less, or more, than its author wrote is worse than an error.

use crate::items::{CacheRule, FirewallRule, Item, OriginRule, RateLimit, RedirectRule, TransformRule};
use crate::store::{ItemOp, Store, StoreError};
use crate::tokens::Area;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashSet};

/// The phases this server has an entrypoint ruleset for.
pub const PHASES: [&str; 8] = [
    "http_request_firewall_custom",
    "http_ratelimit",
    "http_request_dynamic_redirect",
    "http_request_transform",
    "http_request_late_transform",
    "http_response_headers_transform",
    "http_request_cache_settings",
    "http_request_origin",
];

/// The part of a transform rule a phase shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Part {
    Path,
    RequestHeaders,
    ResponseHeaders,
}

/// Which existing type (and, for transforms, which part of it) a phase is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Firewall,
    RateLimit,
    Redirect,
    Transform(Part),
    Cache,
    Origin,
}

fn kind_of(phase: &str) -> Option<Kind> {
    Some(match phase {
        "http_request_firewall_custom" => Kind::Firewall,
        "http_ratelimit" => Kind::RateLimit,
        "http_request_dynamic_redirect" => Kind::Redirect,
        "http_request_transform" => Kind::Transform(Part::Path),
        "http_request_late_transform" => Kind::Transform(Part::RequestHeaders),
        "http_response_headers_transform" => Kind::Transform(Part::ResponseHeaders),
        "http_request_cache_settings" => Kind::Cache,
        "http_request_origin" => Kind::Origin,
        _ => return None,
    })
}

fn phase_of_part(part: Part) -> &'static str {
    match part {
        Part::Path => "http_request_transform",
        Part::RequestHeaders => "http_request_late_transform",
        Part::ResponseHeaders => "http_response_headers_transform",
    }
}

/// The token permission a phase needs: the same one as the type's own API.
fn area_of(kind: Kind) -> Area {
    match kind {
        Kind::Firewall | Kind::RateLimit => Area::Firewall,
        Kind::Redirect => Area::RedirectRules,
        Kind::Transform(_) => Area::TransformRules,
        Kind::Cache => Area::CacheRules,
        Kind::Origin => Area::OriginRules,
    }
}

/// The permission area for a path below `/zones/{zone_id}/rulesets` (`rest`
/// is what follows `rulesets`). A path that names a phase, directly or by its
/// ruleset id, needs that phase's area; the rest (the list, creating a
/// ruleset, an unknown id) needs the firewall's, as the todo asks. Creating a
/// ruleset also checks the phase in its body (see `create_ruleset` in api.rs).
pub fn area(zone_id: &str, rest: &[&str]) -> Area {
    let phase = match rest {
        ["phases", phase, ..] => Some(*phase),
        [id, ..] => PHASES.iter().copied().find(|p| ruleset_id(zone_id, p) == *id),
        [] => None,
    };
    phase.and_then(kind_of).map(area_of).unwrap_or(Area::Firewall)
}

/// A phase's ruleset id: the same on every node and after every restart, so
/// that Terraform state stays valid, and different for every zone, as
/// Cloudflare's are.
pub fn ruleset_id(zone_id: &str, phase: &str) -> String {
    let d = ring::digest::digest(&ring::digest::SHA256, format!("fucf ruleset\n{zone_id}\n{phase}").as_bytes());
    d.as_ref()[..16].iter().map(|b| format!("{b:02x}")).collect()
}

/// A phase by its name, or a 400 that says which phases there are.
pub fn phase_named(name: &str) -> Result<&'static str, StoreError> {
    PHASES.iter().copied().find(|p| *p == name).ok_or_else(|| {
        StoreError::Invalid(format!("unknown phase '{name}'; this server has: {}", PHASES.join(", ")))
    })
}

/// The phase a ruleset id stands for in this zone.
fn phase_by_id(zone_id: &str, ruleset_id: &str) -> Result<&'static str, StoreError> {
    PHASES.iter().copied().find(|p| self::ruleset_id(zone_id, p) == ruleset_id).ok_or(StoreError::NotFound)
}

/// The phase of a body that creates a ruleset (`POST /zones/{zone_id}/rulesets`).
pub fn phase_in(body: &Value) -> Result<&'static str, StoreError> {
    match body.get("phase") {
        Some(Value::String(p)) => phase_named(p),
        Some(_) => invalid("phase must be a string"),
        None => invalid("phase is required"),
    }
}

// ------------------------------------------------------------- helpers ----

fn invalid<T>(msg: impl Into<String>) -> Result<T, StoreError> {
    Err(StoreError::Invalid(msg.into()))
}

/// `base.field`, or `field` alone at the top.
fn at(base: &str, field: &str) -> String {
    if base.is_empty() {
        field.to_string()
    } else {
        format!("{base}.{field}")
    }
}

fn object<'a>(v: &'a Value, path: &str) -> Result<&'a Map<String, Value>, StoreError> {
    v.as_object().ok_or_else(|| StoreError::Invalid(format!("{path} must be a JSON object")))
}

/// A required object member.
fn member<'a>(m: &'a Map<String, Value>, key: &str, base: &str) -> Result<&'a Map<String, Value>, StoreError> {
    match m.get(key) {
        None | Some(Value::Null) => invalid(format!("{} is required", at(base, key))),
        Some(v) => object(v, &at(base, key)),
    }
}

/// An optional object member.
fn maybe<'a>(m: &'a Map<String, Value>, key: &str, base: &str) -> Result<Option<&'a Map<String, Value>>, StoreError> {
    match m.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => object(v, &at(base, key)).map(Some),
    }
}

/// Reject any member that is not in `allowed`, naming it.
fn only(m: &Map<String, Value>, allowed: &[&str], base: &str) -> Result<(), StoreError> {
    match m.keys().find(|k| !allowed.contains(&k.as_str())) {
        Some(k) => invalid(format!("{} is not supported by this server", at(base, k))),
        None => Ok(()),
    }
}

fn text(m: &Map<String, Value>, key: &str, base: &str) -> Result<Option<String>, StoreError> {
    match m.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => invalid(format!("{} must be a string", at(base, key))),
    }
}

fn flag(m: &Map<String, Value>, key: &str, base: &str) -> Result<Option<bool>, StoreError> {
    match m.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(b)) => Ok(Some(*b)),
        Some(_) => invalid(format!("{} must be true or false", at(base, key))),
    }
}

fn number(m: &Map<String, Value>, key: &str, base: &str, max: u64) -> Result<Option<u64>, StoreError> {
    match m.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => match v.as_u64().filter(|n| *n <= max) {
            Some(n) => Ok(Some(n)),
            None => invalid(format!("{} must be a whole number from 0 to {max}", at(base, key))),
        },
    }
}

fn required<T>(v: Option<T>, base: &str, key: &str) -> Result<T, StoreError> {
    v.ok_or_else(|| StoreError::Invalid(format!("{} is required", at(base, key))))
}

/// The action must be one of `allowed` in this phase.
fn action_in(c: &Common, allowed: &[&str], kind: Kind, base: &str) -> Result<(), StoreError> {
    if allowed.contains(&c.action.as_str()) {
        return Ok(());
    }
    invalid(format!(
        "{}: '{}' is not an action of {} here (only {})",
        at(base, "action"),
        c.action,
        phase_name(kind),
        allowed.join(", ")
    ))
}

fn phase_name(kind: Kind) -> &'static str {
    PHASES.iter().copied().find(|p| kind_of(p) == Some(kind)).unwrap_or("this phase")
}

// --------------------------------------------------- one rule, parsed ----

/// The fields every Cloudflare rule has, read and checked.
struct Common {
    id: Option<String>,
    action: String,
    /// `""` for "every request" (Cloudflare writes it `true`).
    expression: String,
    description: String,
    enabled: bool,
    params: Map<String, Value>,
    ratelimit: Option<Map<String, Value>>,
    logging: Option<Value>,
}

/// Read the common part of a Cloudflare rule. `version` and `last_updated`
/// are the server's to say and are not read; `ref` is accepted only as the
/// rule's own id, since rules here have no reference of their own.
fn common(rule: &Value, base: &str) -> Result<Common, StoreError> {
    let Value::Object(m) = rule else {
        return invalid(format!("{} must be a JSON object", if base.is_empty() { "the rule" } else { base }));
    };
    only(
        m,
        &["id", "ref", "version", "last_updated", "action", "expression", "description", "enabled", "action_parameters", "ratelimit", "logging"],
        base,
    )?;
    let id = text(m, "id", base)?.filter(|s| !s.is_empty());
    if let Some(r) = text(m, "ref", base)?.filter(|s| !s.is_empty()) {
        if id.as_deref() != Some(r.as_str()) {
            return invalid(format!("{}: rules here have no reference of their own; ref can only be the rule's id", at(base, "ref")));
        }
    }
    let action = required(text(m, "action", base)?, base, "action")?;
    let expression = required(text(m, "expression", base)?, base, "expression")?;
    let expression = if expression.trim() == "true" { String::new() } else { expression };
    let params = maybe(m, "action_parameters", base)?.cloned().unwrap_or_default();
    let ratelimit = maybe(m, "ratelimit", base)?.cloned();
    Ok(Common {
        id,
        action,
        expression,
        description: text(m, "description", base)?.unwrap_or_default(),
        enabled: flag(m, "enabled", base)?.unwrap_or(true),
        params,
        ratelimit,
        logging: m.get("logging").filter(|v| !v.is_null()).cloned(),
    })
}

/// `ratelimit` and `logging` are read for every rule but mean something in
/// one place only; anywhere else they would be dropped, so they are refused.
fn extras(kind: Kind, c: &Common, base: &str) -> Result<(), StoreError> {
    if kind != Kind::RateLimit && c.ratelimit.is_some() {
        return invalid(format!("{} belongs in http_ratelimit, not {}", at(base, "ratelimit"), phase_name(kind)));
    }
    if c.logging.is_some() && !(kind == Kind::Firewall && c.action == "skip") {
        return invalid(format!("{} is only for skip rules here", at(base, "logging")));
    }
    Ok(())
}

/// What a skip rule here skips: the remaining custom rules (`return
/// Verdict::Skipped` in crate::edge::waf), the security level, rate limits,
/// the managed rules and the waiting room. A Cloudflare skip that names
/// less would skip more here than its author meant, so it is refused
/// rather than widened.
fn skip_params() -> Value {
    json!({
        "ruleset": "current",
        "phases": ["http_ratelimit", "http_request_firewall_managed"],
        "products": ["securityLevel"],
    })
}

fn check_skip(params: &Map<String, Value>, base: &str) -> Result<(), StoreError> {
    if params.is_empty() {
        return Ok(());
    }
    let path = at(base, "action_parameters");
    only(params, &["ruleset", "phases", "products"], &path)?;
    let list = |key: &str, known: &[&str]| -> Result<HashSet<String>, StoreError> {
        let mut out = HashSet::new();
        match params.get(key) {
            None | Some(Value::Null) => {}
            Some(Value::Array(items)) => {
                for item in items {
                    match item.as_str() {
                        Some(s) if known.contains(&s) => {
                            out.insert(s.to_string());
                        }
                        Some(s) => return invalid(format!("{}: '{s}' is not supported by this server", at(&path, key))),
                        None => return invalid(format!("{} must be a list of strings", at(&path, key))),
                    }
                }
            }
            Some(_) => return invalid(format!("{} must be a list of strings", at(&path, key))),
        }
        Ok(out)
    };
    let phases = list("phases", &["http_ratelimit", "http_request_firewall_managed", "http_request_sbfm"])?;
    let products = list("products", &["zoneLockdown", "uaBlock", "bic", "hot", "securityLevel", "rateLimit", "waf"])?;
    let ruleset = text(params, "ruleset", &path)?;
    if let Some(r) = ruleset.as_deref().filter(|r| *r != "current") {
        return invalid(format!("{}: '{r}' is not supported by this server; only \"current\"", at(&path, "ruleset")));
    }
    let covers = ruleset.is_some()
        && phases.contains("http_ratelimit")
        && phases.contains("http_request_firewall_managed")
        && products.contains("securityLevel");
    if !covers {
        return invalid(format!(
            "{path}: a skip rule here always skips the remaining custom rules, the security level, rate limits and \
             the managed rules, so it must say ruleset \"current\", phases http_ratelimit and \
             http_request_firewall_managed, and product securityLevel"
        ));
    }
    Ok(())
}

// --------------------------------------------- the types, as rules ----

/// What the Rulesets view needs from each rule type.
trait Mapped: Item {
    /// Whether the phase's order is the type's `priority` (rate limits have
    /// none and run in the order they were made).
    const ORDERED: bool = true;
    /// Is this object one of the phase's rules?
    fn shown(&self, _kind: Kind) -> bool {
        true
    }
    fn priority(&self) -> i32;
    /// Its expression, description and whether it is on.
    fn basics(&self) -> (&str, &str, bool);
    /// `action` and whatever goes with it (`action_parameters`, `ratelimit`,
    /// `logging`) in Cloudflare's words.
    fn actions(&self, kind: Kind) -> Map<String, Value>;
    /// The fields of this type a Cloudflare rule sets (besides expression,
    /// description, enabled and priority, which are done for every type).
    fn parse(kind: Kind, c: &Common, base: &str) -> Result<Map<String, Value>, StoreError>;
    /// The other phases it is also a rule of (only a transform rule can be).
    fn elsewhere(&self, _kind: Kind) -> Vec<&'static str> {
        Vec::new()
    }
    /// What taking it out of `kind` changes when it stays a rule of other
    /// phases; `None` when it should be deleted.
    fn leave(&self, _kind: Kind) -> Option<Map<String, Value>> {
        None
    }
}

fn map(v: Value) -> Map<String, Value> {
    match v {
        Value::Object(m) => m,
        _ => Map::new(),
    }
}

impl Mapped for FirewallRule {
    /// The automatic firewall's own rules (crate::edge::autofw) are not
    /// shown: they are rewritten every few minutes, and a Terraform plan
    /// that replaced the phase would delete them.
    fn shown(&self, _: Kind) -> bool {
        self.managed_by.is_empty()
    }
    fn priority(&self) -> i32 {
        self.priority
    }
    fn basics(&self) -> (&str, &str, bool) {
        (&self.expression, &self.description, self.enabled)
    }
    fn actions(&self, _: Kind) -> Map<String, Value> {
        let mut m = map(json!({ "action": self.action }));
        if self.action == "skip" {
            m.insert("action_parameters".into(), skip_params());
            m.insert("logging".into(), json!({ "enabled": true }));
        }
        m
    }
    fn parse(kind: Kind, c: &Common, base: &str) -> Result<Map<String, Value>, StoreError> {
        action_in(c, &["block", "js_challenge", "managed_challenge", "log", "skip"], kind, base)?;
        if c.action == "skip" {
            check_skip(&c.params, base)?;
            if let Some(l) = &c.logging {
                if *l != json!({ "enabled": true }) {
                    return invalid(format!("{}: skip rules are always logged here; only {{\"enabled\": true}}", at(base, "logging")));
                }
            }
        } else {
            only(&c.params, &[], &at(base, "action_parameters"))?;
        }
        Ok(map(json!({ "action": c.action })))
    }
}

impl Mapped for RateLimit {
    const ORDERED: bool = false;
    fn priority(&self) -> i32 {
        0
    }
    fn basics(&self) -> (&str, &str, bool) {
        (&self.expression, &self.description, self.enabled)
    }
    fn actions(&self, _: Kind) -> Map<String, Value> {
        let mut characteristics = vec!["cf.colo.id".to_string()];
        match self.characteristics.is_empty() {
            true => characteristics.push("ip.src".into()),
            false => characteristics.extend(self.characteristics.iter().map(|c| cloudflare_characteristic(c))),
        }
        let mut rl = map(json!({
            "characteristics": characteristics,
            "period": self.period,
            "requests_per_period": self.threshold,
            "mitigation_timeout": self.mitigation_timeout,
        }));
        if !self.status_codes.is_empty() {
            rl.insert("counting_expression".into(), json!(counting_expression(&self.expression, &self.status_codes)));
        }
        map(json!({ "action": self.action, "ratelimit": rl }))
    }
    fn parse(kind: Kind, c: &Common, base: &str) -> Result<Map<String, Value>, StoreError> {
        action_in(c, &["block", "log"], kind, base)?;
        only(&c.params, &[], &at(base, "action_parameters"))?;
        let path = at(base, "ratelimit");
        let Some(rl) = &c.ratelimit else { return invalid(format!("{path} is required in http_ratelimit")) };
        only(rl, &["characteristics", "period", "requests_per_period", "mitigation_timeout", "counting_expression", "requests_to_origin"], &path)?;
        // requests are counted on each node (crate::edge::waf::Waf::count), so
        // cf.colo.id is always there; the rest is what tells clients apart
        let mut characteristics = Vec::new();
        if let Some(ch) = rl.get("characteristics").filter(|v| !v.is_null()) {
            let where_ = at(&path, "characteristics");
            let Some(list) = ch.as_array() else { return invalid(format!("{where_} must be a list of strings")) };
            let mut colo = false;
            for c in list {
                let Some(c) = c.as_str() else { return invalid(format!("{where_} must be a list of strings")) };
                if c == "cf.colo.id" {
                    colo = true;
                    continue;
                }
                let Some(ours) = our_characteristic(c) else {
                    return invalid(format!(
                        "{where_}: '{c}' is not supported by this server; cf.colo.id with ip.src, ip.src.asnum, ip.geoip.country, http.host, \
                         http.request.uri.path, http.request.headers[\"name\"] or http.request.cookies[\"name\"]"
                    ));
                };
                if !characteristics.contains(&ours) {
                    characteristics.push(ours);
                }
            }
            if !colo {
                return invalid(format!("{where_} must hold cf.colo.id: requests are counted on each node"));
            }
        }
        if characteristics == ["ip"] {
            characteristics.clear();
        }
        let mut status_codes = Vec::new();
        if let Some(counting) = text(rl, "counting_expression", &path)?.filter(|e| !e.trim().is_empty()) {
            status_codes = counted_statuses(&counting, &c.expression).ok_or_else(|| {
                StoreError::Invalid(format!(
                    "{}: only the rule's own expression and a response code can be counted here, as `<expression> and http.response.code in {{401 403}}` \
                     (or the code alone for a rule that matches every request)",
                    at(&path, "counting_expression")
                ))
            })?;
        }
        if flag(rl, "requests_to_origin", &path)? == Some(true) {
            return invalid(format!("{} is not supported by this server: every matching request is counted", at(&path, "requests_to_origin")));
        }
        let max = u64::from(u32::MAX);
        Ok(map(json!({
            "action": c.action,
            "threshold": required(number(rl, "requests_per_period", &path, max)?, &path, "requests_per_period")?,
            "period": required(number(rl, "period", &path, max)?, &path, "period")?,
            "mitigation_timeout": number(rl, "mitigation_timeout", &path, max)?.unwrap_or(0),
            "characteristics": characteristics,
            "status_codes": status_codes,
        })))
    }
}

/// A characteristic of a rate limit in Cloudflare's words, from this server's.
fn cloudflare_characteristic(ours: &str) -> String {
    match ours.split_once(':') {
        Some(("header", name)) => format!("http.request.headers[\"{name}\"]"),
        Some(("cookie", name)) => format!("http.request.cookies[\"{name}\"]"),
        _ => match ours {
            "asn" => "ip.src.asnum",
            "country" => "ip.geoip.country",
            "host" => "http.host",
            "path" => "http.request.uri.path",
            _ => "ip.src",
        }
        .into(),
    }
}

/// This server's word for a Cloudflare characteristic (not `cf.colo.id`),
/// or None for one it cannot count by. Names are checked again by
/// [`RateLimit`]'s own validation.
fn our_characteristic(cf: &str) -> Option<String> {
    let named = |prefix: &str| cf.strip_prefix(prefix)?.strip_suffix("\"]").filter(|n| !n.is_empty() && !n.contains('"')).map(str::to_string);
    if let Some(name) = named("http.request.headers[\"") {
        return Some(format!("header:{}", name.to_ascii_lowercase()));
    }
    if let Some(name) = named("http.request.cookies[\"") {
        return Some(format!("cookie:{name}"));
    }
    Some(
        match cf {
            "ip.src" => "ip",
            "ip.src.asnum" => "asn",
            "ip.geoip.country" => "country",
            "http.host" => "host",
            "http.request.uri.path" => "path",
            _ => return None,
        }
        .into(),
    )
}

/// May `expression` stand bare before an `and` without changing its meaning?
/// (`and` binds tighter than `or` and `xor`.)
fn binds_alone(expression: &str) -> bool {
    let lower = expression.to_ascii_lowercase();
    ![" or ", "||", " xor ", "^^"].iter().any(|op| lower.contains(op))
}

/// The `counting_expression` a rate limit that counts answers by status is
/// shown with: its own expression and the codes.
fn counting_expression(expression: &str, codes: &[u16]) -> String {
    let codes = format!("http.response.code in {{{}}}", codes.iter().map(u16::to_string).collect::<Vec<_>>().join(" "));
    match expression.trim() {
        "" => codes,
        e if binds_alone(e) => format!("{e} and {codes}"),
        e => format!("({e}) and {codes}"),
    }
}

/// The status codes a `counting_expression` counts, when it is the rule's
/// own expression (as [`counting_expression`] writes it, or bare when that
/// keeps its meaning) and a test of `http.response.code` and nothing else:
/// that is all this server can count. None otherwise.
fn counted_statuses(counting: &str, expression: &str) -> Option<Vec<u16>> {
    let counting = counting.trim();
    let expression = expression.trim();
    let codes = if expression.is_empty() {
        counting
    } else {
        let rest = counting.strip_prefix(&format!("({expression})")).or_else(|| counting.strip_prefix(expression).filter(|_| binds_alone(expression)))?;
        let rest = rest.trim_start();
        rest.strip_prefix("and ").or_else(|| rest.strip_prefix("&&"))?.trim()
    };
    let test = codes.strip_prefix("http.response.code")?.trim_start();
    let parsed: Option<Vec<u16>> = if let Some(set) = test.strip_prefix("in").map(str::trim_start).and_then(|t| t.strip_prefix('{')?.strip_suffix('}')) {
        set.split_whitespace().map(|n| n.parse().ok()).collect()
    } else {
        let one = test.strip_prefix("eq").or_else(|| test.strip_prefix("=="))?.trim();
        Some(vec![one.parse().ok()?])
    };
    parsed.filter(|codes| !codes.is_empty())
}

impl Mapped for RedirectRule {
    fn priority(&self) -> i32 {
        self.priority
    }
    fn basics(&self) -> (&str, &str, bool) {
        (&self.expression, &self.description, self.enabled)
    }
    fn actions(&self, _: Kind) -> Map<String, Value> {
        map(json!({
            "action": "redirect",
            "action_parameters": { "from_value": {
                "target_url": { "value": self.target_url },
                "status_code": self.status_code,
                "preserve_query_string": self.preserve_query_string,
            } },
        }))
    }
    fn parse(kind: Kind, c: &Common, base: &str) -> Result<Map<String, Value>, StoreError> {
        action_in(c, &["redirect"], kind, base)?;
        let params = at(base, "action_parameters");
        only(&c.params, &["from_value"], &params)?;
        let from = member(&c.params, "from_value", &params)?;
        let path = at(&params, "from_value");
        only(from, &["target_url", "status_code", "preserve_query_string"], &path)?;
        let target = member(from, "target_url", &path)?;
        let target_path = at(&path, "target_url");
        only(target, &["value"], &target_path)?;
        Ok(map(json!({
            "target_url": required(text(target, "value", &target_path)?, &target_path, "value")?,
            "status_code": required(number(from, "status_code", &path, u64::from(u16::MAX))?, &path, "status_code")?,
            "preserve_query_string": flag(from, "preserve_query_string", &path)?.unwrap_or(false),
        })))
    }
}

impl TransformRule {
    fn has(&self, part: Part) -> bool {
        match part {
            Part::Path => self.rewrite_path.is_some(),
            Part::RequestHeaders => !self.set_request_headers.is_empty() || !self.remove_request_headers.is_empty(),
            Part::ResponseHeaders => !self.set_response_headers.is_empty() || !self.remove_response_headers.is_empty(),
        }
    }
}

fn part(kind: Kind) -> Part {
    match kind {
        Kind::Transform(p) => p,
        _ => Part::Path,
    }
}

/// The fields of a transform rule one part is made of, as JSON to merge:
/// empty ones clear the part.
fn transform_fields(part: Part, path: Option<String>, set: BTreeMap<String, String>, remove: Vec<String>) -> Map<String, Value> {
    match part {
        Part::Path => map(json!({ "rewrite_path": path })),
        Part::RequestHeaders => map(json!({ "set_request_headers": set, "remove_request_headers": remove })),
        Part::ResponseHeaders => map(json!({ "set_response_headers": set, "remove_response_headers": remove })),
    }
}

impl Mapped for TransformRule {
    fn shown(&self, kind: Kind) -> bool {
        self.has(part(kind))
    }
    fn priority(&self) -> i32 {
        self.priority
    }
    fn basics(&self) -> (&str, &str, bool) {
        (&self.expression, &self.description, self.enabled)
    }
    fn actions(&self, kind: Kind) -> Map<String, Value> {
        let params = match part(kind) {
            Part::Path => json!({ "uri": { "path": { "value": self.rewrite_path } } }),
            p => {
                let (set, remove) = if p == Part::RequestHeaders {
                    (&self.set_request_headers, &self.remove_request_headers)
                } else {
                    (&self.set_response_headers, &self.remove_response_headers)
                };
                let mut headers = Map::new();
                for (name, value) in set {
                    headers.insert(name.clone(), json!({ "operation": "set", "value": value }));
                }
                for name in remove {
                    headers.insert(name.clone(), json!({ "operation": "remove" }));
                }
                json!({ "headers": headers })
            }
        };
        map(json!({ "action": "rewrite", "action_parameters": params }))
    }
    fn parse(kind: Kind, c: &Common, base: &str) -> Result<Map<String, Value>, StoreError> {
        action_in(c, &["rewrite"], kind, base)?;
        let params = at(base, "action_parameters");
        let p = part(kind);
        let (wanted, other) = if p == Part::Path { ("uri", "headers") } else { ("headers", "uri") };
        if c.params.contains_key(other) {
            let belongs = if other == "uri" { "http_request_transform" } else { "http_request_late_transform or http_response_headers_transform" };
            return invalid(format!("{} belongs in {belongs}, not {}", at(&params, other), phase_name(kind)));
        }
        only(&c.params, &[wanted], &params)?;
        if p == Part::Path {
            let uri = member(&c.params, "uri", &params)?;
            let uri_path = at(&params, "uri");
            only(uri, &["path"], &uri_path)?;
            let path = member(uri, "path", &uri_path)?;
            let path_path = at(&uri_path, "path");
            only(path, &["value"], &path_path)?;
            let value = required(text(path, "value", &path_path)?, &path_path, "value")?;
            return Ok(transform_fields(p, Some(value), BTreeMap::new(), Vec::new()));
        }
        let headers = member(&c.params, "headers", &params)?;
        let headers_path = at(&params, "headers");
        if headers.is_empty() {
            return invalid(format!("{headers_path} must name at least one header"));
        }
        let (mut set, mut remove) = (BTreeMap::new(), Vec::new());
        for (name, op) in headers {
            let op_path = at(&headers_path, name);
            let op = object(op, &op_path)?;
            match required(text(op, "operation", &op_path)?, &op_path, "operation")?.as_str() {
                "set" => {
                    only(op, &["operation", "value"], &op_path)?;
                    set.insert(name.clone(), required(text(op, "value", &op_path)?, &op_path, "value")?);
                }
                "remove" => {
                    only(op, &["operation"], &op_path)?;
                    remove.push(name.clone());
                }
                other => {
                    return invalid(format!(
                        "{}: '{other}' is not supported by this server; a header is set (replacing any value it had) or removed",
                        at(&op_path, "operation")
                    ))
                }
            }
        }
        Ok(transform_fields(p, None, set, remove))
    }
    fn elsewhere(&self, kind: Kind) -> Vec<&'static str> {
        [Part::Path, Part::RequestHeaders, Part::ResponseHeaders]
            .into_iter()
            .filter(|p| *p != part(kind) && self.has(*p))
            .map(phase_of_part)
            .collect()
    }
    fn leave(&self, kind: Kind) -> Option<Map<String, Value>> {
        (!self.elsewhere(kind).is_empty()).then(|| transform_fields(part(kind), None, BTreeMap::new(), Vec::new()))
    }
}

impl Mapped for CacheRule {
    fn priority(&self) -> i32 {
        self.priority
    }
    fn basics(&self) -> (&str, &str, bool) {
        (&self.expression, &self.description, self.enabled)
    }
    fn actions(&self, _: Kind) -> Map<String, Value> {
        let mut params = map(json!({ "cache": self.cache }));
        if let Some(ttl) = self.edge_ttl {
            params.insert("edge_ttl".into(), json!({ "mode": "override_origin", "default": ttl }));
        }
        map(json!({ "action": "set_cache_settings", "action_parameters": params }))
    }
    fn parse(kind: Kind, c: &Common, base: &str) -> Result<Map<String, Value>, StoreError> {
        action_in(c, &["set_cache_settings"], kind, base)?;
        let params = at(base, "action_parameters");
        only(&c.params, &["cache", "edge_ttl"], &params)?;
        let cache = required(flag(&c.params, "cache", &params)?, &params, "cache")?;
        let edge_ttl = match maybe(&c.params, "edge_ttl", &params)? {
            None => None,
            Some(ttl) => {
                let path = at(&params, "edge_ttl");
                only(ttl, &["mode", "default"], &path)?;
                match required(text(ttl, "mode", &path)?, &path, "mode")?.as_str() {
                    "override_origin" => Some(required(number(ttl, "default", &path, u64::from(u32::MAX))?, &path, "default")?),
                    "respect_origin" if ttl.get("default").is_none_or(Value::is_null) => None,
                    "respect_origin" => return invalid(format!("{}: a default goes with mode override_origin", at(&path, "default"))),
                    other => {
                        return invalid(format!(
                            "{}: '{other}' is not supported by this server; only override_origin or respect_origin",
                            at(&path, "mode")
                        ))
                    }
                }
            }
        };
        Ok(map(json!({ "cache": cache, "edge_ttl": edge_ttl })))
    }
}

impl Mapped for OriginRule {
    fn priority(&self) -> i32 {
        self.priority
    }
    fn basics(&self) -> (&str, &str, bool) {
        (&self.expression, &self.description, self.enabled)
    }
    /// `origin_node` and `origin_scheme` have no Cloudflare words: they are
    /// not shown, and a change through the Rulesets API leaves them as
    /// they are.
    fn actions(&self, _: Kind) -> Map<String, Value> {
        let mut params = Map::new();
        if let Some(h) = &self.host_header {
            params.insert("host_header".into(), json!(h));
        }
        let mut origin = Map::new();
        if let Some(h) = &self.origin_host {
            origin.insert("host".into(), json!(h));
        }
        if let Some(p) = self.origin_port {
            origin.insert("port".into(), json!(p));
        }
        if !origin.is_empty() {
            params.insert("origin".into(), Value::Object(origin));
        }
        if let Some(s) = &self.sni {
            params.insert("sni".into(), json!({ "value": s }));
        }
        map(json!({ "action": "route", "action_parameters": params }))
    }
    fn parse(kind: Kind, c: &Common, base: &str) -> Result<Map<String, Value>, StoreError> {
        action_in(c, &["route"], kind, base)?;
        let params = at(base, "action_parameters");
        only(&c.params, &["host_header", "origin", "sni"], &params)?;
        let (mut host, mut port) = (None, None);
        if let Some(origin) = maybe(&c.params, "origin", &params)? {
            let path = at(&params, "origin");
            only(origin, &["host", "port"], &path)?;
            host = text(origin, "host", &path)?;
            port = number(origin, "port", &path, u64::from(u16::MAX))?;
        }
        let sni = match maybe(&c.params, "sni", &params)? {
            Some(sni) => {
                let path = at(&params, "sni");
                only(sni, &["value"], &path)?;
                Some(required(text(sni, "value", &path)?, &path, "value")?)
            }
            None => None,
        };
        Ok(map(json!({
            "host_header": text(&c.params, "host_header", &params)?,
            "origin_host": host,
            "origin_port": port,
            "sni": sni,
        })))
    }
}

// ----------------------------------------------------- reading rules ----

/// The phase's rules, in the order they run (the edge sorts by priority,
/// keeping the stored order among equals: crate::store's `compile`).
fn in_order<T: Mapped>(items: &[T], kind: Kind) -> Vec<&T> {
    let mut shown: Vec<&T> = items.iter().filter(|i| i.shown(kind)).collect();
    if T::ORDERED {
        shown.sort_by_key(|i| i.priority());
    }
    shown
}

fn to_rule<T: Mapped>(item: &T, kind: Kind) -> Value {
    let (expression, description, enabled) = item.basics();
    let id = &item.meta().id;
    let mut m = map(json!({
        "id": id,
        "ref": id,
        "version": "1",
        "expression": if expression.trim().is_empty() { "true" } else { expression },
        "description": description,
        "enabled": enabled,
        "last_updated": item.meta().modified_on,
    }));
    m.extend(item.actions(kind));
    Value::Object(m)
}

fn render<T: Mapped>(store: &Store, zone_id: &str, phase: &'static str, kind: Kind) -> Result<Value, StoreError> {
    let items = store.items::<T>(zone_id)?;
    let rules = in_order(&items, kind);
    let last_updated = match rules.iter().map(|r| r.meta().modified_on.clone()).max() {
        Some(t) => t,
        None => store.get_zone(zone_id)?.modified_on,
    };
    Ok(json!({
        "id": ruleset_id(zone_id, phase),
        "name": "default",
        "description": "",
        "kind": "zone",
        "version": "1",
        "phase": phase,
        "last_updated": last_updated,
        "rules": rules.iter().map(|r| to_rule(*r, kind)).collect::<Vec<_>>(),
    }))
}

/// Run `$body` with `$T` standing for the type behind `$kind`.
macro_rules! typed {
    ($kind:expr, $T:ident => $body:expr) => {
        match $kind {
            Kind::Firewall => {
                type $T = FirewallRule;
                $body
            }
            Kind::RateLimit => {
                type $T = RateLimit;
                $body
            }
            Kind::Redirect => {
                type $T = RedirectRule;
                $body
            }
            Kind::Transform(_) => {
                type $T = TransformRule;
                $body
            }
            Kind::Cache => {
                type $T = CacheRule;
                $body
            }
            Kind::Origin => {
                type $T = OriginRule;
                $body
            }
        }
    };
}

fn kind(phase: &str) -> Kind {
    // (every phase in PHASES has a kind; the fallback is never used)
    kind_of(phase).unwrap_or(Kind::Firewall)
}

/// The zone's entrypoint rulesets that have rules, without the rules, as
/// Cloudflare lists them.
pub fn list(store: &Store, zone_id: &str) -> Result<Value, StoreError> {
    let mut out = Vec::new();
    for phase in PHASES {
        let mut rs = typed!(kind(phase), T => render::<T>(store, zone_id, phase, kind(phase)))?;
        let empty = rs["rules"].as_array().is_none_or(Vec::is_empty);
        if let Some(o) = rs.as_object_mut() {
            o.remove("rules");
        }
        if !empty {
            out.push(rs);
        }
    }
    Ok(Value::Array(out))
}

/// One phase's entrypoint ruleset. A phase without rules still answers,
/// with none, since its id exists whether or not it has rules.
pub fn entrypoint(store: &Store, zone_id: &str, phase: &'static str) -> Result<Value, StoreError> {
    typed!(kind(phase), T => render::<T>(store, zone_id, phase, kind(phase)))
}

pub fn get(store: &Store, zone_id: &str, ruleset_id: &str) -> Result<Value, StoreError> {
    entrypoint(store, zone_id, phase_by_id(zone_id, ruleset_id)?)
}

// ---------------------------------------------------- changing rules ----

/// One change to a phase.
enum Change {
    /// The phase's rules become these, in this order. With `only_if_empty`
    /// (creating a ruleset) a phase that has rules already is a conflict.
    Replace { rules: Vec<Value>, only_if_empty: bool },
    Add { rule: Value, position: Option<Map<String, Value>> },
    Update { id: String, rule: Map<String, Value>, position: Option<Map<String, Value>> },
    Remove(String),
}

/// One rule of the phase as it should be: an existing object (`id`) or a new
/// one, with what the request says about it (`None`: left as it is).
struct Want {
    id: Option<String>,
    rule: Option<(Common, String)>,
}

/// Where `position` (`before` / `after` a rule id, or a 1-based `index`)
/// puts a rule among `list`; `default` without one. An empty `before` is the
/// top and an empty `after` the bottom, as on Cloudflare.
fn place(list: &[Want], position: Option<&Map<String, Value>>, default: usize) -> Result<usize, StoreError> {
    let Some(p) = position.filter(|p| !p.is_empty()) else { return Ok(default) };
    only(p, &["before", "after", "index"], "position")?;
    if p.len() > 1 {
        return invalid("position: give one of before, after or index");
    }
    let find = |key: &str| -> Result<Option<usize>, StoreError> {
        match text(p, key, "position")? {
            Some(id) if id.is_empty() => Ok(None),
            Some(id) => list
                .iter()
                .position(|w| w.id.as_deref() == Some(id.as_str()))
                .map(Some)
                .ok_or_else(|| StoreError::Invalid(format!("position.{key}: there is no rule {id} in this phase"))),
            None => Ok(None),
        }
    };
    if p.contains_key("before") {
        return Ok(find("before")?.unwrap_or(0));
    }
    if p.contains_key("after") {
        return Ok(find("after")?.map(|i| i + 1).unwrap_or(list.len()));
    }
    match number(p, "index", "position", u64::MAX)? {
        Some(i) if i >= 1 && usize::try_from(i).is_ok_and(|i| i <= list.len() + 1) => Ok(usize::try_from(i).unwrap_or(1) - 1),
        _ => invalid(format!("position.index must be from 1 to {}", list.len() + 1)),
    }
}

/// A JSON object.
type Object = Map<String, Value>;

/// Split `position` off a single-rule body.
fn split_position(body: Value) -> Result<(Object, Option<Object>), StoreError> {
    let Value::Object(mut m) = body else { return invalid("request body must be a JSON object") };
    let position = match m.remove("position") {
        None | Some(Value::Null) => None,
        Some(Value::Object(p)) => Some(p),
        Some(_) => return invalid("position must be a JSON object"),
    };
    Ok((m, position))
}

/// Has the stored item already got every value of `patch`?
fn unchanged<T: Mapped>(item: &T, patch: &Map<String, Value>) -> bool {
    let now = serde_json::to_value(item).unwrap_or(Value::Null);
    patch.iter().all(|(k, v)| now.get(k).unwrap_or(&Value::Null) == v)
}

/// The saves and deletes that make the phase what `change` asks, from the
/// zone's items as they are (run inside the store's write, so nothing can
/// change between reading and writing).
fn plan<T: Mapped>(items: &[T], kind: Kind, change: Change) -> Result<Vec<ItemOp>, StoreError> {
    let current = in_order(items, kind);
    let ids: Vec<&str> = current.iter().map(|i| i.meta().id.as_str()).collect();
    let keep = |id: &str| Want { id: Some(id.to_string()), rule: None };
    let mut want: Vec<Want> = Vec::new();
    match change {
        Change::Replace { rules, only_if_empty } => {
            if only_if_empty && !current.is_empty() {
                return Err(StoreError::Conflict(format!(
                    "the {} ruleset of this zone exists already and has rules; change it with PUT .../rulesets/phases/{}/entrypoint",
                    phase_name(kind),
                    phase_name(kind)
                )));
            }
            let mut seen = HashSet::new();
            for (i, rule) in rules.iter().enumerate() {
                let base = format!("rules[{i}]");
                let c = common(rule, &base)?;
                if let Some(id) = &c.id {
                    if !ids.contains(&id.as_str()) {
                        return invalid(format!("{base}.id: there is no rule {id} in this phase"));
                    }
                    if !seen.insert(id.clone()) {
                        return invalid(format!("{base}.id: rule {id} is listed twice"));
                    }
                }
                want.push(Want { id: c.id.clone(), rule: Some((c, base)) });
            }
        }
        Change::Add { rule, position } => {
            let c = common(&rule, "")?;
            if c.id.is_some() {
                return invalid("id: a new rule gets its id from the server");
            }
            want = ids.iter().map(|id| keep(id)).collect();
            let at = place(&want, position.as_ref(), want.len())?;
            want.insert(at, Want { id: None, rule: Some((c, String::new())) });
        }
        Change::Update { id, rule, position } => {
            let Some(idx) = ids.iter().position(|i| *i == id) else { return Err(StoreError::NotFound) };
            if let Some(other) = rule.get("id").and_then(Value::as_str).filter(|i| *i != id) {
                return invalid(format!("id: the body names rule {other}, the path rule {id}"));
            }
            // a PATCH changes what it names; the rest stays as it is, except
            // that a new action does not inherit the old one's parameters
            let mut full = map(to_rule(current[idx], kind));
            if rule.get("action").is_some_and(|a| Some(a) != full.get("action")) {
                full.remove("action_parameters");
                full.remove("logging");
            }
            for (k, v) in rule {
                full.insert(k, v);
            }
            let c = common(&Value::Object(full), "")?;
            want = ids.iter().map(|id| keep(id)).collect();
            want.remove(idx);
            let at = place(&want, position.as_ref(), idx)?;
            want.insert(at, Want { id: Some(id), rule: Some((c, String::new())) });
        }
        Change::Remove(id) => {
            if !ids.contains(&id.as_str()) {
                return Err(StoreError::NotFound);
            }
            want = ids.iter().filter(|i| **i != id).map(|id| keep(id)).collect();
        }
    }

    let mut ops = Vec::new();
    // rules left out of the phase
    for item in &current {
        if !want.iter().any(|w| w.id.as_deref() == Some(item.meta().id.as_str())) {
            ops.push(match item.leave(kind) {
                Some(patch) => ItemOp::Save { id: Some(item.meta().id.clone()), body: Value::Object(patch), replace: false, at: String::new() },
                None => ItemOp::Delete(item.meta().id.clone()),
            });
        }
    }

    // the order: priorities stay as they are when the existing rules keep
    // their order and new ones come last; otherwise each rule's priority
    // becomes its place in the list
    let kept: Vec<&str> = want.iter().filter_map(|w| w.id.as_deref()).collect();
    let before: Vec<&str> = ids.iter().copied().filter(|id| kept.contains(id)).collect();
    let new_last = want.iter().skip_while(|w| w.id.is_some()).all(|w| w.id.is_none());
    let in_place = kept == before && new_last;
    if !T::ORDERED && !in_place {
        return invalid(format!(
            "{} rules run in the order they were made here and cannot be reordered; new ones can only go last",
            phase_name(kind)
        ));
    }
    let mut next = current.iter().map(|i| i.priority()).max().map_or(0, |p| p.saturating_add(1));
    let by_id = |id: &str| current.iter().find(|i| i.meta().id == id).copied();
    for (i, w) in want.into_iter().enumerate() {
        let existing = w.id.as_deref().and_then(by_id);
        let priority = match (in_place, existing) {
            (true, Some(e)) => e.priority(),
            (true, None) => {
                let p = next;
                next = next.saturating_add(1);
                p
            }
            (false, _) => i32::try_from(i).unwrap_or(i32::MAX),
        };
        let mut patch = match &w.rule {
            None => Map::new(),
            Some((c, base)) => {
                extras(kind, c, base)?;
                let mut patch = T::parse(kind, c, base)?;
                patch.insert("expression".into(), json!(c.expression));
                patch.insert("description".into(), json!(c.description));
                patch.insert("enabled".into(), json!(c.enabled));
                if let Some(e) = existing {
                    let others = e.elsewhere(kind);
                    let (expression, description, enabled) = e.basics();
                    if !others.is_empty() && (expression != c.expression || description != c.description || enabled != c.enabled) {
                        return invalid(format!(
                            "{}: this rule is also in {}; its expression, description and enabled are shared there, \
                             so change them with the transform_rules API (or in every phase at once)",
                            if base.is_empty() { "the rule" } else { base.as_str() },
                            others.join(" and ")
                        ));
                    }
                }
                patch
            }
        };
        if T::ORDERED {
            patch.insert("priority".into(), json!(priority));
        }
        let at = w.rule.as_ref().map(|(_, base)| base.clone()).unwrap_or_default();
        match existing {
            Some(e) if patch.is_empty() || unchanged(e, &patch) => {}
            Some(e) => ops.push(ItemOp::Save { id: Some(e.meta().id.clone()), body: Value::Object(patch), replace: false, at }),
            None => ops.push(ItemOp::Save { id: None, body: Value::Object(patch), replace: true, at }),
        }
    }
    Ok(ops)
}

async fn apply(store: &Store, zone_id: &str, phase: &'static str, change: Change) -> Result<Value, StoreError> {
    let k = kind(phase);
    typed!(k, T => {
        store.batch_items_async::<T, _>(zone_id, move |items| plan::<T>(&items, k, change)).await?;
        render::<T>(store, zone_id, phase, k)
    })
}

/// The rules of a ruleset body (`PUT` of a ruleset or entrypoint, `POST` of
/// a new ruleset). Its name and description are accepted and not kept:
/// every entrypoint here is called `default`.
fn rules_of(body: Value, zone_id: &str, phase: &str) -> Result<Vec<Value>, StoreError> {
    let Value::Object(mut m) = body else { return invalid("request body must be a JSON object") };
    only(&m, &["id", "name", "description", "kind", "phase", "rules", "version", "last_updated"], "")?;
    if let Some(k) = text(&m, "kind", "")?.filter(|k| k != "zone") {
        return invalid(format!("kind: '{k}' is not supported by this server; only zone"));
    }
    if let Some(p) = text(&m, "phase", "")?.filter(|p| p != phase) {
        return invalid(format!("phase: the body says {p}, but this is the {phase} ruleset"));
    }
    if let Some(id) = text(&m, "id", "")?.filter(|id| *id != ruleset_id(zone_id, phase)) {
        return invalid(format!("id: {id} is not the id of this zone's {phase} ruleset"));
    }
    text(&m, "name", "")?;
    text(&m, "description", "")?;
    match m.remove("rules") {
        Some(Value::Array(rules)) => Ok(rules),
        None | Some(Value::Null) => invalid("rules is required (an empty list removes every rule of the phase)"),
        Some(_) => invalid("rules must be a list"),
    }
}

/// `PUT /zones/{zone_id}/rulesets/phases/{phase}/entrypoint`
pub async fn put_entrypoint(store: &Store, zone_id: &str, phase: &'static str, body: Value) -> Result<Value, StoreError> {
    let rules = rules_of(body, zone_id, phase)?;
    apply(store, zone_id, phase, Change::Replace { rules, only_if_empty: false }).await
}

/// `PUT /zones/{zone_id}/rulesets/{ruleset_id}`
pub async fn put_ruleset(store: &Store, zone_id: &str, ruleset_id: &str, body: Value) -> Result<Value, StoreError> {
    let phase = phase_by_id(zone_id, ruleset_id)?;
    put_entrypoint(store, zone_id, phase, body).await
}

/// `POST /zones/{zone_id}/rulesets`: what Terraform does first. The phase
/// must not have rules yet (Cloudflare refuses a second entrypoint too).
pub async fn create(store: &Store, zone_id: &str, body: Value) -> Result<Value, StoreError> {
    let phase = phase_in(&body)?;
    let rules = rules_of(body, zone_id, phase)?;
    apply(store, zone_id, phase, Change::Replace { rules, only_if_empty: true }).await
}

/// `DELETE /zones/{zone_id}/rulesets/{ruleset_id}`: the phase loses all its rules.
pub async fn delete_ruleset(store: &Store, zone_id: &str, ruleset_id: &str) -> Result<(), StoreError> {
    let phase = phase_by_id(zone_id, ruleset_id)?;
    apply(store, zone_id, phase, Change::Replace { rules: Vec::new(), only_if_empty: false }).await.map(|_| ())
}

/// `POST /zones/{zone_id}/rulesets/{ruleset_id}/rules`: one new rule, last
/// unless `position` says otherwise.
pub async fn add_rule(store: &Store, zone_id: &str, ruleset_id: &str, body: Value) -> Result<Value, StoreError> {
    let phase = phase_by_id(zone_id, ruleset_id)?;
    let (rule, position) = split_position(body)?;
    apply(store, zone_id, phase, Change::Add { rule: Value::Object(rule), position }).await
}

/// `PATCH /zones/{zone_id}/rulesets/{ruleset_id}/rules/{rule_id}`: the
/// fields the body names change, the others stay.
pub async fn update_rule(store: &Store, zone_id: &str, ruleset_id: &str, rule_id: &str, body: Value) -> Result<Value, StoreError> {
    let phase = phase_by_id(zone_id, ruleset_id)?;
    let (rule, position) = split_position(body)?;
    apply(store, zone_id, phase, Change::Update { id: rule_id.to_string(), rule, position }).await
}

/// `DELETE /zones/{zone_id}/rulesets/{ruleset_id}/rules/{rule_id}`
pub async fn delete_rule(store: &Store, zone_id: &str, ruleset_id: &str, rule_id: &str) -> Result<Value, StoreError> {
    let phase = phase_by_id(zone_id, ruleset_id)?;
    apply(store, zone_id, phase, Change::Remove(rule_id.to_string())).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn setup() -> (Arc<Store>, String) {
        let dir = std::env::temp_dir().join(format!("fucf-rulesets-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = Arc::new(Store::open(&dir.join("store.json"), vec![]).unwrap());
        let zone = store.create_zone("example.com").unwrap();
        (store, zone.id)
    }

    /// A rule as it comes back, without what the server fills in.
    fn strip(mut rule: Value) -> Value {
        let o = rule.as_object_mut().unwrap();
        for k in ["id", "ref", "version", "last_updated"] {
            o.remove(k);
        }
        rule
    }

    fn rules(rs: &Value) -> Vec<Value> {
        rs["rules"].as_array().unwrap().iter().cloned().map(strip).collect()
    }

    fn ids(rs: &Value) -> Vec<String> {
        rs["rules"].as_array().unwrap().iter().map(|r| r["id"].as_str().unwrap().to_string()).collect()
    }

    fn err(r: Result<Value, StoreError>) -> String {
        match r {
            Err(StoreError::Invalid(m)) => m,
            Err(StoreError::Conflict(m)) => format!("conflict: {m}"),
            Err(e) => format!("{e:?}"),
            Ok(v) => panic!("expected an error, got {v}"),
        }
    }

    /// One Cloudflare rule of each phase, in the form the server gives back.
    fn samples() -> Vec<(&'static str, Value)> {
        vec![
            ("http_request_firewall_custom", json!({ "action": "block", "expression": "ip.src eq 192.0.2.1", "description": "one address", "enabled": true })),
            (
                "http_request_firewall_custom",
                json!({
                    "action": "skip", "expression": "http.request.uri.path eq \"/health\"", "description": "", "enabled": true,
                    "action_parameters": { "ruleset": "current", "phases": ["http_ratelimit", "http_request_firewall_managed"], "products": ["securityLevel"] },
                    "logging": { "enabled": true },
                }),
            ),
            (
                "http_ratelimit",
                json!({
                    "action": "block", "expression": "starts_with(http.request.uri.path, \"/login\")", "description": "login", "enabled": true,
                    "ratelimit": { "characteristics": ["cf.colo.id", "ip.src"], "period": 60, "requests_per_period": 10, "mitigation_timeout": 600 },
                }),
            ),
            (
                "http_request_dynamic_redirect",
                json!({
                    "action": "redirect", "expression": "http.host eq \"www.example.com\"", "description": "", "enabled": true,
                    "action_parameters": { "from_value": { "target_url": { "value": "https://example.com/" }, "status_code": 301, "preserve_query_string": true } },
                }),
            ),
            (
                "http_request_transform",
                json!({ "action": "rewrite", "expression": "true", "description": "", "enabled": true, "action_parameters": { "uri": { "path": { "value": "/new" } } } }),
            ),
            (
                "http_request_late_transform",
                json!({
                    "action": "rewrite", "expression": "true", "description": "", "enabled": false,
                    "action_parameters": { "headers": { "x-from": { "operation": "set", "value": "edge" }, "x-drop": { "operation": "remove" } } },
                }),
            ),
            (
                "http_response_headers_transform",
                json!({
                    "action": "rewrite", "expression": "true", "description": "", "enabled": true,
                    "action_parameters": { "headers": { "x-frame-options": { "operation": "set", "value": "DENY" } } },
                }),
            ),
            (
                "http_request_cache_settings",
                json!({
                    "action": "set_cache_settings", "expression": "starts_with(http.request.uri.path, \"/static/\")", "description": "", "enabled": true,
                    "action_parameters": { "cache": true, "edge_ttl": { "mode": "override_origin", "default": 3600 } },
                }),
            ),
            (
                "http_request_origin",
                json!({
                    "action": "route", "expression": "starts_with(http.request.uri.path, \"/api/\")", "description": "", "enabled": true,
                    "action_parameters": { "host_header": "api.example.net", "origin": { "host": "198.51.100.20", "port": 8443 }, "sni": { "value": "api.example.net" } },
                }),
            ),
        ]
    }

    #[tokio::test]
    async fn every_phase_gives_back_the_rule_it_was_given() {
        let (store, z) = setup();
        for (phase, rule) in samples() {
            let rs = put_entrypoint(&store, &z, phase, json!({ "rules": [rule.clone()] })).await.unwrap();
            assert_eq!(rules(&rs), vec![rule.clone()], "{phase}");
            assert_eq!(rs["id"], json!(ruleset_id(&z, phase)));
            // and once more through a GET, by phase and by id
            assert_eq!(rules(&entrypoint(&store, &z, phase).unwrap()), vec![rule.clone()], "{phase}");
            assert_eq!(rules(&get(&store, &z, &ruleset_id(&z, phase)).unwrap()), vec![rule], "{phase}");
        }
        // the existing objects are the rules
        assert_eq!(store.items::<FirewallRule>(&z).unwrap().len(), 1, "the second firewall PUT replaced the first");
        assert_eq!(store.items::<RateLimit>(&z).unwrap()[0].threshold, 10);
        assert_eq!(store.items::<OriginRule>(&z).unwrap()[0].origin_port, Some(8443));
        // three transform phases, three objects (each made in its own phase)
        assert_eq!(store.items::<TransformRule>(&z).unwrap().len(), 3);
        let listed = list(&store, &z).unwrap();
        assert_eq!(listed.as_array().unwrap().len(), 8);
        assert!(listed[0].get("rules").is_none(), "the list has no rules");
    }

    #[tokio::test]
    async fn a_put_keeps_ids_follows_the_new_order_and_deletes_what_is_left_out() {
        let (store, z) = setup();
        let phase = "http_request_firewall_custom";
        let rule = |n: u8| json!({ "action": "block", "expression": format!("ip.src eq 192.0.2.{n}") });
        let rs = put_entrypoint(&store, &z, phase, json!({ "rules": [rule(1), rule(2), rule(3)] })).await.unwrap();
        let first = ids(&rs);
        assert_eq!(first.len(), 3);

        // 3 first, then 1, 2 left out, and a new one
        let mut r3 = rule(3);
        r3["id"] = json!(first[2]);
        let mut r1 = rule(1);
        r1["id"] = json!(first[0]);
        let rs = put_entrypoint(&store, &z, phase, json!({ "rules": [r3, r1, rule(4)] })).await.unwrap();
        let now = ids(&rs);
        assert_eq!(&now[..2], &[first[2].clone(), first[0].clone()]);
        assert!(!now.contains(&first[1]));
        assert_eq!(rs["rules"][2]["expression"], json!("ip.src eq 192.0.2.4"));
        let mut stored = store.items::<FirewallRule>(&z).unwrap();
        stored.sort_by_key(|r| r.priority);
        assert_eq!(stored.iter().map(|r| r.meta.id.clone()).collect::<Vec<_>>(), now, "the edge's order is the list's");

        // an empty list empties the phase, and the list no longer shows it
        put_entrypoint(&store, &z, phase, json!({ "rules": [] })).await.unwrap();
        assert!(store.items::<FirewallRule>(&z).unwrap().is_empty());
        assert_eq!(list(&store, &z).unwrap(), json!([]));
    }

    #[tokio::test]
    async fn an_unchanged_put_writes_nothing() {
        let (store, z) = setup();
        let phase = "http_request_dynamic_redirect";
        let (_, rule) = samples().into_iter().find(|(p, _)| *p == phase).unwrap();
        let rs = put_entrypoint(&store, &z, phase, json!({ "rules": [rule] })).await.unwrap();
        let before = store.items::<RedirectRule>(&z).unwrap()[0].meta.modified_on.clone();
        let again = put_entrypoint(&store, &z, phase, rs.clone()).await.unwrap();
        assert_eq!(again["rules"], rs["rules"]);
        assert_eq!(store.items::<RedirectRule>(&z).unwrap()[0].meta.modified_on, before);
    }

    #[tokio::test]
    async fn unknown_actions_and_fields_are_refused_by_name() {
        let (store, z) = setup();
        let put = |phase: &'static str, rule: Value| {
            let store = store.clone();
            let z = z.clone();
            async move { put_entrypoint(&store, &z, phase, json!({ "rules": [rule] })).await }
        };
        let fw = "http_request_firewall_custom";
        let m = err(put(fw, json!({ "action": "challenge", "expression": "true" })).await);
        assert!(m.starts_with("rules[0].action: 'challenge'"), "{m}");
        let m = err(put(fw, json!({ "action": "block", "expression": "true", "exposed_credential_check": {} })).await);
        assert!(m.contains("rules[0].exposed_credential_check"), "{m}");
        let m = err(put(fw, json!({ "action": "block", "expression": "true", "action_parameters": { "response": { "status_code": 403 } } })).await);
        assert!(m.contains("rules[0].action_parameters.response"), "{m}");
        let m = err(put(fw, json!({ "action": "block" })).await);
        assert!(m.contains("rules[0].expression is required"), "{m}");
        let m = err(put(fw, json!({ "action": "block", "expression": "ip.src eq" })).await);
        assert!(m.starts_with("rules[0]: invalid expression"), "{m}");
        let m = err(put(fw, json!({ "action": "block", "expression": "true", "ref": "mine" })).await);
        assert!(m.contains("rules[0].ref"), "{m}");
        let m = err(put(fw, json!({ "action": "block", "expression": "true", "enabled": "yes" })).await);
        assert!(m.contains("rules[0].enabled must be true or false"), "{m}");
        let m = err(put(fw, json!("block")).await);
        assert!(m.contains("rules[0] must be a JSON object"), "{m}");

        let rl = "http_ratelimit";
        let m = err(put(rl, json!({ "action": "managed_challenge", "expression": "true", "ratelimit": { "period": 60, "requests_per_period": 5 } })).await);
        assert!(m.contains("rules[0].action"), "{m}");
        let m = err(put(rl, json!({ "action": "block", "expression": "true" })).await);
        assert!(m.contains("rules[0].ratelimit is required"), "{m}");
        let m = err(put(rl, json!({ "action": "block", "expression": "true", "ratelimit": { "characteristics": ["cf.colo.id", "cf.unique_visitor_id"], "period": 60, "requests_per_period": 5 } })).await);
        assert!(m.contains("rules[0].ratelimit.characteristics: 'cf.unique_visitor_id'"), "{m}");
        let m = err(put(rl, json!({ "action": "block", "expression": "true", "ratelimit": { "characteristics": ["ip.src"], "period": 60, "requests_per_period": 5 } })).await);
        assert!(m.contains("must hold cf.colo.id"), "{m}");
        let m = err(put(rl, json!({ "action": "block", "expression": "true", "ratelimit": { "characteristics": "ip.src", "period": 60, "requests_per_period": 5 } })).await);
        assert!(m.contains("must be a list of strings"), "{m}");
        let m = err(put(rl, json!({ "action": "block", "expression": "true", "ratelimit": { "period": 60, "requests_per_period": 5, "counting_expression": "http.request.uri.path eq \"/x\"" } })).await);
        assert!(m.contains("rules[0].ratelimit.counting_expression"), "{m}");
        let m = err(put(rl, json!({ "action": "block", "expression": "http.host eq \"a.example.com\"", "ratelimit": { "period": 60, "requests_per_period": 5, "counting_expression": "http.response.code eq 401" } })).await);
        assert!(m.contains("counting_expression"), "a code alone would count other requests than the rule's: {m}");
        let m = err(put(rl, json!({ "action": "block", "expression": "true", "ratelimit": { "characteristics": ["cf.colo.id", "http.request.headers[\"x key\"]"], "period": 60, "requests_per_period": 5 } })).await);
        assert!(m.contains("header:x key"), "the store's own check refuses the name: {m}");
        let m = err(put(rl, json!({ "action": "block", "expression": "true", "ratelimit": { "period": 60, "requests_per_period": -1 } })).await);
        assert!(m.contains("rules[0].ratelimit.requests_per_period must be a whole number"), "{m}");
        let m = err(put(rl, json!({ "action": "block", "expression": "true", "ratelimit": { "period": 0, "requests_per_period": 5 } })).await);
        assert!(m.starts_with("rules[0]: "), "the store's own check names the rule too: {m}");

        let m = err(put("http_request_dynamic_redirect", json!({ "action": "redirect", "expression": "true", "action_parameters": { "from_list": { "name": "redirects" } } })).await);
        assert!(m.contains("rules[0].action_parameters.from_list"), "{m}");
        let m = err(put("http_request_dynamic_redirect", json!({ "action": "redirect", "expression": "true", "action_parameters": { "from_value": { "target_url": { "expression": "concat(\"https://example.com\", http.request.uri.path)" }, "status_code": 301 } } })).await);
        assert!(m.contains("rules[0].action_parameters.from_value.target_url.expression"), "{m}");
        let m = err(put("http_request_dynamic_redirect", json!({ "action": "redirect", "expression": "true", "action_parameters": { "from_value": { "target_url": { "value": "/x" } } } })).await);
        assert!(m.contains("from_value.status_code is required"), "{m}");

        let m = err(put("http_request_transform", json!({ "action": "rewrite", "expression": "true", "action_parameters": { "uri": { "query": { "value": "a=1" } } } })).await);
        assert!(m.contains("rules[0].action_parameters.uri.query"), "{m}");
        let m = err(put("http_request_transform", json!({ "action": "rewrite", "expression": "true", "action_parameters": { "headers": { "x": { "operation": "remove" } } } })).await);
        assert!(m.contains("belongs in http_request_late_transform"), "{m}");
        let m = err(put("http_request_late_transform", json!({ "action": "rewrite", "expression": "true", "action_parameters": { "headers": { "x-a": { "operation": "add", "value": "1" } } } })).await);
        assert!(m.contains("rules[0].action_parameters.headers.x-a.operation: 'add'"), "{m}");
        let m = err(put("http_request_late_transform", json!({ "action": "rewrite", "expression": "true", "action_parameters": { "headers": { "x-a": { "operation": "set", "expression": "ip.src" } } } })).await);
        assert!(m.contains("headers.x-a.expression"), "{m}");
        let m = err(put("http_request_late_transform", json!({ "action": "rewrite", "expression": "true", "action_parameters": { "headers": {} } })).await);
        assert!(m.contains("at least one header"), "{m}");
        let m = err(put("http_response_headers_transform", json!({ "action": "rewrite", "expression": "true", "action_parameters": { "headers": { "host": { "operation": "set", "value": "x" } } } })).await);
        assert!(m.contains("cannot be modified"), "{m}");

        let m = err(put("http_request_cache_settings", json!({ "action": "set_cache_settings", "expression": "true", "action_parameters": { "cache": true, "browser_ttl": { "mode": "respect_origin" } } })).await);
        assert!(m.contains("rules[0].action_parameters.browser_ttl"), "{m}");
        let m = err(put("http_request_cache_settings", json!({ "action": "set_cache_settings", "expression": "true", "action_parameters": { "cache": true, "edge_ttl": { "mode": "bypass_by_default" } } })).await);
        assert!(m.contains("edge_ttl.mode: 'bypass_by_default'"), "{m}");
        let m = err(put("http_request_cache_settings", json!({ "action": "set_cache_settings", "expression": "true", "action_parameters": { "edge_ttl": { "mode": "respect_origin" } } })).await);
        assert!(m.contains("action_parameters.cache is required"), "{m}");

        let m = err(put("http_request_origin", json!({ "action": "route", "expression": "true", "action_parameters": { "origin": { "host": "198.51.100.1", "port": 70000 } } })).await);
        assert!(m.contains("origin.port must be a whole number"), "{m}");
        let m = err(put("http_request_origin", json!({ "action": "route", "expression": "true", "action_parameters": {} })).await);
        assert!(m.contains("at least one of"), "{m}");

        // nothing was kept from any of these
        assert!(list(&store, &z).unwrap().as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_narrower_skip_is_refused_rather_than_widened() {
        let (store, z) = setup();
        let skip = |params: Value| json!({ "rules": [{ "action": "skip", "expression": "true", "action_parameters": params }] });
        let phase = "http_request_firewall_custom";
        let m = err(put_entrypoint(&store, &z, phase, skip(json!({ "ruleset": "current" }))).await);
        assert!(m.contains("always skips"), "{m}");
        let m = err(put_entrypoint(&store, &z, phase, skip(json!({ "phases": ["http_ratelimit", "http_request_firewall_managed"], "products": ["securityLevel"] }))).await);
        assert!(m.contains("always skips"), "{m}");
        let m = err(put_entrypoint(&store, &z, phase, skip(json!({ "ruleset": "other" }))).await);
        assert!(m.contains("action_parameters.ruleset"), "{m}");
        let m = err(put_entrypoint(&store, &z, phase, skip(json!({ "rules": { "x": ["y"] } }))).await);
        assert!(m.contains("action_parameters.rules"), "{m}");
        // one that says more than this server skips is fine (there is nothing more to skip)
        let wide = json!({ "ruleset": "current", "phases": ["http_ratelimit", "http_request_firewall_managed", "http_request_sbfm"], "products": ["securityLevel", "waf", "uaBlock"] });
        put_entrypoint(&store, &z, phase, skip(wide)).await.unwrap();
        let m = err(put_entrypoint(&store, &z, phase, json!({ "rules": [{ "action": "skip", "expression": "true", "logging": { "enabled": false } }] })).await);
        assert!(m.contains("rules[0].logging"), "{m}");
        let m = err(put_entrypoint(&store, &z, phase, json!({ "rules": [{ "action": "block", "expression": "true", "logging": { "enabled": true } }] })).await);
        assert!(m.contains("rules[0].logging is only for skip rules"), "{m}");
        let m = err(put_entrypoint(&store, &z, phase, json!({ "rules": [{ "action": "block", "expression": "true", "ratelimit": { "period": 60, "requests_per_period": 1 } }] })).await);
        assert!(m.contains("rules[0].ratelimit belongs in http_ratelimit"), "{m}");
    }

    #[tokio::test]
    async fn a_transform_rule_shows_in_each_of_its_phases_and_changes_one_part_at_a_time() {
        let (store, z) = setup();
        let t = store
            .save_item_async::<TransformRule>(
                &z,
                None,
                json!({ "expression": "", "rewrite_path": "/a", "set_request_headers": { "x-a": "1" }, "set_response_headers": { "x-b": "2" } }),
                true,
            )
            .await
            .unwrap();
        for phase in ["http_request_transform", "http_request_late_transform", "http_response_headers_transform"] {
            assert_eq!(ids(&entrypoint(&store, &z, phase).unwrap()), vec![t.meta.id.clone()], "{phase}");
        }
        // new request headers through the late transform phase: the path and response headers stay
        let rule = json!({ "id": t.meta.id, "action": "rewrite", "expression": "true", "action_parameters": { "headers": { "x-c": { "operation": "remove" } } } });
        put_entrypoint(&store, &z, "http_request_late_transform", json!({ "rules": [rule] })).await.unwrap();
        let now = store.item::<TransformRule>(&z, &t.meta.id).unwrap();
        assert_eq!(now.rewrite_path.as_deref(), Some("/a"));
        assert!(now.set_request_headers.is_empty());
        assert_eq!(now.remove_request_headers, vec!["x-c".to_string()]);
        assert_eq!(now.set_response_headers.get("x-b").map(String::as_str), Some("2"));

        // the expression is shared with the other phases: refused through one
        let rule = json!({ "id": t.meta.id, "action": "rewrite", "expression": "http.host eq \"example.com\"", "action_parameters": { "uri": { "path": { "value": "/a" } } } });
        let m = err(put_entrypoint(&store, &z, "http_request_transform", json!({ "rules": [rule] })).await);
        assert!(m.contains("also in http_request_late_transform and http_response_headers_transform"), "{m}");

        // taken out of one phase it keeps its other parts; out of the last one it is gone
        put_entrypoint(&store, &z, "http_request_transform", json!({ "rules": [] })).await.unwrap();
        assert_eq!(store.item::<TransformRule>(&z, &t.meta.id).unwrap().rewrite_path, None);
        delete_rule(&store, &z, &ruleset_id(&z, "http_request_late_transform"), &t.meta.id).await.unwrap();
        assert!(store.item::<TransformRule>(&z, &t.meta.id).is_ok());
        delete_ruleset(&store, &z, &ruleset_id(&z, "http_response_headers_transform")).await.unwrap();
        assert!(store.items::<TransformRule>(&z).unwrap().is_empty());
    }

    #[tokio::test]
    async fn single_rules_are_added_placed_patched_and_deleted() {
        let (store, z) = setup();
        let rs_id = ruleset_id(&z, "http_request_cache_settings");
        let rule = |ttl: u32| json!({ "action": "set_cache_settings", "expression": "true", "action_parameters": { "cache": true, "edge_ttl": { "mode": "override_origin", "default": ttl } } });
        let rs = add_rule(&store, &z, &rs_id, rule(10)).await.unwrap();
        let a = ids(&rs)[0].clone();
        let rs = add_rule(&store, &z, &rs_id, rule(20)).await.unwrap();
        let b = ids(&rs)[1].clone();
        // a third at the top, a fourth after the first
        let mut top = rule(30);
        top["position"] = json!({ "before": "" });
        let rs = add_rule(&store, &z, &rs_id, top).await.unwrap();
        let c = ids(&rs)[0].clone();
        let mut after = rule(40);
        after["position"] = json!({ "after": a });
        let rs = add_rule(&store, &z, &rs_id, after).await.unwrap();
        let d = ids(&rs)[2].clone();
        assert_eq!(ids(&rs), vec![c.clone(), a.clone(), d.clone(), b.clone()]);

        // a patch changes only what it names, and can move the rule
        let rs = update_rule(&store, &z, &rs_id, &b, json!({ "description": "last one", "position": { "index": 1 } })).await.unwrap();
        assert_eq!(ids(&rs), vec![b.clone(), c.clone(), a.clone(), d.clone()]);
        assert_eq!(rs["rules"][0]["description"], json!("last one"));
        assert_eq!(rs["rules"][0]["action_parameters"]["edge_ttl"]["default"], json!(20));
        let rs = update_rule(&store, &z, &rs_id, &b, json!({ "action_parameters": { "cache": false } })).await.unwrap();
        assert_eq!(rs["rules"][0]["action_parameters"], json!({ "cache": false }));

        let rs = delete_rule(&store, &z, &rs_id, &c).await.unwrap();
        assert_eq!(ids(&rs), vec![b.clone(), a.clone(), d.clone()]);

        // wrong ids and positions
        assert!(matches!(delete_rule(&store, &z, &rs_id, &c).await, Err(StoreError::NotFound)));
        assert!(matches!(update_rule(&store, &z, &rs_id, "nope", json!({})).await, Err(StoreError::NotFound)));
        assert!(matches!(add_rule(&store, &z, "0123456789abcdef0123456789abcdef", rule(1)).await, Err(StoreError::NotFound)));
        let other_zone = store.create_zone("example.net").unwrap().id;
        assert!(matches!(delete_rule(&store, &other_zone, &rs_id, &a).await, Err(StoreError::NotFound)), "a ruleset id is one zone's");
        let mut bad = rule(1);
        bad["position"] = json!({ "index": 9 });
        assert!(err(add_rule(&store, &z, &rs_id, bad).await).contains("position.index must be from 1 to 4"));
        let mut bad = rule(1);
        bad["position"] = json!({ "before": a, "after": d });
        assert!(err(add_rule(&store, &z, &rs_id, bad).await).contains("one of before, after or index"));
        let mut bad = rule(1);
        bad["position"] = json!({ "after": "missing" });
        assert!(err(add_rule(&store, &z, &rs_id, bad).await).contains("no rule missing"));
        let mut bad = rule(1);
        bad["id"] = json!(a);
        assert!(err(add_rule(&store, &z, &rs_id, bad).await).contains("gets its id from the server"));
        assert!(err(update_rule(&store, &z, &rs_id, &a, json!({ "id": d })).await).contains("the body names rule"));
        assert_eq!(store.items::<CacheRule>(&z).unwrap().len(), 3, "nothing changed by the refused ones");
    }

    #[tokio::test]
    async fn a_patched_action_leaves_the_old_actions_parameters_behind() {
        let (store, z) = setup();
        let phase = "http_request_firewall_custom";
        let rs = put_entrypoint(&store, &z, phase, json!({ "rules": [{ "action": "skip", "expression": "true" }] })).await.unwrap();
        assert_eq!(rs["rules"][0]["action_parameters"], skip_params());
        let id = ids(&rs)[0].clone();
        let rs = update_rule(&store, &z, &ruleset_id(&z, phase), &id, json!({ "action": "block" })).await.unwrap();
        assert_eq!(strip(rs["rules"][0].clone()), json!({ "action": "block", "expression": "true", "description": "", "enabled": true }));
        // the same action keeps them
        update_rule(&store, &z, &ruleset_id(&z, phase), &id, json!({ "action": "skip" })).await.unwrap();
        let rs = update_rule(&store, &z, &ruleset_id(&z, phase), &id, json!({ "action": "skip", "description": "health" })).await.unwrap();
        assert_eq!(rs["rules"][0]["action_parameters"], skip_params());
        assert_eq!(rs["rules"][0]["description"], json!("health"));
    }

    #[tokio::test]
    async fn rate_limits_count_by_what_cloudflare_names_and_by_the_answers_status() {
        let (store, z) = setup();
        let rl = "http_ratelimit";
        let given = json!({
            "action": "block", "expression": "http.request.uri.path eq \"/login\"", "description": "sign-ins", "enabled": true,
            "ratelimit": {
                "characteristics": ["cf.colo.id", "ip.src", "http.request.headers[\"x-api-key\"]", "http.request.cookies[\"Sid\"]"],
                "period": 60, "requests_per_period": 5, "mitigation_timeout": 600,
                "counting_expression": "http.request.uri.path eq \"/login\" and http.response.code in {401 403}",
            },
        });
        let rs = put_entrypoint(&store, &z, rl, json!({ "rules": [given.clone()] })).await.unwrap();
        assert_eq!(rules(&rs), vec![given.clone()], "given back as it was written");
        let made = &store.items::<RateLimit>(&z).unwrap()[0];
        assert_eq!((made.characteristics.clone(), made.status_codes.clone()), (vec!["ip".to_string(), "header:x-api-key".into(), "cookie:Sid".into()], vec![401, 403]));

        // every other characteristic, and an expression an `and` would change, which gets brackets
        let wide = json!({
            "action": "log", "expression": "http.host eq \"a.example.com\" or http.host eq \"b.example.com\"", "description": "", "enabled": true,
            "ratelimit": {
                "characteristics": ["cf.colo.id", "ip.src.asnum", "ip.geoip.country", "http.host", "http.request.uri.path"],
                "period": 10, "requests_per_period": 100, "mitigation_timeout": 0,
                "counting_expression": "(http.host eq \"a.example.com\" or http.host eq \"b.example.com\") and http.response.code in {429}",
            },
        });
        let rs = put_entrypoint(&store, &z, rl, json!({ "rules": [wide.clone()] })).await.unwrap();
        assert_eq!(rules(&rs), vec![wide]);
        assert_eq!(store.items::<RateLimit>(&z).unwrap()[0].characteristics, ["asn", "country", "host", "path"]);
        // without the brackets it would mean something else
        let mut bare = rules(&rs)[0].clone();
        bare["ratelimit"]["counting_expression"] = json!("http.host eq \"a.example.com\" or http.host eq \"b.example.com\" and http.response.code in {429}");
        assert!(put_entrypoint(&store, &z, rl, json!({ "rules": [bare] })).await.is_err());

        // a rule for every request may count by the code alone; eq and == are one code, and only the address is the default
        for (counting, codes) in [("http.response.code eq 401", vec![401]), ("http.response.code == 404", vec![404]), ("http.response.code in {500 502}", vec![500, 502])] {
            let rule = json!({ "action": "block", "expression": "true", "ratelimit": { "characteristics": ["ip.src", "cf.colo.id"], "period": 60, "requests_per_period": 5, "counting_expression": counting } });
            let rs = put_entrypoint(&store, &z, rl, json!({ "rules": [rule] })).await.unwrap();
            let made = &store.items::<RateLimit>(&z).unwrap()[0];
            assert!(made.characteristics.is_empty(), "the address alone is stored as the default");
            assert_eq!(made.status_codes, codes, "{counting}");
            assert_eq!(rules(&rs)[0]["ratelimit"]["characteristics"], json!(["cf.colo.id", "ip.src"]));
        }
        for counting in ["http.response.code in {}", "http.response.code in {400..499}", "http.response.code gt 400", "http.response.code eq 99999", "true and http.response.code eq 401"] {
            let rule = json!({ "action": "block", "expression": "true", "ratelimit": { "period": 60, "requests_per_period": 5, "counting_expression": counting } });
            assert!(put_entrypoint(&store, &z, rl, json!({ "rules": [rule] })).await.is_err(), "{counting}");
        }
        // an expression that only starts like the rule's is not the rule's
        let rule = json!({ "action": "block", "expression": "ip.src.asnum eq 1", "ratelimit": { "period": 60, "requests_per_period": 5, "counting_expression": "ip.src.asnum eq 13335 and http.response.code eq 401" } });
        assert!(put_entrypoint(&store, &z, rl, json!({ "rules": [rule] })).await.is_err());
        // an empty counting expression counts every matching request
        let rule = json!({ "action": "block", "expression": "true", "ratelimit": { "period": 60, "requests_per_period": 5, "counting_expression": "" } });
        put_entrypoint(&store, &z, rl, json!({ "rules": [rule] })).await.unwrap();
        assert!(store.items::<RateLimit>(&z).unwrap()[0].status_codes.is_empty());
    }

    #[tokio::test]
    async fn rate_limits_cannot_be_reordered_but_can_be_added_to() {
        let (store, z) = setup();
        let phase = "http_ratelimit";
        let rule = |n: u32| json!({ "action": "log", "expression": "true", "ratelimit": { "period": 60, "requests_per_period": n } });
        let rs = put_entrypoint(&store, &z, phase, json!({ "rules": [rule(1), rule(2)] })).await.unwrap();
        let first = ids(&rs);
        let mut a = rule(1);
        a["id"] = json!(first[0]);
        let mut b = rule(2);
        b["id"] = json!(first[1]);
        let m = err(put_entrypoint(&store, &z, phase, json!({ "rules": [b.clone(), a.clone()] })).await);
        assert!(m.contains("cannot be reordered"), "{m}");
        let rs = put_entrypoint(&store, &z, phase, json!({ "rules": [a, b, rule(3)] })).await.unwrap();
        assert_eq!(&ids(&rs)[..2], &first[..]);
        assert_eq!(rs["rules"][2]["ratelimit"]["requests_per_period"], json!(3));
        // the characteristics may be left out, the action defaults nowhere
        assert_eq!(rs["rules"][0]["ratelimit"]["characteristics"], json!(["cf.colo.id", "ip.src"]));
    }

    #[tokio::test]
    async fn the_automatic_firewall_rule_is_neither_shown_nor_replaced() {
        let (store, z) = setup();
        let auto = store
            .save_item_async::<FirewallRule>(
                &z,
                None,
                json!({ "expression": "ip.src in {192.0.2.9}", "action": "block", "priority": 1000, "managed_by": "auto_firewall", "auto_bans": { "192.0.2.9": 1 } }),
                true,
            )
            .await
            .unwrap();
        let phase = "http_request_firewall_custom";
        assert!(ids(&entrypoint(&store, &z, phase).unwrap()).is_empty());
        put_entrypoint(&store, &z, phase, json!({ "rules": [{ "action": "log", "expression": "true" }] })).await.unwrap();
        put_entrypoint(&store, &z, phase, json!({ "rules": [] })).await.unwrap();
        assert!(store.item::<FirewallRule>(&z, &auto.meta.id).is_ok());
        let m = err(put_entrypoint(&store, &z, phase, json!({ "rules": [{ "id": auto.meta.id, "action": "log", "expression": "true" }] })).await);
        assert!(m.contains("no rule"), "{m}");
        assert!(matches!(delete_rule(&store, &z, &ruleset_id(&z, phase), &auto.meta.id).await, Err(StoreError::NotFound)));
    }

    #[tokio::test]
    async fn an_origin_rule_keeps_what_cloudflare_cannot_say() {
        let (store, z) = setup();
        let o = store
            .save_item_async::<OriginRule>(&z, None, json!({ "expression": "", "origin_node": "jp", "origin_scheme": "https", "host_header": "example.net" }), true)
            .await
            .unwrap();
        let rs_id = ruleset_id(&z, "http_request_origin");
        update_rule(&store, &z, &rs_id, &o.meta.id, json!({ "action_parameters": { "sni": { "value": "example.net" } } })).await.unwrap();
        let now = store.item::<OriginRule>(&z, &o.meta.id).unwrap();
        assert_eq!(now.origin_node.as_deref(), Some("jp"));
        assert_eq!(now.origin_scheme.as_deref(), Some("https"));
        assert_eq!(now.sni.as_deref(), Some("example.net"));
        assert_eq!(now.host_header, None, "action_parameters is replaced as a whole");
    }

    #[tokio::test]
    async fn creating_a_ruleset_needs_an_empty_phase_and_a_body_that_fits() {
        let (store, z) = setup();
        let body = json!({ "name": "default", "kind": "zone", "phase": "http_request_dynamic_redirect", "rules": [
            { "action": "redirect", "expression": "true", "action_parameters": { "from_value": { "target_url": { "value": "/x" }, "status_code": 302 } } }
        ] });
        let rs = create(&store, &z, body.clone()).await.unwrap();
        assert_eq!(rs["rules"].as_array().unwrap().len(), 1);
        assert!(err(create(&store, &z, body.clone()).await).starts_with("conflict:"));

        let mut b = body.clone();
        b["kind"] = json!("root");
        assert!(err(create(&store, &z, b).await).contains("kind: 'root'"));
        let mut b = body.clone();
        b["phase"] = json!("http_request_firewall_managed");
        assert!(err(create(&store, &z, b).await).contains("unknown phase"));
        let mut b = body.clone();
        b.as_object_mut().unwrap().remove("phase");
        assert!(err(create(&store, &z, b).await).contains("phase is required"));
        let m = err(put_entrypoint(&store, &z, "http_request_origin", json!({ "phase": "http_ratelimit", "rules": [] })).await);
        assert!(m.contains("this is the http_request_origin ruleset"), "{m}");
        let m = err(put_entrypoint(&store, &z, "http_request_origin", json!({ "description": "x" })).await);
        assert!(m.contains("rules is required"), "{m}");
        let m = err(put_entrypoint(&store, &z, "http_request_origin", json!({ "rules": {} })).await);
        assert!(m.contains("rules must be a list"), "{m}");
        let m = err(put_entrypoint(&store, &z, "http_request_origin", json!({ "rules": [], "sources": [] })).await);
        assert!(m.contains("sources"), "{m}");
        let m = err(put_entrypoint(&store, &z, "http_request_origin", json!({ "id": ruleset_id(&z, "http_ratelimit"), "rules": [] })).await);
        assert!(m.contains("is not the id"), "{m}");
        let dup = json!({ "action": "route", "expression": "true", "action_parameters": { "host_header": "example.net" } });
        let rs = put_entrypoint(&store, &z, "http_request_origin", json!({ "rules": [dup] })).await.unwrap();
        let mut again = rs["rules"][0].clone();
        again["description"] = json!("twice");
        let m = err(put_entrypoint(&store, &z, "http_request_origin", json!({ "rules": [again.clone(), again] })).await);
        assert!(m.contains("rules[1].id") && m.contains("listed twice"), "{m}");
        assert!(matches!(entrypoint(&store, "missing-zone", "http_request_origin"), Err(StoreError::ZoneNotFound)));
    }

    #[test]
    fn ruleset_ids_are_stable_per_zone_and_phase_and_say_which_area_they_need() {
        let a = ruleset_id("z1", "http_request_origin");
        assert_eq!(a, ruleset_id("z1", "http_request_origin"));
        assert_ne!(a, ruleset_id("z2", "http_request_origin"));
        assert_ne!(a, ruleset_id("z1", "http_request_transform"));
        assert!(a.len() == 32 && a.bytes().all(|b| b.is_ascii_hexdigit()));
        let ids: HashSet<String> = PHASES.iter().map(|p| ruleset_id("z1", p)).collect();
        assert_eq!(ids.len(), PHASES.len());

        assert_eq!(area("z1", &[]), Area::Firewall);
        assert_eq!(area("z1", &["phases", "http_request_origin", "entrypoint"]), Area::OriginRules);
        assert_eq!(area("z1", &["phases", "http_request_late_transform", "entrypoint"]), Area::TransformRules);
        assert_eq!(area("z1", &["phases", "nonsense", "entrypoint"]), Area::Firewall);
        assert_eq!(area("z1", &[&a, "rules"]), Area::OriginRules);
        assert_eq!(area("z2", &[&a, "rules"]), Area::Firewall, "another zone's id names nothing here");
        assert_eq!(area("z1", &[&ruleset_id("z1", "http_request_cache_settings")]), Area::CacheRules);
        assert_eq!(area("z1", &[&ruleset_id("z1", "http_request_dynamic_redirect")]), Area::RedirectRules);
        assert_eq!(area("z1", &[&ruleset_id("z1", "http_ratelimit")]), Area::Firewall);
    }
}
