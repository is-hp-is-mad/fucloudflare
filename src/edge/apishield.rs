//! API Shield: a zone's inventory of API operations and the checks the edge
//! makes against it.
//!
//! An [`ApiOperation`] is a method, a host of the zone and a path template
//! (`GET api.example.com /users/{id}`), optionally with a JSON schema for its
//! request body. Operations are added one by one, in bulk, or from an
//! OpenAPI 3 document (crate::edge::openapi). Every request to a host that
//! has operations is matched against them before the security rules run:
//!
//! - **Matching** is per host and method. A `{name}` segment matches one
//!   non-empty segment, any other segment only itself; where several
//!   templates match, the one with a literal segment at the first place they
//!   differ wins (`/users/me` before `/users/{id}`). The request path is
//!   compared percent-decoded, with empty and `.` segments dropped and `..`
//!   taking the segment before it away, the way most origins read it, so an
//!   encoding cannot walk a request past its operation.
//! - **Unknown endpoints**: a request to such a host that matches no
//!   operation is a fallthrough (`cf.api_gateway.fallthrough_detected`).
//! - **Schema validation** runs only for an operation with a schema. Its
//!   request must have a JSON body (`Content-Type` `application/json` or
//!   `*/*+json`, no `Content-Encoding`) that keeps to the schema; an empty body
//!   passes unless the operation says a body is required. A body the edge did
//!   not read whole -- over the 1 MiB the security checks buffer -- cannot be
//!   checked, and counts as a violation, so that padding a body cannot carry it
//!   past the check. A violation sets `cf.api_gateway.request_violates_schema`.
//!
//! Rules see both fields; on top of them the zone settings
//! `api_shield_schema_action` and `api_shield_fallthrough_action` (`none`,
//! `log` or `block`) act by themselves, right after the custom firewall rules
//! (a `skip` rule skips them too), and log a security event with the source
//! `api_shield`. The event says which check failed and where in the body, never
//! a value from it.
//!
//! The schema language is a subset of JSON Schema ([`Schema`]): `type`
//! (`nullable` too), `properties`, `required`, `additionalProperties`,
//! `items`, `enum`, `const`, `minLength`, `maxLength`, `minItems`,
//! `maxItems`, `minimum`, `maximum`, `exclusiveMinimum`, `exclusiveMaximum`.
//! Annotations (`description`, `format`, `example` ...) are dropped. Every
//! other keyword only narrows what JSON Schema accepts, so leaving it out of
//! an imported schema never refuses a request the full schema accepts (the one
//! exception, `patternProperties` next to `additionalProperties`, drops the
//! latter too); a schema given directly through the API must not use them.
//!
//! Limits keep a hostile schema or body from costing much: 2000 operations
//! per zone, 32 segments per template, schemas nested at most 32 deep and at
//! most 64 KiB each, at most 256 values in an `enum`, and 2 MiB of schemas
//! for a zone (every schema is stored, synced and compiled again with each
//! change of the configuration).
//! A body is parsed by serde_json (nested at most 128 deep) and walked only
//! where its schema goes, so the work is bounded by the body's size.

use super::ReqBody;
use crate::expr::ReqInfo;
use crate::items::{in_zone, Item, Meta, Settings};
use crate::store::{Data, ItemOp, Store, StoreError, Zone, ZoneSnap};
use crate::sync::SyncMeta;
use hyper::header::{self, HeaderMap};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Number, Value};
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap, HashSet};

/// Operations per zone.
pub const MAX_OPERATIONS: usize = 2000;
/// Bytes of a path template.
pub const MAX_ENDPOINT: usize = 512;
/// Segments of a path template.
pub const MAX_SEGMENTS: usize = 32;
const MAX_PARAM_NAME: usize = 64;
/// How deep schemas nest: a schema at this depth has no schemas inside.
pub const MAX_DEPTH: usize = 32;
/// Bytes of one operation's schema, as stored (compact JSON).
pub const MAX_SCHEMA_BYTES: usize = 64 * 1024;
/// Bytes of all the schemas of a zone's operations together.
pub const MAX_ZONE_SCHEMA_BYTES: usize = 2 << 20;
/// Values of one `enum`.
pub const MAX_ENUM: usize = 256;
/// Schema nodes one stored schema may hold (it is compiled again each time
/// the configuration changes).
const STORED_BUDGET: usize = 50_000;
/// The methods an operation can have.
pub const METHODS: [&str; 9] = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT"];
/// What the zone settings can do with a violation or a fallthrough.
pub const ACTIONS: [&str; 3] = ["none", "log", "block"];
/// How much of a request-supplied name (a property, a content type) an
/// event's description quotes.
const QUOTE: usize = 64;

// --------------------------------------------------------------- the item ----

/// One operation of a zone's API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiOperation {
    #[serde(flatten)]
    pub meta: Meta,
    #[serde(default)]
    pub method: String,
    /// One host name of the zone (no wildcard).
    #[serde(default)]
    pub host: String,
    /// The path template, as [`normalize_endpoint`] leaves it.
    #[serde(default)]
    pub endpoint: String,
    /// The JSON schema of the request body, in the subset [`Schema`] reads;
    /// none: the body is not checked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_body_schema: Option<Value>,
    /// An empty body breaks the schema (only with a schema).
    #[serde(default)]
    pub request_body_required: bool,
    /// The size of `request_body_schema` as stored; set by `validate`, never
    /// taken from a request, and counted against the zone's schema budget.
    #[serde(default)]
    pub schema_bytes: usize,
}

impl Item for ApiOperation {
    fn vec(d: &Data) -> &Vec<Self> {
        &d.api_operations
    }
    fn vec_mut(d: &mut Data) -> &mut Vec<Self> {
        &mut d.api_operations
    }
    fn tombstones(d: &Data) -> &BTreeMap<String, SyncMeta> {
        &d.tombstones.api_operations
    }
    fn tombstones_mut(d: &mut Data) -> &mut BTreeMap<String, SyncMeta> {
        &mut d.tombstones.api_operations
    }
    fn meta(&self) -> &Meta {
        &self.meta
    }
    fn meta_mut(&mut self) -> &mut Meta {
        &mut self.meta
    }
    fn validate(&mut self, zone: &Zone, d: &Data) -> Result<(), StoreError> {
        let invalid = |m: String| Err(StoreError::Invalid(m));
        if zone.kind == "cert" {
            return invalid("a certificate-only zone is not proxied: it has no API operations".into());
        }
        let id = self.meta.id.clone();
        let others = || d.api_operations.iter().filter(|o| o.meta.zone_id == zone.id && o.meta.id != id);
        if !d.api_operations.iter().any(|o| o.meta.id == id) && others().count() >= MAX_OPERATIONS {
            return invalid(format!("a zone has at most {MAX_OPERATIONS} API operations"));
        }
        self.method = self.method.trim().to_ascii_uppercase();
        if !METHODS.contains(&self.method.as_str()) {
            return invalid(format!("method must be one of {}", METHODS.join(", ")));
        }
        let host = crate::dns::wire::normalize_name(&self.host).map_err(|e| StoreError::Invalid(format!("host: {e}")))?;
        if host.contains(['*', '_']) {
            return invalid(format!("host: '{host}' must be one host name, not a pattern"));
        }
        if !in_zone(zone, &host) {
            return invalid(format!("host '{host}' is not part of zone {}", zone.name));
        }
        // requests for a name inside a more specific zone go to that zone
        if let Some(inner) = d.zones.iter().find(|z| z.id != zone.id && z.kind != "cert" && z.name.len() > zone.name.len() && in_zone(z, &host)) {
            return invalid(format!("host '{host}' is served by zone {}, not by {}", inner.name, zone.name));
        }
        self.host = host;
        self.endpoint = normalize_endpoint(&self.endpoint).map_err(|e| StoreError::Invalid(format!("endpoint: {e}")))?;
        if let Some(o) = others().find(|o| o.method == self.method && o.host == self.host && same_shape(&o.endpoint, &self.endpoint)) {
            return Err(StoreError::Conflict(format!("operation {} already is {} {}{}", o.meta.id, o.method, o.host, o.endpoint)));
        }
        self.schema_bytes = 0;
        match &self.request_body_schema {
            Some(v) => {
                let schema = Schema::compile(v, &mut Compiler::strict()).map_err(|e| StoreError::Invalid(format!("request_body_schema: {e}")))?;
                let stored = schema.to_value();
                let size = serde_json::to_vec(&stored).map(|b| b.len()).unwrap_or(usize::MAX);
                if size > MAX_SCHEMA_BYTES {
                    return invalid(format!("request_body_schema: at most {MAX_SCHEMA_BYTES} bytes as compact JSON"));
                }
                let total = others().fold(size, |sum, o| sum.saturating_add(o.schema_bytes));
                if total > MAX_ZONE_SCHEMA_BYTES {
                    return invalid(format!("the schemas of a zone's API operations hold at most {MAX_ZONE_SCHEMA_BYTES} bytes together"));
                }
                self.request_body_schema = Some(stored);
                self.schema_bytes = size;
            }
            None if self.request_body_required => return invalid("request_body_required needs a request_body_schema".into()),
            None => {}
        }
        Ok(())
    }
    /// Cloudflare's names next to ours (`operation_id`, `last_updated`).
    fn public(&self) -> Value {
        let mut v = serde_json::to_value(self).unwrap_or(Value::Null);
        if let Some(o) = v.as_object_mut() {
            o.remove("sync");
            o.remove("schema_bytes");
            o.insert("operation_id".into(), json!(self.meta.id));
            o.insert("last_updated".into(), json!(self.meta.modified_on));
        }
        v
    }
}

/// Whether a template segment names a parameter: `{name}`, with the name
/// made of letters, digits, `_`, `.` and `-`.
fn param(seg: &str) -> Option<&str> {
    let name = seg.strip_prefix('{')?.strip_suffix('}')?;
    let ok = (1..=MAX_PARAM_NAME).contains(&name.len()) && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'));
    ok.then_some(name)
}

/// A path template as stored: starts with `/`, no empty segment (so no
/// trailing `/` but the root), no `.` or `..`, no `%`, `?`, `#`, space or
/// control character, and braces only around a whole segment.
pub fn normalize_endpoint(raw: &str) -> Result<String, String> {
    let raw = raw.trim();
    if !raw.starts_with('/') || raw.len() > MAX_ENDPOINT {
        return Err(format!("a path template starts with / and has at most {MAX_ENDPOINT} bytes"));
    }
    let mut segs = Vec::new();
    for seg in raw.split('/').filter(|s| !s.is_empty()) {
        if seg == "." || seg == ".." {
            return Err("no . or .. segments".into());
        }
        if seg.contains(['{', '}']) {
            if param(seg).is_none() {
                return Err(format!(
                    "'{seg}': a parameter is a whole segment like {{id}}, its name at most {MAX_PARAM_NAME} letters, digits, _ . or -"
                ));
            }
        } else if seg.chars().any(|c| c.is_control() || c.is_whitespace() || matches!(c, '%' | '?' | '#')) {
            return Err(format!("'{seg}': write the path decoded, without % escapes, spaces, ? or #"));
        }
        segs.push(seg);
    }
    if segs.len() > MAX_SEGMENTS {
        return Err(format!("at most {MAX_SEGMENTS} segments"));
    }
    Ok(format!("/{}", segs.join("/")))
}

/// Two stored templates match the same paths: their parameters may be named
/// differently.
pub fn same_shape(a: &str, b: &str) -> bool {
    let (mut x, mut y) = (a.split('/'), b.split('/'));
    loop {
        match (x.next(), y.next()) {
            (None, None) => return true,
            (Some(p), Some(q)) if p == q || (param(p).is_some() && param(q).is_some()) => {}
            _ => return false,
        }
    }
}

/// What tells operations apart: the method, the host and the template with
/// its parameters unnamed.
pub fn key(method: &str, host: &str, endpoint: &str) -> (String, String, String) {
    let shape: Vec<&str> = endpoint.split('/').map(|s| if param(s).is_some() { "{}" } else { s }).collect();
    (method.to_string(), host.to_string(), shape.join("/"))
}

// --------------------------------------------------------- the schemas ----

const OBJECT: u8 = 1;
const ARRAY: u8 = 2;
const STRING: u8 = 4;
const NUMBER: u8 = 8;
const INTEGER: u8 = 16;
const BOOLEAN: u8 = 32;
const NULL: u8 = 64;
const TYPES: [(&str, u8); 7] =
    [("object", OBJECT), ("array", ARRAY), ("string", STRING), ("number", NUMBER), ("integer", INTEGER), ("boolean", BOOLEAN), ("null", NULL)];

/// Keywords that only describe: dropped without a word.
const ANNOTATIONS: [&str; 17] = [
    "title", "description", "default", "example", "examples", "deprecated", "readOnly", "writeOnly", "xml", "externalDocs", "$comment",
    "$schema", "$id", "$anchor", "format", "contentMediaType", "discriminator",
];

/// What `additionalProperties` allows.
#[derive(Debug, Clone, Default, PartialEq)]
enum Additional {
    #[default]
    Any,
    Forbidden,
    Schema(Box<Schema>),
}

/// A schema in the subset of JSON Schema that fucf checks. Like JSON
/// Schema, each keyword only applies to values of its kind (`minLength` to
/// strings, `required` to objects ...); an empty schema accepts anything.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Schema {
    /// The allowed types as a bit set; 0: any type. `NUMBER` takes integers too.
    types: u8,
    properties: BTreeMap<String, Schema>,
    required: Vec<String>,
    additional: Additional,
    items: Option<Box<Schema>>,
    enumeration: Option<Vec<Value>>,
    min_length: Option<u64>,
    max_length: Option<u64>,
    min_items: Option<u64>,
    max_items: Option<u64>,
    minimum: Option<Number>,
    maximum: Option<Number>,
    exclusive_minimum: Option<Number>,
    exclusive_maximum: Option<Number>,
}

/// How a schema is read: a stored one strictly (anything outside the subset
/// is an error), an imported one leniently (what is left out is noted, and
/// `$ref`s are followed into the document).
pub struct Compiler<'a> {
    /// The document `$ref`s point into.
    doc: Option<&'a Value>,
    /// Where an import notes what it left out; none: leaving out is an error.
    notes: Option<&'a mut Vec<String>>,
    /// Schema nodes still to read: bounds the work a document can ask for
    /// (`$ref`s can make a small document stand for a huge schema).
    budget: usize,
}

impl<'a> Compiler<'a> {
    /// For a schema as stored (or given through the API).
    pub fn strict() -> Compiler<'static> {
        Compiler { doc: None, notes: None, budget: STORED_BUDGET }
    }

    /// For the schemas of an OpenAPI document: at most `budget` nodes for all
    /// of them together.
    pub fn import(doc: &'a Value, notes: &'a mut Vec<String>, budget: usize) -> Compiler<'a> {
        Compiler { doc: Some(doc), notes: Some(notes), budget }
    }

    /// The nodes an import may still read.
    pub fn remaining(&self) -> usize {
        self.budget
    }

    /// Something left out: noted for an import, an error otherwise.
    fn skip(&mut self, what: String) -> Result<(), String> {
        match &mut self.notes {
            Some(notes) => {
                notes.push(what);
                Ok(())
            }
            None => Err(what),
        }
    }
}

fn count(v: &Value, what: &str, at: &str) -> Result<u64, String> {
    v.as_u64().ok_or_else(|| format!("{at}: {what} is a whole number of at least 0"))
}

fn number(v: &Value, what: &str, at: &str) -> Result<Number, String> {
    match v {
        Value::Number(n) if n.as_f64().is_some_and(f64::is_finite) => Ok(n.clone()),
        _ => Err(format!("{at}: {what} is a number")),
    }
}

impl Schema {
    /// Read a schema. `$ref`s and nesting deeper than [`MAX_DEPTH`] are
    /// errors for a strict compiler; an import follows the first and cuts
    /// the second (the cut part accepts anything).
    pub fn compile(v: &Value, c: &mut Compiler) -> Result<Schema, String> {
        Schema::read(v, c, 0, 0, "$")
    }

    fn read(v: &Value, c: &mut Compiler, depth: usize, hops: usize, at: &str) -> Result<Schema, String> {
        if c.budget == 0 {
            return Err("the schema is too large to check".into());
        }
        c.budget -= 1;
        let o = match v {
            Value::Object(o) => o,
            Value::Bool(true) => return Ok(Schema::default()),
            Value::Bool(false) if c.notes.is_some() => {
                c.skip(format!("{at}: a false schema (nothing allowed) is not checked"))?;
                return Ok(Schema::default());
            }
            _ => return Err(format!("{at}: a schema is a JSON object")),
        };
        if let Some(r) = o.get("$ref") {
            let target = match (c.doc, r.as_str()) {
                (Some(doc), Some(r)) if r.starts_with('#') && hops < MAX_DEPTH => {
                    let pointer = percent_encoding::percent_decode_str(&r[1..]).decode_utf8_lossy().into_owned();
                    doc.pointer(&pointer)
                }
                _ => None,
            };
            return match target {
                Some(t) => Schema::read(t, c, depth, hops + 1, at),
                None => {
                    let what = if hops >= MAX_DEPTH { "a $ref chain this long (a cycle?)" } else { "a $ref fucf cannot follow" };
                    c.skip(format!("{at}: {what} is not checked"))?;
                    Ok(Schema::default())
                }
            };
        }
        if depth >= MAX_DEPTH && o.keys().any(|k| matches!(k.as_str(), "properties" | "items" | "additionalProperties")) {
            if c.notes.is_none() {
                return Err(format!("{at}: schemas nest at most {MAX_DEPTH} deep"));
            }
            c.skip(format!("{at}: nested deeper than {MAX_DEPTH} levels: not checked from here"))?;
            return Ok(Schema::default());
        }
        let mut s = Schema::default();
        let (mut nullable, mut exclusive_min_flag, mut exclusive_max_flag, mut pattern_properties) = (false, false, false, false);
        let child = |k: &str| if k.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '_') { format!("{at}.{k}") } else { format!("{at}[{}]", quote(k)) };
        for (k, val) in o {
            match k.as_str() {
                "type" => {
                    let names: Vec<&Value> = match val {
                        Value::Array(a) if !a.is_empty() => a.iter().collect(),
                        Value::String(_) => vec![val],
                        _ => return Err(format!("{at}: type is a type name or a list of them")),
                    };
                    for n in names {
                        let bit = TYPES.iter().find(|(t, _)| Some(*t) == n.as_str()).map(|(_, b)| *b);
                        s.types |= bit.ok_or_else(|| format!("{at}: type is one of object, array, string, number, integer, boolean, null"))?;
                    }
                }
                "nullable" => nullable = val.as_bool().ok_or_else(|| format!("{at}: nullable is true or false"))?,
                "properties" => {
                    let props = val.as_object().ok_or_else(|| format!("{at}: properties is an object of schemas"))?;
                    for (name, p) in props {
                        let schema = Schema::read(p, c, depth + 1, 0, &format!("{}.properties{}", at, &child(name)[at.len()..]))?;
                        s.properties.insert(name.clone(), schema);
                    }
                }
                "required" => {
                    let names = val.as_array().ok_or_else(|| format!("{at}: required is a list of property names"))?;
                    for n in names {
                        let n = n.as_str().ok_or_else(|| format!("{at}: required is a list of property names"))?;
                        if !s.required.iter().any(|r| r == n) {
                            s.required.push(n.to_string());
                        }
                    }
                }
                "additionalProperties" => {
                    s.additional = match val {
                        Value::Bool(true) => Additional::Any,
                        Value::Bool(false) => Additional::Forbidden,
                        _ => Additional::Schema(Box::new(Schema::read(val, c, depth + 1, 0, &format!("{at}.additionalProperties"))?)),
                    }
                }
                "items" => match val {
                    Value::Array(_) => c.skip(format!("{at}: items as a list (tuples) is not checked"))?,
                    _ => s.items = Some(Box::new(Schema::read(val, c, depth + 1, 0, &format!("{at}.items"))?)),
                },
                "enum" => match val {
                    Value::Array(a) if (1..=MAX_ENUM).contains(&a.len()) => s.enumeration = Some(a.clone()),
                    _ => return Err(format!("{at}: enum is a list of 1 to {MAX_ENUM} values")),
                },
                "const" => s.enumeration = Some(vec![val.clone()]),
                "minLength" => s.min_length = Some(count(val, k, at)?),
                "maxLength" => s.max_length = Some(count(val, k, at)?),
                "minItems" => s.min_items = Some(count(val, k, at)?),
                "maxItems" => s.max_items = Some(count(val, k, at)?),
                "minimum" => s.minimum = Some(number(val, k, at)?),
                "maximum" => s.maximum = Some(number(val, k, at)?),
                // a number (JSON Schema, OpenAPI 3.1) or a flag on minimum / maximum (OpenAPI 3.0)
                "exclusiveMinimum" => match val {
                    Value::Bool(b) => exclusive_min_flag = *b,
                    _ => s.exclusive_minimum = Some(number(val, k, at)?),
                },
                "exclusiveMaximum" => match val {
                    Value::Bool(b) => exclusive_max_flag = *b,
                    _ => s.exclusive_maximum = Some(number(val, k, at)?),
                },
                _ if ANNOTATIONS.contains(&k.as_str()) || k.starts_with("x-") => {}
                "patternProperties" => {
                    pattern_properties = true;
                    c.skip(format!("{at}: patternProperties is not checked"))?;
                }
                _ => c.skip(format!(
                    "{at}: {} is not supported (fucf checks type, properties, required, additionalProperties, items, enum, const, minLength, maxLength, minItems, maxItems, minimum, maximum, exclusiveMinimum, exclusiveMaximum)",
                    quote(k)
                ))?,
            }
        }
        if exclusive_min_flag {
            s.exclusive_minimum = s.minimum.take().or(s.exclusive_minimum);
        }
        if exclusive_max_flag {
            s.exclusive_maximum = s.maximum.take().or(s.exclusive_maximum);
        }
        if nullable && s.types != 0 {
            s.types |= NULL;
        }
        // properties matched by a pattern are not "additional": without the
        // patterns, additionalProperties would refuse them
        if pattern_properties && s.additional != Additional::Any {
            s.additional = Additional::Any;
            c.skip(format!("{at}: additionalProperties is not checked next to patternProperties"))?;
        }
        Ok(s)
    }

    /// The schema as stored: only the keywords of the subset.
    pub fn to_value(&self) -> Value {
        let mut o = Map::new();
        if self.types != 0 {
            let names: Vec<Value> = TYPES.iter().filter(|(_, b)| self.types & b != 0).map(|(t, _)| json!(t)).collect();
            o.insert("type".into(), if names.len() == 1 { names[0].clone() } else { Value::Array(names) });
        }
        if !self.properties.is_empty() {
            o.insert("properties".into(), Value::Object(self.properties.iter().map(|(k, s)| (k.clone(), s.to_value())).collect()));
        }
        if !self.required.is_empty() {
            o.insert("required".into(), json!(self.required));
        }
        match &self.additional {
            Additional::Any => {}
            Additional::Forbidden => {
                o.insert("additionalProperties".into(), json!(false));
            }
            Additional::Schema(s) => {
                o.insert("additionalProperties".into(), s.to_value());
            }
        }
        if let Some(items) = &self.items {
            o.insert("items".into(), items.to_value());
        }
        if let Some(e) = &self.enumeration {
            o.insert("enum".into(), Value::Array(e.clone()));
        }
        let counts = [("minLength", self.min_length), ("maxLength", self.max_length), ("minItems", self.min_items), ("maxItems", self.max_items)];
        for (k, v) in counts {
            if let Some(v) = v {
                o.insert(k.into(), json!(v));
            }
        }
        let bounds = [
            ("minimum", &self.minimum),
            ("maximum", &self.maximum),
            ("exclusiveMinimum", &self.exclusive_minimum),
            ("exclusiveMaximum", &self.exclusive_maximum),
        ];
        for (k, v) in bounds {
            if let Some(v) = v {
                o.insert(k.into(), Value::Number(v.clone()));
            }
        }
        Value::Object(o)
    }

    /// Whether `v` keeps to the schema; the error says where it does not
    /// (`$.items[2].name: expected string`), without quoting a value.
    pub fn check(&self, v: &Value) -> Result<(), String> {
        self.check_at(v).map_err(|(mut path, msg)| {
            path.reverse();
            format!("${}: {msg}", path.concat())
        })
    }

    /// The error's path comes in reverse order, one segment per level.
    fn check_at(&self, v: &Value) -> Result<(), (Vec<String>, String)> {
        let fail = |msg: String| Err((Vec::new(), msg));
        let bits = type_bits(v);
        if self.types != 0 && self.types & bits == 0 && !(self.types & NUMBER != 0 && bits & INTEGER != 0) {
            let names: Vec<&str> = TYPES.iter().filter(|(_, b)| self.types & b != 0).map(|(t, _)| *t).collect();
            return fail(format!("expected {}", names.join(" or ")));
        }
        if let Some(e) = &self.enumeration {
            if !e.iter().any(|x| json_eq(x, v)) {
                return fail("is not one of the allowed values".into());
            }
        }
        match v {
            Value::String(s) => {
                let n = s.chars().count() as u64;
                if self.min_length.is_some_and(|m| n < m) {
                    return fail(format!("expected at least {} characters", self.min_length.unwrap_or(0)));
                }
                if self.max_length.is_some_and(|m| n > m) {
                    return fail(format!("expected at most {} characters", self.max_length.unwrap_or(0)));
                }
            }
            Value::Number(n) => {
                let below = |b: &Option<Number>, bad: &[Ordering]| b.as_ref().is_some_and(|b| num_cmp(n, b).is_none_or(|o| bad.contains(&o)));
                if below(&self.minimum, &[Ordering::Less]) {
                    return fail(format!("expected at least {}", self.minimum.as_ref().map(Number::to_string).unwrap_or_default()));
                }
                if below(&self.maximum, &[Ordering::Greater]) {
                    return fail(format!("expected at most {}", self.maximum.as_ref().map(Number::to_string).unwrap_or_default()));
                }
                if below(&self.exclusive_minimum, &[Ordering::Less, Ordering::Equal]) {
                    return fail(format!("expected more than {}", self.exclusive_minimum.as_ref().map(Number::to_string).unwrap_or_default()));
                }
                if below(&self.exclusive_maximum, &[Ordering::Greater, Ordering::Equal]) {
                    return fail(format!("expected less than {}", self.exclusive_maximum.as_ref().map(Number::to_string).unwrap_or_default()));
                }
            }
            Value::Array(a) => {
                let n = a.len() as u64;
                if self.min_items.is_some_and(|m| n < m) {
                    return fail(format!("expected at least {} items", self.min_items.unwrap_or(0)));
                }
                if self.max_items.is_some_and(|m| n > m) {
                    return fail(format!("expected at most {} items", self.max_items.unwrap_or(0)));
                }
                if let Some(items) = &self.items {
                    for (i, x) in a.iter().enumerate() {
                        items.check_at(x).map_err(|(mut path, msg)| {
                            path.push(format!("[{i}]"));
                            (path, msg)
                        })?;
                    }
                }
            }
            Value::Object(o) => {
                if let Some(missing) = self.required.iter().find(|r| !o.contains_key(r.as_str())) {
                    return Err((vec![segment(missing)], "is required".into()));
                }
                for (k, x) in o {
                    let schema = match (self.properties.get(k), &self.additional) {
                        (Some(s), _) => s,
                        (None, Additional::Any) => continue,
                        (None, Additional::Forbidden) => return Err((vec![segment(k)], "is not allowed".into())),
                        (None, Additional::Schema(s)) => s,
                    };
                    schema.check_at(x).map_err(|(mut path, msg)| {
                        path.push(segment(k));
                        (path, msg)
                    })?;
                }
            }
            Value::Null | Value::Bool(_) => {}
        }
        Ok(())
    }
}

/// The type bits of a value: an integral number is an integer too.
fn type_bits(v: &Value) -> u8 {
    match v {
        Value::Null => NULL,
        Value::Bool(_) => BOOLEAN,
        Value::Number(n) if n.is_i64() || n.is_u64() || n.as_f64().is_some_and(|f| f.fract() == 0.0) => NUMBER | INTEGER,
        Value::Number(_) => NUMBER,
        Value::String(_) => STRING,
        Value::Array(_) => ARRAY,
        Value::Object(_) => OBJECT,
    }
}

/// Numbers compared exactly where both are integers, as floats otherwise.
fn num_cmp(a: &Number, b: &Number) -> Option<Ordering> {
    match (a.as_i64(), b.as_i64(), a.as_u64(), b.as_u64()) {
        (Some(x), Some(y), _, _) => Some(x.cmp(&y)),
        (_, _, Some(x), Some(y)) => Some(x.cmp(&y)),
        // one is above i64::MAX, the other below 0
        (_, Some(_), Some(_), None) => Some(Ordering::Greater),
        (Some(_), _, None, Some(_)) => Some(Ordering::Less),
        _ => a.as_f64()?.partial_cmp(&b.as_f64()?),
    }
}

/// JSON equality as JSON Schema has it: `1` and `1.0` are the same number.
fn json_eq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => num_cmp(x, y) == Some(Ordering::Equal),
        (Value::Array(x), Value::Array(y)) => x.len() == y.len() && x.iter().zip(y).all(|(p, q)| json_eq(p, q)),
        (Value::Object(x), Value::Object(y)) => x.len() == y.len() && x.iter().all(|(k, p)| y.get(k).is_some_and(|q| json_eq(p, q))),
        _ => a == b,
    }
}

/// A name from a request or a document as an event or a note shows it:
/// clipped, as a JSON string.
fn quote(name: &str) -> String {
    let clipped: String = name.chars().take(QUOTE).collect();
    serde_json::to_string(&clipped).unwrap_or_default()
}

/// One step of a violation's path: `.name`, or `["odd name"]`.
fn segment(name: &str) -> String {
    let plain = !name.is_empty() && name.len() <= QUOTE && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
    if plain { format!(".{name}") } else { format!("[{}]", quote(name)) }
}

// ------------------------------------------------------------ matching ----

/// One level of the templates of a host and method.
#[derive(Default)]
struct Node {
    literal: HashMap<String, Node>,
    param: Option<Box<Node>>,
    /// The operation whose template ends here (index into `Inventory::ops`).
    op: Option<usize>,
}

impl Node {
    fn insert(&mut self, segs: &[&str], op: usize) {
        match segs.split_first() {
            None => {
                self.op.get_or_insert(op);
            }
            Some((first, rest)) => {
                let next = match param(first) {
                    Some(_) => self.param.get_or_insert_with(Default::default),
                    None => self.literal.entry(first.to_string()).or_default(),
                };
                next.insert(rest, op);
            }
        }
    }

    /// The operation of a path, literal segments first. Every node is looked
    /// at once at most (its depth fixes the segment it is compared with), so
    /// the work is bounded by the size of the tree.
    fn find(&self, segs: &[String]) -> Option<usize> {
        let Some((first, rest)) = segs.split_first() else { return self.op };
        if let Some(i) = self.literal.get(first.as_str()).and_then(|n| n.find(rest)) {
            return Some(i);
        }
        self.param.as_ref().and_then(|n| n.find(rest))
    }
}

struct Compiled {
    id: String,
    schema: Option<Schema>,
    required: bool,
}

/// A zone's operations, ready for requests (part of its `ZoneSnap`).
#[derive(Default)]
pub struct Inventory {
    /// Host, then method.
    hosts: HashMap<String, HashMap<String, Node>>,
    ops: Vec<Compiled>,
}

impl Inventory {
    fn add(&mut self, op: &ApiOperation) {
        let Ok(endpoint) = normalize_endpoint(&op.endpoint) else { return };
        // validated when it was saved; one that a newer node wrote and this
        // one cannot read is matched, but its body is not checked
        let schema = op.request_body_schema.as_ref().and_then(|v| Schema::compile(v, &mut Compiler::strict()).ok());
        let segs: Vec<&str> = endpoint.split('/').filter(|s| !s.is_empty()).collect();
        let index = self.ops.len();
        self.ops.push(Compiled { id: op.meta.id.clone(), required: op.request_body_required && schema.is_some(), schema });
        self.hosts.entry(op.host.clone()).or_default().entry(op.method.clone()).or_default().insert(&segs, index);
    }

    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }
}

/// Give each zone of the snapshot its inventory. Operations go in by id, so
/// every node settles a clash (two that only a race between nodes can make)
/// the same way.
pub fn attach(ops: &[ApiOperation], zones: &mut HashMap<&str, ZoneSnap>) {
    let mut sorted: Vec<&ApiOperation> = ops.iter().collect();
    sorted.sort_by(|a, b| a.meta.id.cmp(&b.meta.id));
    for op in sorted {
        if let Some(zs) = zones.get_mut(op.meta.zone_id.as_str()) {
            zs.api_shield.add(op);
        }
    }
}

/// A request path as matched: percent-decoded, empty and `.` segments
/// dropped, `..` taking away the segment before it.
fn request_segments(path: &str) -> Vec<String> {
    let decoded = percent_encoding::percent_decode_str(path).decode_utf8_lossy();
    let mut out: Vec<String> = Vec::new();
    for seg in decoded.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            s => out.push(s.to_string()),
        }
    }
    out
}

// ------------------------------------------------------- the checks ----

/// What API Shield found about a request (`ReqInfo::api_gateway`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Outcome {
    /// `cf.api_gateway.request_violates_schema`.
    pub violates_schema: bool,
    /// `cf.api_gateway.fallthrough_detected`: the host has operations, none
    /// of them this one.
    pub fallthrough: bool,
    /// The id of the operation the request matched.
    pub operation: String,
    /// Why the body broke the schema.
    pub reason: String,
}

/// What the edge has of a request body when the security checks run.
pub enum Body<'a> {
    /// All of it (possibly nothing).
    Whole(&'a [u8]),
    /// Not read, or not all of it: over the buffer of the security checks,
    /// or streamed.
    Unread,
}

impl<'a> Body<'a> {
    /// The body as `Edge::process` holds it before the security rules.
    pub(super) fn of(body: &'a ReqBody, headers: &HeaderMap, declared: Option<u64>, method: &str) -> Body<'a> {
        match body {
            ReqBody::Buffered(b) => Body::Whole(b),
            // a request of a method without a body, which announces none, has none
            ReqBody::Stream(_)
                if declared.is_none_or(|n| n == 0)
                    && !headers.contains_key(header::TRANSFER_ENCODING)
                    && !matches!(method, "POST" | "PUT" | "PATCH") =>
            {
                Body::Whole(&[])
            }
            ReqBody::Stream(_) => Body::Unread,
        }
    }
}

/// Match a request against the zone's operations and check its body.
pub fn assess(zone: &ZoneSnap, info: &ReqInfo, headers: &HeaderMap, body: Body) -> Outcome {
    let Some(methods) = zone.api_shield.hosts.get(&info.host) else { return Outcome::default() };
    let segs = request_segments(&info.path);
    let Some(index) = methods.get(info.method.as_str()).and_then(|n| n.find(&segs)) else {
        return Outcome { fallthrough: true, ..Default::default() };
    };
    let op = &zone.api_shield.ops[index];
    let mut out = Outcome { operation: op.id.clone(), ..Default::default() };
    if let Some(schema) = &op.schema {
        if let Err(reason) = check_body(schema, op.required, headers, body) {
            (out.violates_schema, out.reason) = (true, reason);
        }
    }
    out
}

/// Whether a media type is JSON: `application/json`, `*/*+json`.
pub fn is_json(content_type: &str) -> bool {
    let media = content_type.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    media.split_once('/').is_some_and(|(top, sub)| !top.is_empty() && (sub == "json" || sub.ends_with("+json")))
}

fn check_body(schema: &Schema, required: bool, headers: &HeaderMap, body: Body) -> Result<(), String> {
    let bytes = match body {
        Body::Whole(b) => b,
        Body::Unread => return Err(format!("the request body was not read whole (over {} bytes, or streamed), so it cannot be checked", super::INSPECT_LIMIT)),
    };
    if bytes.is_empty() {
        return if required { Err("the request body is missing".into()) } else { Ok(()) };
    }
    let text = |name: header::HeaderName| headers.get(name).map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned());
    if let Some(encoding) = text(header::CONTENT_ENCODING).filter(|e| !e.trim().eq_ignore_ascii_case("identity")) {
        return Err(format!("an encoded body (Content-Encoding {}) cannot be checked", quote(&encoding)));
    }
    let content_type = text(header::CONTENT_TYPE).unwrap_or_default();
    if !is_json(&content_type) {
        return Err(format!("the body is not JSON (Content-Type {})", quote(&content_type)));
    }
    let value: Value = serde_json::from_slice(bytes).map_err(|e| format!("the body is not valid JSON ({})", e.classify_name()))?;
    schema.check(&value)
}

/// The words for what serde_json found wrong, without the place.
trait Classify {
    fn classify_name(&self) -> &'static str;
}

impl Classify for serde_json::Error {
    fn classify_name(&self) -> &'static str {
        match self.classify() {
            serde_json::error::Category::Io => "unreadable",
            serde_json::error::Category::Syntax => "a syntax error",
            serde_json::error::Category::Data => "unexpected data",
            serde_json::error::Category::Eof => "it ends too early",
        }
    }
}

/// Paths the edge answers for itself (or for certificates), never a fallthrough.
fn exempt(path: &str) -> bool {
    path.starts_with("/.well-known/acme-challenge/") || path.starts_with("/cdn-cgi/")
}

/// What the zone's settings make of a request's outcome: the rule id and
/// the description of the security event, and `log` or `block`.
pub fn mitigation(settings: &Settings, info: &ReqInfo) -> Option<(&'static str, String, &'static str)> {
    let act = |setting: &str| match setting {
        "log" => Some("log"),
        "block" => Some("block"),
        _ => None,
    };
    let out = &info.api_gateway;
    if out.violates_schema {
        if let Some(action) = act(&settings.api_shield_schema_action) {
            return Some(("schema_validation", format!("Operation {}: {}", out.operation, out.reason), action));
        }
    }
    if out.fallthrough && !exempt(&info.path) {
        if let Some(action) = act(&settings.api_shield_fallthrough_action) {
            return Some(("fallthrough", format!("No API operation of {} matches {}", info.host, info.method), action));
        }
    }
    None
}

// ---------------------------------------------------------- the API ----

/// What a request body names as operations: a list, or one object.
fn entries(body: Value) -> Result<(Vec<Value>, bool), StoreError> {
    match body {
        Value::Array(a) if (1..=MAX_OPERATIONS).contains(&a.len()) => Ok((a, true)),
        Value::Array(_) => Err(StoreError::Invalid(format!("a list of 1 to {MAX_OPERATIONS} operations"))),
        Value::Object(_) => Ok((vec![body], false)),
        _ => Err(StoreError::Invalid("the body is an operation or a list of them".into())),
    }
}

/// The key an entry will have once saved, as far as can be told before
/// `validate` (which still has the last word).
fn entry_key(e: &Value) -> Option<(String, String, String)> {
    let text = |k: &str| e.get(k).and_then(Value::as_str);
    let method = text("method")?.trim().to_ascii_uppercase();
    let host = crate::dns::wire::normalize_name(text("host")?).ok()?;
    let endpoint = normalize_endpoint(text("endpoint")?).ok()?;
    Some(key(&method, &host, &endpoint))
}

/// `POST .../operations`: add operations (a list, or one). One that is
/// there already is answered as it is, not added twice; all or none are added.
pub async fn create(store: &Store, zone_id: &str, body: Value) -> Result<Value, StoreError> {
    let (list, many) = entries(body)?;
    let wanted: Vec<Option<(String, String, String)>> = list.iter().map(entry_key).collect();
    let plan_wanted = wanted.clone();
    store
        .batch_items_async::<ApiOperation, _>(zone_id, move |current| {
            let mut seen: HashSet<(String, String, String)> = current.iter().map(|o| key(&o.method, &o.host, &o.endpoint)).collect();
            let mut ops = Vec::new();
            for (i, (entry, k)) in list.into_iter().zip(plan_wanted).enumerate() {
                if k.as_ref().is_some_and(|k| !seen.insert(k.clone())) {
                    continue;
                }
                ops.push(ItemOp::Save { id: None, body: entry, replace: true, at: format!("operations[{i}]") });
            }
            Ok(ops)
        })
        .await?;
    let now: HashMap<(String, String, String), ApiOperation> =
        store.items::<ApiOperation>(zone_id)?.into_iter().map(|o| (key(&o.method, &o.host, &o.endpoint), o)).collect();
    let answered: Vec<Value> = wanted.iter().filter_map(|k| now.get(k.as_ref()?)).map(Item::public).collect();
    Ok(if many { Value::Array(answered) } else { answered.into_iter().next().unwrap_or(Value::Null) })
}

/// `DELETE .../operations`: delete several (`[{"operation_id": ...}]`, or
/// the ids as strings); all or none.
pub async fn delete_many(store: &Store, zone_id: &str, body: Value) -> Result<Value, StoreError> {
    let (list, _) = entries(body)?;
    let mut ids = Vec::new();
    for e in &list {
        let id = e.as_str().or_else(|| e.get("operation_id").and_then(Value::as_str));
        ids.push(id.ok_or_else(|| StoreError::Invalid("name each operation by its operation_id".into()))?.to_string());
    }
    let count = ids.len();
    store.batch_items_async::<ApiOperation, _>(zone_id, move |_| Ok(ids.into_iter().map(ItemOp::Delete).collect())).await?;
    Ok(json!({ "deleted": count }))
}

const SCHEMA_SETTING: &str = "api_shield_schema_action";
const FALLTHROUGH_SETTING: &str = "api_shield_fallthrough_action";

/// `GET .../settings/schema_validation`: the zone settings under Cloudflare's
/// name for the first (`validation_default_mitigation_action`) and ours for
/// the second.
pub fn settings_view(zone: &Zone) -> Value {
    json!({
        "validation_default_mitigation_action": zone.settings.api_shield_schema_action,
        "fallthrough_mitigation_action": zone.settings.api_shield_fallthrough_action,
    })
}

/// `PUT` / `PATCH .../settings/schema_validation`: change either action.
/// Both are checked before either is written.
pub async fn update_settings(store: &Store, zone_id: &str, body: Value) -> Result<Value, StoreError> {
    let Value::Object(o) = body else { return Err(StoreError::Invalid("the body is a JSON object".into())) };
    let mut changes = Vec::new();
    for (k, v) in o {
        let setting = match k.as_str() {
            "validation_default_mitigation_action" => SCHEMA_SETTING,
            "fallthrough_mitigation_action" => FALLTHROUGH_SETTING,
            _ => return Err(StoreError::Invalid(format!("unknown field {}: only validation_default_mitigation_action and fallthrough_mitigation_action", quote(&k)))),
        };
        if !v.as_str().is_some_and(|a| ACTIONS.contains(&a)) {
            return Err(StoreError::Invalid(format!("{k} is one of none, log, block")));
        }
        changes.push((setting, v));
    }
    let mut zone = store.get_zone(zone_id)?;
    for (setting, value) in changes {
        zone = store.update_setting_async(zone_id, setting, value).await?;
    }
    Ok(settings_view(&zone))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::testutil::temp_store;

    fn schema(v: Value) -> Schema {
        Schema::compile(&v, &mut Compiler::strict()).unwrap()
    }

    fn op(id: &str, method: &str, host: &str, endpoint: &str, body_schema: Option<Value>) -> ApiOperation {
        ApiOperation {
            meta: Meta { id: id.into(), zone_id: "z".into(), ..Default::default() },
            method: method.into(),
            host: host.into(),
            endpoint: endpoint.into(),
            request_body_schema: body_schema,
            request_body_required: false,
            schema_bytes: 0,
        }
    }

    fn inventory(ops: &[ApiOperation]) -> Inventory {
        let mut inv = Inventory::default();
        let mut sorted: Vec<&ApiOperation> = ops.iter().collect();
        sorted.sort_by(|a, b| a.meta.id.cmp(&b.meta.id));
        for o in sorted {
            inv.add(o);
        }
        inv
    }

    fn found<'a>(inv: &'a Inventory, host: &str, method: &str, path: &str) -> Option<&'a str> {
        let i = inv.hosts.get(host)?.get(method)?.find(&request_segments(path))?;
        Some(inv.ops[i].id.as_str())
    }

    #[test]
    fn a_parameter_segment_matches_exactly_one_non_empty_segment() {
        let inv = inventory(&[op("a", "GET", "api.example.com", "/users/{id}", None)]);
        assert_eq!(found(&inv, "api.example.com", "GET", "/users/42"), Some("a"));
        assert_eq!(found(&inv, "api.example.com", "GET", "/users/42/"), Some("a"), "a trailing slash is an empty segment");
        assert_eq!(found(&inv, "api.example.com", "GET", "/users"), None);
        assert_eq!(found(&inv, "api.example.com", "GET", "/users//"), None, "an empty segment is no parameter");
        assert_eq!(found(&inv, "api.example.com", "GET", "/users/42/posts"), None);
        assert_eq!(found(&inv, "api.example.com", "POST", "/users/42"), None, "matching is per method");
        assert_eq!(found(&inv, "www.example.com", "GET", "/users/42"), None, "and per host");
    }

    #[test]
    fn exact_segments_win_over_parameters_wherever_they_differ_first() {
        let inv = inventory(&[
            op("1", "GET", "example.com", "/users/{id}", None),
            op("2", "GET", "example.com", "/users/me", None),
            op("3", "GET", "example.com", "/{a}/me/{b}", None),
            op("4", "GET", "example.com", "/users/{id}/posts", None),
            op("5", "GET", "example.com", "/{a}/{b}/posts", None),
        ]);
        assert_eq!(found(&inv, "example.com", "GET", "/users/me"), Some("2"));
        assert_eq!(found(&inv, "example.com", "GET", "/users/you"), Some("1"));
        assert_eq!(found(&inv, "example.com", "GET", "/users/me/posts"), Some("4"), "users is literal before {{a}}");
        assert_eq!(found(&inv, "example.com", "GET", "/teams/me/posts"), Some("3"), "me is literal at the second place");
        assert_eq!(found(&inv, "example.com", "GET", "/teams/x/posts"), Some("5"));
        assert_eq!(found(&inv, "example.com", "GET", "/users/x/y"), None, "a dead end on the literal side falls back, then finds nothing");
    }

    #[test]
    fn a_request_path_is_matched_decoded_and_with_dot_segments_resolved() {
        let inv = inventory(&[op("a", "POST", "example.com", "/api/users", None), op("b", "GET", "example.com", "/caf\u{e9}", None)]);
        for path in ["/api/users", "/api//users", "/api/./users", "/api/x/../users", "/%61pi/us%65rs", "/api%2Fusers", "/a/../../api/users"] {
            assert_eq!(found(&inv, "example.com", "POST", path), Some("a"), "{path}");
        }
        assert_eq!(found(&inv, "example.com", "GET", "/caf%C3%A9"), Some("b"));
        assert_eq!(found(&inv, "example.com", "POST", "/API/users"), None, "paths keep their case");
    }

    #[test]
    fn templates_are_stored_in_one_form_and_odd_ones_are_refused() {
        assert_eq!(normalize_endpoint("/a//b/").unwrap(), "/a/b");
        assert_eq!(normalize_endpoint("  /users/{user-id}  ").unwrap(), "/users/{user-id}");
        assert_eq!(normalize_endpoint("/").unwrap(), "/");
        for bad in ["", "users", "/a/../b", "/a/./b", "/files/{name}.json", "/{}", "/{a b}", "/a%20b", "/a?b", "/a#b", "/a b", "/{a}}", "/x\u{1}"] {
            assert!(normalize_endpoint(bad).is_err(), "{bad:?}");
        }
        assert!(normalize_endpoint(&format!("/{}", "x".repeat(MAX_ENDPOINT))).is_err());
        assert!(normalize_endpoint(&"/a".repeat(MAX_SEGMENTS)).is_ok());
        assert!(normalize_endpoint(&"/a".repeat(MAX_SEGMENTS + 1)).is_err());
        assert!(normalize_endpoint(&format!("/{{{}}}", "p".repeat(MAX_PARAM_NAME + 1))).is_err());
        assert!(same_shape("/u/{id}/x", "/u/{name}/x") && !same_shape("/u/{id}", "/u/me") && !same_shape("/u", "/u/{id}"));
        assert_eq!(key("GET", "example.com", "/u/{id}"), key("GET", "example.com", "/u/{other}"));
    }

    #[test]
    fn many_overlapping_templates_are_matched_without_blowing_up() {
        // every mix of a literal and a parameter at each of 12 places, and a
        // request that runs into a dead end at the last step of each: the
        // tree is walked once, not once per combination
        let mut ops = Vec::new();
        for i in 0..MAX_OPERATIONS {
            let segs: Vec<String> = (0..12).map(|b| if i >> b & 1 == 1 { "{p}".to_string() } else { "a".to_string() }).collect();
            ops.push(op(&format!("{i:05}"), "GET", "example.com", &format!("/{}/end", segs.join("/")), None));
        }
        let inv = inventory(&ops);
        let start = std::time::Instant::now();
        assert_eq!(found(&inv, "example.com", "GET", &format!("{}/nope", "/a".repeat(12))), None);
        assert_eq!(found(&inv, "example.com", "GET", &format!("{}/end", "/a".repeat(12))), Some("00000"), "all literal wins");
        assert!(start.elapsed() < std::time::Duration::from_secs(1));
    }

    #[test]
    fn the_schema_subset_checks_types_required_enums_lengths_and_ranges() {
        let s = schema(json!({
            "type": "object",
            "required": ["name", "age"],
            "additionalProperties": false,
            "properties": {
                "name": { "type": "string", "minLength": 2, "maxLength": 5 },
                "age": { "type": "integer", "minimum": 0, "exclusiveMaximum": 150 },
                "role": { "enum": ["admin", "user"] },
                "score": { "type": "number", "exclusiveMinimum": 0, "maximum": 1.5 },
                "tags": { "type": "array", "maxItems": 2, "items": { "type": "string" } },
                "note": { "type": ["string", "null"] },
            }
        }));
        assert_eq!(s.check(&json!({ "name": "ann", "age": 30 })), Ok(()));
        assert_eq!(s.check(&json!({ "name": "ann", "age": 30.0, "role": "user", "score": 1.5, "tags": ["a"], "note": null })), Ok(()));
        let err = |v: Value| s.check(&v).unwrap_err();
        assert_eq!(err(json!([])), "$: expected object");
        assert_eq!(err(json!({ "name": "ann" })), "$.age: is required");
        assert_eq!(err(json!({ "name": "a", "age": 1 })), "$.name: expected at least 2 characters");
        assert_eq!(err(json!({ "name": "\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}", "age": 1 })), "$.name: expected at most 5 characters", "characters, not bytes");
        assert_eq!(err(json!({ "name": "ann", "age": 1.5 })), "$.age: expected integer");
        assert_eq!(err(json!({ "name": "ann", "age": -1 })), "$.age: expected at least 0");
        assert_eq!(err(json!({ "name": "ann", "age": 150 })), "$.age: expected less than 150");
        assert_eq!(err(json!({ "name": "ann", "age": 1, "role": "root" })), "$.role: is not one of the allowed values");
        assert_eq!(err(json!({ "name": "ann", "age": 1, "score": 0 })), "$.score: expected more than 0");
        assert_eq!(err(json!({ "name": "ann", "age": 1, "score": 2 })), "$.score: expected at most 1.5");
        assert_eq!(err(json!({ "name": "ann", "age": 1, "tags": ["a", "b", "c"] })), "$.tags: expected at most 2 items");
        assert_eq!(err(json!({ "name": "ann", "age": 1, "tags": ["a", 1] })), "$.tags[1]: expected string");
        assert_eq!(err(json!({ "name": "ann", "age": 1, "note": 3 })), "$.note: expected string or null");
        assert_eq!(err(json!({ "name": "ann", "age": 1, "is admin": true })), "$[\"is admin\"]: is not allowed");
    }

    #[test]
    fn keywords_apply_only_to_values_of_their_kind_and_numbers_compare_exactly() {
        let s = schema(json!({ "minLength": 3, "maximum": 10, "required": ["a"], "maxItems": 1 }));
        for ok in [json!(true), json!(null), json!(5), json!("abc"), json!({ "a": 1 }), json!([1])] {
            assert_eq!(s.check(&ok), Ok(()), "{ok}");
        }
        assert!(s.check(&json!("ab")).is_err() && s.check(&json!(11)).is_err() && s.check(&json!({})).is_err() && s.check(&json!([1, 2])).is_err());
        let big = schema(json!({ "maximum": 9007199254740992u64 }));
        assert!(big.check(&json!(9007199254740993u64)).is_err(), "integers are compared as integers");
        assert!(big.check(&json!(-1)).is_ok());
        let e = schema(json!({ "enum": [1, [2.0], { "a": 3 }] }));
        assert!(e.check(&json!(1.0)).is_ok() && e.check(&json!([2])).is_ok() && e.check(&json!({ "a": 3.0 })).is_ok());
        assert!(e.check(&json!(2)).is_err());
        let c = schema(json!({ "const": "x", "type": "integer", "nullable": true }));
        assert!(c.check(&json!("x")).is_err(), "the type still applies");
        assert_eq!(schema(json!({ "type": "integer", "nullable": true })).to_value(), json!({ "type": ["integer", "null"] }));
    }

    #[test]
    fn open_api_3_0_exclusive_flags_and_annotations_are_read_and_stored_in_the_subset() {
        let s = schema(json!({ "type": "number", "minimum": 1, "exclusiveMinimum": true, "maximum": 5, "exclusiveMaximum": false, "description": "d", "format": "double", "x-anything": 1 }));
        assert_eq!(s.to_value(), json!({ "type": "number", "exclusiveMinimum": 1, "maximum": 5 }));
        assert!(s.check(&json!(1)).is_err() && s.check(&json!(5)).is_ok());
        let stored = s.to_value();
        assert_eq!(schema(stored.clone()).to_value(), stored, "the stored form reads back the same");
    }

    #[test]
    fn a_stored_schema_refuses_what_it_cannot_check() {
        let strict = |v: Value| Schema::compile(&v, &mut Compiler::strict());
        for bad in [
            json!({ "pattern": "^a" }),
            json!({ "oneOf": [] }),
            json!({ "$ref": "#/x" }),
            json!({ "items": [{}] }),
            json!({ "type": "text" }),
            json!({ "type": [] }),
            json!({ "enum": [] }),
            json!({ "minLength": -1 }),
            json!({ "minLength": 1.5 }),
            json!({ "maximum": "5" }),
            json!({ "required": "a" }),
            json!({ "properties": [] }),
            json!("string"),
            json!(false),
        ] {
            assert!(strict(bad.clone()).is_err(), "{bad}");
        }
        assert!(strict(json!({ "enum": (0..MAX_ENUM + 1).collect::<Vec<_>>() })).is_err());
        assert!(strict(json!(true)).is_ok());
    }

    #[test]
    fn schemas_nest_at_most_thirty_two_deep() {
        let nested = |n: usize| (0..n).fold(json!({ "type": "string" }), |inner, _| json!({ "properties": { "a": inner } }));
        assert!(Schema::compile(&nested(MAX_DEPTH), &mut Compiler::strict()).is_ok());
        assert!(Schema::compile(&nested(MAX_DEPTH + 1), &mut Compiler::strict()).is_err());
        // an import cuts instead, and what it keeps reads back strictly
        let mut notes = Vec::new();
        let doc = json!({});
        let cut = Schema::compile(&nested(100), &mut Compiler::import(&doc, &mut notes, 10_000)).unwrap();
        assert_eq!(notes.len(), 1, "{notes:?}");
        assert!(Schema::compile(&cut.to_value(), &mut Compiler::strict()).is_ok());
        // a body nested far deeper than the schema is not walked
        let deep_body = (0..120).fold(json!(1), |inner, _| json!({ "a": inner }));
        assert!(cut.check(&deep_body).is_ok());
    }

    #[test]
    fn an_import_follows_refs_within_its_budget_and_notes_what_it_drops() {
        let doc = json!({ "components": { "schemas": {
            "User": { "type": "object", "properties": { "name": { "$ref": "#/components/schemas/Name" }, "email": { "type": "string", "pattern": ".+@.+" } } },
            "Name": { "type": "string", "maxLength": 3 },
            "Loop": { "$ref": "#/components/schemas/Loop" },
            "Tree": { "type": "object", "properties": { "kids": { "type": "array", "items": { "$ref": "#/components/schemas/Tree" } } } },
            "Odd": { "type": "object", "additionalProperties": false, "patternProperties": { "^x": {} } },
        } } });
        let mut notes = Vec::new();
        let user = Schema::compile(&json!({ "$ref": "#/components/schemas/User" }), &mut Compiler::import(&doc, &mut notes, 10_000)).unwrap();
        assert!(user.check(&json!({ "name": "abcd" })).is_err() && user.check(&json!({ "name": "abc", "email": "nope" })).is_ok());
        assert!(notes.len() == 1 && notes[0].contains("pattern"), "{notes:?}");

        for (name, ok) in [("Loop", json!(1)), ("Tree", json!({ "kids": [{ "kids": [] }] })), ("Odd", json!({ "xa": 1 }))] {
            let mut notes = Vec::new();
            let s = Schema::compile(&json!({ "$ref": format!("#/components/schemas/{name}") }), &mut Compiler::import(&doc, &mut notes, 100_000)).unwrap();
            assert_eq!(s.check(&ok), Ok(()), "{name}");
            assert!(!notes.is_empty(), "{name}");
        }
        let mut notes = Vec::new();
        assert!(Schema::compile(&json!({ "$ref": "other.json#/A" }), &mut Compiler::import(&doc, &mut notes, 100)).unwrap() == Schema::default());

        // a document whose refs double at each step stands for 2^40 nodes: the budget stops it
        let mut schemas = Map::new();
        for i in 0..40 {
            let next = format!("#/components/schemas/s{}", i + 1);
            schemas.insert(format!("s{i}"), json!({ "type": "object", "properties": { "a": { "$ref": next }, "b": { "$ref": next } } }));
        }
        schemas.insert("s40".into(), json!({ "type": "string" }));
        let bomb = json!({ "components": { "schemas": schemas } });
        let mut notes = Vec::new();
        let start = std::time::Instant::now();
        let r = Schema::compile(&json!({ "$ref": "#/components/schemas/s0" }), &mut Compiler::import(&bomb, &mut notes, 50_000));
        assert!(r.is_err(), "too large to check");
        assert!(start.elapsed() < std::time::Duration::from_secs(2));
    }

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(header::HeaderName::from_bytes(k.as_bytes()).unwrap(), v.parse().unwrap());
        }
        h
    }

    #[test]
    fn a_body_must_be_whole_json_for_an_operation_with_a_schema() {
        let s = schema(json!({ "type": "object", "required": ["a"] }));
        let json_ct = headers(&[("content-type", "application/json; charset=utf-8")]);
        assert_eq!(check_body(&s, false, &json_ct, Body::Whole(br#"{"a":1}"#)), Ok(()));
        assert_eq!(check_body(&s, false, &headers(&[("content-type", "application/problem+json")]), Body::Whole(br#"{"a":1}"#)), Ok(()));
        assert_eq!(check_body(&s, false, &json_ct, Body::Whole(b"")), Ok(()), "an empty body passes when it is optional");
        assert!(check_body(&s, true, &json_ct, Body::Whole(b"")).unwrap_err().contains("missing"));
        assert!(check_body(&s, false, &json_ct, Body::Whole(br#"{"b":1}"#)).unwrap_err().contains("$.a: is required"));
        let not_json = check_body(&s, false, &headers(&[("content-type", "text/plain")]), Body::Whole(br#"{"a":1}"#)).unwrap_err();
        assert!(not_json.contains("not JSON"), "{not_json}");
        assert!(check_body(&s, false, &HeaderMap::new(), Body::Whole(br#"{"a":1}"#)).is_err(), "no content type is no JSON");
        assert!(check_body(&s, false, &json_ct, Body::Whole(b"{\"a\":")).unwrap_err().contains("not valid JSON"));
        let encoded = headers(&[("content-type", "application/json"), ("content-encoding", "gzip")]);
        assert!(check_body(&s, false, &encoded, Body::Whole(b"\x1f\x8b")).unwrap_err().contains("encoded"));
        assert!(check_body(&s, false, &json_ct, Body::Unread).unwrap_err().contains("not read whole"), "a body too large to check breaks the schema");
        // a body nested deeper than serde_json reads is refused, not a stack overflow
        let deep = format!("{}{}", "[".repeat(100_000), "]".repeat(100_000));
        assert!(check_body(&s, false, &json_ct, Body::Whole(deep.as_bytes())).is_err());
        // the reason never quotes a value from the body
        let secret = check_body(&schema(json!({ "properties": { "pin": { "enum": ["0000"] } } })), false, &json_ct, Body::Whole(br#"{"pin":"8642"}"#)).unwrap_err();
        assert!(!secret.contains("8642"), "{secret}");
    }

    #[test]
    fn media_types_are_json_by_their_subtype() {
        for yes in ["application/json", "Application/JSON", "application/vnd.api+json; q=1", "text/json"] {
            assert!(is_json(yes), "{yes}");
        }
        for no in ["", "json", "application/jsonx", "text/plain", "multipart/form-data", "/json"] {
            assert!(!is_json(no), "{no}");
        }
    }

    fn request(method: &str, path: &str) -> ReqInfo {
        ReqInfo { method: method.into(), host: "api.example.com".into(), path: path.into(), ..Default::default() }
    }

    #[test]
    fn requests_are_assessed_per_host_and_unknown_endpoints_fall_through() {
        let store = temp_store();
        let z = store.create_zone("example.com").unwrap().id;
        let a = store
            .save_item::<ApiOperation>(&z, None, json!({ "method": "POST", "host": "api.example.com", "endpoint": "/users", "request_body_schema": { "type": "object", "required": ["name"] } }), true)
            .unwrap()
            .meta
            .id;
        store.save_item::<ApiOperation>(&z, None, json!({ "method": "GET", "host": "api.example.com", "endpoint": "/users/{id}" }), true).unwrap();
        let snap = store.snapshot();
        let zs = &snap.zones["example.com"];
        assert!(!zs.api_shield.is_empty());
        assert!(snap.zones.values().filter(|o| o.zone.id != z).all(|o| o.api_shield.is_empty()));
        let ct = headers(&[("content-type", "application/json")]);
        let ok = assess(&zs, &request("POST", "/users"), &ct, Body::Whole(br#"{"name":"x"}"#));
        assert_eq!(ok, Outcome { operation: a, ..Default::default() });
        let bad = assess(&zs, &request("POST", "/users"), &ct, Body::Whole(b"{}"));
        assert!(bad.violates_schema && !bad.fallthrough && bad.reason.contains("$.name"), "{bad:?}");
        let no_schema = assess(&zs, &request("GET", "/users/7"), &HeaderMap::new(), Body::Unread);
        assert!(!no_schema.violates_schema, "an operation without a schema checks no body");
        assert!(assess(&zs, &request("DELETE", "/users/7"), &ct, Body::Whole(b"")).fallthrough, "a method of no operation");
        assert!(assess(&zs, &request("GET", "/admin"), &ct, Body::Whole(b"")).fallthrough);
        let other = ReqInfo { host: "www.example.com".into(), ..request("GET", "/admin") };
        assert_eq!(assess(&zs, &other, &ct, Body::Whole(b"")), Outcome::default(), "a host without operations is not covered");
    }

    #[test]
    fn the_settings_act_on_violations_and_fallthroughs_but_spare_the_edge_paths() {
        let mut settings = Settings::default();
        assert_eq!((settings.api_shield_schema_action.as_str(), settings.api_shield_fallthrough_action.as_str()), ("none", "none"));
        let violating = ReqInfo { api_gateway: Outcome { violates_schema: true, operation: "o1".into(), reason: "$.a: is required".into(), ..Default::default() }, ..request("POST", "/users") };
        let unknown = ReqInfo { api_gateway: Outcome { fallthrough: true, ..Default::default() }, ..request("GET", "/admin") };
        assert_eq!(mitigation(&settings, &violating), None, "none by default");
        assert_eq!(mitigation(&settings, &unknown), None);
        settings.api_shield_schema_action = "log".into();
        settings.api_shield_fallthrough_action = "block".into();
        assert_eq!(mitigation(&settings, &violating), Some(("schema_validation", "Operation o1: $.a: is required".into(), "log")));
        assert_eq!(mitigation(&settings, &unknown).map(|m| (m.0, m.2)), Some(("fallthrough", "block")));
        for path in ["/cdn-cgi/trace", "/.well-known/acme-challenge/t"] {
            let spared = ReqInfo { path: path.into(), ..unknown.clone() };
            assert_eq!(mitigation(&settings, &spared), None, "{path}");
        }
        assert_eq!(mitigation(&settings, &ReqInfo { api_gateway: Outcome::default(), ..request("GET", "/x") }), None);
    }

    #[tokio::test]
    async fn operations_are_validated_capped_and_deduplicated_per_zone() {
        let store = temp_store();
        let z = store.create_zone("example.com").unwrap().id;
        let other = store.create_zone("example.net").unwrap().id;
        store.create_zone("inner.example.com").unwrap();
        let save = |v: Value| store.save_item::<ApiOperation>(&z, None, v, true);
        let saved = save(json!({ "method": "get", "host": "API.example.com.", "endpoint": "/users//{id}/" })).unwrap();
        assert_eq!((saved.method.as_str(), saved.host.as_str(), saved.endpoint.as_str()), ("GET", "api.example.com", "/users/{id}"));
        let public = saved.public();
        assert_eq!(public["operation_id"], json!(saved.meta.id));
        assert!(public.get("schema_bytes").is_none() && public.get("sync").is_none());
        assert!(matches!(save(json!({ "method": "GET", "host": "api.example.com", "endpoint": "/users/{other}" })), Err(StoreError::Conflict(_))));
        for bad in [
            json!({ "method": "FETCH", "host": "example.com", "endpoint": "/" }),
            json!({ "method": "GET", "host": "example.net", "endpoint": "/" }),
            json!({ "method": "GET", "host": "*.example.com", "endpoint": "/" }),
            json!({ "method": "GET", "host": "a.inner.example.com", "endpoint": "/" }),
            json!({ "method": "GET", "host": "example.com", "endpoint": "x" }),
            json!({ "method": "GET", "host": "example.com", "endpoint": "/", "request_body_schema": { "pattern": "x" } }),
            json!({ "method": "GET", "host": "example.com", "endpoint": "/", "request_body_required": true }),
            json!({ "host": "example.com", "endpoint": "/" }),
        ] {
            assert!(matches!(save(bad.clone()), Err(StoreError::Invalid(_))), "{bad}");
        }
        // the stored schema is the subset, and its size is ours to say
        let with = save(json!({ "method": "POST", "host": "example.com", "endpoint": "/a", "request_body_schema": { "type": "object", "description": "dropped" }, "schema_bytes": 0 })).unwrap();
        assert_eq!(with.request_body_schema, Some(json!({ "type": "object" })));
        assert_eq!(with.schema_bytes, r#"{"type":"object"}"#.len());
        let huge = json!({ "enum": [ "x".repeat(MAX_SCHEMA_BYTES) ] });
        assert!(matches!(save(json!({ "method": "PUT", "host": "example.com", "endpoint": "/a", "request_body_schema": huge })), Err(StoreError::Invalid(_))));
        assert!(store.items::<ApiOperation>(&other).unwrap().is_empty());

        // the cap: a list that would pass it adds nothing at all
        let many: Vec<Value> = (0..MAX_OPERATIONS - 2).map(|i| json!({ "method": "GET", "host": "example.com", "endpoint": format!("/n/{i}") })).collect();
        create(&store, &z, Value::Array(many)).await.unwrap();
        assert_eq!(store.items::<ApiOperation>(&z).unwrap().len(), MAX_OPERATIONS);
        let one_more = create(&store, &z, json!([{ "method": "GET", "host": "example.com", "endpoint": "/n/{i}/x" }])).await;
        assert!(matches!(one_more, Err(StoreError::Invalid(m)) if m.contains("at most 2000")));
        // one that is there already is answered, not added
        let again = create(&store, &z, json!({ "method": "GET", "host": "api.example.com", "endpoint": "/users/{x}" })).await.unwrap();
        assert_eq!(again["operation_id"], json!(saved.meta.id));
        assert!(entries(Value::Array(vec![json!({}); MAX_OPERATIONS + 1])).is_err());
        assert!(entries(json!([])).is_err() && entries(json!("x")).is_err());
        // other zones' operations are not this zone's to delete
        assert!(delete_many(&store, &other, json!([{ "operation_id": saved.meta.id }])).await.is_err());
        assert_eq!(delete_many(&store, &z, json!([saved.meta.id, { "operation_id": with.meta.id }])).await.unwrap(), json!({ "deleted": 2 }));
        assert_eq!(store.items::<ApiOperation>(&z).unwrap().len(), MAX_OPERATIONS - 2);
    }

    #[tokio::test]
    async fn the_zone_budget_caps_all_schemas_together() {
        let store = temp_store();
        let z = store.create_zone("example.com").unwrap().id;
        // just under the per-operation cap each
        let big = json!({ "enum": ["x".repeat(MAX_SCHEMA_BYTES - 32)] });
        let fits = MAX_ZONE_SCHEMA_BYTES / MAX_SCHEMA_BYTES;
        for i in 0..fits {
            store.save_item::<ApiOperation>(&z, None, json!({ "method": "POST", "host": "example.com", "endpoint": format!("/b/{i}"), "request_body_schema": big }), true).unwrap();
        }
        let over = store.save_item::<ApiOperation>(&z, None, json!({ "method": "POST", "host": "example.com", "endpoint": "/b/last", "request_body_schema": big }), true);
        assert!(matches!(over, Err(StoreError::Invalid(m)) if m.contains("together")));
        // replacing one's schema does not count it twice
        let first = store.items::<ApiOperation>(&z).unwrap().remove(0);
        assert!(store.save_item::<ApiOperation>(&z, Some(&first.meta.id), json!({ "request_body_schema": big }), false).is_ok());
    }

    #[tokio::test]
    async fn the_settings_endpoint_changes_both_actions_or_neither() {
        let store = temp_store();
        let z = store.create_zone("example.com").unwrap().id;
        let v = update_settings(&store, &z, json!({ "validation_default_mitigation_action": "block", "fallthrough_mitigation_action": "log" })).await.unwrap();
        assert_eq!(v, json!({ "validation_default_mitigation_action": "block", "fallthrough_mitigation_action": "log" }));
        for bad in [json!({ "validation_default_mitigation_action": "drop" }), json!({ "fallthrough_mitigation_action": "none", "other": 1 }), json!([]), json!({ "fallthrough_mitigation_action": null })] {
            assert!(update_settings(&store, &z, bad.clone()).await.is_err(), "{bad}");
        }
        assert_eq!(settings_view(&store.get_zone(&z).unwrap()), v, "nothing changed");
        assert!(update_settings(&store, "no-such-zone", json!({})).await.is_err());
        assert!(store.update_setting(&z, SCHEMA_SETTING, json!("maybe")).is_err(), "the setting itself is checked too");
    }
}
