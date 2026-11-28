//! Reading an OpenAPI 3 document into API Shield operations
//! (crate::edge::apishield).
//!
//! Only JSON is read: fucf has no YAML parser among its dependencies, so a
//! YAML document has to be converted first. Of the document fucf takes the
//! `servers` (for the hosts and base paths), the `paths` with their methods,
//! and each operation's `requestBody` (its JSON schema and whether it is
//! required). Everything else is left out, and each thing left out that could
//! matter is named in the answer's warnings: parameters (only bodies are
//! checked), schema keywords outside fucf's subset (each makes the check
//! looser, never stricter), partial path templates like `/files/{name}.json`,
//! servers outside the zone. An upload adds operations and updates the ones
//! it names again; it never deletes one.
//!
//! The document is at most 2 MiB, and the schemas it stands for at most
//! 200 000 nodes together, `$ref`s followed: a small document whose
//! references fan out cannot make the import do much work.

use super::apishield::{self, normalize_endpoint, ApiOperation, Compiler, Schema, MAX_OPERATIONS, MAX_SCHEMA_BYTES};
use crate::items::{in_zone, Item};
use crate::store::{ItemOp, Store, StoreError, Zone};
use serde_json::{json, Map, Value};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

/// Bytes of an uploaded document.
pub const MAX_DOCUMENT: usize = 2 << 20;
/// Schema nodes one document may stand for.
const DOC_BUDGET: usize = 200_000;
/// Warnings an answer lists by themselves.
const MAX_NOTES: usize = 200;
/// The methods OpenAPI names under a path.
const METHODS: [&str; 8] = ["get", "put", "post", "delete", "options", "head", "patch", "trace"];
/// `$ref` hops to a request body or a path item.
const MAX_HOPS: usize = 8;

/// What a document comes to: the operations (as bodies for the store, in
/// the document's order, each method, host and template once) and what was
/// left out.
#[derive(Debug, Default)]
pub struct Import {
    pub operations: Vec<Value>,
    pub notes: Vec<String>,
}

/// The `#/...` target of a local `$ref`, followed `MAX_HOPS` times at most.
fn resolve<'a>(doc: &'a Value, mut v: &'a Value) -> Option<&'a Value> {
    for _ in 0..MAX_HOPS {
        let Some(r) = v.get("$ref") else { return Some(v) };
        let pointer = r.as_str()?.strip_prefix('#')?;
        v = doc.pointer(&percent_encoding::percent_decode_str(pointer).decode_utf8_lossy())?;
    }
    None
}

/// Where the API is served: hosts of the zone and base paths.
fn servers(doc: &Value, zone: &Zone, host: Option<&str>, notes: &mut Vec<String>) -> Result<Vec<(String, String)>, String> {
    let default_host = host.map(str::to_string).unwrap_or_else(|| zone.name.clone());
    let Some(list) = doc.get("servers").and_then(Value::as_array).filter(|l| !l.is_empty()) else {
        return Ok(vec![(default_host, String::new())]);
    };
    let mut out: Vec<(String, String)> = Vec::new();
    for (i, s) in list.iter().enumerate() {
        let Some(mut url) = s.get("url").and_then(Value::as_str).map(str::to_string) else {
            notes.push(format!("servers[{i}]: no url, left out"));
            continue;
        };
        // variables stand for their defaults
        if let Some(vars) = s.get("variables").and_then(Value::as_object) {
            for (name, var) in vars {
                if let Some(default) = var.get("default").and_then(Value::as_str) {
                    url = url.replace(&format!("{{{name}}}"), default);
                }
            }
        }
        if url.contains(['{', '}']) {
            notes.push(format!("servers[{i}]: a variable without a default, left out"));
            continue;
        }
        let rest = url.strip_prefix("https://").or_else(|| url.strip_prefix("http://")).or_else(|| url.strip_prefix("//"));
        let (server_host, base) = match rest {
            Some(rest) => {
                let (authority, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
                let name = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
                let name = name.split(':').next().unwrap_or("");
                match crate::dns::wire::normalize_name(name) {
                    Ok(h) => (h, path.to_string()),
                    Err(_) => {
                        notes.push(format!("servers[{i}]: the host of the url is not a host name, left out"));
                        continue;
                    }
                }
            }
            None if url.starts_with('/') || url.is_empty() => (default_host.clone(), url.clone()),
            None => {
                notes.push(format!("servers[{i}]: fucf reads http, https and relative urls, left out"));
                continue;
            }
        };
        if host.is_some_and(|h| h != server_host) {
            continue;
        }
        if !in_zone(zone, &server_host) {
            notes.push(format!("servers[{i}]: {server_host} is not part of zone {}, left out", zone.name));
            continue;
        }
        let base = base.split(['?', '#']).next().unwrap_or("").trim_end_matches('/').to_string();
        if !out.iter().any(|(h, b)| *h == server_host && *b == base) {
            out.push((server_host, base));
        }
    }
    if out.is_empty() {
        return Err(match host {
            Some(h) => format!("no server of the document is on {h}"),
            None => format!("no server of the document is a host of zone {}", zone.name),
        });
    }
    Ok(out)
}

/// The body schema of one operation, in the subset, as it will be stored;
/// none where it cannot be checked (noted).
fn body_schema(doc: &Value, request_body: &Value, what: &str, budget: &mut usize, notes: &mut Vec<String>) -> (Option<Value>, bool) {
    let Some(rb) = resolve(doc, request_body) else {
        notes.push(format!("{what}: a requestBody $ref fucf cannot follow; the body is not checked"));
        return (None, false);
    };
    let required = rb.get("required").and_then(Value::as_bool).unwrap_or(false);
    let content = rb.get("content").and_then(Value::as_object);
    let media = content.and_then(|c| c.get("application/json").map(|m| ("application/json", m)).or_else(|| c.iter().find(|(k, _)| apishield::is_json(k)).map(|(k, m)| (k.as_str(), m))));
    let Some((media_type, media)) = media else {
        let types: Vec<String> = content.into_iter().flat_map(|c| c.keys()).take(8).map(|k| clip(k)).collect();
        notes.push(format!("{what}: no JSON request body ({}); only JSON bodies are checked, so this one is not", if types.is_empty() { "no content".to_string() } else { types.join(", ") }));
        return (None, false);
    };
    let others: Vec<String> = content.into_iter().flat_map(|c| c.keys()).filter(|k| *k != media_type).take(8).map(|k| clip(k)).collect();
    if !others.is_empty() {
        notes.push(format!("{what}: only {} bodies are checked; bodies sent as {} break the schema", clip(media_type), others.join(", ")));
    }
    let Some(schema) = media.get("schema") else { return (Some(json!({})), required) };
    let mut found = Vec::new();
    let mut c = Compiler::import(doc, &mut found, *budget);
    let compiled = Schema::compile(schema, &mut c);
    *budget = c.remaining();
    notes.extend(found.into_iter().map(|n| format!("{what}: {n}")));
    match compiled {
        Ok(s) => {
            let stored = s.to_value();
            if serde_json::to_vec(&stored).map_or(true, |b| b.len() > MAX_SCHEMA_BYTES) {
                notes.push(format!("{what}: the schema is over {MAX_SCHEMA_BYTES} bytes in fucf's subset; the body is not checked"));
                return (None, false);
            }
            (Some(stored), required)
        }
        Err(e) => {
            notes.push(format!("{what}: {e}; the body is not checked"));
            (None, false)
        }
    }
}

/// Read a document for a zone (`host`: only the servers on that host, and
/// the host of relative servers; by default the zone's apex).
pub fn read(doc: &Value, zone: &Zone, host: Option<&str>) -> Result<Import, String> {
    let version = doc.get("openapi").and_then(Value::as_str).unwrap_or("");
    if !version.starts_with("3.") {
        return Err(r#"only OpenAPI 3 documents ("openapi": "3.x") are read; Swagger 2 is not"#.into());
    }
    let paths = doc.get("paths").and_then(Value::as_object).ok_or("the document has no paths object")?;
    let mut notes = Vec::new();
    let servers = servers(doc, zone, host, &mut notes)?;
    let mut budget = DOC_BUDGET;
    let mut out = Import::default();
    let mut seen = HashSet::new();
    let mut parameters = false;
    for (path, item) in paths {
        let Some(item) = resolve(doc, item).and_then(Value::as_object) else {
            notes.push(format!("{}: a path item fucf cannot read, left out", clip(path)));
            continue;
        };
        parameters |= item.get("parameters").is_some_and(|p| p.as_array().is_some_and(|a| !a.is_empty()));
        if item.contains_key("servers") {
            notes.push(format!("{}: servers of a path are not read; the document's are used", clip(path)));
        }
        for method in METHODS {
            let Some(op) = item.get(method).and_then(Value::as_object) else { continue };
            let what = format!("{} {}", method.to_ascii_uppercase(), clip(path));
            parameters |= op.get("parameters").is_some_and(|p| p.as_array().is_some_and(|a| !a.is_empty()));
            if op.contains_key("servers") {
                notes.push(format!("{what}: servers of an operation are not read; the document's are used"));
            }
            let (schema, required) = match op.get("requestBody") {
                Some(rb) => body_schema(doc, rb, &what, &mut budget, &mut notes),
                None => (None, false),
            };
            for (server_host, base) in &servers {
                let endpoint = match normalize_endpoint(&format!("{base}{path}")) {
                    Ok(e) => e,
                    Err(e) => {
                        notes.push(format!("{what}: {e}; left out"));
                        break;
                    }
                };
                if !seen.insert(apishield::key(&method.to_ascii_uppercase(), server_host, &endpoint)) {
                    notes.push(format!("{what}: the same operation as an earlier one on {server_host}; left out"));
                    continue;
                }
                let mut body = Map::new();
                body.insert("method".into(), json!(method.to_ascii_uppercase()));
                body.insert("host".into(), json!(server_host));
                body.insert("endpoint".into(), json!(endpoint));
                if let Some(s) = &schema {
                    body.insert("request_body_schema".into(), s.clone());
                    body.insert("request_body_required".into(), json!(required));
                }
                out.operations.push(Value::Object(body));
                if out.operations.len() > MAX_OPERATIONS {
                    return Err(format!("the document has more than {MAX_OPERATIONS} operations, the most a zone has"));
                }
            }
        }
    }
    if parameters {
        notes.push("parameters are not checked: API Shield checks request bodies only".into());
    }
    if notes.len() > MAX_NOTES {
        let more = notes.len() - MAX_NOTES;
        notes.truncate(MAX_NOTES);
        notes.push(format!("... and {more} more"));
    }
    out.notes = notes;
    Ok(out)
}

/// A name from the document as a warning shows it.
fn clip(name: &str) -> String {
    name.chars().take(128).collect()
}

/// `POST .../api_gateway/openapi`: import a document (raw JSON). Every
/// operation lands or none does.
pub async fn upload(store: &Store, zone_id: &str, bytes: &[u8], host: Option<&str>) -> Result<Value, StoreError> {
    let zone = store.get_zone(zone_id)?;
    if bytes.len() > MAX_DOCUMENT {
        return Err(StoreError::Invalid(format!("an OpenAPI document has at most {MAX_DOCUMENT} bytes")));
    }
    let doc: Value = serde_json::from_slice(bytes).map_err(|e| {
        let first = bytes.iter().find(|b| !b.is_ascii_whitespace());
        StoreError::Invalid(match first {
            Some(b'{') => format!("the document is not valid JSON: {e}"),
            _ => "send the OpenAPI document as JSON: fucf does not read YAML".into(),
        })
    })?;
    let host = match host {
        Some(h) => Some(crate::dns::wire::normalize_name(h).map_err(|e| StoreError::Invalid(format!("host: {e}")))?),
        None => None,
    };
    let import = read(&doc, &zone, host.as_deref()).map_err(StoreError::Invalid)?;
    let wanted: Vec<(String, String, String)> = import.operations.iter().map(key_of).collect();
    let counts = Arc::new(Mutex::new((0usize, 0usize)));
    let plan_counts = counts.clone();
    let operations = import.operations;
    store
        .batch_items_async::<ApiOperation, _>(zone_id, move |current| {
            let ids: HashMap<(String, String, String), String> =
                current.iter().map(|o| (apishield::key(&o.method, &o.host, &o.endpoint), o.meta.id.clone())).collect();
            let mut ops = Vec::new();
            let (mut created, mut updated) = (0, 0);
            for (i, body) in operations.into_iter().enumerate() {
                let id = ids.get(&key_of(&body)).cloned();
                if id.is_some() { updated += 1 } else { created += 1 }
                ops.push(ItemOp::Save { id, body, replace: true, at: format!("operations[{i}]") });
            }
            if let Ok(mut c) = plan_counts.lock() {
                *c = (created, updated);
            }
            Ok(ops)
        })
        .await?;
    let (created, updated) = counts.lock().map(|c| *c).unwrap_or_default();
    let now: HashMap<(String, String, String), Value> =
        store.items::<ApiOperation>(zone_id)?.iter().map(|o| (apishield::key(&o.method, &o.host, &o.endpoint), o.public())).collect();
    let operations: Vec<Value> = wanted.iter().filter_map(|k| now.get(k).cloned()).collect();
    let warnings: Vec<Value> = import.notes.iter().map(|n| json!({ "message": n })).collect();
    Ok(json!({ "operations": operations, "created": created, "updated": updated, "upload_details": { "warnings": warnings } }))
}

/// The key of an operation body that `read` made (its fields are normalized).
fn key_of(body: &Value) -> (String, String, String) {
    let text = |k: &str| body.get(k).and_then(Value::as_str).unwrap_or("");
    apishield::key(text("method"), text("host"), text("endpoint"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::testutil::temp_store;

    fn zone() -> Zone {
        let store = temp_store();
        store.create_zone("example.com").unwrap()
    }

    fn doc(servers: Value, paths: Value) -> Value {
        json!({ "openapi": "3.0.3", "info": { "title": "t", "version": "1" }, "servers": servers, "paths": paths })
    }

    fn endpoints(i: &Import) -> Vec<String> {
        i.operations.iter().map(|o| format!("{} {}{}", o["method"].as_str().unwrap(), o["host"].as_str().unwrap(), o["endpoint"].as_str().unwrap())).collect()
    }

    #[test]
    fn servers_give_the_hosts_and_base_paths_of_the_zone() {
        let z = zone();
        let d = doc(
            json!([
                { "url": "https://api.example.com/v1/" },
                { "url": "https://{env}.example.com:8443", "variables": { "env": { "default": "staging" } } },
                { "url": "https://api.example.net/v1" },
                { "url": "ftp://example.com" },
                { "url": "https://{x}.example.com" },
                { "url": "/rel" },
            ]),
            json!({ "/users/{id}": { "get": {}, "summary": "s" } }),
        );
        let i = read(&d, &z, None).unwrap();
        assert_eq!(endpoints(&i), ["GET api.example.com/v1/users/{id}", "GET staging.example.com/users/{id}", "GET example.com/rel/users/{id}"]);
        assert_eq!(i.notes.len(), 3, "{:?}", i.notes);
        // a host picks its servers, and is the host of relative ones
        let only = read(&d, &z, Some("api.example.com")).unwrap();
        assert_eq!(endpoints(&only), ["GET api.example.com/v1/users/{id}", "GET api.example.com/rel/users/{id}"]);
        assert!(read(&d, &z, Some("www.example.com")).unwrap().operations.len() == 1, "only the relative server");
        let none = doc(json!([{ "url": "https://example.net" }]), json!({ "/": { "get": {} } }));
        assert!(read(&none, &z, None).unwrap_err().contains("no server"));
        let bare = json!({ "openapi": "3.1.0", "paths": { "/": { "get": {} } } });
        assert_eq!(endpoints(&read(&bare, &z, None).unwrap()), ["GET example.com/"], "no servers: the zone apex");
    }

    #[test]
    fn only_open_api_3_documents_with_paths_are_read() {
        let z = zone();
        assert!(read(&json!({ "swagger": "2.0", "paths": {} }), &z, None).unwrap_err().contains("OpenAPI 3"));
        assert!(read(&json!({ "openapi": "3.0.0" }), &z, None).is_err());
        assert!(read(&json!([]), &z, None).is_err());
        assert!(read(&json!({ "openapi": "3.0.0", "paths": {} }), &z, None).unwrap().operations.is_empty());
    }

    #[test]
    fn request_bodies_become_schemas_and_what_is_left_out_is_noted() {
        let z = zone();
        let d = json!({
            "openapi": "3.0.0",
            "paths": {
                "/users": {
                    "parameters": [{ "name": "x", "in": "query" }],
                    "post": { "requestBody": { "$ref": "#/components/requestBodies/NewUser" } },
                    "put": { "requestBody": { "content": { "application/vnd.api+json": { "schema": { "type": "object", "oneOf": [] } }, "text/plain": {} } } },
                    "patch": { "requestBody": { "content": { "multipart/form-data": {} } } },
                    "delete": { "requestBody": { "required": true, "content": { "application/json": {} } } },
                    "x-other": {}
                },
                "/files/{name}.json": { "get": {} },
                "/weird": { "$ref": "#/nowhere" },
            },
            "components": {
                "requestBodies": { "NewUser": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/User" } } } } },
                "schemas": { "User": { "type": "object", "required": ["name"], "properties": { "name": { "type": "string", "format": "email" } } } }
            }
        });
        let i = read(&d, &z, None).unwrap();
        assert_eq!(endpoints(&i), ["PUT example.com/users", "POST example.com/users", "DELETE example.com/users", "PATCH example.com/users"]);
        let by = |m: &str| i.operations.iter().find(|o| o["method"] == m).unwrap();
        assert_eq!(by("POST")["request_body_schema"], json!({ "type": "object", "required": ["name"], "properties": { "name": { "type": "string" } } }));
        assert_eq!(by("POST")["request_body_required"], json!(true));
        assert_eq!(by("PUT")["request_body_schema"], json!({ "type": "object" }), "oneOf left out");
        assert_eq!(by("DELETE")["request_body_schema"], json!({}), "a JSON body without a schema is still JSON");
        assert!(by("PATCH").get("request_body_schema").is_none(), "a multipart body is not checked");
        let notes = i.notes.join("\n");
        for word in ["oneOf", "text/plain", "multipart", "{name}.json", "/weird", "parameters are not checked"] {
            assert!(notes.contains(word), "{word}: {notes}");
        }
        assert!(!notes.contains("format"), "annotations are dropped quietly");
    }

    #[test]
    fn a_document_is_capped_in_operations_work_and_warnings() {
        let z = zone();
        let paths: Map<String, Value> = (0..=MAX_OPERATIONS).map(|i| (format!("/p/{i}"), json!({ "get": {} }))).collect();
        let big = json!({ "openapi": "3.0.0", "paths": paths });
        assert!(read(&big, &z, None).unwrap_err().contains("more than 2000"));
        // every operation pointing at a schema that fans out: the budget runs
        // out, each later schema is noted and its body left unchecked
        let mut schemas = Map::new();
        for n in 0..30 {
            schemas.insert(format!("s{n}"), json!({ "type": "object", "properties": { "a": { "$ref": format!("#/components/schemas/s{}", n + 1) }, "b": { "$ref": format!("#/components/schemas/s{}", n + 1) } } }));
        }
        schemas.insert("s30".into(), json!({ "type": "string" }));
        let paths: Map<String, Value> = (0..300)
            .map(|i| (format!("/q/{i}"), json!({ "post": { "requestBody": { "content": { "application/json": { "schema": { "$ref": "#/components/schemas/s0" } } } } } })))
            .collect();
        let bomb = json!({ "openapi": "3.0.0", "paths": paths, "components": { "schemas": schemas } });
        let start = std::time::Instant::now();
        let i = read(&bomb, &z, None).unwrap();
        assert!(start.elapsed() < std::time::Duration::from_secs(5));
        assert_eq!(i.operations.len(), 300);
        assert!(i.operations.iter().all(|o| o.get("request_body_schema").is_none()));
        assert_eq!(i.notes.len(), MAX_NOTES + 1);
        assert!(i.notes.last().unwrap().starts_with("... and "));
    }

    #[tokio::test]
    async fn an_upload_adds_and_updates_operations_but_never_deletes_one() {
        let store = temp_store();
        let z = store.create_zone("example.com").unwrap().id;
        let kept = store.save_item::<ApiOperation>(&z, None, json!({ "method": "GET", "host": "example.com", "endpoint": "/kept" }), true).unwrap();
        let first = json!({ "openapi": "3.0.0", "paths": { "/users/{id}": { "get": {}, "put": { "requestBody": { "content": { "application/json": { "schema": { "type": "object" } } } } } } } });
        let v = upload(&store, &z, &serde_json::to_vec(&first).unwrap(), None).await.unwrap();
        assert_eq!((v["created"].clone(), v["updated"].clone()), (json!(2), json!(0)));
        assert_eq!(v["operations"].as_array().unwrap().len(), 2);
        let put_id = v["operations"][1]["operation_id"].clone();
        let again = json!({ "openapi": "3.0.0", "paths": { "/users/{user}": { "put": {} } } });
        let v = upload(&store, &z, &serde_json::to_vec(&again).unwrap(), None).await.unwrap();
        assert_eq!((v["created"].clone(), v["updated"].clone()), (json!(0), json!(1)));
        assert_eq!(v["operations"][0]["operation_id"], put_id, "the same operation, updated");
        assert!(v["operations"][0].get("request_body_schema").is_none(), "the new document has no body for it");
        let ops = store.items::<ApiOperation>(&z).unwrap();
        assert_eq!(ops.len(), 3);
        assert!(ops.iter().any(|o| o.meta.id == kept.meta.id));

        for (bad, why) in [
            (b"openapi: 3.0.0\npaths: {}".to_vec(), "YAML"),
            (b"{\"openapi\": ".to_vec(), "not valid JSON"),
            (vec![b' '; MAX_DOCUMENT + 1], "at most"),
            (br#"{"openapi":"3.0.0","servers":[{"url":"https://example.net"}],"paths":{}}"#.to_vec(), "no server"),
        ] {
            let e = upload(&store, &z, &bad, None).await.unwrap_err();
            assert!(matches!(&e, StoreError::Invalid(m) if m.contains(why)), "{why}: {e:?}");
        }
        assert!(matches!(upload(&store, &z, br#"{"openapi":"3.0.0","paths":{}}"#, Some("bad host!")).await, Err(StoreError::Invalid(_))));
        assert!(matches!(upload(&store, "no-such-zone", b"{}", None).await, Err(StoreError::ZoneNotFound)));
        // a host of the zone that another zone serves fails the whole upload
        store.create_zone("inner.example.com").unwrap();
        let inner = json!({ "openapi": "3.0.0", "servers": [{ "url": "https://example.com" }, { "url": "https://a.inner.example.com" }], "paths": { "/new": { "get": {} } } });
        assert!(upload(&store, &z, &serde_json::to_vec(&inner).unwrap(), None).await.is_err());
        assert_eq!(store.items::<ApiOperation>(&z).unwrap().len(), 3, "all or nothing");
    }
}
