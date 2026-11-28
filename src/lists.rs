//! IP lists: named, reusable sets of addresses and networks, written into
//! rule expressions as `ip.src in $office` (crate::expr), managed like
//! Cloudflare's account-level lists (`/accounts/{id}/rules/lists`).
//!
//! A list is a global object stored with the configuration and replicated
//! with it. Its name is what rules use, so the name is resolved when the
//! snapshot is built: a rule compiled then holds the list's addresses as an
//! [`IpSet`], and the next change to the list builds a new snapshot in which
//! the rule sees the new addresses. A name no list has matches no address.
//!
//! Because rules hold names, not ids, a list that a rule uses cannot be
//! deleted or renamed (409): either would silently change what the rule
//! does, and `not ip.src in $office` would start to match everybody. For the
//! same reason a rule may only be saved with lists that exist.
//!
//! Only IP lists are kept (Cloudflare also has hostname, ASN and redirect
//! lists); anything else is refused by name rather than ignored.

use crate::expr::Expr;
use crate::items::Meta;
use crate::store::{now, Data, Store, StoreError};
use crate::sync::SyncMeta;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, LazyLock, Mutex};

/// Longest list name (Cloudflare's limit too).
pub const MAX_NAME: usize = 50;
/// Longest description and item comment, in characters.
pub const MAX_TEXT: usize = 500;
/// Most items one list holds: enough for an office or a provider's ranges,
/// small enough that compiling every rule's lists stays quick.
pub const MAX_ITEMS: usize = 10_000;
/// Most lists there can be.
pub const MAX_LISTS: usize = 100;

/// A list as it is stored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpList {
    pub id: String,
    /// What expressions call it: `$name`.
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub items: Vec<ListItem>,
    pub created_on: String,
    pub modified_on: String,
    #[serde(default, skip_serializing_if = "SyncMeta::is_unset")]
    pub sync: SyncMeta,
}

/// One address or network of a list.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ListItem {
    pub id: String,
    /// Normalized: a single address without a prefix length, a network as
    /// `address/prefix` with no host bits set.
    pub ip: String,
    #[serde(default)]
    pub comment: String,
    pub created_on: String,
    pub modified_on: String,
}

/// The addresses of one list, as closed ranges sorted and merged so that a
/// lookup is one binary search however long the list is.
#[derive(Debug, Default)]
pub struct IpSet {
    /// IPv4 ranges, held in the low 32 bits.
    v4: Vec<(u128, u128)>,
    v6: Vec<(u128, u128)>,
}

/// What `$name` stands for, by list name, when a snapshot is built.
pub type ListSets = HashMap<String, Arc<IpSet>>;

impl IpSet {
    fn new(nets: impl IntoIterator<Item = (IpAddr, u8)>) -> IpSet {
        let (mut v4, mut v6) = (Vec::new(), Vec::new());
        for (ip, prefix) in nets {
            match ip {
                IpAddr::V4(a) => v4.push(range(u32::from(a).into(), prefix, 32)),
                IpAddr::V6(a) => v6.push(range(u128::from(a), prefix, 128)),
            }
        }
        IpSet { v4: merge(v4), v6: merge(v6) }
    }

    /// Is `ip` in one of the ranges? An IPv4-mapped IPv6 address counts as
    /// the IPv4 address it carries, as `ip.src in {...}` does.
    pub fn contains(&self, ip: IpAddr) -> bool {
        let (ranges, x) = match ip {
            IpAddr::V4(a) => (&self.v4, u128::from(u32::from(a))),
            IpAddr::V6(a) => match a.to_ipv4_mapped() {
                Some(m) => (&self.v4, u128::from(u32::from(m))),
                None => (&self.v6, u128::from(a)),
            },
        };
        let i = ranges.partition_point(|r| r.0 <= x);
        i > 0 && ranges[i - 1].1 >= x
    }
}

/// The closed range a network covers.
fn range(bits: u128, prefix: u8, width: u32) -> (u128, u128) {
    let host = width - u32::from(prefix).min(width);
    let span = if host >= 128 { u128::MAX } else { (1u128 << host) - 1 };
    let low = bits & !span;
    (low, low | span)
}

fn merge(mut ranges: Vec<(u128, u128)>) -> Vec<(u128, u128)> {
    ranges.sort_unstable();
    let mut out: Vec<(u128, u128)> = Vec::with_capacity(ranges.len());
    for (low, high) in ranges {
        match out.last_mut() {
            Some(last) if low <= last.1.saturating_add(1) => last.1 = last.1.max(high),
            _ => out.push((low, high)),
        }
    }
    out
}

/// The sets every list name stands for. Two lists can only share a name
/// when two peers created them at once; then the older one (by creation,
/// then id) is the one rules see, the same on every node.
pub fn sets(lists: &[IpList]) -> ListSets {
    let mut ordered: Vec<&IpList> = lists.iter().collect();
    ordered.sort_by(|a, b| (&a.created_on, &a.id).cmp(&(&b.created_on, &b.id)));
    let mut out = ListSets::new();
    for l in ordered {
        out.entry(l.name.clone()).or_insert_with(|| Arc::new(IpSet::new(l.items.iter().filter_map(|i| parse_ip(&i.ip).ok()))));
    }
    out
}

/// Lowercase letters, digits and underscores, 1 to [`MAX_NAME`] of them.
pub fn valid_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= MAX_NAME && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// An item's address or network, strictly: no host bits set (a network
/// written with them is more likely a typo than meant), no IPv4-mapped IPv6
/// (it would be matched as IPv4 anyway, so it is to be written that way).
fn parse_ip(s: &str) -> Result<(IpAddr, u8), String> {
    let (addr, prefix) = match s.split_once('/') {
        Some((a, p)) => {
            // `u8::from_str` takes a leading '+'; a prefix is plain digits
            if p.is_empty() || p.len() > 3 || !p.bytes().all(|b| b.is_ascii_digit()) {
                return Err(format!("'{s}' is not an IP address or CIDR network"));
            }
            (a, Some(p.parse::<u8>().map_err(|_| format!("'{s}' is not an IP address or CIDR network"))?))
        }
        None => (s, None),
    };
    let ip: IpAddr = addr.parse().map_err(|_| format!("'{s}' is not an IP address or CIDR network"))?;
    if let IpAddr::V6(a) = ip {
        if let Some(v4) = a.to_ipv4_mapped() {
            return Err(format!("'{s}' is an IPv4-mapped address: write it as {v4}"));
        }
    }
    let width: u8 = if ip.is_ipv4() { 32 } else { 128 };
    let prefix = prefix.unwrap_or(width);
    if prefix > width {
        return Err(format!("'{s}': the prefix length is at most {width}"));
    }
    let network = match ip {
        IpAddr::V4(a) => IpAddr::V4(((range(u32::from(a).into(), prefix, 32).0) as u32).into()),
        IpAddr::V6(a) => IpAddr::V6(range(u128::from(a), prefix, 128).0.into()),
    };
    if network != ip {
        return Err(format!("'{s}' has host bits set: the network is {network}/{prefix}"));
    }
    Ok((ip, prefix))
}

/// An item's address or network as it is stored.
fn normalize_ip(s: &str) -> Result<String, String> {
    let (ip, prefix) = parse_ip(s.trim())?;
    let width = if ip.is_ipv4() { 32 } else { 128 };
    Ok(if prefix == width { ip.to_string() } else { format!("{ip}/{prefix}") })
}

// ------------------------------------------------------- references ----

/// A rule that uses a list.
#[derive(Debug, Clone, PartialEq)]
pub struct Ref {
    pub kind: &'static str,
    /// The zone's name (its id if the zone is gone).
    pub zone: String,
    pub id: String,
}

/// The rules of every zone that name each list, by list name. Disabled
/// rules count: switching one back on must not find its list gone.
pub fn references(d: &Data) -> HashMap<String, Vec<Ref>> {
    let zone = |id: &str| d.zones.iter().find(|z| z.id == id).map(|z| z.name.clone()).unwrap_or_else(|| id.to_string());
    let mut out: HashMap<String, Vec<Ref>> = HashMap::new();
    let mut add = |kind: &'static str, meta: &Meta, expression: &str| {
        if !expression.contains('$') {
            return;
        }
        let Ok(e) = Expr::parse(expression) else { return };
        for name in e.lists() {
            out.entry(name.to_string()).or_default().push(Ref { kind, zone: zone(&meta.zone_id), id: meta.id.clone() });
        }
    };
    for r in &d.firewall_rules {
        add("firewall rule", &r.meta, &r.expression);
    }
    for r in &d.rate_limits {
        add("rate limit", &r.meta, &r.expression);
    }
    for r in &d.origin_rules {
        add("origin rule", &r.meta, &r.expression);
    }
    for r in &d.redirect_rules {
        add("redirect rule", &r.meta, &r.expression);
    }
    for r in &d.transform_rules {
        add("transform rule", &r.meta, &r.expression);
    }
    for r in &d.cache_rules {
        add("cache rule", &r.meta, &r.expression);
    }
    out
}

/// A rule may only be saved with lists that exist (see the module docs).
pub fn check_refs(expr: &Expr, d: &Data) -> Result<(), String> {
    match expr.lists().into_iter().find(|name| !d.ip_lists.iter().any(|l| l.name == *name)) {
        Some(name) => Err(format!("there is no IP list named '{name}' (create it under /rules/lists first)")),
        None => Ok(()),
    }
}

/// "firewall rule 1a2b... in example.com, ..." for an error message.
fn describe(refs: &[Ref]) -> String {
    const SHOWN: usize = 5;
    let mut s = refs.iter().take(SHOWN).map(|r| format!("{} {} in {}", r.kind, r.id, r.zone)).collect::<Vec<_>>().join(", ");
    if refs.len() > SHOWN {
        s.push_str(&format!(" and {} more", refs.len() - SHOWN));
    }
    s
}

fn in_use(d: &Data, name: &str) -> Option<Vec<Ref>> {
    references(d).remove(name).filter(|r| !r.is_empty())
}

// ------------------------------------------------------------- bodies ----

fn invalid<T>(msg: impl Into<String>) -> Result<T, StoreError> {
    Err(StoreError::Invalid(msg.into()))
}

fn new_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

/// A JSON object whose fields are all in `allowed`.
fn object(v: Value, at: &str, allowed: &[&str]) -> Result<Map<String, Value>, StoreError> {
    let Value::Object(m) = v else { return invalid(format!("{at} must be a JSON object")) };
    if let Some(k) = m.keys().find(|k| !allowed.contains(&k.as_str())) {
        return match k.as_str() {
            "items" => invalid("items are changed through /rules/lists/{list_id}/items"),
            "hostname" | "asn" | "redirect" => invalid(format!("{at}.{k}: only IP lists are kept here")),
            _ => invalid(format!("{at}.{k} is not a field here (allowed: {})", allowed.join(", "))),
        };
    }
    Ok(m)
}

/// A string field (null counts as absent), at most [`MAX_TEXT`] characters.
fn text(m: &Map<String, Value>, key: &str, at: &str) -> Result<Option<String>, StoreError> {
    match m.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if s.chars().count() > MAX_TEXT => invalid(format!("{at}.{key} is longer than {MAX_TEXT} characters")),
        Some(Value::String(s)) => Ok(Some(s.trim().to_string())),
        Some(_) => invalid(format!("{at}.{key} must be a string")),
    }
}

/// The fields of a list in a create or update body.
struct ListFields {
    name: Option<String>,
    description: Option<String>,
}

fn list_fields(body: Value) -> Result<ListFields, StoreError> {
    let m = object(body, "body", &["name", "description", "kind"])?;
    match m.get("kind") {
        None | Some(Value::Null) => {}
        Some(Value::String(k)) if k == "ip" => {}
        Some(_) => return invalid("kind: only IP lists (\"ip\") are kept here"),
    }
    let name = match m.get("name") {
        None | Some(Value::Null) => None,
        Some(Value::String(n)) if valid_name(n) => Some(n.clone()),
        Some(_) => return invalid(format!("name: lowercase letters, digits and underscores, 1 to {MAX_NAME} of them")),
    };
    Ok(ListFields { name, description: text(&m, "description", "body")? })
}

/// One item of an append or replace body, checked.
struct NewItem {
    ip: String,
    comment: Option<String>,
}

/// The items of an append or replace body: a JSON array, as Cloudflare's.
/// The same address twice in one request is refused; it says nothing the
/// first one did not, and with two comments it is unclear which is meant.
fn new_items(body: Value) -> Result<Vec<NewItem>, StoreError> {
    let Value::Array(items) = body else { return invalid("the body must be a JSON array of items, like [{\"ip\": \"192.0.2.1\"}]") };
    if items.len() > MAX_ITEMS {
        return invalid(format!("a list holds at most {MAX_ITEMS} items"));
    }
    let mut out: Vec<NewItem> = Vec::with_capacity(items.len());
    let mut seen: HashMap<String, usize> = HashMap::new();
    for (i, item) in items.into_iter().enumerate() {
        let at = format!("[{i}]");
        let m = object(item, &at, &["ip", "comment"])?;
        let ip = match m.get("ip") {
            Some(Value::String(s)) => normalize_ip(s).map_err(|e| StoreError::Invalid(format!("{at}.ip: {e}")))?,
            Some(_) => return invalid(format!("{at}.ip must be a string")),
            None => return invalid(format!("{at}.ip is missing")),
        };
        if let Some(first) = seen.insert(ip.clone(), i) {
            return invalid(format!("{at}.ip: {ip} is already given at [{first}]"));
        }
        out.push(NewItem { ip, comment: text(&m, "comment", &at)? });
    }
    Ok(out)
}

/// The ids of a delete body: `{"items": [{"id": "..."}]}`, as Cloudflare's.
fn item_ids(body: Value) -> Result<Vec<String>, StoreError> {
    let m = object(body, "body", &["items"])?;
    let Some(Value::Array(items)) = m.get("items") else { return invalid("the body must be {\"items\": [{\"id\": \"...\"}]}") };
    if items.is_empty() {
        return invalid("items: no item to delete was given");
    }
    let mut ids: Vec<String> = Vec::with_capacity(items.len());
    for (i, item) in items.iter().enumerate() {
        let at = format!("items[{i}]");
        let m = object(item.clone(), &at, &["id"])?;
        let Some(Value::String(id)) = m.get("id") else { return invalid(format!("{at}.id must be a string")) };
        if ids.contains(id) {
            return invalid(format!("{at}.id: {id} is given twice"));
        }
        ids.push(id.clone());
    }
    Ok(ids)
}

// ---------------------------------------------------------- responses ----

fn public(l: &IpList, refs: usize) -> Value {
    json!({
        "id": l.id,
        "name": l.name,
        "description": l.description,
        "kind": "ip",
        "num_items": l.items.len(),
        "num_referencing_filters": refs,
        "created_on": l.created_on,
        "modified_on": l.modified_on,
    })
}

fn public_item(i: &ListItem) -> Value {
    let mut v = json!({ "id": i.id, "ip": i.ip, "created_on": i.created_on, "modified_on": i.modified_on });
    if !i.comment.is_empty() {
        v["comment"] = json!(i.comment);
    }
    v
}

fn found(d: &Data, id: &str) -> Result<IpList, StoreError> {
    d.ip_lists.iter().find(|l| l.id == id).cloned().ok_or(StoreError::NotFound)
}

fn shown(store: &Store, list: &IpList) -> Value {
    let refs = store.inspect(|d| references(d).get(&list.name).map_or(0, Vec::len));
    public(list, refs)
}

/// Item changes answer with an operation id, as Cloudflare's do (where they
/// run in the background and are polled). Here they are done when the
/// answer comes; the ids are remembered so that a client polling
/// `bulk_operations` is told so. Only the latest ones, on this node.
static OPERATIONS: LazyLock<Mutex<VecDeque<(String, String)>>> = LazyLock::new(Default::default);
const KEPT_OPERATIONS: usize = 1024;

fn operation_done() -> Value {
    let id = new_id();
    let mut ops = OPERATIONS.lock().unwrap();
    if ops.len() >= KEPT_OPERATIONS {
        ops.pop_front();
    }
    ops.push_back((id.clone(), now()));
    json!({ "operation_id": id })
}

// ---------------------------------------------------------------- API ----

/// `GET /rules/lists`, by name.
pub fn list(store: &Store) -> Value {
    store.inspect(|d| {
        let refs = references(d);
        let mut lists: Vec<&IpList> = d.ip_lists.iter().collect();
        lists.sort_by(|a, b| a.name.cmp(&b.name));
        Value::Array(lists.into_iter().map(|l| public(l, refs.get(&l.name).map_or(0, Vec::len))).collect())
    })
}

/// `GET /rules/lists/{id}`.
pub fn get(store: &Store, id: &str) -> Result<Value, StoreError> {
    store.inspect(|d| {
        let l = found(d, id)?;
        Ok(public(&l, references(d).get(&l.name).map_or(0, Vec::len)))
    })
}

/// `POST /rules/lists`: `name` (required), `description`, `kind` ("ip").
pub async fn create(store: &Store, body: Value) -> Result<Value, StoreError> {
    let f = list_fields(body)?;
    let Some(name) = f.name else { return invalid("name is missing") };
    let saved = store
        .change_ip_list_async(None, move |d, _| {
            if d.ip_lists.len() >= MAX_LISTS {
                return invalid(format!("there can be at most {MAX_LISTS} lists"));
            }
            if d.ip_lists.iter().any(|l| l.name == name) {
                return Err(StoreError::Conflict(format!("a list named '{name}' already exists")));
            }
            let ts = now();
            Ok(Some(IpList {
                id: new_id(),
                name,
                description: f.description.unwrap_or_default(),
                items: Vec::new(),
                created_on: ts.clone(),
                modified_on: ts,
                sync: SyncMeta::default(),
            }))
        })
        .await?
        .ok_or(StoreError::NotFound)?;
    Ok(shown(store, &saved))
}

/// `PUT` / `PATCH /rules/lists/{id}`: what is given of `name` and
/// `description` is changed. A rename is refused while rules use the name.
pub async fn update(store: &Store, id: &str, body: Value) -> Result<Value, StoreError> {
    let f = list_fields(body)?;
    let saved = store
        .change_ip_list_async(Some(id.to_string()), move |d, current| {
            let Some(current) = current else { return Err(StoreError::NotFound) };
            let mut l = current.clone();
            if let Some(name) = f.name.filter(|n| *n != l.name) {
                if d.ip_lists.iter().any(|o| o.id != l.id && o.name == name) {
                    return Err(StoreError::Conflict(format!("a list named '{name}' already exists")));
                }
                if let Some(refs) = in_use(d, &l.name) {
                    return Err(StoreError::Conflict(format!(
                        "list '{}' cannot be renamed while rules use it: {}",
                        l.name,
                        describe(&refs)
                    )));
                }
                l.name = name;
            }
            if let Some(description) = f.description {
                l.description = description;
            }
            l.modified_on = now();
            Ok(Some(l))
        })
        .await?
        .ok_or(StoreError::NotFound)?;
    Ok(shown(store, &saved))
}

/// `DELETE /rules/lists/{id}`, refused while rules use the list.
pub async fn delete(store: &Store, id: &str) -> Result<Value, StoreError> {
    store
        .change_ip_list_async(Some(id.to_string()), |d, current| {
            let Some(current) = current else { return Err(StoreError::NotFound) };
            match in_use(d, &current.name) {
                Some(refs) => Err(StoreError::Conflict(format!(
                    "list '{}' is used by {}; change those rules first",
                    current.name,
                    describe(&refs)
                ))),
                None => Ok(None),
            }
        })
        .await?;
    Ok(json!({ "id": id }))
}

/// `GET /rules/lists/{id}/items`, all of them, optionally only those whose
/// address or comment contains `search` (any case).
pub fn items(store: &Store, id: &str, search: Option<&str>) -> Result<Value, StoreError> {
    let l = store.inspect(|d| found(d, id))?;
    let search = search.map(str::to_lowercase).filter(|s| !s.is_empty());
    let hit = |i: &ListItem| search.as_ref().is_none_or(|s| i.ip.contains(s.as_str()) || i.comment.to_lowercase().contains(s.as_str()));
    Ok(Value::Array(l.items.iter().filter(|i| hit(i)).map(public_item).collect()))
}

/// `GET /rules/lists/{id}/items/{item_id}`.
pub fn item(store: &Store, id: &str, item_id: &str) -> Result<Value, StoreError> {
    let l = store.inspect(|d| found(d, id))?;
    l.items.iter().find(|i| i.id == item_id).map(public_item).ok_or(StoreError::NotFound)
}

/// `POST /rules/lists/{id}/items`: adds the items. An address the list
/// already has keeps its id; its comment is replaced if one is given.
pub async fn append_items(store: &Store, id: &str, body: Value) -> Result<Value, StoreError> {
    let new = new_items(body)?;
    if new.is_empty() {
        return invalid("no item to add was given");
    }
    store
        .change_ip_list_async(Some(id.to_string()), move |_, current| {
            let Some(current) = current else { return Err(StoreError::NotFound) };
            let mut l = current.clone();
            let ts = now();
            for n in new {
                match l.items.iter_mut().find(|i| i.ip == n.ip) {
                    Some(old) => {
                        if let Some(c) = n.comment {
                            old.comment = c;
                            old.modified_on = ts.clone();
                        }
                    }
                    None => l.items.push(ListItem {
                        id: new_id(),
                        ip: n.ip,
                        comment: n.comment.unwrap_or_default(),
                        created_on: ts.clone(),
                        modified_on: ts.clone(),
                    }),
                }
            }
            if l.items.len() > MAX_ITEMS {
                return invalid(format!("a list holds at most {MAX_ITEMS} items; this one would hold {}", l.items.len()));
            }
            l.modified_on = ts;
            Ok(Some(l))
        })
        .await?;
    Ok(operation_done())
}

/// `PUT /rules/lists/{id}/items`: the list holds exactly these items
/// afterwards (none, for `[]`). Addresses it had already keep their ids.
pub async fn replace_items(store: &Store, id: &str, body: Value) -> Result<Value, StoreError> {
    let new = new_items(body)?;
    store
        .change_ip_list_async(Some(id.to_string()), move |_, current| {
            let Some(current) = current else { return Err(StoreError::NotFound) };
            let mut l = current.clone();
            let ts = now();
            l.items = new
                .into_iter()
                .map(|n| {
                    let comment = n.comment.unwrap_or_default();
                    match current.items.iter().find(|i| i.ip == n.ip) {
                        Some(old) if old.comment == comment => old.clone(),
                        Some(old) => ListItem { comment, modified_on: ts.clone(), ..old.clone() },
                        None => ListItem { id: new_id(), ip: n.ip, comment, created_on: ts.clone(), modified_on: ts.clone() },
                    }
                })
                .collect();
            l.modified_on = ts;
            Ok(Some(l))
        })
        .await?;
    Ok(operation_done())
}

/// `DELETE /rules/lists/{id}/items` with `{"items": [{"id": "..."}]}`.
/// All or nothing: an id the list does not have fails the whole request.
pub async fn delete_items(store: &Store, id: &str, body: Value) -> Result<Value, StoreError> {
    let ids = item_ids(body)?;
    store
        .change_ip_list_async(Some(id.to_string()), move |_, current| {
            let Some(current) = current else { return Err(StoreError::NotFound) };
            if let Some((i, missing)) = ids.iter().enumerate().find(|(_, id)| !current.items.iter().any(|item| &item.id == *id)) {
                return invalid(format!("items[{i}].id: this list has no item {missing}"));
            }
            let mut l = current.clone();
            l.items.retain(|item| !ids.contains(&item.id));
            l.modified_on = now();
            Ok(Some(l))
        })
        .await?;
    Ok(operation_done())
}

/// `GET /rules/lists/bulk_operations/{operation_id}`.
pub fn operation(id: &str) -> Result<Value, StoreError> {
    let ops = OPERATIONS.lock().unwrap();
    let (id, at) = ops.iter().find(|(op, _)| op == id).ok_or(StoreError::NotFound)?;
    Ok(json!({ "id": id, "status": "completed", "completed": at }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::expr::ReqInfo;
    use crate::items::FirewallRule;

    fn setup() -> (Arc<Store>, String) {
        let dir = std::env::temp_dir().join(format!("fucf-lists-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = Arc::new(Store::open(&dir.join("store.json"), vec![]).unwrap());
        let zone = store.create_zone("example.com").unwrap();
        (store, zone.id)
    }

    fn err(r: Result<Value, StoreError>) -> String {
        match r {
            Err(StoreError::Invalid(m)) => m,
            Err(StoreError::Conflict(m)) => format!("conflict: {m}"),
            Err(e) => format!("{e:?}"),
            Ok(v) => panic!("expected an error, got {v}"),
        }
    }

    fn set(items: &[&str]) -> IpSet {
        IpSet::new(items.iter().map(|s| parse_ip(s).unwrap()))
    }

    fn has(s: &IpSet, ip: &str) -> bool {
        s.contains(ip.parse().unwrap())
    }

    /// Does the zone's first compiled firewall rule match a visitor at `ip`?
    fn blocks(store: &Store, ip: &str) -> bool {
        let snap = store.snapshot();
        let zs = snap.find_zone("example.com").unwrap();
        let info = ReqInfo { ip: Some(ip.parse().unwrap()), ..Default::default() };
        zs.firewall.first().is_some_and(|(_, e)| e.matches(&info))
    }

    #[test]
    fn addresses_and_networks_are_normalized_or_refused() {
        assert_eq!(normalize_ip("192.0.2.1").unwrap(), "192.0.2.1");
        assert_eq!(normalize_ip(" 192.0.2.1/32 ").unwrap(), "192.0.2.1");
        assert_eq!(normalize_ip("198.51.100.0/24").unwrap(), "198.51.100.0/24");
        assert_eq!(normalize_ip("2001:DB8:0:0::/32").unwrap(), "2001:db8::/32");
        assert_eq!(normalize_ip("2001:db8::1/128").unwrap(), "2001:db8::1");
        assert_eq!(normalize_ip("0.0.0.0/0").unwrap(), "0.0.0.0/0");
        assert_eq!(normalize_ip("::/0").unwrap(), "::/0");
        assert_eq!(normalize_ip("203.0.113.0/024").unwrap(), "203.0.113.0/24");
        for bad in [
            "",
            "/24",
            "192.0.2.1/",
            "192.0.2.1/+8",
            "192.0.2.1/-1",
            "192.0.2.1/33",
            "2001:db8::/129",
            "192.0.2.1/24",
            "2001:db8::1/32",
            "192.0.2",
            "192.0.2.256",
            "192.000.2.1",
            "example.com",
            "192.0.2.1 198.51.100.1",
            "::ffff:192.0.2.1",
            "2001:db8::1%eth0",
            "192.0.2.0/24/8",
        ] {
            assert!(normalize_ip(bad).is_err(), "{bad:?} should be refused");
        }
        assert!(normalize_ip("192.0.2.1/24").unwrap_err().contains("192.0.2.0/24"), "the error names the network");
    }

    #[test]
    fn names_are_lowercase_letters_digits_and_underscores() {
        for good in ["office", "a", "office_2", "0day", &"x".repeat(MAX_NAME)] {
            assert!(valid_name(good), "{good}");
        }
        for bad in ["", "Office", "office-2", "office.2", "office 2", "办公室", &"x".repeat(MAX_NAME + 1)] {
            assert!(!valid_name(bad), "{bad}");
        }
    }

    #[test]
    fn a_set_matches_its_addresses_and_networks_on_both_families() {
        let s = set(&["192.0.2.1", "198.51.100.0/24", "203.0.113.64/27", "203.0.113.96/27", "2001:db8:1::/48", "2001:db8::5"]);
        assert!(has(&s, "192.0.2.1"));
        assert!(!has(&s, "192.0.2.2") && !has(&s, "192.0.2.0"));
        assert!(has(&s, "198.51.100.0") && has(&s, "198.51.100.255") && has(&s, "203.0.113.64") && has(&s, "203.0.113.127"), "adjacent networks are merged");
        assert!(!has(&s, "203.0.113.63") && !has(&s, "203.0.113.128"));
        assert_eq!(s.v4.len(), 3, "the two /27s are one range");
        assert!(has(&s, "2001:db8:1:ffff::1") && has(&s, "2001:db8::5"));
        assert!(!has(&s, "2001:db8:2::1") && !has(&s, "2001:db8::6"));
        assert!(has(&s, "::ffff:192.0.2.1"), "a mapped address is its IPv4 address");
        assert!(!has(&s, "::c000:201"), "the IPv4 range is not looked up for IPv6 addresses");
        let all = set(&["0.0.0.0/0", "::/0"]);
        assert!(has(&all, "203.0.113.9") && has(&all, "2001:db8::9") && has(&all, "255.255.255.255") && has(&all, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"));
        assert!(!has(&IpSet::default(), "192.0.2.1"));
        let nested = set(&["203.0.113.0/24", "203.0.113.128/25", "203.0.113.7"]);
        assert_eq!(nested.v4.len(), 1);
        assert!(has(&nested, "203.0.113.200"));
    }

    #[tokio::test]
    async fn lists_are_created_read_renamed_and_deleted() {
        let (store, _) = setup();
        let made = create(&store, json!({ "name": "office", "description": "the office", "kind": "ip" })).await.unwrap();
        let id = made["id"].as_str().unwrap().to_string();
        assert_eq!((made["name"].as_str(), made["kind"].as_str(), made["num_items"].as_u64()), (Some("office"), Some("ip"), Some(0)));
        assert_eq!(get(&store, &id).unwrap()["description"], "the office");
        assert_eq!(list(&store).as_array().unwrap().len(), 1);

        assert!(err(create(&store, json!({ "name": "office" })).await).starts_with("conflict"), "names are unique");
        assert!(err(create(&store, json!({ "description": "x" })).await).contains("name is missing"));
        for bad in [json!({ "name": "Office" }), json!({ "name": "" }), json!({ "name": 5 }), json!({ "name": "x".repeat(MAX_NAME + 1) })] {
            assert!(err(create(&store, bad.clone()).await).contains("lowercase"), "{bad}");
        }
        assert!(err(create(&store, json!({ "name": "hosts", "kind": "hostname" })).await).contains("only IP lists"));
        assert!(err(create(&store, json!({ "name": "x", "items": [] })).await).contains("/items"));
        assert!(err(create(&store, json!({ "name": "x", "colour": "red" })).await).contains("colour"));
        assert!(err(create(&store, json!({ "name": "x", "description": "d".repeat(MAX_TEXT + 1) })).await).contains("longer"));
        assert!(err(create(&store, json!(["office"])).await).contains("JSON object"));

        let renamed = update(&store, &id, json!({ "name": "head_office" })).await.unwrap();
        assert_eq!((renamed["name"].as_str(), renamed["description"].as_str()), (Some("head_office"), Some("the office")), "what is not given stays");
        let other = create(&store, json!({ "name": "branch" })).await.unwrap();
        assert!(err(update(&store, &id, json!({ "name": "branch" })).await).starts_with("conflict"));
        assert!(matches!(update(&store, "nope", json!({ "description": "x" })).await, Err(StoreError::NotFound)));
        assert!(matches!(get(&store, "nope"), Err(StoreError::NotFound)));
        assert!(matches!(delete(&store, "nope").await, Err(StoreError::NotFound)));

        delete(&store, other["id"].as_str().unwrap()).await.unwrap();
        assert_eq!(list(&store)[0]["name"], "head_office");
        assert!(store.inspect(|d| d.tombstones.ip_lists.contains_key(other["id"].as_str().unwrap())), "a deletion is replicated");
    }

    #[tokio::test]
    async fn items_are_appended_replaced_and_deleted_by_id() {
        let (store, _) = setup();
        let id = create(&store, json!({ "name": "office" })).await.unwrap()["id"].as_str().unwrap().to_string();
        let op = append_items(&store, &id, json!([{ "ip": "192.0.2.1", "comment": "door" }, { "ip": "198.51.100.0/24" }])).await.unwrap();
        let op_id = op["operation_id"].as_str().unwrap();
        assert_eq!(operation(op_id).unwrap()["status"], "completed");
        assert!(matches!(operation("nope"), Err(StoreError::NotFound)));
        let all = items(&store, &id, None).unwrap();
        assert_eq!(all.as_array().unwrap().len(), 2);
        assert_eq!((all[0]["ip"].as_str(), all[0]["comment"].as_str()), (Some("192.0.2.1"), Some("door")));
        assert!(all[1].get("comment").is_none(), "no comment, no field");
        let door = all[0]["id"].as_str().unwrap().to_string();
        assert_eq!(item(&store, &id, &door).unwrap()["ip"], "192.0.2.1");
        assert!(matches!(item(&store, &id, "nope"), Err(StoreError::NotFound)));
        assert_eq!(get(&store, &id).unwrap()["num_items"], 2);

        // the same address again keeps its id; a comment given replaces the old one
        append_items(&store, &id, json!([{ "ip": "192.0.2.1/32", "comment": "front door" }, { "ip": "2001:db8::/32" }])).await.unwrap();
        append_items(&store, &id, json!([{ "ip": "192.0.2.1" }])).await.unwrap();
        let all = items(&store, &id, None).unwrap();
        assert_eq!(all.as_array().unwrap().len(), 3);
        assert_eq!((all[0]["id"].as_str(), all[0]["comment"].as_str()), (Some(door.as_str()), Some("front door")));
        assert_eq!(items(&store, &id, Some("FRONT")).unwrap().as_array().unwrap().len(), 1);
        assert_eq!(items(&store, &id, Some("2001:db8")).unwrap().as_array().unwrap().len(), 1);

        // refused as a whole, nothing changes
        let before = items(&store, &id, None).unwrap();
        for (bad, says) in [
            (json!([{ "ip": "203.0.113.1" }, { "ip": "nonsense" }]), "[1].ip"),
            (json!([{ "ip": "203.0.113.1" }, { "ip": "203.0.113.1/32" }]), "already given at [0]"),
            (json!([{ "ip": "203.0.113.1/24" }]), "host bits"),
            (json!([{ "comment": "x" }]), "[0].ip is missing"),
            (json!([{ "ip": 1 }]), "must be a string"),
            (json!([{ "ip": "203.0.113.1", "comment": 7 }]), "comment must be a string"),
            (json!([{ "ip": "203.0.113.1", "id": "x" }]), "[0].id is not a field"),
            (json!([{ "hostname": { "url_hostname": "example.com" } }]), "only IP lists"),
            (json!({ "ip": "203.0.113.1" }), "JSON array"),
            (json!([]), "no item to add"),
            (json!(["203.0.113.1"]), "JSON object"),
        ] {
            assert!(err(append_items(&store, &id, bad.clone()).await).contains(says), "{bad} should say {says}");
        }
        assert_eq!(items(&store, &id, None).unwrap(), before);
        assert!(matches!(append_items(&store, "nope", json!([{ "ip": "203.0.113.1" }])).await, Err(StoreError::NotFound)));

        // replace: exactly these afterwards, known addresses keep their ids
        replace_items(&store, &id, json!([{ "ip": "203.0.113.0/24" }, { "ip": "192.0.2.1", "comment": "front door" }])).await.unwrap();
        let all = items(&store, &id, None).unwrap();
        let ips: Vec<&str> = all.as_array().unwrap().iter().map(|i| i["ip"].as_str().unwrap()).collect();
        assert_eq!(ips, ["203.0.113.0/24", "192.0.2.1"]);
        assert_eq!(all[1]["id"].as_str(), Some(door.as_str()));
        let net = all[0]["id"].as_str().unwrap().to_string();

        // delete by id, all or nothing
        for (bad, says) in [
            (json!({ "items": [{ "id": net }, { "id": "nope" }] }), "items[1].id"),
            (json!({ "items": [{ "id": net }, { "id": net }] }), "twice"),
            (json!({ "items": [] }), "no item to delete"),
            (json!({ "items": [{ "ip": "192.0.2.1" }] }), "items[0].ip is not a field"),
            (json!({ "items": [{ "id": 5 }] }), "must be a string"),
            (json!([{ "id": net }]), "JSON object"),
            (json!({}), "the body must be"),
        ] {
            assert!(err(delete_items(&store, &id, bad.clone()).await).contains(says), "{bad} should say {says}");
        }
        assert_eq!(items(&store, &id, None).unwrap().as_array().unwrap().len(), 2);
        delete_items(&store, &id, json!({ "items": [{ "id": net }] })).await.unwrap();
        assert_eq!(items(&store, &id, None).unwrap()[0]["id"].as_str(), Some(door.as_str()));
        replace_items(&store, &id, json!([])).await.unwrap();
        assert_eq!(get(&store, &id).unwrap()["num_items"], 0);
    }

    #[tokio::test]
    async fn a_list_holds_at_most_so_many_items() {
        let (store, _) = setup();
        let id = create(&store, json!({ "name": "big" })).await.unwrap()["id"].as_str().unwrap().to_string();
        let many = |from: u32, n: u32| Value::Array((from..from + n).map(|i| json!({ "ip": format!("2001:db8::{i:x}") })).collect());
        replace_items(&store, &id, many(0, MAX_ITEMS as u32)).await.unwrap();
        assert_eq!(get(&store, &id).unwrap()["num_items"], MAX_ITEMS);
        assert!(err(append_items(&store, &id, many(MAX_ITEMS as u32, 1)).await).contains("at most"));
        assert!(err(replace_items(&store, &id, many(0, MAX_ITEMS as u32 + 1)).await).contains("at most"));
        append_items(&store, &id, many(0, 1)).await.unwrap();
        assert_eq!(get(&store, &id).unwrap()["num_items"], MAX_ITEMS, "an address it has already does not count twice");
    }

    #[tokio::test]
    async fn there_are_at_most_so_many_lists() {
        let (store, _) = setup();
        for i in 0..MAX_LISTS {
            create(&store, json!({ "name": format!("l{i}") })).await.unwrap();
        }
        assert!(err(create(&store, json!({ "name": "one_more" })).await).contains("at most"));
    }

    #[tokio::test]
    async fn rules_follow_their_list_and_a_used_list_cannot_be_deleted_or_renamed() {
        let (store, zone) = setup();
        let id = create(&store, json!({ "name": "office" })).await.unwrap()["id"].as_str().unwrap().to_string();
        let rule = json!({ "expression": "ip.src in $office", "action": "block" });
        let saved: FirewallRule = store.save_item_async(&zone, None, rule, true).await.unwrap();
        assert!(!blocks(&store, "192.0.2.1"), "an empty list matches nothing");

        append_items(&store, &id, json!([{ "ip": "192.0.2.0/24" }, { "ip": "2001:db8::/32" }])).await.unwrap();
        assert!(blocks(&store, "192.0.2.77") && blocks(&store, "2001:db8::77") && blocks(&store, "::ffff:192.0.2.77"));
        assert!(!blocks(&store, "198.51.100.1"));
        replace_items(&store, &id, json!([{ "ip": "198.51.100.1" }])).await.unwrap();
        assert!(!blocks(&store, "192.0.2.77"), "the rule follows the list");
        assert!(blocks(&store, "198.51.100.1"));

        assert_eq!(get(&store, &id).unwrap()["num_referencing_filters"], 1);
        let e = err(delete(&store, &id).await);
        assert!(e.starts_with("conflict") && e.contains(&saved.meta.id) && e.contains("example.com"), "{e}");
        assert!(err(update(&store, &id, json!({ "name": "elsewhere" })).await).starts_with("conflict"));
        update(&store, &id, json!({ "name": "office", "description": "same name is fine" })).await.unwrap();
        assert!(blocks(&store, "198.51.100.1"));

        // disabled rules still hold on to their list
        store.save_item_async::<FirewallRule>(&zone, Some(&saved.meta.id), json!({ "enabled": false }), false).await.unwrap();
        assert!(err(delete(&store, &id).await).starts_with("conflict"));

        // a rule may not name a list that does not exist
        let e = store.save_item_async::<FirewallRule>(&zone, None, json!({ "expression": "ip.src in $nowhere", "action": "block" }), true).await;
        assert!(matches!(&e, Err(StoreError::Invalid(m)) if m.contains("nowhere")), "{e:?}");

        // once the rule lets go, the list can go
        store.delete_item_async::<FirewallRule>(&zone, &saved.meta.id).await.unwrap();
        assert_eq!(get(&store, &id).unwrap()["num_referencing_filters"], 0);
        update(&store, &id, json!({ "name": "renamed" })).await.unwrap();
        delete(&store, &id).await.unwrap();
        assert!(list(&store).as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn every_rule_type_with_an_expression_holds_on_to_its_list() {
        use crate::items::{CacheRule, OriginRule, RateLimit, RedirectRule, TransformRule};
        let (store, zone) = setup();
        let other = store.create_zone("example.net").unwrap().id;
        let id = create(&store, json!({ "name": "office" })).await.unwrap()["id"].as_str().unwrap().to_string();
        let expr = "not ip.src in $office";
        store.save_item_async::<RateLimit>(&other, None, json!({ "expression": expr, "threshold": 10, "period": 60 }), true).await.unwrap();
        store.save_item_async::<OriginRule>(&zone, None, json!({ "expression": expr, "origin_host": "origin.example.com" }), true).await.unwrap();
        store.save_item_async::<RedirectRule>(&zone, None, json!({ "expression": expr, "target_url": "https://example.com/" }), true).await.unwrap();
        store.save_item_async::<TransformRule>(&zone, None, json!({ "expression": expr, "rewrite_path": "/x" }), true).await.unwrap();
        store.save_item_async::<CacheRule>(&zone, None, json!({ "expression": expr, "cache": true }), true).await.unwrap();
        let refs = store.inspect(|d| references(d).remove("office").unwrap());
        let kinds: Vec<&str> = refs.iter().map(|r| r.kind).collect();
        assert_eq!(kinds, ["rate limit", "origin rule", "redirect rule", "transform rule", "cache rule"]);
        assert_eq!(refs[0].zone, "example.net", "the rules of every zone count");
        let e = err(delete(&store, &id).await);
        assert!(e.contains("rate limit") && e.contains("cache rule"), "{e}");
        let snap = store.snapshot();
        let zs = snap.find_zone("example.com").unwrap();
        let visitor = ReqInfo { ip: Some("192.0.2.1".parse().unwrap()), ..Default::default() };
        assert!(zs.cache_rules[0].1.matches(&visitor), "not in an empty list: compiled for every rule type");
    }

    #[tokio::test]
    async fn a_list_and_its_deletion_reach_a_peer_whose_rules_follow() {
        use crate::sync::SyncProvider;
        let (a, zone) = setup();
        let dir = std::env::temp_dir().join(format!("fucf-lists-peer-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir).unwrap();
        let b = Store::open(&dir.join("store.json"), vec![]).unwrap();
        let id = create(&a, json!({ "name": "office" })).await.unwrap()["id"].as_str().unwrap().to_string();
        append_items(&a, &id, json!([{ "ip": "192.0.2.0/24" }])).await.unwrap();
        let rule: FirewallRule =
            a.save_item_async(&zone, None, json!({ "expression": "ip.src in $office", "action": "block" }), true).await.unwrap();
        let delta = a.export_since(0, None).unwrap();
        assert!(b.merge_delta(&delta, &b.clock()).unwrap());
        assert_eq!(b.inspect(|d| d.ip_lists.len()), 1);
        assert!(blocks(&b, "192.0.2.9") && !blocks(&b, "198.51.100.9"), "the peer compiles the rule with the list");

        a.delete_item_async::<FirewallRule>(&zone, &rule.meta.id).await.unwrap();
        delete(&a, &id).await.unwrap();
        let delta = a.export_since(delta.to_rev, Some(&a.epoch())).unwrap();
        assert!(!delta.full_resync);
        assert!(b.merge_delta(&delta, &b.clock()).unwrap());
        assert!(b.inspect(|d| d.ip_lists.is_empty() && d.tombstones.ip_lists.contains_key(&id)));
        assert!(!blocks(&b, "192.0.2.9"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn rules_written_through_the_rulesets_api_use_lists_the_same_way() {
        let (store, zone) = setup();
        let phase = "http_request_firewall_custom";
        let put = |expression: &str| json!({ "rules": [{ "action": "block", "expression": expression }] });
        let e = err(crate::rulesets::put_entrypoint(&store, &zone, phase, put("ip.src in $office")).await);
        assert!(e.contains("rules[0]") && e.contains("office"), "{e}");
        let id = create(&store, json!({ "name": "office" })).await.unwrap()["id"].as_str().unwrap().to_string();
        append_items(&store, &id, json!([{ "ip": "203.0.113.0/24" }])).await.unwrap();
        let rs = crate::rulesets::put_entrypoint(&store, &zone, phase, put("ip.src in $office")).await.unwrap();
        assert_eq!(rs["rules"][0]["expression"], "ip.src in $office");
        assert!(blocks(&store, "203.0.113.5") && !blocks(&store, "192.0.2.5"));
        assert!(err(delete(&store, &id).await).starts_with("conflict"));
        crate::rulesets::put_entrypoint(&store, &zone, phase, json!({ "rules": [] })).await.unwrap();
        delete(&store, &id).await.unwrap();
    }

    #[test]
    fn the_older_of_two_lists_with_one_name_is_the_one_rules_see() {
        let list = |id: &str, created: &str, ip: &str| IpList {
            id: id.into(),
            name: "office".into(),
            description: String::new(),
            items: vec![ListItem { id: "i".into(), ip: ip.into(), comment: String::new(), created_on: created.into(), modified_on: created.into() }],
            created_on: created.into(),
            modified_on: created.into(),
            sync: SyncMeta::default(),
        };
        let a = list("b", "2026-01-01T00:00:00Z", "192.0.2.1");
        let b = list("a", "2026-01-02T00:00:00Z", "198.51.100.1");
        for lists in [vec![a.clone(), b.clone()], vec![b, a]] {
            let s = sets(&lists);
            assert!(s["office"].contains("192.0.2.1".parse().unwrap()));
            assert!(!s["office"].contains("198.51.100.1".parse().unwrap()));
        }
    }

    #[test]
    fn references_name_the_rules_and_ignore_strings_that_look_like_names() {
        let (store, zone) = setup();
        let mut d = store.inspect(Data::clone);
        d.ip_lists.push(IpList {
            id: "l".into(),
            name: "office".into(),
            description: String::new(),
            items: vec![],
            created_on: String::new(),
            modified_on: String::new(),
            sync: SyncMeta::default(),
        });
        let rule = |id: &str, expression: &str| {
            let mut r: FirewallRule = serde_json::from_value(json!({ "expression": expression, "action": "block" })).unwrap();
            r.meta.id = id.into();
            r.meta.zone_id = zone.clone();
            r
        };
        d.firewall_rules.push(rule("r1", r#"http.request.uri.path contains "$office""#));
        d.firewall_rules.push(rule("r2", "ip.src in $office or ip.src in $office"));
        let refs = references(&d);
        assert_eq!(refs["office"], vec![Ref { kind: "firewall rule", zone: "example.com".into(), id: "r2".into() }], "once per rule, not for a string");
        assert!(check_refs(&Expr::parse("ip.src in $office").unwrap(), &d).is_ok());
        assert!(check_refs(&Expr::parse("ip.src in $office and ip.src in $other").unwrap(), &d).unwrap_err().contains("'other'"));
        let many: Vec<Ref> = (0..7).map(|i| Ref { kind: "cache rule", zone: "example.com".into(), id: format!("c{i}") }).collect();
        assert!(describe(&many).ends_with("c4 in example.com and 2 more"));
    }
}
