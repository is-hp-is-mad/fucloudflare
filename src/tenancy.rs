//! Zones belong to the user who made them (`Zone.owner`): somebody who is
//! not an administrator sees and changes only their own zones, and only
//! administrators change account-level objects (nodes, steering, Workers,
//! KV, D1, lists, ...). Zones without an owner, those from before owners
//! existed and those the fleet's own API token made, are the
//! administrators'.
//!
//! The check is in one place, the API's `auth` middleware, and covers
//! every `/zones/{zone_id}/...` path whatever the handler behind it does;
//! the few answers that list zones (`GET /zones`, `GET /analytics`) filter
//! with [`may_see`]. A token of a user can never reach further than its
//! user: the token's own grant is checked first, and this on top.

use crate::auth::{Principal, Role};
use crate::store::Store;
use crate::tokens::Need;

/// Why a request was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum Denied {
    /// A zone of somebody else: answered as if it did not exist, so ids of
    /// other users' zones cannot be told from wrong ones.
    Zone,
    /// A change to an account-level object by somebody not an administrator.
    Account,
}

/// May `who` see a zone owned by `owner`? Administrators see every zone;
/// everybody else only those whose owner is their own user id.
pub fn may_see(who: &Principal, owner: Option<&str>) -> bool {
    who.role == Role::Admin || who.user_id.as_deref().is_some_and(|me| owner == Some(me))
}

/// The zone id a path is about, for `/zones/{zone_id}` and everything
/// under it, percent-decoded as the router decodes it for the handler
/// (so `/zones/%61bc` is about the zone `abc`, not a zone that is not
/// there). `Err`: an id that does not decode, which no zone has.
pub fn zone_of(path: &str) -> Option<Result<String, ()>> {
    let mut segs = path.trim_start_matches('/').split('/');
    match (segs.next(), segs.next()) {
        (Some("zones"), Some(id)) if !id.is_empty() => Some(percent_encoding::percent_decode_str(id).decode_utf8().map(|s| s.into_owned()).map_err(|_| ())),
        _ => None,
    }
}

/// The check the `auth` middleware makes once it knows who is asking. A
/// zone id that does not exist passes, so the handler answers it as it
/// always has (not found); one that exists but is somebody else's is
/// refused the same way.
pub fn check(who: &Principal, reads: bool, path: &str, store: &Store) -> Result<(), Denied> {
    if who.role == Role::Admin {
        return Ok(());
    }
    if let Some(zone_id) = zone_of(path) {
        let Ok(zone_id) = zone_id else { return Err(Denied::Zone) };
        if store.get_zone(&zone_id).is_ok_and(|z| !may_see(who, z.owner.as_deref())) {
            return Err(Denied::Zone);
        }
        // a route to a Worker runs the administrators' code, with its bindings, on this zone
        if !reads && path.trim_start_matches('/').split('/').nth(2) == Some("workers") {
            return Err(Denied::Account);
        }
        return Ok(());
    }
    if !reads && matches!(crate::tokens::need(path), Need::Account(_)) {
        return Err(Denied::Account);
    }
    Ok(())
}

/// Is this a write to a zone's e-mail rules, whose body [`binds_worker`]
/// must be looked at?
pub fn is_email_rule(path: &str) -> bool {
    let segs: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    matches!(segs.as_slice(), ["zones", _, "email", "rules", ..])
}

/// Does an e-mail rule body hand mail to a Worker (`"action": "worker"` or
/// a `worker` name)? Those are the administrators' to make, as routes to
/// Workers are. A body that is not JSON is not looked at: the handler
/// refuses it anyway.
pub fn binds_worker(body: &[u8]) -> bool {
    let Ok(serde_json::Value::Object(o)) = serde_json::from_slice::<serde_json::Value>(body) else { return false };
    o.get("action").and_then(|a| a.as_str()).is_some_and(|a| a.trim().eq_ignore_ascii_case("worker"))
        || o.get("worker").is_some_and(|w| !w.is_null() && w.as_str() != Some(""))
}

/// May a zone called `name` be made for `owner` by somebody who is not an
/// administrator? Not at or below a zone of anybody else, which would take
/// over hosts of that zone, and not above one, which would take its parent
/// name: an error saying which zone stands in the way.
pub fn may_create(zones: &[crate::store::Zone], name: &str, owner: Option<&str>) -> Result<(), String> {
    let under = |child: &str, parent: &str| child.strip_suffix(parent).is_some_and(|rest| rest.ends_with('.'));
    match zones.iter().find(|z| (z.name == name || under(name, &z.name) || under(&z.name, name)) && z.owner.as_deref() != owner) {
        Some(z) if z.name == name => Err(format!("zone '{name}' already exists")),
        Some(z) => Err(format!("'{name}' overlaps the zone '{}' of another user: ask an administrator", z.name)),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Via;

    fn user(id: Option<&str>, role: Role) -> Principal {
        Principal {
            user_id: id.map(str::to_string),
            email: "someone@example.com".into(),
            role,
            session_id: None,
            must_change_password: false,
            via: Via::Session,
            grant: None,
        }
    }

    fn store() -> Store {
        let dir = std::env::temp_dir().join(format!("fucf-tenancy-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir).unwrap();
        Store::open(&dir.join("store.json"), vec![]).unwrap()
    }

    #[test]
    fn only_the_owner_and_administrators_see_a_zone() {
        let (alice, bob, admin) = (user(Some("alice"), Role::Editor), user(Some("bob"), Role::Viewer), user(Some("root"), Role::Admin));
        assert!(may_see(&alice, Some("alice")));
        assert!(!may_see(&alice, Some("bob")));
        assert!(!may_see(&bob, Some("alice")));
        assert!(!may_see(&alice, None), "an unowned zone is the administrators'");
        assert!(may_see(&admin, Some("alice")) && may_see(&admin, None));
        assert!(!may_see(&user(None, Role::Editor), None), "no user id owns nothing, not even unowned zones");
        assert!(may_see(&Principal::system(), Some("alice")), "the fleet's own token is an administrator");
    }

    #[test]
    fn zone_paths_are_found_whatever_follows_the_id() {
        let id = |s: &str| Some(Ok(s.to_string()));
        assert_eq!(zone_of("/zones/z1"), id("z1"));
        assert_eq!(zone_of("/zones/z1/dns_records/r1"), id("z1"));
        assert_eq!(zone_of("zones/z1/rulesets"), id("z1"));
        assert_eq!(zone_of("/zones/%7a%31/settings"), id("z1"), "decoded as the handler sees it");
        assert_eq!(zone_of("/zones/%ff"), Some(Err(())));
        assert_eq!(zone_of("/zones"), None);
        assert_eq!(zone_of("/zones/"), None);
        assert_eq!(zone_of("/workers/scripts/zones"), None);
        assert_eq!(zone_of("/zonesx/z1"), None);
    }

    #[test]
    fn other_users_zones_are_hidden_and_account_writes_are_the_administrators() {
        let store = store();
        let mine = store.create_zone_owned("mine.example.com", "full", Some("alice".into()), false).unwrap();
        let theirs = store.create_zone_owned("theirs.example.com", "full", Some("bob".into()), false).unwrap();
        let old = store.create_zone("old.example.com").unwrap();
        let alice = user(Some("alice"), Role::Editor);
        assert_eq!(check(&alice, false, &format!("/zones/{}/dns_records", mine.id), &store), Ok(()));
        for path in [format!("/zones/{}", theirs.id), format!("/zones/{}/dns_records/x", theirs.id), format!("/zones/{}/settings", old.id)] {
            assert_eq!(check(&alice, true, &path, &store), Err(Denied::Zone), "{path}");
            assert_eq!(check(&alice, false, &path, &store), Err(Denied::Zone), "{path}");
        }
        assert_eq!(check(&alice, true, "/zones/0123456789abcdef0123456789abcdef", &store), Ok(()), "an unknown id is the handler's 404");
        let encoded: String = theirs.id.bytes().map(|b| format!("%{b:02x}")).collect();
        assert_eq!(check(&alice, true, &format!("/zones/{encoded}/dns_records"), &store), Err(Denied::Zone), "an encoded id is still theirs");
        assert_eq!(check(&alice, true, "/zones/%ff/dns_records", &store), Err(Denied::Zone));
        assert_eq!(check(&alice, false, "/zones", &store), Ok(()), "anybody who may write may add a zone");
        for path in ["/workers/scripts/w", "/kv/namespaces", "/d1/database", "/steering", "/rules/lists", "/nodes", "/warp/purge_cache"] {
            assert_eq!(check(&alice, false, path, &store), Err(Denied::Account), "{path}");
            assert_eq!(check(&alice, true, path, &store), Ok(()), "{path}");
        }
        assert_eq!(check(&alice, false, "/user/tokens", &store), Ok(()), "their own tokens");
        assert_eq!(check(&alice, false, &format!("/zones/{}/workers/routes", mine.id), &store), Err(Denied::Account), "routes to the administrators' Workers");
        assert_eq!(check(&alice, true, &format!("/zones/{}/workers/routes", mine.id), &store), Ok(()));
        assert_eq!(check(&alice, false, &format!("/zones/{}/workers/routes", theirs.id), &store), Err(Denied::Zone), "not even told it is a Worker path");
        let admin = user(Some("root"), Role::Admin);
        assert_eq!(check(&admin, false, &format!("/zones/{}", theirs.id), &store), Ok(()));
        assert_eq!(check(&admin, false, "/workers/scripts/w", &store), Ok(()));
    }

    #[test]
    fn e_mail_rules_that_hand_mail_to_a_worker_are_found() {
        assert!(is_email_rule("/zones/z1/email/rules") && is_email_rule("/zones/z1/email/rules/r1"));
        assert!(!is_email_rule("/zones/z1/email") && !is_email_rule("/zones/z1/dns_records"));
        for body in [r#"{"action":"worker","worker":"w"}"#, r#"{"action":" Worker "}"#, r#"{"worker":"w"}"#, r#"{"action":"forward","worker":"w"}"#, r#"{"worker":{"name":"w"}}"#] {
            assert!(binds_worker(body.as_bytes()), "{body}");
        }
        for body in [r#"{"action":"forward","destinations":["a@example.net"]}"#, r#"{"worker":null}"#, r#"{"worker":""}"#, r#"{"description":"worker"}"#, "not json", "[]", ""] {
            assert!(!binds_worker(body.as_bytes()), "{body}");
        }
    }

    #[test]
    fn a_new_zone_may_not_overlap_a_zone_of_somebody_else() {
        let store = store();
        store.create_zone_owned("example.com", "full", Some("bob".into()), false).unwrap();
        store.create_zone_owned("mine.example.net", "full", Some("alice".into()), false).unwrap();
        store.create_zone("old.example.org").unwrap();
        let zones = store.list_zones();
        let alice = Some("alice");
        assert!(may_create(&zones, "shop.example.com", alice).unwrap_err().contains("example.com"));
        assert!(may_create(&zones, "a.b.example.com", alice).is_err());
        assert!(may_create(&zones, "example.net", alice).is_ok(), "above a zone of their own");
        assert!(may_create(&zones, "sub.mine.example.net", alice).is_ok(), "below a zone of their own");
        assert!(may_create(&zones, "example.org", alice).is_err(), "above an unowned zone");
        assert!(may_create(&zones, "x.old.example.org", alice).is_err(), "below an unowned zone");
        assert!(may_create(&zones, "notexample.com", alice).is_ok(), "a longer name is not below");
        assert!(may_create(&zones, "example.com", alice).unwrap_err().contains("already exists"));
        // through the store, refused before anything is written
        let refused = store.create_zone_owned("shop.example.com", "full", Some("alice".into()), true);
        assert!(matches!(refused, Err(crate::store::StoreError::Conflict(_))), "{refused:?}");
        assert!(store.create_zone_owned("shop.example.com", "full", Some("root".into()), false).is_ok(), "administrators may");
    }
}
