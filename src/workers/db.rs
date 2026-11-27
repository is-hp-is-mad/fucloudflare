//! Workers D1 (`env.<BINDING>`): bundled SQLite databases (`rusqlite`) with
//! bounded `PRAGMA cache_size = -2000`, atomic `batch()`, `D1_TYPE_ERROR` on
//! `undefined`, and HLC/LWW + oplog/snapshot peer sync.

use crate::sync::clock::{unix_ms, HlcClock, SyncMeta};
use crate::sync::{DomainDelta, SyncProvider};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use rusqlite::types::{Value as SqlValue, ValueRef};
use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

const MAX_OPLOG: usize = 2000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct D1Database {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub created_on: String,
    #[serde(default)]
    pub modified_on: String,
    #[serde(default, skip_serializing_if = "SyncMeta::is_unset")]
    pub sync: SyncMeta,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum D1Param {
    Null,
    Integer(i64),
    Real(f64),
    Text(String),
    Blob(String), // base64
}

impl D1Param {
    fn to_sql(&self) -> Result<SqlValue, String> {
        Ok(match self {
            D1Param::Null => SqlValue::Null,
            D1Param::Integer(i) => SqlValue::Integer(*i),
            D1Param::Real(f) => SqlValue::Real(*f),
            D1Param::Text(s) => SqlValue::Text(s.clone()),
            D1Param::Blob(b) => SqlValue::Blob(B64.decode(b).map_err(|e| e.to_string())?),
        })
    }

    pub fn from_json(v: &Value) -> Result<Self, String> {
        match v {
            Value::Null => Ok(D1Param::Null),
            Value::Bool(b) => Ok(D1Param::Integer(if *b { 1 } else { 0 })),
            Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    Ok(D1Param::Integer(i))
                } else if let Some(f) = n.as_f64() {
                    Ok(D1Param::Real(f))
                } else {
                    Err("D1_TYPE_ERROR: unsupported number".into())
                }
            }
            Value::String(s) => Ok(D1Param::Text(s.clone())),
            Value::Object(obj) => {
                if let Some(b64) = obj.get("__d1_blob").and_then(|x| x.as_str()) {
                    Ok(D1Param::Blob(b64.to_string()))
                } else if obj.get("__d1_undefined").and_then(|x| x.as_bool()) == Some(true) {
                    Err("D1_TYPE_ERROR: Type 'undefined' not supported for value".into())
                } else {
                    Err("D1_TYPE_ERROR: unsupported object parameter".into())
                }
            }
            Value::Array(_) => Err("D1_TYPE_ERROR: unsupported array parameter".into()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct D1StmtSpec {
    sql: String,
    #[serde(default)]
    params: Vec<D1Param>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct D1Op {
    db_id: String,
    #[serde(default)]
    is_exec: bool,
    statements: Vec<D1StmtSpec>,
    sync: SyncMeta,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
struct D1Index {
    epoch: String,
    local_rev: u64,
    databases: BTreeMap<String, D1Database>,
    db_tombstones: BTreeMap<String, SyncMeta>,
    oplog: Vec<D1Op>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
struct D1DeltaPayload {
    databases: Vec<D1Database>,
    db_tombstones: Vec<(String, SyncMeta)>,
    ops: Vec<D1Op>,
    snapshots: Vec<(String, String)>, // (db_id, sqlite_bytes_b64)
}

pub struct D1Store {
    dir: Option<PathBuf>,
    read_only: AtomicBool,
    clock: Arc<HlcClock>,
    sync_node: std::sync::RwLock<String>,
    index: Mutex<D1Index>,
    write_lock: Mutex<()>,
    /// Per-DB mutex serializing SQLite writes and ensuring bounded cache.
    db_locks: Mutex<HashMap<String, Arc<Mutex<()>>>>,
    /// In-memory connections for `open_ephemeral` (`--role accelerate`).
    mem_conns: Mutex<HashMap<String, Arc<Mutex<Connection>>>>,
    /// Deduplication of applied remote ops `(node, updated_ms, seq)`.
    seen_ops: Mutex<HashSet<(String, u64, u64)>>,
}

fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn new_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

fn configure_conn(conn: &Connection, wal: bool) -> Result<(), String> {
    conn.pragma_update(None, "cache_size", -2000i64)
        .map_err(|e| e.to_string())?;
    conn.pragma_update(None, "foreign_keys", "ON")
        .map_err(|e| e.to_string())?;
    if wal {
        let _ = conn.pragma_update(None, "journal_mode", "WAL");
        let _ = conn.pragma_update(None, "synchronous", "NORMAL");
    }
    conn.set_db_config(rusqlite::config::DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)
        .map_err(|e| e.to_string())?;
    conn.authorizer(Some(|ctx: rusqlite::hooks::AuthContext<'_>| {
        use rusqlite::hooks::{AuthAction, Authorization};
        match ctx.action {
            AuthAction::Attach { .. } | AuthAction::Detach { .. } => Authorization::Deny,
            AuthAction::Pragma { pragma_name, pragma_value } => {
                let name = pragma_name.to_ascii_lowercase();
                let inspect_schema = matches!(
                    name.as_str(),
                    "table_info" | "table_xinfo" | "index_list" | "index_info" | "foreign_key_list"
                );
                let safe_read = matches!(
                    name.as_str(),
                    "cache_size" | "foreign_keys" | "user_version" | "collation_list"
                );
                if inspect_schema || (safe_read && pragma_value.is_none()) {
                    Authorization::Allow
                } else {
                    Authorization::Deny
                }
            }
            AuthAction::Function { function_name } => {
                let name = function_name.to_ascii_lowercase();
                if matches!(name.as_str(), "load_extension" | "fts3_tokenizer") {
                    Authorization::Deny
                } else {
                    Authorization::Allow
                }
            }
            _ => {
                if ctx.database_name == Some("vacuum_db") {
                    Authorization::Deny
                } else {
                    Authorization::Allow
                }
            }
        }
    }));
    Ok(())
}

fn sql_val_to_json(v: ValueRef<'_>) -> Value {
    match v {
        ValueRef::Null => Value::Null,
        ValueRef::Integer(i) => json!(i),
        ValueRef::Real(f) => json!(f),
        ValueRef::Text(t) => Value::String(String::from_utf8_lossy(t).into_owned()),
        ValueRef::Blob(b) => json!({ "__d1_blob": B64.encode(b) }),
    }
}

fn strip_leading_sql_comments(mut s: &str) -> &str {
    loop {
        s = s.trim_start();
        if let Some(rest) = s.strip_prefix("--") {
            s = rest.split_once('\n').map(|(_, r)| r).unwrap_or("");
        } else if let Some(rest) = s.strip_prefix("/*") {
            s = rest.split_once("*/").map(|(_, r)| r).unwrap_or("");
        } else {
            return s;
        }
    }
}

fn starts_with_keyword(s: &str, kw: &str) -> bool {
    if s.len() < kw.len() {
        return false;
    }
    let (head, tail) = s.split_at(kw.len());
    head.eq_ignore_ascii_case(kw)
        && (tail.is_empty() || (!tail.as_bytes()[0].is_ascii_alphanumeric() && tail.as_bytes()[0] != b'_'))
}

fn is_read_only_sql(sql: &str) -> bool {
    let s = strip_leading_sql_comments(sql);
    starts_with_keyword(s, "SELECT")
        || starts_with_keyword(s, "EXPLAIN")
        || starts_with_keyword(s, "PRAGMA")
        || starts_with_keyword(s, "WITH")
}

fn exec_query_on_conn(
    conn: &Connection,
    sql: &str,
    params: &[D1Param],
    raw: bool,
    column_names: bool,
    first_col: Option<&str>,
    enforce_read_only: bool,
) -> Result<Value, String> {
    let started = Instant::now();
    let sql_vals: Vec<SqlValue> = params.iter().map(|p| p.to_sql()).collect::<Result<_, _>>()?;
    let mut stmt = conn.prepare(sql).map_err(|e| format!("D1_ERROR: {e}"))?;
    if enforce_read_only && !stmt.readonly() {
        return Err("D1_READ_ONLY: write queries are not allowed on accelerate nodes".into());
    }
    let col_count = stmt.column_count();
    let col_names: Vec<String> = (0..col_count)
        .map(|i| stmt.column_name(i).unwrap_or("").to_string())
        .collect();

    if col_count == 0 {
        let changes = stmt
            .execute(rusqlite::params_from_iter(sql_vals.iter()))
            .map_err(|e| format!("D1_ERROR: {e}"))?;
        let last_row_id = conn.last_insert_rowid();
        let duration = started.elapsed().as_secs_f64() * 1000.0;
        if raw {
            return Ok(json!([]));
        }
        if first_col.is_some() {
            return Ok(Value::Null);
        }
        return Ok(json!({
            "results": [],
            "success": true,
            "meta": {
                "duration": duration,
                "changes": changes,
                "last_row_id": last_row_id,
                "rows_read": 0,
                "rows_written": changes,
            }
        }));
    }

    let mut rows = stmt
        .query(rusqlite::params_from_iter(sql_vals.iter()))
        .map_err(|e| format!("D1_ERROR: {e}"))?;

    if raw {
        let mut out: Vec<Value> = Vec::new();
        if column_names {
            out.push(Value::Array(col_names.iter().cloned().map(Value::String).collect()));
        }
        while let Some(row) = rows.next().map_err(|e| format!("D1_ERROR: {e}"))? {
            let mut arr = Vec::with_capacity(col_count);
            for i in 0..col_count {
                let v = row.get_ref(i).map_err(|e| format!("D1_ERROR: {e}"))?;
                arr.push(sql_val_to_json(v));
            }
            out.push(Value::Array(arr));
        }
        return Ok(Value::Array(out));
    }

    let mut objects: Vec<Value> = Vec::new();
    while let Some(row) = rows.next().map_err(|e| format!("D1_ERROR: {e}"))? {
        let mut map = Map::new();
        for (i, name) in col_names.iter().enumerate() {
            let v = row.get_ref(i).map_err(|e| format!("D1_ERROR: {e}"))?;
            map.insert(name.clone(), sql_val_to_json(v));
        }
        objects.push(Value::Object(map));
        if first_col.is_some() {
            break;
        }
    }

    if let Some(col) = first_col {
        return match objects.into_iter().next() {
            None => Ok(Value::Null),
            Some(Value::Object(mut m)) => {
                if col.is_empty() {
                    Ok(Value::Object(m))
                } else {
                    m.remove(col)
                        .ok_or_else(|| format!("D1_ERROR: column '{col}' not found"))
                }
            }
            Some(v) => Ok(v),
        };
    }

    let rows_read = objects.len();
    let duration = started.elapsed().as_secs_f64() * 1000.0;
    Ok(json!({
        "results": objects,
        "success": true,
        "meta": {
            "duration": duration,
            "changes": 0,
            "last_row_id": 0,
            "rows_read": rows_read,
            "rows_written": 0,
        }
    }))
}

impl D1Store {
    pub fn open(dir: PathBuf, clock: Arc<HlcClock>, sync_node: String) -> anyhow::Result<Arc<Self>> {
        std::fs::create_dir_all(&dir)?;
        let idx_path = dir.join("index.json");
        let mut idx: D1Index = match std::fs::read(&idx_path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| anyhow::anyhow!("corrupt D1 index {}: {e}", idx_path.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => D1Index::default(),
            Err(e) => return Err(e.into()),
        };
        if idx.epoch.is_empty() {
            idx.epoch = new_id();
        }
        Ok(Arc::new(D1Store {
            dir: Some(dir),
            read_only: AtomicBool::new(false),
            clock,
            sync_node: std::sync::RwLock::new(sync_node),
            index: Mutex::new(idx),
            write_lock: Mutex::new(()),
            db_locks: Mutex::new(HashMap::new()),
            mem_conns: Mutex::new(HashMap::new()),
            seen_ops: Mutex::new(HashSet::new()),
        }))
    }

    pub fn open_ephemeral(clock: Arc<HlcClock>, sync_node: String) -> Arc<Self> {
        let mut idx = D1Index::default();
        idx.epoch = new_id();
        Arc::new(D1Store {
            dir: None,
            read_only: AtomicBool::new(true),
            clock,
            sync_node: std::sync::RwLock::new(sync_node),
            index: Mutex::new(idx),
            write_lock: Mutex::new(()),
            db_locks: Mutex::new(HashMap::new()),
            mem_conns: Mutex::new(HashMap::new()),
            seen_ops: Mutex::new(HashSet::new()),
        })
    }

    fn db_path(&self, id: &str) -> Option<PathBuf> {
        if !crate::workers::kv::is_valid_id(id) {
            return None;
        }
        self.dir.as_ref().map(|d| d.join(format!("{id}.sqlite")))
    }

    fn db_lock(&self, id: &str) -> Arc<Mutex<()>> {
        self.db_locks
            .lock()
            .unwrap()
            .entry(id.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    fn save_index(&self, idx: &D1Index) -> Result<(), String> {
        let Some(dir) = &self.dir else { return Ok(()) };
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        let data = serde_json::to_vec(idx).map_err(|e| e.to_string())?;
        let tmp = dir.join(format!("index.{}.tmp", uuid::Uuid::new_v4().simple()));
        std::fs::write(&tmp, data).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, dir.join("index.json")).map_err(|e| e.to_string())?;
        Ok(())
    }

    fn stamp(&self, idx: &mut D1Index, deleted: bool) -> SyncMeta {
        idx.local_rev = idx.local_rev.saturating_add(1);
        let node = self.sync_node.read().unwrap().clone();
        self.clock.stamp(&node, deleted, idx.local_rev)
    }

    fn with_conn<T>(&self, db_id: &str, f: impl FnOnce(&Connection) -> Result<T, String>) -> Result<T, String> {
        if !crate::workers::kv::is_valid_id(db_id) {
            return Err("invalid database id".into());
        }
        {
            let idx = self.index.lock().unwrap();
            if !idx.databases.contains_key(db_id) {
                return Err(format!("D1 database '{db_id}' not found"));
            }
        }
        if let Some(path) = self.db_path(db_id) {
            let conn = Connection::open_with_flags(
                &path,
                OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
            )
            .map_err(|e| e.to_string())?;
            configure_conn(&conn, true)?;
            f(&conn)
        } else {
            let mc = {
                let mut map = self.mem_conns.lock().unwrap();
                map.entry(db_id.to_string())
                    .or_insert_with(|| {
                        let c = Connection::open_in_memory().expect("in-memory sqlite");
                        let _ = configure_conn(&c, false);
                        Arc::new(Mutex::new(c))
                    })
                    .clone()
            };
            let conn = mc.lock().unwrap();
            f(&conn)
        }
    }

    fn record_op(&self, db_id: &str, is_exec: bool, statements: Vec<D1StmtSpec>) -> Result<(), String> {
        let _w = self.write_lock.lock().unwrap();
        let mut idx = self.index.lock().unwrap().clone();
        let sync = self.stamp(&mut idx, false);
        idx.oplog.push(D1Op {
            db_id: db_id.to_string(),
            is_exec,
            statements,
            sync,
        });
        if idx.oplog.len() > MAX_OPLOG {
            let drain = idx.oplog.len() - MAX_OPLOG;
            idx.oplog.drain(0..drain);
        }
        self.save_index(&idx)?;
        *self.index.lock().unwrap() = idx;
        Ok(())
    }

    // ---- Database Management ----

    pub fn list_databases(&self) -> Vec<D1Database> {
        self.index.lock().unwrap().databases.values().cloned().collect()
    }

    pub fn get_database(&self, id: &str) -> Option<D1Database> {
        self.index.lock().unwrap().databases.get(id).cloned()
    }

    pub fn create_database(&self, name: &str) -> Result<D1Database, String> {
        if self.read_only.load(Ordering::Relaxed) {
            return Err("read-only accelerate node".into());
        }
        let name = name.trim();
        if name.is_empty() || name.len() > 64 {
            return Err("database name must be 1..=64 characters".into());
        }
        let _w = self.write_lock.lock().unwrap();
        let mut idx = self.index.lock().unwrap().clone();
        if idx.databases.values().any(|d| d.name == name) {
            return Err(format!("D1 database '{name}' already exists"));
        }
        let ts = now_iso();
        let sync = self.stamp(&mut idx, false);
        let db = D1Database {
            id: new_id(),
            name: name.to_string(),
            created_on: ts.clone(),
            modified_on: ts,
            sync,
        };
        if let Some(path) = self.db_path(&db.id) {
            let conn = Connection::open(&path).map_err(|e| e.to_string())?;
            configure_conn(&conn, true)?;
        }
        idx.db_tombstones.remove(&db.id);
        idx.databases.insert(db.id.clone(), db.clone());
        self.save_index(&idx)?;
        *self.index.lock().unwrap() = idx;
        Ok(db)
    }

    pub fn delete_database(&self, id: &str) -> Result<(), String> {
        if self.read_only.load(Ordering::Relaxed) {
            return Err("read-only accelerate node".into());
        }
        let _w = self.write_lock.lock().unwrap();
        let mut idx = self.index.lock().unwrap().clone();
        if idx.databases.remove(id).is_none() {
            return Err("database not found".into());
        }
        let tomb = self.stamp(&mut idx, true);
        idx.db_tombstones.insert(id.to_string(), tomb);
        idx.oplog.retain(|op| op.db_id != id);
        self.save_index(&idx)?;
        *self.index.lock().unwrap() = idx;
        if let Some(path) = self.db_path(id) {
            let _ = std::fs::remove_file(&path);
            let _ = std::fs::remove_file(format!("{}-wal", path.display()));
            let _ = std::fs::remove_file(format!("{}-shm", path.display()));
        } else {
            self.mem_conns.lock().unwrap().remove(id);
        }
        Ok(())
    }

    // ---- Query Execution ----

    pub fn query(
        &self,
        db_id: &str,
        sql: &str,
        params: Vec<D1Param>,
        raw: bool,
        column_names: bool,
        first_col: Option<&str>,
    ) -> Result<Value, String> {
        let lock = self.db_lock(db_id);
        let _g = lock.lock().unwrap();
        let ro = self.read_only.load(Ordering::Relaxed);
        if ro && !is_read_only_sql(sql) {
            return Err("D1_READ_ONLY: write queries are not allowed on accelerate nodes".into());
        }
        let (out, wrote) = self.with_conn(db_id, |conn| {
            let val = exec_query_on_conn(conn, sql, &params, raw, column_names, first_col, ro)?;
            let wrote = val["meta"]["changes"].as_u64().unwrap_or(0) > 0
                || !sql.trim_start().to_ascii_uppercase().starts_with("SELECT");
            Ok((val, wrote))
        })?;
        if wrote && !ro {
            // Only record DDL/DML mutations (skip pure PRAGMA/EXPLAIN/WITH SELECT).
            let upper = sql.trim_start().to_ascii_uppercase();
            let is_read = upper.starts_with("SELECT")
                || upper.starts_with("EXPLAIN")
                || upper.starts_with("PRAGMA")
                || upper.starts_with("WITH");
            if !is_read {
                self.record_op(
                    db_id,
                    false,
                    vec![D1StmtSpec {
                        sql: sql.to_string(),
                        params,
                    }],
                )?;
            }
        }
        Ok(out)
    }

    pub fn batch(&self, db_id: &str, stmts: Vec<(String, Vec<D1Param>)>) -> Result<Value, String> {
        if self.read_only.load(Ordering::Relaxed) {
            return Err("read-only accelerate node".into());
        }
        let lock = self.db_lock(db_id);
        let _g = lock.lock().unwrap();
        let results = self.with_conn(db_id, |conn| {
            conn.execute_batch("BEGIN IMMEDIATE").map_err(|e| format!("D1_ERROR: {e}"))?;
            let mut out = Vec::with_capacity(stmts.len());
            for (sql, params) in &stmts {
                match exec_query_on_conn(conn, sql, params, false, false, None, false) {
                    Ok(v) => out.push(v),
                    Err(e) => {
                        let _ = conn.execute_batch("ROLLBACK");
                        return Err(e);
                    }
                }
            }
            conn.execute_batch("COMMIT").map_err(|e| format!("D1_ERROR: {e}"))?;
            Ok(out)
        })?;
        let specs = stmts
            .into_iter()
            .map(|(sql, params)| D1StmtSpec { sql, params })
            .collect();
        self.record_op(db_id, false, specs)?;
        Ok(Value::Array(results))
    }

    pub fn exec(&self, db_id: &str, sql: &str) -> Result<Value, String> {
        if self.read_only.load(Ordering::Relaxed) {
            return Err("read-only accelerate node".into());
        }
        let lock = self.db_lock(db_id);
        let _g = lock.lock().unwrap();
        let started = Instant::now();
        let count = self.with_conn(db_id, |conn| {
            conn.execute_batch(sql).map_err(|e| format!("D1_ERROR: {e}"))?;
            Ok(sql.split(';').filter(|s| !s.trim().is_empty()).count())
        })?;
        self.record_op(
            db_id,
            true,
            vec![D1StmtSpec {
                sql: sql.to_string(),
                params: Vec::new(),
            }],
        )?;
        Ok(json!({
            "count": count,
            "duration": started.elapsed().as_secs_f64() * 1000.0,
        }))
    }

    fn export_sqlite_bytes(&self, db_id: &str) -> Result<Option<Vec<u8>>, String> {
        let lock = self.db_lock(db_id);
        let _g = lock.lock().unwrap();
        if let Some(path) = self.db_path(db_id) {
            if !path.exists() {
                return Ok(None);
            }
            // Checkpoint WAL so the main .sqlite file is self-contained.
            if let Ok(conn) = Connection::open(&path) {
                let _ = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
            }
            std::fs::read(&path).map(Some).map_err(|e| e.to_string())
        } else {
            Ok(None)
        }
    }

    fn restore_sqlite_bytes(&self, db_id: &str, bytes: &[u8]) -> Result<(), String> {
        let lock = self.db_lock(db_id);
        let _g = lock.lock().unwrap();
        if let Some(path) = self.db_path(db_id) {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            let tmp = path.with_extension(format!("{}.tmp", uuid::Uuid::new_v4().simple()));
            std::fs::write(&tmp, bytes).map_err(|e| e.to_string())?;
            let _ = std::fs::remove_file(format!("{}-wal", path.display()));
            let _ = std::fs::remove_file(format!("{}-shm", path.display()));
            std::fs::rename(&tmp, &path).map_err(|e| e.to_string())?;
        } else {
            // Write to temp file and use rusqlite::backup into in-memory DB.
            let tmp = std::env::temp_dir().join(format!("fucf-d1-sync-{}.sqlite", uuid::Uuid::new_v4().simple()));
            std::fs::write(&tmp, bytes).map_err(|e| e.to_string())?;
            let src = Connection::open_with_flags(&tmp, OpenFlags::SQLITE_OPEN_READ_ONLY).map_err(|e| e.to_string())?;
            let mc = {
                let mut map = self.mem_conns.lock().unwrap();
                map.entry(db_id.to_string())
                    .or_insert_with(|| {
                        let c = Connection::open_in_memory().expect("in-memory sqlite");
                        let _ = configure_conn(&c, false);
                        Arc::new(Mutex::new(c))
                    })
                    .clone()
            };
            {
                let mut dst = mc.lock().unwrap();
                let backup = rusqlite::backup::Backup::new(&src, &mut dst).map_err(|e| e.to_string())?;
                backup.run_to_completion(100, std::time::Duration::from_millis(0), None).map_err(|e| e.to_string())?;
            }
            drop(src);
            let _ = std::fs::remove_file(&tmp);
        }
        Ok(())
    }
}

impl SyncProvider for D1Store {
    fn domain(&self) -> &'static str {
        "d1"
    }

    fn current_rev(&self) -> u64 {
        self.index.lock().unwrap().local_rev
    }

    fn epoch(&self) -> String {
        self.index.lock().unwrap().epoch.clone()
    }

    fn export_since(&self, since_rev: u64, peer_epoch: Option<&str>) -> Result<DomainDelta, String> {
        let idx = self.index.lock().unwrap().clone();
        let oldest_op_rev = idx.oplog.first().map(|o| o.sync.local_rev).unwrap_or(u64::MAX);
        let full_resync = peer_epoch != Some(idx.epoch.as_str())
            || since_rev == 0
            || since_rev > idx.local_rev
            || (!idx.oplog.is_empty() && since_rev + 1 < oldest_op_rev);
        let threshold = if full_resync { 0 } else { since_rev };

        let mut payload = D1DeltaPayload::default();
        for db in idx.databases.values() {
            if full_resync || db.sync.local_rev > threshold {
                payload.databases.push(db.clone());
            }
        }
        for (id, t) in &idx.db_tombstones {
            if full_resync || t.local_rev > threshold {
                payload.db_tombstones.push((id.clone(), t.clone()));
            }
        }
        if full_resync {
            for id in idx.databases.keys() {
                if let Some(bytes) = self.export_sqlite_bytes(id)? {
                    payload.snapshots.push((id.clone(), B64.encode(&bytes)));
                }
            }
        } else {
            for op in &idx.oplog {
                if op.sync.local_rev > threshold {
                    payload.ops.push(op.clone());
                }
            }
        }

        Ok(DomainDelta {
            domain: "d1".into(),
            epoch: idx.epoch,
            from_rev: if full_resync { 0 } else { since_rev },
            to_rev: idx.local_rev,
            full_resync,
            payload: serde_json::to_value(payload).map_err(|e| e.to_string())?,
        })
    }

    fn merge_delta(&self, delta: &DomainDelta, clock: &HlcClock) -> Result<bool, String> {
        if delta.domain != "d1" {
            return Err("wrong domain for D1Store".into());
        }
        let payload: D1DeltaPayload = serde_json::from_value(delta.payload.clone()).map_err(|e| e.to_string())?;
        let _w = self.write_lock.lock().unwrap();
        let mut idx = self.index.lock().unwrap().clone();
        let mut changed = false;
        let mut adopted_dbs: HashSet<String> = HashSet::new();

        let now_ms = unix_ms();
        for mut db in payload.databases {
            if !crate::workers::kv::is_valid_id(&db.id) {
                continue;
            }
            db.sync.clamp_skew(now_ms);
            clock.observe(db.sync.updated_ms, db.sync.seq);
            let tomb = idx.db_tombstones.get(&db.id);
            if tomb.is_some_and(|t| !db.sync.wins_over(t)) {
                continue;
            }
            let cur = idx.databases.get(&db.id).map(|x| &x.sync);
            if cur.is_none_or(|c| db.sync.wins_over(c)) {
                idx.local_rev = idx.local_rev.saturating_add(1);
                db.sync.local_rev = idx.local_rev;
                idx.db_tombstones.remove(&db.id);
                adopted_dbs.insert(db.id.clone());
                idx.databases.insert(db.id.clone(), db);
                changed = true;
            }
        }

        for (id, mut tomb) in payload.db_tombstones {
            if !crate::workers::kv::is_valid_id(&id) {
                continue;
            }
            tomb.deleted = true;
            tomb.clamp_skew(now_ms);
            clock.observe(tomb.updated_ms, tomb.seq);
            let cur_live = idx.databases.get(&id).map(|x| &x.sync);
            let cur_tomb = idx.db_tombstones.get(&id);
            if cur_live.is_none_or(|c| tomb.wins_over(c)) && cur_tomb.is_none_or(|c| tomb.wins_over(c)) {
                idx.local_rev = idx.local_rev.saturating_add(1);
                tomb.local_rev = idx.local_rev;
                if idx.databases.remove(&id).is_some() {
                    changed = true;
                }
                idx.oplog.retain(|op| op.db_id != id);
                idx.db_tombstones.insert(id.clone(), tomb);
                if let Some(path) = self.db_path(&id) {
                    let _ = std::fs::remove_file(&path);
                } else {
                    self.mem_conns.lock().unwrap().remove(&id);
                }
            }
        }

        // Save updated database registry before applying snapshots / ops.
        *self.index.lock().unwrap() = idx.clone();

        for (db_id, b64) in payload.snapshots {
            if !crate::workers::kv::is_valid_id(&db_id) || !idx.databases.contains_key(&db_id) {
                continue;
            }
            if !adopted_dbs.contains(&db_id) && idx.oplog.iter().any(|op| op.db_id == db_id) {
                continue;
            }
            let bytes = B64.decode(&b64).map_err(|e| e.to_string())?;
            self.restore_sqlite_bytes(&db_id, &bytes)?;
            changed = true;
        }

        for mut op in payload.ops {
            if !crate::workers::kv::is_valid_id(&op.db_id) {
                continue;
            }
            op.sync.clamp_skew(now_ms);
            clock.observe(op.sync.updated_ms, op.sync.seq);
            if !idx.databases.contains_key(&op.db_id) {
                continue;
            }
            let key = (op.sync.node.clone(), op.sync.updated_ms, op.sync.seq);
            if !self.seen_ops.lock().unwrap().insert(key) {
                continue;
            }
            let lock = self.db_lock(&op.db_id);
            let _g = lock.lock().unwrap();
            self.with_conn(&op.db_id, |conn| {
                if op.is_exec {
                    for s in &op.statements {
                        let _ = conn.execute_batch(&s.sql);
                    }
                } else {
                    let _ = conn.execute_batch("BEGIN IMMEDIATE");
                    let mut ok = true;
                    for s in &op.statements {
                        if exec_query_on_conn(conn, &s.sql, &s.params, false, false, None, false).is_err() {
                            ok = false;
                            break;
                        }
                    }
                    if ok {
                        let _ = conn.execute_batch("COMMIT");
                    } else {
                        let _ = conn.execute_batch("ROLLBACK");
                    }
                }
                Ok(())
            })?;
            idx.local_rev = idx.local_rev.saturating_add(1);
            op.sync.local_rev = idx.local_rev;
            idx.oplog.push(op);
            if idx.oplog.len() > MAX_OPLOG {
                let drain = idx.oplog.len() - MAX_OPLOG;
                idx.oplog.drain(0..drain);
            }
            changed = true;
        }

        if changed {
            self.save_index(&idx)?;
            *self.index.lock().unwrap() = idx;
        }
        Ok(changed)
    }
}

// ---- Worker Host Functions ----

#[derive(Deserialize)]
struct D1QueryReq {
    db_id: String,
    sql: String,
    #[serde(default)]
    params: Vec<Value>,
    #[serde(default)]
    raw: bool,
    #[serde(default)]
    column_names: bool,
    first_col: Option<String>,
}

#[derive(Deserialize)]
struct D1BatchItem {
    sql: String,
    #[serde(default)]
    params: Vec<Value>,
}

#[derive(Deserialize)]
struct D1BatchReq {
    db_id: String,
    statements: Vec<D1BatchItem>,
}

#[derive(Deserialize)]
struct D1ExecReq {
    db_id: String,
    sql: String,
}

pub fn host_d1_query(
    d1: &Arc<D1Store>,
    runtime: &tokio::runtime::Handle,
    arg_json: &str,
) -> Result<String, String> {
    let req: D1QueryReq = serde_json::from_str(arg_json).map_err(|e| e.to_string())?;
    let params = req
        .params
        .iter()
        .map(D1Param::from_json)
        .collect::<Result<Vec<_>, _>>()?;
    let d1 = d1.clone();
    runtime.block_on(async move {
        tokio::task::spawn_blocking(move || {
            let v = d1.query(
                &req.db_id,
                &req.sql,
                params,
                req.raw,
                req.column_names,
                req.first_col.as_deref(),
            )?;
            Ok(v.to_string())
        })
        .await
        .map_err(|e| e.to_string())?
    })
}

pub fn host_d1_batch(
    d1: &Arc<D1Store>,
    runtime: &tokio::runtime::Handle,
    arg_json: &str,
) -> Result<String, String> {
    let req: D1BatchReq = serde_json::from_str(arg_json).map_err(|e| e.to_string())?;
    let mut stmts = Vec::with_capacity(req.statements.len());
    for s in req.statements {
        let p = s.params.iter().map(D1Param::from_json).collect::<Result<Vec<_>, _>>()?;
        stmts.push((s.sql, p));
    }
    let d1 = d1.clone();
    runtime.block_on(async move {
        tokio::task::spawn_blocking(move || {
            let v = d1.batch(&req.db_id, stmts)?;
            Ok(v.to_string())
        })
        .await
        .map_err(|e| e.to_string())?
    })
}

pub fn host_d1_exec(
    d1: &Arc<D1Store>,
    runtime: &tokio::runtime::Handle,
    arg_json: &str,
) -> Result<String, String> {
    let req: D1ExecReq = serde_json::from_str(arg_json).map_err(|e| e.to_string())?;
    let d1 = d1.clone();
    runtime.block_on(async move {
        tokio::task::spawn_blocking(move || {
            let v = d1.exec(&req.db_id, &req.sql)?;
            Ok(v.to_string())
        })
        .await
        .map_err(|e| e.to_string())?
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn d1_crud_batch_rollback_type_error_and_sync() {
        let dir_a = std::env::temp_dir().join(format!("fucf-d1-a-{}", uuid::Uuid::new_v4().simple()));
        let dir_b = std::env::temp_dir().join(format!("fucf-d1-b-{}", uuid::Uuid::new_v4().simple()));
        let clk_a = Arc::new(HlcClock::default());
        let clk_b = Arc::new(HlcClock::default());
        let a = D1Store::open(dir_a.clone(), clk_a, "au".into()).unwrap();
        let b = D1Store::open(dir_b.clone(), clk_b.clone(), "eu".into()).unwrap();

        let db = a.create_database("app").unwrap();

        // Verify PRAGMA cache_size = -2000
        let cache = a.query(&db.id, "PRAGMA cache_size", vec![], true, false, None).unwrap();
        assert_eq!(cache[0][0], -2000);

        // Reject undefined with D1_TYPE_ERROR
        let err = D1Param::from_json(&json!({ "__d1_undefined": true })).unwrap_err();
        assert!(err.contains("D1_TYPE_ERROR"), "got: {err}");

        a.exec(&db.id, "CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT NOT NULL);").unwrap();
        a.query(&db.id, "INSERT INTO users (id, name) VALUES (?, ?)", vec![D1Param::Integer(1), D1Param::Text("Alice".into())], false, false, None).unwrap();

        let first = a.query(&db.id, "SELECT name FROM users WHERE id = ?", vec![D1Param::Integer(1)], false, false, Some("name")).unwrap();
        assert_eq!(first, "Alice");

        let raw = a.query(&db.id, "SELECT id, name FROM users", vec![], true, true, None).unwrap();
        assert_eq!(raw, json!([["id", "name"], [1, "Alice"]]));

        // Batch atomic rollback: second statement violates NOT NULL, first must roll back
        let batch_err = a.batch(&db.id, vec![
            ("INSERT INTO users (id, name) VALUES (?, ?)".into(), vec![D1Param::Integer(2), D1Param::Text("Bob".into())]),
            ("INSERT INTO users (id, name) VALUES (?, ?)".into(), vec![D1Param::Integer(3), D1Param::Null]),
        ]);
        assert!(batch_err.is_err());
        let check_bob = a.query(&db.id, "SELECT name FROM users WHERE id = 2", vec![], false, false, Some("name")).unwrap();
        assert_eq!(check_bob, Value::Null);

        // Sync A -> B (full resync + incremental op)
        let d0 = a.export_since(0, None).unwrap();
        assert!(b.merge_delta(&d0, &clk_b).unwrap());
        let b_alice = b.query(&db.id, "SELECT name FROM users WHERE id = 1", vec![], false, false, Some("name")).unwrap();
        assert_eq!(b_alice, "Alice");

        let rev_b = d0.to_rev;
        let ep_a = d0.epoch;
        a.query(&db.id, "INSERT INTO users (id, name) VALUES (?, ?)", vec![D1Param::Integer(4), D1Param::Text("Dave".into())], false, false, None).unwrap();
        let d1 = a.export_since(rev_b, Some(&ep_a)).unwrap();
        assert!(!d1.full_resync);
        assert!(b.merge_delta(&d1, &clk_b).unwrap());
        let b_dave = b.query(&db.id, "SELECT name FROM users WHERE id = 4", vec![], false, false, Some("name")).unwrap();
        assert_eq!(b_dave, "Dave");

        let _ = std::fs::remove_dir_all(dir_a);
        let _ = std::fs::remove_dir_all(dir_b);
    }

    #[test]
    fn d1_pragma_not_replicated_and_stale_snapshot_ignored() {
        let dir_a = std::env::temp_dir().join(format!("fucf-d1-p1-{}", uuid::Uuid::new_v4().simple()));
        let dir_b = std::env::temp_dir().join(format!("fucf-d1-p2-{}", uuid::Uuid::new_v4().simple()));
        let clk_a = Arc::new(HlcClock::default());
        let clk_b = Arc::new(HlcClock::default());
        let a = D1Store::open(dir_a.clone(), clk_a, "au".into()).unwrap();
        let b = D1Store::open(dir_b.clone(), clk_b.clone(), "eu".into()).unwrap();

        let db = a.create_database("app").unwrap();
        a.exec(&db.id, "CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT);").unwrap();
        a.query(&db.id, "INSERT INTO t (id, v) VALUES (1, 'one')", vec![], false, false, None).unwrap();

        let rev_before = a.current_rev();
        a.query(&db.id, "PRAGMA table_info(t)", vec![], false, false, None).unwrap();
        a.query(&db.id, "WITH x AS (SELECT 1 AS n) SELECT * FROM x", vec![], false, false, None).unwrap();
        assert_eq!(a.current_rev(), rev_before, "PRAGMA/WITH must not record oplog entries");

        // B pulls initial snapshot (has id=1)
        let d0 = a.export_since(0, None).unwrap();
        assert!(b.merge_delta(&d0, &clk_b).unwrap());

        // A writes id=2 locally
        a.query(&db.id, "INSERT INTO t (id, v) VALUES (2, 'two')", vec![], false, false, None).unwrap();

        // B pushes its stale full_resync snapshot back to A: A must NOT overwrite id=2!
        let stale_push = b.export_since(0, None).unwrap();
        assert!(stale_push.full_resync);
        let _ = a.merge_delta(&stale_push, &Arc::new(HlcClock::default())).unwrap();
        let row2 = a.query(&db.id, "SELECT v FROM t WHERE id = 2", vec![], false, false, Some("v")).unwrap();
        assert_eq!(row2, "two", "stale peer snapshot must not overwrite newer local DB");

        let _ = std::fs::remove_dir_all(dir_a);
        let _ = std::fs::remove_dir_all(dir_b);
    }

    #[test]
    fn d1_authorizer_blocks_attach_unsafe_pragma_vacuum_into_and_path_traversal() {
        let dir = std::env::temp_dir().join(format!("fucf-d1-sec-{}", uuid::Uuid::new_v4().simple()));
        let clk = Arc::new(HlcClock::default());
        let d1 = D1Store::open(dir.clone(), clk, "au".into()).unwrap();
        let db = d1.create_database("sec").unwrap();

        let attach_err = d1.exec(&db.id, "ATTACH DATABASE ':memory:' AS evil;").unwrap_err();
        assert!(attach_err.contains("D1_ERROR"), "ATTACH must be denied: {attach_err}");

        let pragma_err = d1.exec(&db.id, "PRAGMA writable_schema = ON;").unwrap_err();
        assert!(pragma_err.contains("D1_ERROR"), "writable_schema must be denied: {pragma_err}");

        let vacuum_err = d1.exec(&db.id, "VACUUM INTO 'evil.sqlite';").unwrap_err();
        assert!(vacuum_err.contains("D1_ERROR"), "VACUUM INTO must be denied: {vacuum_err}");

        let trav_err = d1.query("../evil", "SELECT 1", vec![], false, false, None).unwrap_err();
        assert!(trav_err.contains("invalid database id"), "path traversal must be rejected: {trav_err}");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn d1_read_only_rejects_write_queries() {
        let dir_a = std::env::temp_dir().join(format!("fucf-d1-ro-a-{}", uuid::Uuid::new_v4().simple()));
        let clk_a = Arc::new(HlcClock::default());
        let clk_ro = Arc::new(HlcClock::default());
        let a = D1Store::open(dir_a.clone(), clk_a, "au".into()).unwrap();
        let ro = D1Store::open_ephemeral(clk_ro, "edge-ro".into());

        let db = a.create_database("app").unwrap();
        a.exec(&db.id, "CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT);").unwrap();
        a.query(&db.id, "INSERT INTO t (id, v) VALUES (1, 'hello')", vec![], false, false, None).unwrap();

        let delta = a.export_since(0, None).unwrap();
        assert!(ro.merge_delta(&delta, &Arc::new(HlcClock::default())).unwrap());

        // Read-only queries succeed
        let sel = ro.query(&db.id, "SELECT v FROM t WHERE id = 1", vec![], false, false, Some("v")).unwrap();
        assert_eq!(sel, "hello");
        ro.query(&db.id, "EXPLAIN SELECT v FROM t", vec![], false, false, None).unwrap();
        ro.query(&db.id, "PRAGMA table_info(t)", vec![], false, false, None).unwrap();
        let cte = ro.query(&db.id, "WITH c AS (SELECT v FROM t) SELECT v FROM c", vec![], false, false, Some("v")).unwrap();
        assert_eq!(cte, "hello");

        // Write queries are rejected with D1_READ_ONLY
        for bad_sql in [
            "INSERT INTO t (id, v) VALUES (2, 'nope')",
            "CREATE TABLE evil (x INT)",
            "  -- comment\nINSERT INTO t (id, v) VALUES (3, 'nope')",
            "/* c */ UPDATE t SET v = 'x'",
            "WITH c AS (SELECT 2 AS id, 'x' AS v) INSERT INTO t (id, v) SELECT id, v FROM c",
        ] {
            let err = ro.query(&db.id, bad_sql, vec![], false, false, None).unwrap_err();
            assert!(err.contains("D1_READ_ONLY"), "expected D1_READ_ONLY for '{bad_sql}', got: {err}");
        }

        let _ = std::fs::remove_dir_all(dir_a);
    }
}
