//! What a node can say about itself, and the few things it can be told to
//! do from the panel: the detail behind the fleet page.

use crate::edge::cache::Cache;
use crate::edge::front::Front;
use crate::gfw::GfwMonitor;
use crate::limits::Limits;
use crate::release::Updater;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Instant;

pub struct NodeInfo {
    pub started: Instant,
    pub started_at: String,
    /// What this process listens on, for people to read.
    pub listeners: Vec<String>,
    pub cache: Arc<Cache>,
    pub limits: Arc<Limits>,
    pub gfw: Arc<GfwMonitor>,
    pub updater: Arc<Updater>,
    pub front: Option<Arc<Front>>,
}

/// A number from a "Key:   12345 kB" line of a /proc file, in bytes.
fn proc_kb(text: &str, key: &str) -> Option<u64> {
    let line = text.lines().find(|l| l.starts_with(key))?;
    line[key.len()..].split_whitespace().next()?.parse::<u64>().ok().map(|kb| kb * 1024)
}

impl NodeInfo {
    /// Non-blocking wrapper around [`NodeInfo::status`] for Tokio handlers and
    /// background sync loops (`spawn_blocking` for `/proc/*` reads).
    pub async fn status_async(self: &Arc<Self>) -> Value {
        let this = self.clone();
        tokio::task::spawn_blocking(move || this.status()).await.unwrap_or(Value::Null)
    }

    /// The state of this node right now. Host figures come from /proc and
    /// are simply missing elsewhere.
    pub fn status(&self) -> Value {
        let read = |path: &str| std::fs::read_to_string(path).unwrap_or_default();
        let (own, meminfo, load) = (read("/proc/self/status"), read("/proc/meminfo"), read("/proc/loadavg"));
        let (cache_bytes, cache_objects, cache_max) = self.cache.usage();
        let (trusted, _, rejected) = self.updater.standing();
        let (_, limit) = self.limits.own();
        let load: Vec<f64> = load.split_whitespace().take(3).filter_map(|v| v.parse().ok()).collect();
        json!({
            "build": env!("CARGO_PKG_VERSION"),
            "exe": self.updater.own(),
            "started_at": self.started_at,
            "uptime_seconds": self.started.elapsed().as_secs(),
            "pid": std::process::id(),
            "hostname": read("/proc/sys/kernel/hostname").trim(),
            "os": format!("{} {}", std::env::consts::OS, std::env::consts::ARCH),
            "kernel": read("/proc/sys/kernel/osrelease").trim(),
            "cpus": std::thread::available_parallelism().map_or(0, |n| n.get()),
            "load": load,
            "memory_bytes": proc_kb(&own, "VmRSS:"),
            "host_memory_bytes": proc_kb(&meminfo, "MemTotal:"),
            "host_memory_available_bytes": proc_kb(&meminfo, "MemAvailable:"),
            "cache": { "bytes": cache_bytes, "objects": cache_objects, "max_bytes": cache_max },
            "listeners": self.listeners,
            "limit_state": limit.as_str(),
            "usage": self.limits.usage(),
            "gfw": self.gfw.get(),
            "releases": { "enabled": self.updater.enabled(), "on_trial": !trusted, "rejected": rejected },
            "http3_front": self.front.as_ref().map(|front| json!({ "port": front.port, "certificate_expires_on": front.expires().map(crate::store::rfc3339) })),
        })
    }

    /// Do what the panel asked of this node. Returns what to say about it,
    /// or the reason it cannot be done.
    pub async fn run(&self, action: &str) -> Result<String, String> {
        match action {
            "purge_cache" => {
                let (bytes, objects, _) = self.cache.usage();
                self.cache.clear();
                Ok(format!("cache emptied ({objects} objects, {bytes} bytes)"))
            }
            "restart" => {
                tracing::warn!("restarting, as asked from the panel");
                let updater = self.updater.clone();
                // gives the answer a moment to leave before the process is replaced
                tokio::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    let failure = tokio::task::spawn_blocking(move || updater.relaunch()).await.unwrap_or_else(|e| e.to_string());
                    tracing::error!("{failure}: stopping for the service manager to start the node again");
                    std::process::exit(1);
                });
                Ok("restarting".into())
            }
            other => Err(format!("'{other}' is not something a node can be told to do (restart, purge_cache)")),
        }
    }
}

pub const ACTIONS: [&str; 2] = ["restart", "purge_cache"];

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn describes_itself_and_empties_its_cache() {
        assert_eq!(proc_kb("VmPeak:\t  100 kB\nVmRSS:\t   2048 kB\n", "VmRSS:"), Some(2048 * 1024));
        assert_eq!(proc_kb("nothing here", "VmRSS:"), None);
        let dir = std::env::temp_dir().join(format!("fucf-node-{}", uuid::Uuid::new_v4().simple()));
        let node = NodeInfo {
            started: Instant::now(),
            started_at: crate::store::now(),
            listeners: vec!["dns 127.0.0.1:53".into()],
            cache: Arc::new(Cache::new(1 << 20)),
            limits: Arc::default(),
            gfw: Arc::default(),
            updater: Arc::new(Updater::new(&dir, None)),
            front: None,
        };
        let status = node.status();
        assert_eq!((&status["build"], &status["listeners"][0], &status["cache"]["max_bytes"]), (&json!(env!("CARGO_PKG_VERSION")), &json!("dns 127.0.0.1:53"), &json!(1 << 20)));
        assert!(status["exe"].as_str().is_some_and(|exe| exe.len() == 64) && status["releases"]["enabled"] == false && status["releases"]["on_trial"] == false);
        assert!(status["http3_front"].is_null() && status["limit_state"] == "ok" && status["pid"].as_u64().is_some());
        assert!(node.run("purge_cache").await.unwrap().starts_with("cache emptied (0 objects"));
        assert!(node.run("format-the-disk").await.unwrap_err().contains("not something a node can be told"));
    }
}
