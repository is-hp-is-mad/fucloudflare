//! Workers Cron Triggers: 5-field UTC cron parser, matcher, and peer-deduped
//! background scheduler invoking `scheduled(controller, env, ctx)`.

use crate::edge::Edge;
use crate::fleet::Fleet;
use crate::store::Store;
use chrono::{DateTime, Datelike, Timelike, Utc};
use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CronExpr {
    pub raw: String,
    minutes: BTreeSet<u32>,
    hours: BTreeSet<u32>,
    doms: BTreeSet<u32>,
    months: BTreeSet<u32>,
    dows: BTreeSet<u32>,
    dom_wild: bool,
    dow_wild: bool,
}

fn parse_named(tok: &str, names: &[&str], offset: u32) -> Option<u32> {
    let up = tok.to_ascii_uppercase();
    names
        .iter()
        .position(|&n| n == up)
        .map(|i| i as u32 + offset)
}

fn parse_field(
    field: &str,
    min: u32,
    max: u32,
    names: &[&str],
    name_offset: u32,
    wrap_seven: bool,
) -> Result<(BTreeSet<u32>, bool), String> {
    let field = field.trim();
    if field.is_empty() {
        return Err("empty cron field".into());
    }
    let is_wild = field == "*";
    let mut set = BTreeSet::new();

    let parse_atom = |s: &str| -> Result<u32, String> {
        let mut v = if let Some(n) = parse_named(s, names, name_offset) {
            n
        } else {
            s.parse::<u32>()
                .map_err(|_| format!("invalid cron value '{s}'"))?
        };
        if wrap_seven && v == 7 {
            v = 0;
        }
        if v < min || v > max {
            return Err(format!("cron value {v} out of range {min}..={max}"));
        }
        Ok(v)
    };

    for part in field.split(',') {
        let (range_part, step) = match part.split_once('/') {
            Some((r, s)) => {
                let step = s
                    .parse::<u32>()
                    .map_err(|_| format!("invalid cron step '{s}'"))?;
                if step == 0 {
                    return Err("cron step must be >= 1".into());
                }
                (r, step)
            }
            None => (part, 1),
        };

        let (start, end) = if range_part == "*" {
            (min, max)
        } else if let Some((a, b)) = range_part.split_once('-') {
            let a = parse_atom(a)?;
            let b = parse_atom(b)?;
            if a > b {
                return Err(format!("invalid cron range '{range_part}'"));
            }
            (a, b)
        } else {
            let v = parse_atom(range_part)?;
            if step > 1 {
                (v, max)
            } else {
                set.insert(v);
                continue;
            }
        };

        let mut v = start;
        while v <= end {
            set.insert(if wrap_seven && v == 7 { 0 } else { v });
            v += step;
        }
    }

    if set.is_empty() {
        return Err("cron field matched no values".into());
    }
    Ok((set, is_wild))
}

impl CronExpr {
    pub fn parse(expr: &str) -> Result<Self, String> {
        let trimmed = expr.trim();
        let expanded = match trimmed {
            "@yearly" | "@annually" => "0 0 1 1 *",
            "@monthly" => "0 0 1 * *",
            "@weekly" => "0 0 * * 0",
            "@daily" | "@midnight" => "0 0 * * *",
            "@hourly" => "0 * * * *",
            _ => trimmed,
        };
        let parts: Vec<&str> = expanded.split_whitespace().collect();
        if parts.len() != 5 {
            return Err(format!("cron expression must have 5 fields, got '{}'", expr));
        }
        let (minutes, _) = parse_field(parts[0], 0, 59, &[], 0, false)?;
        let (hours, _) = parse_field(parts[1], 0, 23, &[], 0, false)?;
        let (doms, dom_wild) = parse_field(parts[2], 1, 31, &[], 0, false)?;
        let months_names = ["JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC"];
        let (months, _) = parse_field(parts[3], 1, 12, &months_names, 1, false)?;
        let dow_names = ["SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"];
        let (dows, dow_wild) = parse_field(parts[4], 0, 7, &dow_names, 0, true)?;

        Ok(CronExpr {
            raw: trimmed.to_string(),
            minutes,
            hours,
            doms,
            months,
            dows,
            dom_wild,
            dow_wild,
        })
    }

    pub fn matches_utc(&self, dt: DateTime<Utc>) -> bool {
        if !self.minutes.contains(&dt.minute())
            || !self.hours.contains(&dt.hour())
            || !self.months.contains(&dt.month())
        {
            return false;
        }
        let dom_ok = self.doms.contains(&dt.day());
        let dow_ok = self.dows.contains(&dt.weekday().num_days_from_sunday());
        match (self.dom_wild, self.dow_wild) {
            (true, true) => true,
            (true, false) => dow_ok,
            (false, true) => dom_ok,
            // Standard Vixie cron: if both DOM and DOW are restricted, either matching triggers.
            (false, false) => dom_ok || dow_ok,
        }
    }
}

/// Spawn the background UTC cron scheduler on `NodeRole::Peer` nodes.
pub fn spawn_scheduler(
    edge: Arc<Edge>,
    store: Arc<Store>,
    fleet: Arc<Fleet>,
    self_node: String,
) {
    tokio::spawn(async move {
        let mut fired: HashMap<(String, String), i64> = HashMap::new();
        loop {
            tokio::time::sleep(Duration::from_secs(10)).await;
            if store.is_read_only() {
                continue;
            }
            let now = Utc::now();
            let minute_epoch = now.timestamp() / 60;
            let scheduled_ms = (minute_epoch * 60) * 1000;

            // Peer dedup: only the deterministic leader among online peers fires.
            let online = fleet.online_peers();
            let preferred = crate::sync::acme_lease::preferred_leader(&self_node, &online);
            if preferred != self_node {
                continue;
            }

            let snap = store.snapshot();
            for script in snap.workers.values() {
                for expr_str in &script.crons {
                    let Ok(parsed) = CronExpr::parse(expr_str) else {
                        continue;
                    };
                    if !parsed.matches_utc(now) {
                        continue;
                    }
                    let key = (script.name.clone(), expr_str.clone());
                    if fired.get(&key).copied() == Some(minute_epoch) {
                        continue;
                    }
                    fired.insert(key, minute_epoch);
                    let edge_c = edge.clone();
                    let snap_c = snap.clone();
                    let script_c = script.clone();
                    let cron_c = expr_str.clone();
                    tokio::spawn(async move {
                        if let Err(e) = crate::workers::run_scheduled(
                            edge_c,
                            snap_c,
                            script_c,
                            &cron_c,
                            scheduled_ms as u64,
                        )
                        .await
                        {
                            tracing::warn!(cron = %cron_c, "scheduled worker failed: {e}");
                        }
                    });
                }
            }

            // Prune stale minute markers.
            fired.retain(|_, &mut m| m >= minute_epoch - 5);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn cron_parse_and_match_utc() {
        let c = CronExpr::parse("*/15 2-4 * JAN,JUN MON-FRI").unwrap();
        let ok_dt = Utc.with_ymd_and_hms(2026, 6, 1, 3, 30, 0).unwrap(); // Monday June 1, 2026 03:30 UTC
        assert!(c.matches_utc(ok_dt));

        let wrong_min = Utc.with_ymd_and_hms(2026, 6, 1, 3, 31, 0).unwrap();
        assert!(!c.matches_utc(wrong_min));

        let wrong_day = Utc.with_ymd_and_hms(2026, 6, 6, 3, 30, 0).unwrap(); // Saturday
        assert!(!c.matches_utc(wrong_day));

        assert!(CronExpr::parse("@hourly").unwrap().matches_utc(Utc.with_ymd_and_hms(2026, 1, 1, 12, 0, 0).unwrap()));
        assert!(CronExpr::parse("bad cron").is_err());
        assert!(CronExpr::parse("60 * * * *").is_err());
    }
}
