//! Rolling updates: the fleet replaces its own binary, one node at a time,
//! and goes back to what it ran before when that does not work out.
//!
//! A release is a binary signed with the operator's key (Ed25519; the nodes
//! only know the public half, so the API token alone cannot make them run
//! anything). It is uploaded to the primary, which then lets the replicas
//! take it one after the other -- the next one only once the one before
//! is back, in sync and has passed its trial -- and takes it itself last.
//!
//! On a node, the binary that the service manager starts stays where it is
//! and acts as a launcher: at start it looks into `<data-dir>/releases` and,
//! if a properly signed release is current there, becomes that release
//! (`exec`). A release is on trial at first. It goes back to what ran
//! before it -- an earlier release, or the launcher's own binary -- when it
//!
//! - does not stay up for the length of the trial, twice in a row;
//! - stays up but fails its self-test at the end of the trial (the node's
//!   listeners do not answer, a replica cannot reach its primary);
//! - hangs, so that it never gets to the self-test (a watchdog thread).
//!
//! The roll-out stops at the first node where that happens, or that does
//! not come back at all, and the nodes that had taken the release before
//! are told to go back as well, again one at a time: a failed update leaves
//! the whole fleet on what it ran before. Withdrawing a release by hand
//! does the same.
//!
//! A binary installed by hand (a new launcher) overrides all of this: the
//! releases that were rolled out on top of the one before are forgotten.

use crate::acme::{b64, unb64};
use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

/// How long a release has to stay up to be trusted with the node.
const TRIAL: Duration = Duration::from_secs(45);
/// Starts a release gets to prove itself.
const TRIAL_STARTS: u32 = 2;
/// How long after the trial a release may take to pass its self-test
/// before the watchdog decides that it hangs.
const WATCHDOG: Duration = Duration::from_secs(60);
/// Set for the process a launcher turned into, to the launcher's path: it
/// never launches in circles, and knows what to turn into to start over.
const LAUNCHED: &str = "FUCF_LAUNCHED";

pub fn sha256_hex(bytes: &[u8]) -> String {
    crate::acme::sha256(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

fn is_digest(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// What a signature is made over: the digest of the binary, in a sentence
/// that cannot be mistaken for anything else signed with the key.
fn statement(sha256: &str) -> Vec<u8> {
    format!("fucf release {sha256}").into_bytes()
}

/// A new signing key: `(private key to keep, public key for the nodes)`.
pub fn keygen() -> Result<(String, String), String> {
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).map_err(|_| "cannot generate a key")?;
    let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).map_err(|_| "cannot use the generated key")?;
    Ok((b64(pkcs8.as_ref()), b64(pair.public_key().as_ref())))
}

/// The public half of a private key.
pub fn public_key(private_key: &str) -> Result<String, String> {
    let pkcs8 = unb64(private_key.trim()).ok_or("the private key is not base64url")?;
    let pair = Ed25519KeyPair::from_pkcs8(&pkcs8).map_err(|_| "the private key is not an Ed25519 key")?;
    Ok(b64(pair.public_key().as_ref()))
}

pub fn sign(private_key: &str, sha256: &str) -> Result<String, String> {
    let pkcs8 = unb64(private_key.trim()).ok_or("the private key is not base64url")?;
    let pair = Ed25519KeyPair::from_pkcs8(&pkcs8).map_err(|_| "the private key is not an Ed25519 key")?;
    Ok(b64(pair.sign(&statement(sha256)).as_ref()))
}

pub fn verify(public_key: &str, sha256: &str, signature: &str) -> Result<(), String> {
    let key = unb64(public_key.trim()).filter(|k| k.len() == 32).ok_or("the release key is not a 32-byte base64url public key")?;
    let signature = unb64(signature.trim()).ok_or("the signature is not base64url")?;
    UnparsedPublicKey::new(&ED25519, key)
        .verify(&statement(sha256), &signature)
        .map_err(|_| "the signature does not match the release key".to_string())
}

// ---------------------------------------------------------- on a node ----

/// What a node knows about the releases it holds (`releases/state.json`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
struct Local {
    /// The release to run, by digest.
    current: Option<String>,
    /// What ran before it: where to go back to.
    previous: Option<String>,
    /// `current` stayed up through its trial.
    committed: bool,
    /// Times `current` was started without getting that far.
    starts: u32,
    /// Releases that failed their trial here; never run again.
    bad: Vec<String>,
    /// Digest of the launcher all of this was rolled out on top of.
    base: Option<String>,
    /// The last submission this node heard of (see `Updater::forgive`).
    submission: Option<String>,
}

impl Local {
    fn reject(&mut self, sha256: &str) {
        if !self.bad.iter().any(|b| b == sha256) {
            self.bad.push(sha256.to_string());
            let excess = self.bad.len().saturating_sub(16);
            self.bad.drain(..excess);
        }
        if self.current.as_deref() == Some(sha256) {
            // what ran before had proven itself
            (self.current, self.committed, self.starts) = (self.previous.take(), true, 0);
        } else if self.previous.as_deref() == Some(sha256) {
            self.previous = None;
        }
    }
}

/// Which release to run on a node whose own binary is `own`. Counts the
/// start if it is one more attempt of a release on trial, and drops
/// releases that used up their attempts (or are not `usable`: not on disk,
/// not signed) in favour of the one before.
fn pick(state: &mut Local, own: &str, usable: impl Fn(&str) -> bool) -> Option<String> {
    loop {
        let current = state.current.clone()?;
        let rejected = state.bad.contains(&current);
        if !rejected && current == own {
            return Some(current); // running already
        }
        if !rejected && usable(&current) && (state.committed || state.starts < TRIAL_STARTS) {
            if !state.committed {
                state.starts += 1;
            }
            return Some(current);
        }
        state.reject(&current);
    }
}

pub struct Updater {
    dir: PathBuf,
    /// Public key releases must be signed with; without one nothing is ever run.
    key: Option<String>,
    /// Digest of the binary this process runs.
    own: String,
    /// The binary the service manager starts: what to turn into to start over.
    launcher: PathBuf,
    /// This process is a release that a launcher turned into.
    launched: bool,
    trial: Duration,
    /// Run right before the process turns into another binary.
    before_exec: OnceLock<Box<dyn Fn() + Send + Sync>>,
    /// Cached `releases/state.json` so `standing()` / `on_trial()` / `rejected()` never block on disk I/O.
    local: Mutex<Local>,
    lock: Mutex<()>,
}

impl Updater {
    pub fn new(data_dir: &Path, key: Option<String>) -> Updater {
        let exe = std::env::current_exe().unwrap_or_default();
        // the file may have been replaced since this process started
        let own = std::fs::read("/proc/self/exe").or_else(|_| std::fs::read(&exe)).map(|bytes| sha256_hex(&bytes)).unwrap_or_default();
        let exe = match exe.to_str().and_then(|p| p.strip_suffix(" (deleted)")) {
            Some(path) => PathBuf::from(path),
            None => exe,
        };
        let launcher = std::env::var_os(LAUNCHED).filter(|l| !l.is_empty()).map(PathBuf::from);
        let trial = std::env::var("FUCF_RELEASE_TRIAL").ok().and_then(|secs| secs.trim().parse().ok()).map(Duration::from_secs);
        let mut updater = Updater::with(data_dir.join("releases"), key, own);
        updater.launched = launcher.is_some();
        updater.launcher = launcher.unwrap_or(exe);
        updater.trial = trial.unwrap_or(TRIAL);
        updater
    }

    fn read_disk(dir: &Path) -> Local {
        std::fs::read(dir.join("state.json")).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
    }

    fn with(dir: PathBuf, key: Option<String>, own: String) -> Updater {
        let key = key.map(|k| k.trim().to_string()).filter(|k| !k.is_empty());
        let initial = Self::read_disk(&dir);
        Updater {
            dir,
            key,
            own,
            launcher: PathBuf::new(),
            launched: false,
            trial: TRIAL,
            before_exec: OnceLock::new(),
            local: Mutex::new(initial),
            lock: Mutex::default(),
        }
    }

    /// Digest of the running binary.
    pub fn own(&self) -> &str {
        &self.own
    }

    pub fn enabled(&self) -> bool {
        self.key.is_some()
    }

    pub fn on_exec(&self, hook: impl Fn() + Send + Sync + 'static) {
        let _ = self.before_exec.set(Box::new(hook));
    }

    fn load(&self) -> Local {
        self.local.lock().unwrap().clone()
    }

    fn save(&self, state: &Local) -> Result<(), String> {
        *self.local.lock().unwrap() = state.clone();
        let (path, tmp) = (self.dir.join("state.json"), self.dir.join("state.json.tmp"));
        std::fs::create_dir_all(&self.dir)
            .and_then(|_| std::fs::write(&tmp, serde_json::to_vec(state).unwrap_or_default()))
            .and_then(|_| std::fs::rename(&tmp, &path))
            .map_err(|e| format!("cannot write {}: {e}", path.display()))
    }

    fn persist_state_file(&self, state: &Local) -> Result<(), String> {
        let (path, tmp) = (self.dir.join("state.json"), self.dir.join("state.json.tmp"));
        std::fs::create_dir_all(&self.dir)
            .and_then(|_| std::fs::write(&tmp, serde_json::to_vec(state).unwrap_or_default()))
            .and_then(|_| std::fs::rename(&tmp, &path))
            .map_err(|e| format!("cannot write {}: {e}", path.display()))
    }

    /// Releases that failed their trial on this node (cached in memory).
    pub fn rejected(&self) -> Vec<String> {
        self.local.lock().unwrap().bad.clone()
    }

    /// What this node tells its peers: whether its binary is trusted (not
    /// on trial), the last submission it heard of, and what failed here.
    pub fn standing(&self) -> (bool, String, Vec<String>) {
        let state = self.local.lock().unwrap();
        let on_trial = self.key.is_some() && state.current.as_deref() == Some(self.own.as_str()) && !state.committed;
        (!on_trial, state.submission.clone().unwrap_or_default(), state.bad.clone())
    }

    /// Is the running binary a release that has yet to pass its trial?
    pub fn on_trial(&self) -> bool {
        if self.key.is_none() {
            return false;
        }
        let state = self.local.lock().unwrap();
        state.current.as_deref() == Some(self.own.as_str()) && !state.committed
    }

    /// Is this release on disk, intact and signed with our key?
    fn usable(&self, sha256: &str) -> bool {
        let Some(key) = &self.key else { return false };
        let signed = std::fs::read_to_string(self.dir.join(format!("{sha256}.sig"))).is_ok_and(|sig| verify(key, sha256, &sig).is_ok());
        signed && std::fs::read(self.dir.join(sha256)).is_ok_and(|bytes| sha256_hex(&bytes) == sha256)
    }

    /// Check a release and put it on disk (running it is another matter).
    pub fn install(&self, sha256: &str, signature: &str, bytes: &[u8]) -> Result<(), String> {
        let key = self.key.as_ref().ok_or("no release key is configured on this node (--release-key): updates are off")?;
        if !is_digest(sha256) || sha256_hex(bytes) != sha256 {
            return Err("the release is not the one announced: its digest differs".into());
        }
        verify(key, sha256, signature)?;
        let path = self.dir.join(sha256);
        let write = || -> std::io::Result<()> {
            std::fs::create_dir_all(&self.dir)?;
            let tmp = self.dir.join(format!("{sha256}.part"));
            std::fs::write(&tmp, bytes)?;
            #[cfg(unix)]
            std::fs::set_permissions(&tmp, std::os::unix::fs::PermissionsExt::from_mode(0o755))?;
            std::fs::rename(&tmp, &path)?;
            std::fs::write(self.dir.join(format!("{sha256}.sig")), signature.trim())
        };
        write().map_err(|e| format!("cannot store the release in {}: {e}", self.dir.display()))
    }

    pub fn read(&self, sha256: &str) -> std::io::Result<Vec<u8>> {
        if !is_digest(sha256) {
            return Err(std::io::Error::other("not a release digest"));
        }
        std::fs::read(self.dir.join(sha256))
    }

    /// Make an installed release the one to run (on trial).
    pub fn activate(&self, sha256: &str) -> Result<(), String> {
        let snapshot = {
            let _guard = self.lock.lock().unwrap();
            let mut state = self.local.lock().unwrap().clone();
            if state.bad.iter().any(|b| b == sha256) {
                return Err("this release failed on this node before".into());
            }
            if state.current.as_deref() != Some(sha256) {
                // go back to what is proven: the current release if it got that far, else the one before it
                if state.committed && state.current.is_some() {
                    state.previous = state.current.take();
                }
                (state.current, state.committed, state.starts) = (Some(sha256.to_string()), false, 0);
            }
            *self.local.lock().unwrap() = state.clone();
            state
        };
        self.persist_state_file(&snapshot)
    }

    /// Never run this release (again): if it is the current one, what ran
    /// before it is current again.
    pub fn reject(&self, sha256: &str) -> Result<(), String> {
        let snapshot = {
            let _guard = self.lock.lock().unwrap();
            let mut state = self.local.lock().unwrap().clone();
            state.reject(sha256);
            *self.local.lock().unwrap() = state.clone();
            state
        };
        self.persist_state_file(&snapshot)
    }

    /// A release was submitted (again): whatever happened to it on this
    /// node before no longer counts. Once per submission.
    pub fn forgive(&self, submission: &str, sha256: &str) {
        let snapshot = {
            let _guard = self.lock.lock().unwrap();
            let mut state = self.local.lock().unwrap().clone();
            if state.submission.as_deref() == Some(submission) {
                return;
            }
            state.submission = Some(submission.to_string());
            state.bad.retain(|b| b != sha256);
            *self.local.lock().unwrap() = state.clone();
            state
        };
        if let Err(e) = self.persist_state_file(&snapshot) {
            tracing::warn!("{e}");
        }
    }

    /// At start: turn into the release that should be running, if that is
    /// not this binary. Returns (with the reason, if there is something to
    /// say) when this binary is to go on.
    pub fn launch(&self) -> Option<String> {
        self.key.as_ref()?;
        let (target, to_persist) = {
            let _guard = self.lock.lock().unwrap();
            let mut state = self.local.lock().unwrap().clone();
            let before = state.clone();
            if !self.launched && state.base.as_deref() != Some(self.own.as_str()) {
                // a binary installed by hand: what was rolled out on top of the one before is history
                if state.current.is_some() {
                    tracing::info!("this binary is new here: forgetting the releases rolled out on top of the one before");
                }
                state = Local { base: Some(self.own.clone()), ..Default::default() };
            }
            let target = pick(&mut state, &self.own, |sha| self.usable(sha));
            let changed = state != before;
            if changed {
                *self.local.lock().unwrap() = state.clone();
            }
            (target, changed.then_some(state))
        };
        if let Some(state) = to_persist {
            if let Err(e) = self.persist_state_file(&state) {
                return Some(e);
            }
        }
        let target = target.filter(|sha| *sha != self.own)?;
        if self.launched {
            return Some(format!("started as a release, but release {target} is current: staying"));
        }
        Some(format!("cannot start release {target}: {}", exec(&self.dir.join(&target), Some(&self.launcher))))
    }

    /// Start over as whatever should be running now (decided by the
    /// launcher, which this process turns into). Only returns, with the
    /// reason, if that did not work.
    pub fn relaunch(&self) -> String {
        if let Some(hook) = self.before_exec.get() {
            hook();
        }
        format!("cannot start {}: {}", self.launcher.display(), exec(&self.launcher, None))
    }

    /// The trial of the running release is over: it has passed, or it goes.
    /// Returns whether this process is to start over (as what ran before).
    fn conclude(&self, verdict: Result<(), String>) -> bool {
        let (snapshot, restart) = {
            let _guard = self.lock.lock().unwrap();
            let mut state = self.local.lock().unwrap().clone();
            if state.current.as_deref() != Some(self.own.as_str()) || state.committed {
                return false;
            }
            match verdict {
                Ok(()) => {
                    (state.committed, state.starts) = (true, 0);
                    tracing::info!("release {} has passed its trial", self.own);
                }
                Err(reason) => {
                    tracing::error!("release {} does not work on this node ({reason}): going back to what ran before", self.own);
                    state.reject(&self.own);
                }
            }
            *self.local.lock().unwrap() = state.clone();
            let restart = !state.committed || state.current.as_deref() != Some(self.own.as_str());
            (state, restart)
        };
        if let Err(e) = self.persist_state_file(&snapshot) {
            tracing::warn!("{e}");
        }
        restart
    }

    /// Start over, or stop for the service manager to do it.
    fn start_over(&self) -> ! {
        tracing::error!("{}", self.relaunch());
        std::process::exit(1)
    }

    /// Once this binary has run long enough: if it is a release on trial,
    /// `check` decides whether it stays. Releases no longer needed are deleted.
    pub async fn settle<F, Fut>(self: Arc<Self>, check: F)
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<(), String>>,
    {
        if self.key.is_none() {
            return;
        }
        tokio::time::sleep(self.trial).await;
        if self.on_trial() {
            let verdict = check().await;
            let this = self.clone();
            let should_restart = tokio::task::spawn_blocking(move || this.conclude(verdict))
                .await
                .unwrap_or(false);
            if should_restart {
                let this = self.clone();
                let _ = tokio::task::spawn_blocking(move || this.start_over()).await;
            }
        }
        let this = self;
        let _ = tokio::task::spawn_blocking(move || this.tidy()).await;
    }

    /// Delete the releases nobody needs any more: all but the current one,
    /// the one to go back to, the one the fleet is rolling out (on the
    /// primary, which hands it to the replicas), and whatever arrived in
    /// the last minutes (it may be about to become one of those).
    fn tidy(&self) {
        let state = {
            let _guard = self.lock.lock().unwrap();
            self.local.lock().unwrap().clone()
        };
        let rolling: Option<String> = std::fs::read(self.dir.join("target.json"))
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
            .and_then(|target| target["sha256"].as_str().map(String::from));
        let keep: Vec<&String> = state.current.iter().chain(&state.previous).chain(&rolling).collect();
        for entry in std::fs::read_dir(&self.dir).into_iter().flatten().flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let digest = name.split('.').next().unwrap_or_default();
            let fresh = entry.metadata().and_then(|m| m.modified()).is_ok_and(|at| at.elapsed().is_ok_and(|age| age < Duration::from_secs(600)));
            if is_digest(digest) && !fresh && !keep.iter().any(|k| *k == digest) {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }

    /// A release on trial that never gets to its self-test (it hangs) is
    /// taken off the node by a thread of its own.
    pub fn watchdog(self: &Arc<Self>) {
        if !self.on_trial() {
            return;
        }
        let this = self.clone();
        std::thread::spawn(move || {
            std::thread::sleep(this.trial + WATCHDOG);
            if this.on_trial() && this.conclude(Err("it never finished its self-test".into())) {
                this.start_over();
            }
        });
    }
}

/// Replace this process by `path`, with the same arguments and environment.
/// A release is told which launcher it came from. Only returns if that did
/// not work.
#[cfg(unix)]
fn exec(path: &Path, launcher: Option<&Path>) -> std::io::Error {
    use std::os::unix::process::CommandExt;
    let mut args = std::env::args_os();
    let mut command = std::process::Command::new(path);
    if let Some(name) = args.next() {
        command.arg0(name);
    }
    match launcher {
        Some(launcher) => command.env(LAUNCHED, launcher),
        None => command.env_remove(LAUNCHED),
    };
    command.args(args).exec()
}

#[cfg(not(unix))]
fn exec(_: &Path, _: Option<&Path>) -> std::io::Error {
    std::io::Error::other("a process cannot be replaced in place on this platform")
}

// ------------------------------------------------------ on the primary ----

/// A replica as the roll-out sees it.
#[derive(Debug, Clone, Serialize)]
pub struct PeerView {
    pub name: String,
    pub online: bool,
    /// Runs the current configuration.
    pub in_sync: bool,
    /// Digest of the binary it runs (empty: it did not say).
    pub exe: String,
    /// That binary is not on trial (any more).
    pub trusted: bool,
    /// It tried the release and went back.
    pub rejected: bool,
}

/// The primary itself, as the roll-out sees it.
#[derive(Debug, Clone, Copy)]
pub struct Own<'a> {
    pub exe: &'a str,
    pub trusted: bool,
    pub rejected: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "phase", rename_all = "snake_case")]
pub enum Phase {
    /// No release to roll out.
    Idle,
    /// The primary just started and waits for the replicas to get in touch.
    Starting,
    /// `node` has leave to update: it is `updating`, or back and `settling`.
    Rolling { node: String, step: &'static str },
    /// Every replica runs the release: now the primary itself.
    UpdatingPrimary,
    Done,
    /// The roll-out failed: `node` goes back to what it ran before.
    RollingBack { node: String, reason: String },
    /// ... and so does the primary, last.
    RevertingPrimary { reason: String },
    /// The roll-out failed, and nobody runs the release (any more).
    Failed { reason: String },
}

/// What a node may do about the release right now.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Leave {
    None,
    Update,
    Revert,
}

/// What became of a release (kept by the primary across restarts).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Outcome {
    Rolling,
    Done,
    Failed { reason: String },
}

struct Grant {
    node: String,
    sha256: String,
    /// Leave to go back, not to update.
    revert: bool,
    at: Instant,
    /// Since when the node is back on the release and in sync.
    back: Option<Instant>,
}

/// The primary's side of a roll-out: who may update (or go back) now.
pub struct Rollout {
    /// How long a node has to stay up on the release, after its trial,
    /// before the next one goes.
    pub soak: Duration,
    /// How long a node gets to come back on the release.
    pub patience: Duration,
    /// How long after its own start the primary waits before deciding anything.
    pub grace: Duration,
    started: Instant,
    granted: Option<Grant>,
    /// The release that failed, and why: all that is left to do is going back.
    failed: Option<(String, String)>,
    /// The release that made it onto the whole fleet.
    accepted: Option<String>,
    /// Nodes that did not go back when told to: not waited for again.
    stuck: Vec<String>,
    pub phase: Phase,
}

impl Default for Rollout {
    fn default() -> Self {
        Rollout {
            soak: Duration::from_secs(15),
            patience: Duration::from_secs(300),
            grace: Duration::from_secs(20),
            started: Instant::now(),
            granted: None,
            failed: None,
            accepted: None,
            stuck: Vec::new(),
            phase: Phase::Idle,
        }
    }
}

impl Rollout {
    /// Timings that go with a trial of this length.
    fn timed(trial: Duration) -> Rollout {
        Rollout { soak: trial / 3, grace: Duration::from_secs(20).min(trial * 4), ..Default::default() }
    }

    /// May `node`, which runs something else, replace its binary by release
    /// `sha256` now -- or, running it, must it go back?
    pub fn leave(&self, node: &str, sha256: &str) -> Leave {
        match &self.granted {
            Some(g) if g.node == node && g.sha256 == sha256 => {
                if g.revert {
                    Leave::Revert
                } else {
                    Leave::Update
                }
            }
            _ => Leave::None,
        }
    }

    /// A release was (re)submitted: whatever happened to an earlier one is history.
    pub fn restart(&mut self) {
        (self.granted, self.failed, self.accepted) = (None, None, None);
        self.stuck.clear();
    }

    /// The release does not work out (or is withdrawn): everyone goes back.
    pub fn fail(&mut self, sha256: &str, reason: String) {
        tracing::warn!("roll-out of release {sha256} failed ({reason}): the fleet goes back to what it ran before");
        self.restart();
        self.failed = Some((sha256.to_string(), reason));
    }

    /// Pick up where a primary left off before its restart.
    pub fn resume(&mut self, sha256: &str, outcome: &Outcome) {
        self.restart();
        match outcome {
            Outcome::Rolling => {}
            Outcome::Done => self.accepted = Some(sha256.to_string()),
            Outcome::Failed { reason } => self.failed = Some((sha256.to_string(), reason.clone())),
        }
    }

    pub fn outcome(&self, sha256: &str) -> Outcome {
        if let Some((_, reason)) = self.failed.as_ref().filter(|(sha, _)| sha == sha256) {
            return Outcome::Failed { reason: reason.clone() };
        }
        if self.accepted.as_deref() == Some(sha256) {
            return Outcome::Done;
        }
        Outcome::Rolling
    }

    /// Look at the fleet and decide what happens next.
    pub fn step(&mut self, target: Option<&str>, own: Own, peers: &[PeerView], now: Instant) -> Phase {
        self.phase = self.decide(target, own, peers, now);
        self.phase.clone()
    }

    fn decide(&mut self, target: Option<&str>, own: Own, peers: &[PeerView], now: Instant) -> Phase {
        let Some(target) = target else {
            self.restart();
            return Phase::Idle;
        };
        if self.accepted.as_deref() == Some(target) {
            return Phase::Done;
        }
        if now.duration_since(self.started) < self.grace {
            return Phase::Starting;
        }
        if let Some((_, reason)) = self.failed.clone().filter(|(sha, _)| sha == target) {
            return self.roll_back(target, reason, own, peers, now);
        }
        if let Some(peer) = peers.iter().find(|p| p.online && p.rejected) {
            let reason = format!("{} could not run the release and went back to what it ran before", peer.name);
            return self.fail_now(target, reason, own, peers, now);
        }
        self.granted = self.granted.take().filter(|g| g.sha256 == target && !g.revert);
        if let Some(grant) = &mut self.granted {
            let node = grant.node.clone();
            let back = peers.iter().any(|p| p.name == node && p.online && p.in_sync && p.exe == target && p.trusted);
            if !back {
                grant.back = None;
                if now.duration_since(grant.at) > self.patience {
                    let reason = format!("{node} did not come back on the release within {} s", self.patience.as_secs());
                    return self.fail_now(target, reason, own, peers, now);
                }
                return Phase::Rolling { node, step: "updating" };
            }
            if now.duration_since(*grant.back.get_or_insert(now)) < self.soak {
                return Phase::Rolling { node, step: "settling" };
            }
            self.granted = None;
        }
        // replicas that do not say what they run do not take releases
        let mut waiting: Vec<&PeerView> = peers.iter().filter(|p| p.online && !p.exe.is_empty() && p.exe != target).collect();
        waiting.sort_by(|a, b| a.name.cmp(&b.name));
        if let Some(next) = waiting.first() {
            tracing::info!("roll-out of release {target}: {} goes now", next.name);
            self.granted = Some(Grant { node: next.name.clone(), sha256: target.to_string(), revert: false, at: now, back: None });
            return Phase::Rolling { node: next.name.clone(), step: "updating" };
        }
        if own.exe == target {
            if !own.trusted {
                return Phase::UpdatingPrimary; // on trial
            }
            tracing::info!("release {target} runs on the whole fleet");
            self.accepted = Some(target.to_string());
            return Phase::Done;
        }
        if own.rejected {
            let reason = "the primary could not run the release and went back to what it ran before".to_string();
            return self.fail_now(target, reason, own, peers, now);
        }
        Phase::UpdatingPrimary
    }

    fn fail_now(&mut self, target: &str, reason: String, own: Own, peers: &[PeerView], now: Instant) -> Phase {
        self.fail(target, reason.clone());
        self.roll_back(target, reason, own, peers, now)
    }

    /// After a failure: the nodes that run the release go back, one at a
    /// time, the primary last.
    fn roll_back(&mut self, target: &str, reason: String, own: Own, peers: &[PeerView], now: Instant) -> Phase {
        if let Some(grant) = self.granted.take().filter(|g| g.sha256 == target && g.revert) {
            let off = peers.iter().any(|p| p.name == grant.node && p.online && p.in_sync && p.exe != target);
            if !off && now.duration_since(grant.at) <= self.patience / 5 {
                let node = grant.node.clone();
                self.granted = Some(grant);
                return Phase::RollingBack { node, reason };
            }
            if !off {
                tracing::warn!("{} does not go back from release {target}: not waiting for it", grant.node);
                self.stuck.push(grant.node);
            }
        }
        let mut on_it: Vec<&PeerView> = peers.iter().filter(|p| p.online && p.exe == target && !self.stuck.contains(&p.name)).collect();
        on_it.sort_by(|a, b| a.name.cmp(&b.name));
        if let Some(next) = on_it.first() {
            tracing::warn!("release {target} failed: {} goes back now", next.name);
            self.granted = Some(Grant { node: next.name.clone(), sha256: target.to_string(), revert: true, at: now, back: None });
            return Phase::RollingBack { node: next.name.clone(), reason };
        }
        if own.exe == target {
            return Phase::RevertingPrimary { reason };
        }
        Phase::Failed { reason }
    }
}

/// The release the fleet is to run (`releases/target.json` on the primary).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    /// One per submission: the same binary submitted again is a new attempt.
    pub id: String,
    pub sha256: String,
    pub signature: String,
    pub size: u64,
    pub submitted_at: String,
    #[serde(flatten)]
    pub outcome: Outcome,
}

/// Everything about releases on one node: its own binaries and, on the
/// primary, the roll-out.
pub struct Releases {
    pub updater: Arc<Updater>,
    target: Mutex<Option<Target>>,
    rollout: Mutex<Rollout>,
}

impl Releases {
    pub fn new(updater: Arc<Updater>, primary: bool) -> Releases {
        let target: Option<Target> = Some(updater.dir.join("target.json"))
            .filter(|_| primary && updater.enabled())
            .and_then(|path| std::fs::read(path).ok())
            .and_then(|bytes| serde_json::from_slice(&bytes).ok());
        let mut rollout = Rollout::timed(updater.trial);
        if let Some(target) = &target {
            rollout.resume(&target.sha256, &target.outcome);
        }
        Releases { updater, target: Mutex::new(target), rollout: Mutex::new(rollout) }
    }

    fn persist(&self, target: &Option<Target>) {
        let path = self.updater.dir.join("target.json");
        let done = match target {
            Some(target) => std::fs::create_dir_all(&self.updater.dir).and_then(|_| std::fs::write(&path, serde_json::to_vec(target).unwrap_or_default())),
            None => std::fs::remove_file(&path).or_else(|e| if e.kind() == std::io::ErrorKind::NotFound { Ok(()) } else { Err(e) }),
        };
        if let Err(e) = done {
            tracing::warn!("cannot write {}: {e}", path.display());
        }
    }

    /// The submission and digest of the release the fleet is to run.
    pub fn target(&self) -> Option<(String, String)> {
        self.target.lock().unwrap().as_ref().map(|t| (t.id.clone(), t.sha256.clone()))
    }

    /// Primary/Peer: a release is uploaded. It is checked, kept, and rolled out.
    pub fn submit(&self, sha256: &str, signature: &str, bytes: &[u8]) -> Result<Target, String> {
        {
            let rollout = self.rollout.lock().unwrap();
            if matches!(rollout.phase, Phase::RollingBack { .. } | Phase::RevertingPrimary { .. }) {
                return Err("the fleet is still going back from the release that failed: try again when it is done".into());
            }
        }
        self.updater.install(sha256, signature, bytes)?;
        let new = Target {
            id: uuid::Uuid::new_v4().simple().to_string(),
            sha256: sha256.to_string(),
            signature: signature.trim().to_string(),
            size: bytes.len() as u64,
            submitted_at: crate::store::now(),
            outcome: Outcome::Rolling,
        };
        self.updater.forgive(&new.id, sha256);
        let to_persist = {
            let mut target = self.target.lock().unwrap();
            let mut rollout = self.rollout.lock().unwrap();
            if matches!(rollout.phase, Phase::RollingBack { .. } | Phase::RevertingPrimary { .. }) {
                return Err("the fleet is still going back from the release that failed: try again when it is done".into());
            }
            rollout.restart();
            tracing::info!("release {sha256} submitted ({} bytes): rolling it out", bytes.len());
            *target = Some(new.clone());
            target.clone()
        };
        self.persist(&to_persist);
        Ok(new)
    }

    /// Primary/Peer: take the release back. Every node that runs it goes back
    /// to what it ran before -- unless it is only to be forgotten (`forget`:
    /// the nodes stay as they are, and nothing more is rolled out).
    pub fn withdraw(&self, sha256: &str, forget: bool) -> Result<(), String> {
        let to_persist = {
            let mut target = self.target.lock().unwrap();
            let mut rollout = self.rollout.lock().unwrap();
            let Some(current) = target.as_mut().filter(|t| t.sha256 == sha256) else {
                return Err("that is not the release of this fleet".into());
            };
            if forget {
                tracing::info!("release {sha256} is forgotten: the nodes stay on what they run");
                rollout.restart();
                *target = None;
            } else if !matches!(current.outcome, Outcome::Failed { .. }) {
                rollout.fail(sha256, "withdrawn by the operator".into());
                current.outcome = rollout.outcome(sha256);
            }
            target.clone()
        };
        self.persist(&to_persist);
        Ok(())
    }

    /// The binary of the fleet's release, for the replicas to fetch.
    pub fn binary(&self, sha256: &str) -> Option<Vec<u8>> {
        self.target().filter(|(_, sha)| sha == sha256)?;
        self.updater.read(sha256).ok()
    }

    /// What a replica is told about the release with every poll.
    pub fn directive(&self, node: &str) -> Value {
        let target = self.target.lock().unwrap();
        let Some(target) = target.as_ref() else { return Value::Null };
        let leave = self.rollout.lock().unwrap().leave(node, &target.sha256);
        json!({
            "id": target.id, "sha256": target.sha256, "signature": target.signature, "size": target.size,
            "go": leave == Leave::Update, "revert": leave == Leave::Revert,
        })
    }

    /// Where this node and, on the primary, the roll-out stand.
    pub fn status(&self, node: &str, peers: &[PeerView]) -> Value {
        let target = self.target.lock().unwrap().clone();
        let sha = target.as_ref().map(|t| t.sha256.clone()).unwrap_or_default();
        let on = |exe: &str| !sha.is_empty() && exe == sha;
        let mut nodes = vec![json!({
            "name": node, "self": true, "online": true, "exe": self.updater.own(), "trusted": !self.updater.on_trial(),
            "rejected": self.updater.rejected().contains(&sha), "on_release": on(self.updater.own()),
        })];
        nodes.extend(peers.iter().map(|p| {
            let mut v = serde_json::to_value(p).unwrap_or_default();
            v["on_release"] = json!(on(&p.exe));
            v
        }));
        json!({
            "enabled": self.updater.enabled(),
            "exe": self.updater.own(),
            "on_trial": self.updater.on_trial(),
            "trial_seconds": self.updater.trial.as_secs(),
            "target": target,
            "rollout": if target.is_some() { serde_json::to_value(&self.rollout.lock().unwrap().phase).unwrap_or_default() } else { Value::Null },
            "nodes": nodes,
        })
    }

    /// Primary/Peer: one look at the fleet. Returns what this node itself has to
    /// do now, if anything: take the release (`Update`) or go back (`Revert`).
    fn turn(&self, peers: &[PeerView], now: Instant) -> Option<(Leave, String)> {
        let (action, to_persist) = self.turn_inner(peers, now);
        if let Some(target_snap) = to_persist {
            self.persist(&target_snap);
        }
        action
    }

    fn turn_inner(&self, peers: &[PeerView], now: Instant) -> (Option<(Leave, String)>, Option<Option<Target>>) {
        let mut target = self.target.lock().unwrap();
        let mut rollout = self.rollout.lock().unwrap();
        let Some(current) = target.as_mut() else {
            rollout.step(None, Own { exe: "", trusted: true, rejected: false }, &[], now);
            return (None, None);
        };
        let sha = current.sha256.clone();
        let own = Own { exe: self.updater.own(), trusted: !self.updater.on_trial(), rejected: self.updater.rejected().contains(&sha) };
        let before = rollout.phase.clone();
        let phase = rollout.step(Some(&sha), own, peers, now);
        if phase != before {
            tracing::info!("roll-out of release {sha}: {}", serde_json::to_string(&phase).unwrap_or_default());
        }
        let outcome = rollout.outcome(&sha);
        let to_persist = if outcome != current.outcome {
            current.outcome = outcome;
            Some(target.clone())
        } else {
            None
        };
        let action = match phase {
            Phase::UpdatingPrimary if own.exe != sha => Some((Leave::Update, sha)),
            Phase::RevertingPrimary { .. } => Some((Leave::Revert, sha)),
            _ => None,
        };
        (action, to_persist)
    }

    /// Peer: drive the roll-out (non-blocking: disk writes run in `spawn_blocking`).
    pub async fn drive(self: Arc<Self>, store: Arc<crate::store::Store>, fleet: Arc<crate::fleet::Fleet>) {
        if !self.updater.enabled() {
            return;
        }
        loop {
            tokio::time::sleep(Duration::from_secs(2)).await;
            let peers = match self.target() {
                Some((id, sha)) => fleet.views(&store.version(), &id, &sha),
                None => Vec::new(),
            };
            let (action, to_persist) = self.turn_inner(&peers, Instant::now());
            if let Some(snap) = to_persist {
                let this = self.clone();
                let _ = tokio::task::spawn_blocking(move || this.persist(&snap)).await;
            }
            let Some((leave, sha)) = action else { continue };
            let u = self.updater.clone();
            let sha_s = sha.clone();
            let ready = tokio::task::spawn_blocking(move || match leave {
                Leave::Update => u.activate(&sha_s),
                _ => u.reject(&sha_s),
            })
            .await
            .unwrap_or_else(|e| Err(e.to_string()));
            let failure = match ready {
                Ok(()) => {
                    tracing::info!("this node {} release {sha}: starting over", if leave == Leave::Update { "takes" } else { "goes back from" });
                    let updater = self.updater.clone();
                    tokio::task::spawn_blocking(move || updater.relaunch()).await.unwrap_or_else(|e| e.to_string())
                }
                Err(e) => e,
            };
            // still here: cannot change what it runs
            tracing::error!("{failure}");
            if leave == Leave::Update {
                let u = self.updater.clone();
                let sha_s = sha.clone();
                let _ = tokio::task::spawn_blocking(move || u.reject(&sha_s)).await;
                self.rollout.lock().unwrap().fail(&sha, format!("this node cannot take the release: {failure}"));
            } else {
                tokio::time::sleep(Duration::from_secs(60)).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signatures() {
        let (private, public) = keygen().unwrap();
        let sha = sha256_hex(b"a binary");
        assert_eq!((sha.len(), unb64(&public).unwrap().len()), (64, 32));
        assert_eq!(public_key(&private).unwrap(), public);
        let signature = sign(&private, &sha).unwrap();
        assert_eq!(verify(&public, &sha, &signature), Ok(()));
        assert!(verify(&public, &sha256_hex(b"another binary"), &signature).is_err());
        let (_, other) = keygen().unwrap();
        assert!(verify(&other, &sha, &signature).is_err(), "signed with a different key");
        assert!(verify("not a key", &sha, &signature).is_err() && verify(&public, &sha, "not a signature").is_err());
        assert!(sign("not a key", &sha).is_err() && public_key("not a key").is_err());
    }

    #[test]
    fn a_release_gets_two_starts_to_prove_itself() {
        let all = |_: &str| true;
        // nothing installed: run what the service manager started
        assert_eq!(pick(&mut Local::default(), "base", all), None);

        // r1 has proven itself, r2 is new
        let mut state = Local { current: Some("r2".into()), previous: Some("r1".into()), ..Default::default() };
        assert_eq!(pick(&mut state, "base", all).as_deref(), Some("r2"));
        assert_eq!(state.starts, 1);
        // the release itself, once started, finds itself current and does not count again
        assert_eq!(pick(&mut state, "r2", all).as_deref(), Some("r2"));
        assert_eq!(state.starts, 1);
        // it died before its trial was over: one more attempt
        assert_eq!(pick(&mut state, "base", all).as_deref(), Some("r2"));
        // died again: back to the one before, for good
        assert_eq!(pick(&mut state, "base", all).as_deref(), Some("r1"));
        assert_eq!(state, Local { current: Some("r1".into()), committed: true, bad: vec!["r2".into()], ..Default::default() });
        assert_eq!(pick(&mut state, "base", all).as_deref(), Some("r1"), "a proven release is started as often as it takes");

        // a release that passed its trial is never counted
        let mut state = Local { current: Some("r2".into()), committed: true, ..Default::default() };
        for _ in 0..5 {
            assert_eq!(pick(&mut state, "base", all).as_deref(), Some("r2"));
        }
        // a release that is not on disk (or not signed) is not run: back to the base binary
        let mut state = Local { current: Some("r2".into()), ..Default::default() };
        assert_eq!(pick(&mut state, "base", |_| false), None);
        assert_eq!(state.bad, ["r2"]);
        // ... nor one that failed here before
        let mut state = Local { current: Some("r2".into()), previous: Some("r1".into()), bad: vec!["r2".into()], ..Default::default() };
        assert_eq!(pick(&mut state, "base", all).as_deref(), Some("r1"));
    }

    fn temp_dir() -> PathBuf {
        std::env::temp_dir().join(format!("fucf-releases-{}", uuid::Uuid::new_v4().simple()))
    }

    #[tokio::test]
    async fn installs_only_signed_releases_and_tracks_them() {
        let dir = temp_dir();
        let (private, public) = keygen().unwrap();
        let release = b"#!/bin/sh\nexit 0\n".to_vec();
        let sha = sha256_hex(&release);
        let signature = sign(&private, &sha).unwrap();

        let off = Updater::with(dir.clone(), None, "base".into());
        assert!(!off.enabled() && off.install(&sha, &signature, &release).unwrap_err().contains("no release key"));
        assert_eq!(off.launch(), None);
        assert!(!dir.exists(), "without a key nothing is ever written");
        let node = Updater::with(dir.clone(), Some(format!(" {public}\n")), "base".into());
        assert!(node.enabled() && node.own() == "base");
        assert!(node.install(&sha, &signature, b"something else").unwrap_err().contains("digest differs"));
        assert!(node.install("../../etc/passwd", &signature, &release).unwrap_err().contains("digest differs"));
        let (other_private, _) = keygen().unwrap();
        assert!(node.install(&sha, &sign(&other_private, &sha).unwrap(), &release).unwrap_err().contains("does not match"));
        assert!(!node.usable(&sha));
        node.install(&sha, &signature, &release).unwrap();
        assert!(node.usable(&sha) && node.read(&sha).unwrap() == release && node.read("state.json").is_err());
        // tampering with the file on disk is noticed
        std::fs::write(dir.join(&sha), b"#!/bin/sh\nrm -rf /\n").unwrap();
        assert!(!node.usable(&sha));
        node.install(&sha, &signature, &release).unwrap();

        // the release running this very process: activated, then trusted once it stayed up
        let mut running = Updater::with(dir.clone(), Some(public.clone()), sha.clone());
        (running.launched, running.trial) = (true, Duration::from_millis(20));
        let running = Arc::new(running);
        running.activate(&sha).unwrap();
        assert_eq!(running.load(), Local { current: Some(sha.clone()), ..Default::default() });
        assert!(running.on_trial() && !node.on_trial());
        assert_eq!(running.launch(), None, "nothing to turn into: it is what runs");
        // left over from long ago, left over from a moment ago, and what the fleet is rolling out
        let age = |name: &str, secs: u64| {
            std::fs::write(dir.join(name), b"left over").unwrap();
            let file = std::fs::File::options().write(true).open(dir.join(name)).unwrap();
            file.set_modified(std::time::SystemTime::now() - Duration::from_secs(secs)).unwrap();
        };
        let (old, young, rolling) = ("0".repeat(64), "1".repeat(64), "2".repeat(64));
        (age(&old, 3600), age(&young, 5), age(&rolling, 3600));
        std::fs::write(dir.join("target.json"), json!({ "sha256": rolling }).to_string()).unwrap();
        running.clone().settle(|| async { Ok(()) }).await;
        assert!(running.load().committed && !running.on_trial() && dir.join(&sha).exists());
        assert!(!dir.join(&old).exists() && dir.join(&young).exists() && dir.join(&rolling).exists());
        std::fs::remove_file(dir.join("target.json")).unwrap();
        // a newer one on top: the proven one is where to go back to
        let newer = sha256_hex(b"newer");
        running.activate(&newer).unwrap();
        assert_eq!(running.load(), Local { current: Some(newer.clone()), previous: Some(sha.clone()), ..Default::default() });
        // ... which happens at once here, since that newer release is not even on disk
        assert_eq!(running.launch(), None);
        assert_eq!((running.rejected(), running.load().current), (vec![newer.clone()], Some(sha.clone())));
        assert!(running.activate(&newer).unwrap_err().contains("failed on this node before"));
        // submitted again, it gets another chance -- once
        running.forgive("second submission", &newer);
        assert!(running.rejected().is_empty() && running.load().submission.as_deref() == Some("second submission"));
        running.reject(&newer).unwrap();
        running.forgive("second submission", &newer);
        assert_eq!(running.rejected(), [newer.clone()]);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_release_that_fails_its_trial_goes() {
        let dir = temp_dir();
        let (_, public) = keygen().unwrap();
        let (old, new) = (sha256_hex(b"old"), sha256_hex(b"new"));
        let state = |updater: &Updater| updater.load();
        let on = |own: &str| {
            let mut updater = Updater::with(dir.clone(), Some(public.clone()), own.to_string());
            updater.launched = true;
            updater
        };

        // the self-test fails: back to the release before, and never again
        let node = on(&new);
        node.save(&Local { current: Some(new.clone()), previous: Some(old.clone()), starts: 1, ..Default::default() }).unwrap();
        assert!(node.on_trial());
        assert!(node.conclude(Err("DNS does not answer".into())), "it has to start over");
        assert_eq!(state(&node), Local { current: Some(old.clone()), committed: true, bad: vec![new.clone()], ..Default::default() });
        assert!(!node.on_trial() && !node.conclude(Err("again".into())), "a verdict is only for a release on trial");
        // nothing before it: the launcher's own binary runs again
        node.save(&Local { current: Some(new.clone()), ..Default::default() }).unwrap();
        assert!(node.conclude(Err("the API does not answer".into())));
        assert_eq!((state(&node).current, state(&node).bad), (None, vec![new.clone()]));
        // it passes: it stays, and a later verdict changes nothing
        node.save(&Local { current: Some(new.clone()), previous: Some(old.clone()), starts: 2, ..Default::default() }).unwrap();
        assert!(!node.conclude(Ok(())));
        assert_eq!(state(&node), Local { current: Some(new.clone()), previous: Some(old.clone()), committed: true, ..Default::default() });
        assert!(!node.conclude(Err("too late".into())) && state(&node).committed);

        // taken back by the primary while it runs: the one before is current again
        node.reject(&new).unwrap();
        assert_eq!(state(&node), Local { current: Some(old.clone()), committed: true, bad: vec![new.clone()], ..Default::default() });
        // rejecting something that is not current only remembers it
        node.reject(&sha256_hex(b"other")).unwrap();
        assert_eq!((state(&node).current, state(&node).bad.len()), (Some(old.clone()), 2));

        // a binary installed by hand is a new start: the launcher drops what was rolled out before
        let launcher = Updater::with(dir.clone(), Some(public.clone()), "base-2".into());
        assert_eq!(launcher.launch(), None);
        assert_eq!(state(&launcher), Local { base: Some("base-2".into()), ..Default::default() });
        // ... once: what is rolled out on top of it from then on stays (here it is not on disk, so it is dropped as unusable)
        launcher.save(&Local { current: Some(old.clone()), committed: true, base: Some("base-2".into()), ..Default::default() }).unwrap();
        assert_eq!(launcher.launch(), None);
        assert_eq!((state(&launcher).base, state(&launcher).bad), (Some("base-2".into()), vec![old.clone()]));
        std::fs::remove_dir_all(&dir).ok();
    }

    fn peer(name: &str, exe: &str) -> PeerView {
        PeerView { name: name.into(), online: true, in_sync: true, exe: exe.into(), trusted: true, rejected: false }
    }

    fn own(exe: &str) -> Own<'_> {
        Own { exe, trusted: true, rejected: false }
    }

    #[test]
    fn rolls_one_node_at_a_time_and_the_primary_last() {
        let mut rollout = Rollout { soak: Duration::from_secs(30), patience: Duration::from_secs(300), grace: Duration::from_secs(20), ..Default::default() };
        let t0 = rollout.started;
        let at = |secs: u64| t0 + Duration::from_secs(secs);
        let rolling = |node: &str, step: &'static str| Phase::Rolling { node: node.into(), step };

        assert_eq!(rollout.step(None, own("old"), &[], at(0)), Phase::Idle);
        // right after its start the primary does not know its replicas yet
        assert_eq!(rollout.step(Some("new"), own("old"), &[], at(5)), Phase::Starting);
        let mut fleet = vec![peer("us", "old"), peer("eu", "old")];
        assert_eq!(rollout.step(Some("new"), own("old"), &fleet, at(30)), rolling("eu", "updating"));
        assert_eq!((rollout.leave("eu", "new"), rollout.leave("us", "new"), rollout.leave("eu", "other")), (Leave::Update, Leave::None, Leave::None));
        // eu restarts: offline for a moment, then back but not in sync yet, then on trial
        fleet[1].online = false;
        assert_eq!(rollout.step(Some("new"), own("old"), &fleet, at(40)), rolling("eu", "updating"));
        fleet[1] = PeerView { in_sync: false, trusted: false, ..peer("eu", "new") };
        assert_eq!(rollout.step(Some("new"), own("old"), &fleet, at(45)), rolling("eu", "updating"));
        fleet[1].in_sync = true;
        assert_eq!(rollout.step(Some("new"), own("old"), &fleet, at(48)), rolling("eu", "updating"), "still on trial");
        fleet[1].trusted = true;
        assert_eq!(rollout.step(Some("new"), own("old"), &fleet, at(50)), rolling("eu", "settling"));
        assert_eq!(rollout.leave("us", "new"), Leave::None, "one at a time");
        assert_eq!(rollout.step(Some("new"), own("old"), &fleet, at(79)), rolling("eu", "settling"));
        // eu held: us goes
        assert_eq!(rollout.step(Some("new"), own("old"), &fleet, at(81)), rolling("us", "updating"));
        fleet[0] = peer("us", "new");
        assert_eq!(rollout.step(Some("new"), own("old"), &fleet, at(90)), rolling("us", "settling"));
        // then the primary itself: on trial first, and that is it
        assert_eq!(rollout.step(Some("new"), own("old"), &fleet, at(121)), Phase::UpdatingPrimary);
        assert_eq!(rollout.outcome("new"), Outcome::Rolling);
        assert_eq!(rollout.step(Some("new"), Own { exe: "new", trusted: false, rejected: false }, &fleet, at(125)), Phase::UpdatingPrimary);
        assert_eq!(rollout.step(Some("new"), own("new"), &fleet, at(170)), Phase::Done);
        assert_eq!(rollout.outcome("new"), Outcome::Done);
        // from then on nobody is touched: a node that was away, or got a binary by hand, stays as it is
        fleet.push(peer("ap", "old"));
        assert_eq!(rollout.step(Some("new"), own("new"), &fleet, at(180)), Phase::Done);
        assert_eq!(rollout.leave("ap", "new"), Leave::None);
        // ... until the release is submitted again
        rollout.restart();
        assert_eq!(rollout.step(Some("new"), own("new"), &fleet, at(190)), rolling("ap", "updating"));
        // replicas that do not say what they run do not take releases
        fleet[2].exe = String::new();
        rollout.restart();
        assert_eq!(rollout.step(Some("new"), own("new"), &fleet, at(200)), Phase::Done);
        // the release is forgotten
        assert_eq!(rollout.step(None, own("new"), &fleet, at(210)), Phase::Idle);
        assert_eq!(rollout.outcome("new"), Outcome::Rolling);
        // a primary that restarts picks up where it left off
        let mut resumed = Rollout { grace: Duration::ZERO, ..Default::default() };
        resumed.resume("new", &Outcome::Done);
        assert_eq!(resumed.step(Some("new"), own("new"), &[peer("ap", "old")], at(0)), Phase::Done);
        resumed.resume("new", &Outcome::Failed { reason: "because".into() });
        assert_eq!(resumed.step(Some("new"), own("old"), &[peer("ap", "old")], at(0)), Phase::Failed { reason: "because".into() });
        assert_eq!(serde_json::to_value(Phase::Rolling { node: "eu".into(), step: "settling" }).unwrap(), json!({ "phase": "rolling", "node": "eu", "step": "settling" }));
        assert_eq!(serde_json::to_value(Outcome::Failed { reason: "x".into() }).unwrap(), json!({ "state": "failed", "reason": "x" }));
    }

    #[test]
    fn stops_at_the_first_node_that_does_not_make_it() {
        let fresh = || Rollout { grace: Duration::ZERO, ..Default::default() };
        let failed = |phase: &Phase, what: &str| matches!(phase, Phase::Failed { reason } if reason.contains(what));

        // a node that never comes back
        let mut rollout = fresh();
        let t0 = rollout.started;
        let fleet = [peer("us", "old"), peer("eu", "old")];
        rollout.step(Some("new"), own("old"), &fleet, t0);
        assert!(matches!(rollout.step(Some("new"), own("old"), &fleet, t0 + Duration::from_secs(299)), Phase::Rolling { .. }));
        let phase = rollout.step(Some("new"), own("old"), &fleet, t0 + Duration::from_secs(301));
        assert!(failed(&phase, "eu did not come back"), "{phase:?}");
        assert!(matches!(rollout.outcome("new"), Outcome::Failed { .. }));
        // nobody else is touched, however long it takes
        assert_eq!((rollout.leave("us", "new"), rollout.leave("eu", "new")), (Leave::None, Leave::None));
        assert!(failed(&rollout.step(Some("new"), own("old"), &fleet, t0 + Duration::from_secs(9999)), "eu did not come back"));
        // a different release is a new story; so is the same one submitted again
        assert!(matches!(rollout.step(Some("newer"), own("old"), &fleet, t0 + Duration::from_secs(10000)), Phase::Rolling { .. }));
        rollout.fail("newer", "because".into());
        rollout.restart();
        assert!(matches!(rollout.step(Some("newer"), own("old"), &fleet, t0 + Duration::from_secs(10001)), Phase::Rolling { .. }));

        // a node that tried the release and went back says so
        let mut rollout = fresh();
        let mut fleet = [peer("us", "old"), peer("eu", "old")];
        rollout.step(Some("new"), own("old"), &fleet, t0);
        fleet[1].rejected = true;
        assert!(failed(&rollout.step(Some("new"), own("old"), &fleet, t0 + Duration::from_secs(60)), "eu could not run"));
        // a node that falls over during its soak is not "back"
        let mut rollout = fresh();
        let mut fleet = [peer("eu", "old")];
        rollout.step(Some("new"), own("old"), &fleet, t0);
        fleet[0].exe = "new".into();
        assert_eq!(rollout.step(Some("new"), own("old"), &fleet, t0 + Duration::from_secs(10)), Phase::Rolling { node: "eu".into(), step: "settling" });
        fleet[0].online = false;
        assert_eq!(rollout.step(Some("new"), own("old"), &fleet, t0 + Duration::from_secs(12)), Phase::Rolling { node: "eu".into(), step: "updating" });
        // the primary itself
        let mut rollout = fresh();
        assert_eq!(rollout.step(Some("new"), own("old"), &[], t0), Phase::UpdatingPrimary);
        assert!(failed(&rollout.step(Some("new"), Own { exe: "old", trusted: true, rejected: true }, &[], t0), "the primary could not run"));
    }

    #[test]
    fn a_failed_roll_out_takes_everyone_back() {
        let fresh = || Rollout { grace: Duration::ZERO, soak: Duration::ZERO, ..Default::default() };
        let back = |node: &str, phase: &Phase| matches!(phase, Phase::RollingBack { node: n, .. } if n == node);
        let secs = Duration::from_secs;

        // eu took the release, us cannot run it: eu goes back
        let mut rollout = fresh();
        let t0 = rollout.started;
        let mut fleet = [peer("eu", "old"), peer("us", "old")];
        rollout.step(Some("new"), own("old"), &fleet, t0);
        fleet[0].exe = "new".into();
        rollout.step(Some("new"), own("old"), &fleet, t0 + secs(50));
        assert_eq!(rollout.step(Some("new"), own("old"), &fleet, t0 + secs(51)), Phase::Rolling { node: "us".into(), step: "updating" });
        fleet[1].rejected = true;
        let phase = rollout.step(Some("new"), own("old"), &fleet, t0 + secs(100));
        assert!(back("eu", &phase), "{phase:?}");
        assert_eq!((rollout.leave("eu", "new"), rollout.leave("us", "new")), (Leave::Revert, Leave::None));
        assert!(matches!(rollout.outcome("new"), Outcome::Failed { reason } if reason.contains("us could not run")));
        // it restarts: away for a moment, then back on what it ran before
        fleet[0].online = false;
        assert!(back("eu", &rollout.step(Some("new"), own("old"), &fleet, t0 + secs(105))));
        fleet[0] = peer("eu", "old");
        assert!(matches!(rollout.step(Some("new"), own("old"), &fleet, t0 + secs(110)), Phase::Failed { reason } if reason.contains("us could not run")));
        assert_eq!(rollout.leave("eu", "new"), Leave::None);

        // the primary's own update fails, after both replicas took the release: one after the other goes back
        let mut rollout = fresh();
        let mut fleet = [peer("eu", "new"), peer("us", "new")];
        assert_eq!(rollout.step(Some("new"), own("old"), &fleet, t0), Phase::UpdatingPrimary);
        let failing = Own { exe: "old", trusted: true, rejected: true };
        assert!(back("eu", &rollout.step(Some("new"), failing, &fleet, t0 + secs(100))));
        assert!(back("eu", &rollout.step(Some("new"), failing, &fleet, t0 + secs(102))), "us waits for eu to be back");
        assert_eq!(rollout.leave("us", "new"), Leave::None);
        fleet[0] = PeerView { in_sync: false, ..peer("eu", "old") };
        assert!(back("eu", &rollout.step(Some("new"), failing, &fleet, t0 + secs(104))), "back means serving the configuration again");
        fleet[0].in_sync = true;
        assert!(back("us", &rollout.step(Some("new"), failing, &fleet, t0 + secs(106))));
        assert_eq!(rollout.leave("us", "new"), Leave::Revert);
        // us does not react: after a minute it is given up on (its own launcher will sort it out)
        assert!(back("us", &rollout.step(Some("new"), failing, &fleet, t0 + secs(160))));
        assert!(matches!(rollout.step(Some("new"), failing, &fleet, t0 + secs(170)), Phase::Failed { .. }));
        assert_eq!(rollout.leave("us", "new"), Leave::None);

        // withdrawn by the operator when everyone runs it: the replicas first, the primary last
        let mut rollout = fresh();
        let mut fleet = [peer("eu", "new")];
        assert_eq!(rollout.step(Some("new"), own("new"), &fleet, t0), Phase::Done);
        rollout.fail("new", "withdrawn by the operator".into());
        assert!(back("eu", &rollout.step(Some("new"), own("new"), &fleet, t0 + secs(1))));
        fleet[0] = peer("eu", "old");
        assert_eq!(rollout.step(Some("new"), own("new"), &fleet, t0 + secs(8)), Phase::RevertingPrimary { reason: "withdrawn by the operator".into() });
        assert_eq!(rollout.step(Some("new"), own("old"), &fleet, t0 + secs(12)), Phase::Failed { reason: "withdrawn by the operator".into() });
        // a node that turns up on the failed release later goes back as well
        let fleet = [peer("eu", "old"), peer("ap", "new")];
        assert!(back("ap", &rollout.step(Some("new"), own("old"), &fleet, t0 + secs(500))));
    }

    #[test]
    fn the_primary_keeps_the_release_and_what_became_of_it() {
        let dir = temp_dir();
        let (private, public) = keygen().unwrap();
        let release = b"a release".to_vec();
        let sha = sha256_hex(&release);
        let signature = sign(&private, &sha).unwrap();
        let updater = |dir: &Path| Arc::new(Updater::with(dir.to_path_buf(), Some(public.clone()), "old".into()));
        let now = Instant::now() + Duration::from_secs(3600); // past any grace

        let releases = Releases::new(updater(&dir), true);
        assert_eq!((releases.target(), releases.directive("eu")), (None, Value::Null));
        assert!(releases.turn(&[], now).is_none());
        assert!(releases.submit(&sha, "bm90IGEgc2lnbmF0dXJl", &release).is_err() && releases.target().is_none());
        let target = releases.submit(&sha, &signature, &release).unwrap();
        assert_eq!((target.size, target.outcome.clone(), releases.target()), (9, Outcome::Rolling, Some((target.id.clone(), sha.clone()))));
        assert_eq!(releases.binary(&sha).as_deref(), Some(&release[..]));
        assert!(releases.binary(&sha256_hex(b"something else")).is_none());

        // eu goes first, and is told so with its next poll
        let mut eu = peer("eu", "old");
        assert!(releases.turn(std::slice::from_ref(&eu), now).is_none());
        let directive = releases.directive("eu");
        assert_eq!((directive["sha256"].as_str(), directive["signature"].as_str(), &directive["go"], &directive["revert"]), (Some(sha.as_str()), Some(signature.as_str()), &json!(true), &json!(false)));
        assert_eq!(releases.directive("us")["go"], false);
        let status = releases.status("au", std::slice::from_ref(&eu));
        assert_eq!((&status["rollout"]["phase"], &status["rollout"]["node"], &status["target"]["state"]), (&json!("rolling"), &json!("eu"), &json!("rolling")));
        assert_eq!((&status["nodes"][0]["name"], &status["nodes"][0]["on_release"], &status["nodes"][1]["name"]), (&json!("au"), &json!(false), &json!("eu")));
        // it cannot run it: the roll-out has failed, which a restarted primary still knows
        eu.rejected = true;
        assert!(releases.turn(std::slice::from_ref(&eu), now).is_none());
        let restarted = Releases::new(updater(&dir), true);
        assert!(matches!(restarted.target.lock().unwrap().as_ref().unwrap().outcome, Outcome::Failed { .. }));
        assert_eq!(restarted.status("au", &[])["target"]["state"], "failed");
        assert!(matches!(restarted.rollout.lock().unwrap().outcome(&sha), Outcome::Failed { .. }));
        // a replica (or a node without a key) has no roll-out of its own
        assert!(Releases::new(updater(&dir), false).target().is_none());

        // submitted again, then the primary's turn comes
        let again = restarted.submit(&sha, &signature, &release).unwrap();
        assert_ne!(again.id, target.id);
        assert_eq!(restarted.turn(&[peer("eu", &sha)], now), Some((Leave::Update, sha.clone())));
        // withdrawn: eu is to go back, and that is remembered too
        assert!(restarted.withdraw("0000", false).is_err());
        restarted.withdraw(&sha, false).unwrap();
        assert!(restarted.turn(&[peer("eu", &sha)], now).is_none());
        assert_eq!(restarted.directive("eu")["revert"], true);
        assert!(restarted.submit(&sha, &signature, &release).unwrap_err().contains("still going back"));
        assert_eq!(Releases::new(updater(&dir), true).status("au", &[])["target"]["reason"], "withdrawn by the operator");
        // forgotten: nothing is left
        restarted.withdraw(&sha, true).unwrap();
        assert!(restarted.target().is_none() && Releases::new(updater(&dir), true).target().is_none());
        std::fs::remove_dir_all(&dir).ok();
    }
}
