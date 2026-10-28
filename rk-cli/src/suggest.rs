//! `rk policy suggest`: an ENFORCE profile from what the audit log shows a
//! profile's agents did (docs/design/adoption.md §3.3). It reads only sealed,
//! verified batches, never applies anything, and never loosens a file rule.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::net::IpAddr;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use serde_json::Value as Json;
use toml::{Table, Value};

use crate::toml_out::{self, Comments};

/// Interpreters: allowing one allows any script it runs.
const INTERPRETERS: &[&str] = &[
    "sh", "bash", "dash", "zsh", "ksh", "fish", "python", "python3", "perl", "ruby", "node",
    "deno", "bun", "php", "lua", "tclsh", "awk", "gawk", "busybox", "env",
];

/// Directories searched for executables besides `PATH` and `--search`.
const BIN_DIRS: &[&str] = &[
    "/usr/local/sbin",
    "/usr/local/bin",
    "/usr/sbin",
    "/usr/bin",
    "/sbin",
    "/bin",
];

/// Port/protocol ranges the kernel holds per address (docs/policy.md).
const MAX_RANGES: usize = 8;

/// An executed file seen in the log, by kernel identity.
#[derive(Debug, Default, Clone)]
pub struct ExecSeen {
    pub names: BTreeSet<String>,
    pub count: usize,
}

/// What the log shows a profile's agents did.
#[derive(Debug, Default)]
pub struct Observed {
    /// Decision records of the profile that were read.
    pub records: usize,
    /// Of those, denied in ENFORCE: attempts, never turned into rules.
    pub denied: usize,
    pub first_ms: Option<i64>,
    pub last_ms: Option<i64>,
    /// (kernel dev, ino) -> names it ran under.
    pub execs: BTreeMap<(u64, u64), ExecSeen>,
    /// (address, IPPROTO) -> ports and connection count.
    pub net: BTreeMap<(IpAddr, u8), (BTreeSet<u16>, usize)>,
    /// Protected file (from the rule's origin) -> reads and access kinds.
    pub secrets: BTreeMap<String, (usize, BTreeSet<String>)>,
    /// Raw sockets, TUN/TAP, tampering: listed, never allowed.
    pub other: BTreeMap<String, usize>,
    /// Records in batches not sealed yet, left out.
    pub unsealed: usize,
}

fn str_at<'a>(v: &'a Json, pointer: &str) -> Option<&'a str> {
    v.pointer(pointer).and_then(Json::as_str)
}

fn u64_at(v: &Json, pointer: &str) -> Option<u64> {
    v.pointer(pointer).and_then(Json::as_u64)
}

impl Observed {
    /// Takes one audit record into account if it belongs to `profile` and is
    /// not older than `since_ms`.
    pub fn observe(&mut self, v: &Json, profile: &str, since_ms: Option<i64>) {
        if !rk_audit::tail::is_record(v) || str_at(v, "/policy/name") != Some(profile) {
            return;
        }
        let time = v.get("time").and_then(Json::as_i64).unwrap_or(0);
        if since_ms.is_some_and(|s| time < s) {
            return;
        }
        let verdict = str_at(v, "/unmapped/rk/verdict").unwrap_or("");
        self.records += 1;
        self.first_ms = Some(self.first_ms.map_or(time, |t| t.min(time)));
        self.last_ms = Some(self.last_ms.map_or(time, |t| t.max(time)));
        if verdict == "deny" {
            self.denied += 1;
            return;
        }
        // An allowed decision is already allowed: only would-denies teach.
        if verdict != "audit_would_deny" {
            return;
        }
        let class = u64_at(v, "/class_uid").unwrap_or(0);
        let activity = u64_at(v, "/activity_id").unwrap_or(0);
        match (class, activity) {
            (4001, 1 | 6) => {
                let ip = str_at(v, "/dst_endpoint/ip").and_then(|s| s.parse::<IpAddr>().ok());
                let port = u64_at(v, "/dst_endpoint/port").and_then(|p| u16::try_from(p).ok());
                let proto =
                    u64_at(v, "/connection_info/protocol_num").and_then(|p| u8::try_from(p).ok());
                if let (Some(ip), Some(port), Some(proto)) = (ip, port, proto) {
                    let e = self.net.entry((ip, proto)).or_default();
                    e.0.insert(port);
                    e.1 += 1;
                }
            }
            (4001, _) => {
                let what = match (
                    v.pointer("/unmapped/rk/socket"),
                    str_at(v, "/unmapped/rk/tun_op"),
                ) {
                    (Some(s), _) => format!(
                        "raw or packet socket (family {}, type {})",
                        s["family"], s["type"]
                    ),
                    (None, Some(op)) => format!("TUN/TAP {op}"),
                    (None, None) => "other network activity".to_string(),
                };
                *self.other.entry(what).or_default() += 1;
            }
            (1007, 1) => {
                let dev = u64_at(v, "/unmapped/rk/file_dev");
                let ino = u64_at(v, "/unmapped/rk/file_ino");
                let name =
                    str_at(v, "/process/file/path").or_else(|| str_at(v, "/process/file/name"));
                if let (Some(dev), Some(ino)) = (dev, ino) {
                    let e = self.execs.entry((dev, ino)).or_default();
                    e.count += 1;
                    if let Some(n) = name {
                        e.names.insert(n.to_string());
                    }
                }
            }
            (1007, _) => {
                let hook = v
                    .pointer("/unmapped/rk/tamper_hook")
                    .cloned()
                    .unwrap_or(Json::Null);
                *self
                    .other
                    .entry(format!("tampering (hook {hook})"))
                    .or_default() += 1;
            }
            (1001, _) => {
                let origin = str_at(v, "/policy/desc").unwrap_or("");
                // "files.deny[2] /home/dev/.aws/credentials": the rule's path.
                let path = origin
                    .split_once(' ')
                    .map_or(origin, |(_, p)| p)
                    .to_string();
                let path = if path.is_empty() {
                    str_at(v, "/file/name").unwrap_or("?").to_string()
                } else {
                    path
                };
                let e = self.secrets.entry(path).or_default();
                e.0 += 1;
                if let Some(access) = v.pointer("/unmapped/rk/access").and_then(Json::as_array) {
                    e.1.extend(access.iter().filter_map(Json::as_str).map(str::to_string));
                }
            }
            _ => {}
        }
    }
}

/// Reads every sealed record of `dir` into an [`Observed`].
pub fn collect(dir: &Path, profile: &str, since_ms: Option<i64>) -> Result<Observed> {
    let mut obs = Observed::default();
    for seg in rk_audit::chain::segments(dir)? {
        let text = fs::read_to_string(&seg).with_context(|| format!("read {}", seg.display()))?;
        let mut pending: Vec<Json> = Vec::new();
        for line in text.lines() {
            let Ok(v) = serde_json::from_str::<Json>(line) else {
                continue;
            };
            if v.get("rk_batch").is_some() {
                for r in pending.drain(..) {
                    obs.observe(&r, profile, since_ms);
                }
            } else if v.get("rk_segment").is_none() {
                pending.push(v);
            }
        }
        obs.unsealed += pending.len();
    }
    Ok(obs)
}

/// The userspace `st_dev` encoding of a device as the kernel's `dev_t`
/// (`MAJOR << 20 | MINOR`), which audit records carry. Same as
/// rk-sensor's `selftest::kernel_dev`.
pub fn kernel_dev(st_dev: u64) -> u64 {
    let major = ((st_dev >> 32) & 0xffff_f000) | ((st_dev >> 8) & 0x0000_0fff);
    let minor = ((st_dev >> 12) & 0xffff_ff00) | (st_dev & 0x0000_00ff);
    (major << 20) | minor
}

fn identity(path: &Path) -> Option<(u64, u64)> {
    let m = fs::metadata(path).ok()?;
    m.is_file().then(|| (kernel_dev(m.dev()), m.ino()))
}

/// (kernel dev, ino) -> path for the files in `dirs` (and below the
/// `deep` ones, four levels down).
fn index(dirs: &[PathBuf], deep: &[PathBuf]) -> HashMap<(u64, u64), PathBuf> {
    fn walk(dir: &Path, depth: u32, out: &mut HashMap<(u64, u64), PathBuf>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for e in entries.flatten() {
            let path = e.path();
            match e.file_type() {
                Ok(t) if t.is_dir() => {
                    if depth > 0 {
                        walk(&path, depth - 1, out);
                    }
                }
                _ => {
                    if let Some(id) = identity(&path) {
                        out.entry(id).or_insert(path);
                    }
                }
            }
        }
    }
    let mut out = HashMap::new();
    for d in dirs {
        walk(d, 0, &mut out);
    }
    for d in deep {
        walk(d, 4, &mut out);
    }
    out
}

/// A located executable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Located {
    pub path: String,
}

/// Absolute paths for the executed files, by identity. Returns the located
/// files, descriptions of those that could not be found, and of those whose
/// path now holds another file (never learned: the file there is not the
/// one that ran, and may be a payload put in its place).
pub fn locate(
    execs: &BTreeMap<(u64, u64), ExecSeen>,
    search: &[PathBuf],
) -> (Vec<Located>, Vec<String>, Vec<String>) {
    let mut dirs: Vec<PathBuf> = std::env::var("PATH")
        .unwrap_or_default()
        .split(':')
        .filter(|d| d.starts_with('/'))
        .map(PathBuf::from)
        .collect();
    dirs.extend(BIN_DIRS.iter().map(PathBuf::from));
    let mut idx: Option<HashMap<(u64, u64), PathBuf>> = None;
    let mut found = Vec::new();
    let mut missing = Vec::new();
    let mut replaced = Vec::new();
    for (&(dev, ino), seen) in execs {
        // The name it ran under, when that still names the same file.
        let direct = seen
            .names
            .iter()
            .filter(|n| n.starts_with('/'))
            .find(|n| identity(Path::new(n)) == Some((dev, ino)));
        if let Some(path) = direct {
            found.push(Located { path: path.clone() });
            continue;
        }
        let idx = idx.get_or_insert_with(|| index(&dirs, search));
        if let Some(path) = idx.get(&(dev, ino)) {
            found.push(Located {
                path: path.to_string_lossy().into_owned(),
            });
            continue;
        }
        // The path still exists but holds another file now: not learned.
        let changed: Vec<&str> = seen
            .names
            .iter()
            .filter(|n| n.starts_with('/') && Path::new(n).is_file())
            .map(String::as_str)
            .collect();
        if !changed.is_empty() {
            replaced.push(format!(
                "{}: the agent ran another file there (device {dev}, inode {ino}, {} time(s)); \
                 the file now at this path was put in its place after it ran. Not learned: \
                 check the file, and add it to exec.allow by hand if the agent needs it",
                changed.join(", "),
                seen.count
            ));
            continue;
        }
        let names: Vec<&str> = seen.names.iter().map(String::as_str).collect();
        missing.push(format!(
            "an executable run {} time(s) as {} (device {dev}, inode {ino}): not found; add its absolute path to exec.allow if the agent needs it (--search DIR helps)",
            seen.count,
            if names.is_empty() { "?".to_string() } else { names.join(", ") }
        ));
    }
    found.sort_by(|a, b| a.path.cmp(&b.path));
    found.dedup_by(|a, b| a.path == b.path);
    (found, missing, replaced)
}

fn is_interpreter(path: &str) -> bool {
    let base = path.rsplit('/').next().unwrap_or(path);
    let stem = base.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
    INTERPRETERS.contains(&base) || INTERPRETERS.contains(&stem)
}

fn is_public(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || (o[0] == 100 && (64..128).contains(&o[1])))
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80)
        }
    }
}

/// Sorted ports as `"N"` / `"LO-HI"` ranges.
fn port_ranges(ports: &BTreeSet<u16>) -> Vec<(u16, u16)> {
    let mut out: Vec<(u16, u16)> = Vec::new();
    for &p in ports {
        match out.last_mut() {
            Some((_, hi)) if u32::from(*hi) + 1 == u32::from(p) => *hi = p,
            _ => out.push((p, p)),
        }
    }
    out
}

fn range_text((lo, hi): (u16, u16)) -> String {
    if lo == hi {
        lo.to_string()
    } else {
        format!("{lo}-{hi}")
    }
}

fn proto_name(p: u8) -> &'static str {
    match p {
        6 => "tcp",
        17 => "udp",
        _ => "other",
    }
}

fn s(v: &str) -> Value {
    Value::String(v.to_string())
}

fn sub_table<'a>(t: &'a mut Table, k: &str) -> &'a mut Table {
    let entry = t
        .entry(k.to_string())
        .or_insert_with(|| Value::Table(Table::new()));
    if !entry.is_table() {
        *entry = Value::Table(Table::new());
    }
    match entry {
        Value::Table(t) => t,
        _ => unreachable!("just made a table"),
    }
}

/// The suggested profile: `base` (the profile from the policy file) in
/// ENFORCE with the observed connections and executables allowed. Returns
/// the profile, comments for its new rules, and notes for the header.
pub fn build_profile(
    name: &str,
    base: &Table,
    obs: &Observed,
    execs: &[Located],
) -> (Table, Comments, Vec<String>) {
    let mut p = base.clone();
    let mut comments = Comments::default();
    let mut notes = Vec::new();
    let path = format!("profiles.{}", toml_out::key(name));
    p.insert("mode".into(), s("enforce"));

    // Network: one rule per address and protocol; loopback grouped.
    let mut rules: BTreeMap<(String, u8), (BTreeSet<u16>, usize, bool)> = BTreeMap::new();
    for (&(ip, proto), (ports, count)) in &obs.net {
        let cidr = match ip {
            IpAddr::V4(v4) if v4.is_loopback() => "127.0.0.0/8".to_string(),
            IpAddr::V4(v4) => format!("{v4}/32"),
            IpAddr::V6(v6) => format!("{v6}/128"),
        };
        let r = rules.entry((cidr, proto)).or_default();
        r.0.extend(ports);
        r.1 += count;
        r.2 |= is_public(&ip);
    }
    // The kernel holds at most MAX_RANGES port/protocol ranges per address,
    // across protocols. Past that the lowest are kept and the rest reported,
    // never widened into one covering range: that would allow ports the
    // agent never used.
    let mut room: BTreeMap<&str, usize> = BTreeMap::new();
    let mut left_out: Vec<String> = Vec::new();
    let network = sub_table(&mut p, "network");
    network.insert("default".into(), s("deny"));
    let allow = network
        .entry("allow".to_string())
        .or_insert_with(|| Value::Array(Vec::new()));
    if !allow.is_array() {
        *allow = Value::Array(Vec::new());
    }
    let Value::Array(allow) = allow else {
        unreachable!("just made an array")
    };
    let mut public = 0;
    for ((cidr, proto), (ports, count, is_pub)) in &rules {
        let mut ranges = port_ranges(ports);
        let left = room.entry(cidr.as_str()).or_insert(MAX_RANGES);
        let dropped = ranges.split_off((*left).min(ranges.len()));
        *left -= ranges.len();
        let cut = !dropped.is_empty();
        if cut {
            let text: Vec<String> = dropped.into_iter().map(range_text).collect();
            left_out.push(format!(
                "  {cidr} {}: {}",
                proto_name(*proto),
                text.join(", ")
            ));
        }
        if ranges.is_empty() {
            continue;
        }
        let mut rule = Table::new();
        rule.insert("cidr".into(), s(cidr));
        rule.insert("proto".into(), Value::Array(vec![s(proto_name(*proto))]));
        rule.insert(
            "ports".into(),
            Value::Array(ranges.into_iter().map(|r| s(&range_text(r))).collect()),
        );
        let mut c = format!("learned: {count} connection(s)");
        if cut {
            c.push_str(
                "; more ports were seen than the kernel holds for one address: see the header",
            );
        }
        if *is_pub {
            public += 1;
            c.push_str("; public address, may change if it is a service behind a CDN");
        }
        comments.add(&format!("{path}.network.allow"), allow.len(), c);
        allow.push(Value::Table(rule));
    }
    if allow.is_empty() {
        network.remove("allow");
    }
    if public > 0 {
        notes.push(format!(
            "{public} rule(s) allow public addresses. A service behind a CDN changes address, \
             and the rule then goes stale; hostname rules arrive in v0.3.0 (ROADMAP.md)."
        ));
    }
    if !left_out.is_empty() {
        notes.push(format!(
            "Ports seen but left out, not allowed: the kernel holds {MAX_RANGES} port ranges \
             per address, and they are never widened into one range. Allow the ones the agent \
             needs by hand, within the limit:"
        ));
        notes.extend(left_out);
    }

    // Exec: only when the profile has exec rules (BPF LSM hosts).
    if let Some(Value::Table(exec)) = p.get_mut("exec") {
        exec.insert("default".into(), s("deny"));
        let mut list: Vec<String> = exec
            .get("allow")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        let existing = list.len();
        for l in execs {
            if !list.contains(&l.path) {
                list.push(l.path.clone());
            }
        }
        for (i, path) in list.iter().enumerate().skip(existing) {
            let c = if is_interpreter(path) {
                "interpreter: allows any script it runs"
            } else {
                "learned"
            };
            comments.add(
                &format!("{path_prefix}.exec.allow", path_prefix = path_of(name)),
                i,
                c.to_string(),
            );
        }
        if !list.is_empty() {
            exec.insert(
                "allow".into(),
                Value::Array(list.iter().map(|p| s(p)).collect()),
            );
        }
    }

    if !obs.secrets.is_empty() {
        notes.push(
            "The agent read these protected files. They stay denied; remove a rule only if \
             the agent needs the file:"
                .to_string(),
        );
        for (file, (count, access)) in &obs.secrets {
            let access: Vec<&str> = access.iter().map(String::as_str).collect();
            notes.push(format!("  {file}: {count} time(s) ({})", access.join(", ")));
        }
    }
    if !obs.other.is_empty() {
        notes.push("Seen and never allowed automatically:".to_string());
        for (what, count) in &obs.other {
            notes.push(format!("  {what}: {count} time(s)"));
        }
    }
    if obs.denied > 0 {
        notes.push(format!(
            "{} attempt(s) were denied in ENFORCE; denials are never turned into rules.",
            obs.denied
        ));
    }
    (p, comments, notes)
}

fn path_of(name: &str) -> String {
    format!("profiles.{}", toml_out::key(name))
}

/// Whether a table header (`[a.b]` or `[[a.b]]`, already trimmed) is the
/// profile's own or below it.
fn in_profile(header: &str, name: &str) -> bool {
    let inner = header
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim()
        .replace(' ', "");
    [
        format!("profiles.{name}"),
        format!("profiles.\"{name}\""),
        format!("profiles.'{name}'"),
    ]
    .iter()
    .any(|p| inner == *p || inner.starts_with(&format!("{p}.")))
}

/// `original` with the profile's tables replaced by `profile_text`, keeping
/// everything else as written. `None` when the profile is not written as
/// plain tables (the caller then writes the whole document).
pub fn splice(original: &str, name: &str, profile_text: &str) -> Option<String> {
    let mut out = String::new();
    let mut inside = false;
    let mut placed = false;
    // Blank and comment lines after the profile's last key belong to
    // whatever header comes next.
    let mut held: Vec<&str> = Vec::new();
    for line in original.lines() {
        let t = line.trim_start();
        if t.starts_with('[') {
            let header = t.split('#').next().unwrap_or(t).trim();
            inside = in_profile(header, name);
            if inside {
                held.clear();
                if !placed {
                    out.push_str(profile_text.trim_end());
                    out.push_str("\n\n");
                    placed = true;
                }
            } else {
                for h in held.drain(..) {
                    out.push_str(h);
                    out.push('\n');
                }
            }
        }
        if inside {
            if t.is_empty() || t.starts_with('#') {
                held.push(line);
            } else {
                held.clear();
            }
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    placed.then_some(out)
}

/// `30s`, `15m`, `2h`, `1d` in milliseconds.
pub fn parse_since(text: &str) -> Result<i64> {
    let text = text.trim();
    if !text.is_ascii() || text.len() < 2 {
        bail!("--since {text}: expected a number and s, m, h or d");
    }
    let (num, unit) = text.split_at(text.len() - 1);
    let n: i64 = num
        .parse()
        .with_context(|| format!("--since {text}: expected a number and s, m, h or d"))?;
    let secs = match unit {
        "s" => n,
        "m" => n * 60,
        "h" => n * 3600,
        "d" => n * 86_400,
        _ => bail!("--since {text}: expected a number and s, m, h or d"),
    };
    Ok(secs * 1000)
}

pub struct Options {
    pub profile: String,
    pub policy: PathBuf,
    pub dir: PathBuf,
    pub pubkey: Option<String>,
    pub no_verify: bool,
    pub since: Option<String>,
    pub search: Vec<PathBuf>,
    pub out: Option<PathBuf>,
}

/// `rk policy suggest`: the suggested policy text, and a summary for stderr.
pub fn suggest(opts: &Options) -> Result<(String, String)> {
    let verified = if opts.no_verify {
        false
    } else {
        let default_pub = rk_audit::key::public_path(Path::new(rk_audit::DEFAULT_KEY));
        let pinned = match &opts.pubkey {
            Some(p) => Some(crate::read_public_key(p)?),
            None if default_pub.is_file() => {
                Some(crate::read_public_key(&default_pub.to_string_lossy())?)
            }
            None => None,
        };
        let report = rk_audit::chain::verify_dir(&opts.dir, pinned)?;
        if !report.ok() {
            let problems: Vec<String> = report
                .problems
                .iter()
                .take(5)
                .map(|p| format!("{} line {}: {}", p.segment, p.line, p.what))
                .collect();
            bail!(
                "the audit log in {} does not verify, so it cannot be trusted to suggest a policy \
                 (rk audit verify): {}",
                opts.dir.display(),
                problems.join("; ")
            );
        }
        true
    };

    let original = fs::read_to_string(&opts.policy)
        .with_context(|| format!("read {}", opts.policy.display()))?;
    let mut doc: Table =
        toml::from_str(&original).with_context(|| format!("parse {}", opts.policy.display()))?;
    let base = doc
        .get("profiles")
        .and_then(Value::as_table)
        .and_then(|p| p.get(&opts.profile))
        .and_then(Value::as_table)
        .cloned()
        .with_context(|| {
            format!(
                "profile `{}` is not in {}",
                opts.profile,
                opts.policy.display()
            )
        })?;

    let since_ms = match &opts.since {
        Some(text) => {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX));
            Some(now - parse_since(text)?)
        }
        None => None,
    };
    let obs = collect(&opts.dir, &opts.profile, since_ms)?;
    if obs.records == 0 {
        bail!(
            "no decision records for profile `{}` in {}{}: run the agent under it first \
             (rk run --profile {} -- <command>)",
            opts.profile,
            opts.dir.display(),
            opts.since
                .as_ref()
                .map_or(String::new(), |s| format!(" in the last {s}")),
            opts.profile
        );
    }
    let (located, missing, replaced) = if base.contains_key("exec") {
        locate(&obs.execs, &opts.search)
    } else {
        (Vec::new(), Vec::new(), Vec::new())
    };
    let (profile, comments, mut notes) = build_profile(&opts.profile, &base, &obs, &located);
    if !missing.is_empty() {
        notes.push("Executables the agent ran that could not be located:".to_string());
        notes.extend(missing.iter().map(|m| format!("  {m}")));
    }
    if !replaced.is_empty() {
        notes.push("Executables replaced after the agent ran them, not learned:".to_string());
        notes.extend(replaced.iter().map(|m| format!("  {m}")));
    }

    let profile_text = toml_out::profile(&opts.profile, &profile, &comments);
    if let Some(Value::Table(profiles)) = doc.get_mut("profiles") {
        profiles.insert(opts.profile.clone(), Value::Table(profile));
    }
    let body = match splice(&original, &opts.profile, &profile_text) {
        Some(text) if toml::from_str::<Table>(&text).ok().as_ref() == Some(&doc) => text,
        _ => {
            notes.push(
                "The profile was not written as plain tables, so the file was rewritten \
                 without its comments."
                    .to_string(),
            );
            toml_out::document(&doc, &comments)
        }
    };

    let time = |ms: Option<i64>| ms.map_or("?".to_string(), rk_audit::tail::format_time);
    let mut header = vec![
        format!(
            "Suggested by `rk policy suggest` for profile `{}` from {} decision record(s),",
            opts.profile, obs.records
        ),
        format!(
            "{} to {}, audit log {} ({}).",
            time(obs.first_ms),
            time(obs.last_ms),
            opts.dir.display(),
            if verified {
                "verified"
            } else {
                "NOT verified: --no-verify"
            }
        ),
        "Review it before applying:".to_string(),
        "  rk policy diff FILE".to_string(),
        "  sudo install -m 0644 FILE /etc/rk/policy.toml && sudo systemctl reload rk-sensor"
            .to_string(),
    ];
    if obs.unsealed > 0 {
        header.push(format!(
            "{} record(s) in batches not sealed yet were left out.",
            obs.unsealed
        ));
    }
    if !notes.is_empty() {
        header.push(String::new());
        header.extend(notes);
    }
    let mut text: String = header
        .iter()
        .map(|l| format!("{}\n", toml_out::comment(l).trim_end()))
        .collect();
    text.push('\n');
    text.push_str(&body);
    crate::init::validate(&text)
        .context("internal error: the suggested policy does not validate")?;

    let summary = format!(
        "{} records: {} destination(s), {} executable(s) ({} not located, {} replaced since and not learned), {} protected file(s) read",
        obs.records,
        obs.net.len(),
        located.len(),
        missing.len(),
        replaced.len(),
        obs.secrets.len()
    );
    Ok((text, summary))
}

pub fn run(opts: &Options) -> Result<()> {
    let (text, summary) = suggest(opts)?;
    match &opts.out {
        // Often run under sudo in a directory the user (or the agent) can
        // write: an existing file is replaced by rename, a link there is
        // refused, never written through.
        Some(path) => {
            crate::safe_write::replace(path, text.as_bytes(), 0o644)?;
            eprintln!("Wrote {}: {summary}", path.display());
            eprintln!("Next: rk policy diff {}", path.display());
        }
        None => {
            print!("{text}");
            eprintln!("{summary}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rk_audit::ocsf::{self, Activity, Decision, Process, Verdict};

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("rk-suggest-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn record(
        activity: Activity<'_>,
        verdict: Verdict,
        profile: &str,
        origin: Option<&str>,
    ) -> Json {
        ocsf::decision(&Decision {
            time_ms: 1_760_000_000_000,
            activity,
            verdict,
            rule_id: 0,
            policy_gen: 1,
            profile: Some(profile),
            rule_origin: origin,
            cgroup_id: 7,
            session: None,
            process: Process {
                pid: 1,
                tid: 1,
                uid: 1000,
                gid: 1000,
                exe: None,
                ppid: None,
                enrichment: "unavailable",
            },
            hostname: "h",
            version: "0",
        })
    }

    fn connect(ip: &str, port: u16, protocol: u8) -> Activity<'static> {
        Activity::Connect {
            addr: ip.parse().unwrap(),
            port,
            protocol,
            sendmsg: false,
        }
    }

    const POLICY: &str = r#"# my policy
[profiles.agent]
mode = "audit"
launchable_by = ["user:dev"]

[profiles.agent.network]
default = "deny"

[profiles.agent.exec]
default = "deny"

[[profiles.agent.files.deny]]
path = "/home/dev/.aws/credentials"
access = ["all"]

# another profile, kept as written
[profiles.other]
mode = "enforce"
network.default = "allow"
"#;

    /// A signed log with the records, a policy file, and the options.
    fn setup(name: &str, records: &[Json]) -> (PathBuf, Options) {
        let dir = scratch(name);
        let log = dir.join("audit");
        let key_path = dir.join("audit.key");
        let key = rk_audit::key::AuditKey::load_or_create(&key_path).unwrap();
        let mut w = rk_audit::chain::Writer::open(
            &log,
            key,
            rk_audit::chain::WriterOptions {
                batch_records: 100,
                batch_interval: std::time::Duration::from_secs(3600),
                segment_bytes: 1 << 30,
            },
        )
        .unwrap();
        for r in records {
            w.append(r).unwrap();
        }
        w.seal().unwrap();
        let policy = dir.join("policy.toml");
        fs::write(&policy, POLICY).unwrap();
        let opts = Options {
            profile: "agent".into(),
            policy,
            dir: log,
            pubkey: Some(
                rk_audit::key::public_path(&key_path)
                    .to_string_lossy()
                    .into_owned(),
            ),
            no_verify: false,
            since: None,
            search: vec![dir.clone()],
            out: None,
        };
        (dir, opts)
    }

    #[test]
    fn suggests_an_enforce_profile_from_would_denies() {
        let dir = scratch("bin");
        let bin = dir.join("tool");
        fs::write(&bin, "#!/bin/true\n").unwrap();
        let m = fs::metadata(&bin).unwrap();
        let bin_path = bin.to_string_lossy().into_owned();
        let records = vec![
            record(
                connect("127.0.0.1", 8080, 6),
                Verdict::AuditWouldDeny,
                "agent",
                None,
            ),
            record(
                connect("127.0.0.1", 8081, 6),
                Verdict::AuditWouldDeny,
                "agent",
                None,
            ),
            record(
                connect("203.0.113.7", 443, 6),
                Verdict::AuditWouldDeny,
                "agent",
                None,
            ),
            record(
                Activity::Exec {
                    path: Some(&bin_path),
                    argv: None,
                    dev: kernel_dev(m.dev()),
                    ino: m.ino(),
                    committed: false,
                },
                Verdict::AuditWouldDeny,
                "agent",
                None,
            ),
            record(
                Activity::File {
                    path: Some("credentials"),
                    hook: 1,
                    access: 1,
                    dev: 1,
                    ino: 2,
                },
                Verdict::AuditWouldDeny,
                "agent",
                Some("files.deny[0] /home/dev/.aws/credentials"),
            ),
            record(
                Activity::Tun { op: 1 },
                Verdict::AuditWouldDeny,
                "agent",
                None,
            ),
            // Not learned: another profile, an allowed and a denied decision.
            record(
                connect("198.51.100.1", 22, 6),
                Verdict::AuditWouldDeny,
                "other",
                None,
            ),
            record(
                connect("198.51.100.2", 22, 6),
                Verdict::Allow,
                "agent",
                None,
            ),
            record(connect("198.51.100.3", 22, 6), Verdict::Deny, "agent", None),
        ];
        let (_, opts) = setup("full", &records);
        let (text, _) = suggest(&opts).unwrap();
        crate::init::validate(&text).unwrap();
        let t: Table = toml::from_str(&text).unwrap();
        let p = &t["profiles"]["agent"];
        assert_eq!(p["mode"].as_str(), Some("enforce"));
        let allow = p["network"]["allow"].as_array().unwrap();
        let cidrs: Vec<&str> = allow.iter().map(|r| r["cidr"].as_str().unwrap()).collect();
        assert_eq!(cidrs, ["127.0.0.0/8", "203.0.113.7/32"], "{text}");
        assert_eq!(allow[0]["ports"].as_array().unwrap(), &[s("8080-8081")]);
        assert_eq!(p["exec"]["allow"].as_array().unwrap(), &[s(&bin_path)]);
        // The protected file stays denied and is reported.
        assert_eq!(p["files"]["deny"].as_array().unwrap().len(), 1);
        assert!(
            text.contains("/home/dev/.aws/credentials: 1 time(s) (read)"),
            "{text}"
        );
        assert!(text.contains("TUN/TAP create: 1 time(s)"), "{text}");
        assert!(text.contains("1 attempt(s) were denied"), "{text}");
        assert!(text.contains("public address"), "{text}");
        // The rest of the file is kept as written, comments included.
        assert!(
            text.contains("# another profile, kept as written"),
            "{text}"
        );
        assert_eq!(t["profiles"]["other"]["mode"].as_str(), Some("enforce"));
        assert!(!text.contains("198.51.100"), "{text}");
    }

    #[test]
    fn a_log_that_does_not_verify_is_refused() {
        let records = vec![record(
            connect("127.0.0.1", 80, 6),
            Verdict::AuditWouldDeny,
            "agent",
            None,
        )];
        let (_, opts) = setup("tampered", &records);
        let seg = rk_audit::chain::segments(&opts.dir).unwrap().remove(0);
        let text = fs::read_to_string(&seg)
            .unwrap()
            .replace("127.0.0.1", "127.0.0.2");
        fs::write(&seg, text).unwrap();
        let err = suggest(&opts).unwrap_err().to_string();
        assert!(err.contains("does not verify"), "{err}");
    }

    #[test]
    fn no_records_is_an_error_not_an_empty_allow_list() {
        let (_, opts) = setup("empty", &[]);
        let err = suggest(&opts).unwrap_err().to_string();
        assert!(err.contains("no decision records"), "{err}");
    }

    /// More port ranges than the kernel holds for one address: the first
    /// eight are kept as seen and the rest reported, never widened into one
    /// covering range (nine ports once produced 22-65535).
    #[test]
    fn observed_port_ranges_are_never_widened() {
        let ports = [22, 80, 443, 3000, 5432, 6379, 8080, 9000, 65535];
        let mut records: Vec<Json> = ports
            .iter()
            .map(|&p| {
                record(
                    connect("127.0.0.1", p, 6),
                    Verdict::AuditWouldDeny,
                    "agent",
                    None,
                )
            })
            .collect();
        // Same address, another protocol: no room left, reported too.
        records.push(record(
            connect("127.0.0.1", 53, 17),
            Verdict::AuditWouldDeny,
            "agent",
            None,
        ));
        let (_, opts) = setup("ports", &records);
        let (text, _) = suggest(&opts).unwrap();
        let t: Table = toml::from_str(&text).unwrap();
        let allow = t["profiles"]["agent"]["network"]["allow"]
            .as_array()
            .unwrap();
        assert_eq!(allow.len(), 1, "{text}");
        let kept: Vec<&str> = allow[0]["ports"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p.as_str().unwrap())
            .collect();
        assert_eq!(
            kept,
            ["22", "80", "443", "3000", "5432", "6379", "8080", "9000"],
            "{text}"
        );
        assert!(!text.contains("22-65535"), "{text}");
        assert!(text.contains("127.0.0.0/8 tcp: 65535"), "{text}");
        assert!(text.contains("127.0.0.0/8 udp: 53"), "{text}");
    }

    /// An executed path whose file is no longer the one that ran (another
    /// device/inode there now) is reported, never added to exec.allow.
    #[test]
    fn a_replaced_executable_is_not_learned() {
        let dir = scratch("replaced-bin");
        let bin = dir.join("tool");
        fs::write(&bin, "#!/bin/true\n").unwrap();
        let m = fs::metadata(&bin).unwrap();
        // Keep the original inode alive (so it is not reused) and put
        // another file at the path the agent ran.
        fs::rename(&bin, dir.join("ran")).unwrap();
        fs::write(&bin, "#!/bin/sh\necho payload\n").unwrap();
        assert_ne!(fs::metadata(&bin).unwrap().ino(), m.ino());
        let bin_path = bin.to_string_lossy().into_owned();
        let records = vec![record(
            Activity::Exec {
                path: Some(&bin_path),
                argv: None,
                dev: kernel_dev(m.dev()),
                ino: m.ino(),
                committed: false,
            },
            Verdict::AuditWouldDeny,
            "agent",
            None,
        )];
        let (_, opts) = setup("replaced", &records);
        let (text, summary) = suggest(&opts).unwrap();
        let t: Table = toml::from_str(&text).unwrap();
        assert!(
            t["profiles"]["agent"]["exec"].get("allow").is_none(),
            "{text}"
        );
        assert!(text.contains("replaced after the agent ran them"), "{text}");
        assert!(
            text.contains(&format!("{bin_path}: the agent ran another file")),
            "{text}"
        );
        assert!(summary.contains("1 replaced"), "{summary}");
    }

    /// `--out` onto a planted symbolic link is refused; the link's target is
    /// not overwritten.
    #[test]
    fn out_never_writes_through_a_planted_symlink() {
        let records = vec![record(
            connect("127.0.0.1", 80, 6),
            Verdict::AuditWouldDeny,
            "agent",
            None,
        )];
        let (dir, mut opts) = setup("out-link", &records);
        let victim = dir.join("victim");
        fs::write(&victim, "precious\n").unwrap();
        let out = dir.join("agent.toml");
        std::os::unix::fs::symlink(&victim, &out).unwrap();
        opts.out = Some(out.clone());
        let err = run(&opts).unwrap_err().to_string();
        assert!(err.contains("symbolic link"), "{err}");
        assert_eq!(fs::read_to_string(&victim).unwrap(), "precious\n");
        // A regular file there is replaced with the suggestion.
        fs::remove_file(&out).unwrap();
        fs::write(&out, "old\n").unwrap();
        run(&opts).unwrap();
        crate::init::validate(&fs::read_to_string(&out).unwrap()).unwrap();
    }

    #[test]
    fn helpers() {
        assert_eq!(parse_since("2h").unwrap(), 7_200_000);
        assert!(parse_since("2w").is_err());
        let ports: BTreeSet<u16> = [80, 81, 82, 443].into_iter().collect();
        assert_eq!(port_ranges(&ports), [(80, 82), (443, 443)]);
        assert!(is_interpreter("/usr/bin/python3.12"));
        assert!(!is_interpreter("/usr/bin/git"));
        assert!(is_public(&"203.0.113.7".parse().unwrap()));
        assert!(!is_public(&"10.1.2.3".parse().unwrap()));
        assert!(!is_public(&"100.64.0.1".parse().unwrap()));
        assert!(in_profile("[[profiles.agent.files.deny]]", "agent"));
        assert!(in_profile("[profiles.\"agent\"]", "agent"));
        assert!(!in_profile("[profiles.agent2]", "agent"));
        assert_eq!(kernel_dev(0x0803), (8 << 20) | 3);
    }
}
