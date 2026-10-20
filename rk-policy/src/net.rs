//! Kernel network policy (Phase 2): TOML policy file → validated IR → compiled
//! map contents for `rk_profiles`, `rk_net_deny` and `rk_net_allow`.
//!
//! [`evaluate`] is the reference semantics, written as a plain linear scan.
//! [`Compiled::lookup`] simulates the kernel's longest-prefix lookup over the
//! compiled entries. Property tests check that the two always agree. This crate
//! has no BPF dependency; `rk-sensor` writes the compiled entries into the maps.
//!
//! See `docs/design/phase-2.md` and `docs/policy.md`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::{IpAddr, Ipv6Addr};

use ipnet::{IpNet, Ipv6Net};
use serde::Deserialize;

/// Maximum number of profiles (`RK_MAX_PROFILES` in rk_abi.h).
pub const MAX_PROFILES: u32 = 1024;
/// Maximum port/protocol ranges per compiled prefix (`RK_NET_MAX_RANGES`).
pub const MAX_RANGES: usize = 8;

/// Protocol bits (`enum rk_proto_bit`).
pub const PROTO_TCP: u8 = 1;
pub const PROTO_UDP: u8 = 2;
pub const PROTO_OTHER: u8 = 4;
pub const PROTO_ANY: u8 = PROTO_TCP | PROTO_UDP | PROTO_OTHER;

/// `rk_profile.flags` bit: deny raw and packet sockets.
pub const FLAG_DENY_RAW_SOCKETS: u16 = 1;
/// `rk_profile.flags` bit: exec allowlist mode (unlisted executables denied).
pub const FLAG_EXEC_DENY_DEFAULT: u16 = 2;
/// `rk_profile.flags` bit: allow executing files with no links (memfd, deleted).
pub const FLAG_EXEC_ALLOW_UNLINKED: u16 = 4;

/// Built-in profile that denies all exec and all network; see
/// docs/design/phase-3.md §6. Its name is reserved.
pub const QUARANTINE: &str = "quarantine";

/// Maximum files an `exec.allow_dirs` expansion may add per profile.
pub const MAX_EXEC_DIR_FILES: usize = 4096;

/// Root of every binding: hooks are attached at `/sys/fs/cgroup/rk.slice`.
pub const CGROUP_ROOT: &str = "rk.slice";

/// Built-in rule lists that profiles can `include`.
pub const BUILTIN_LISTS: &[(&str, &str)] = &[(
    "cloud-metadata",
    include_str!("../../deploy/policy/cloud-metadata.toml"),
)];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Audit,
    Enforce,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    Tcp,
    Udp,
    Other,
    Any,
}

impl Proto {
    fn mask(self) -> u8 {
        match self {
            Proto::Tcp => PROTO_TCP,
            Proto::Udp => PROTO_UDP,
            Proto::Other => PROTO_OTHER,
            Proto::Any => PROTO_ANY,
        }
    }
}

/// A policy error, with the location in the policy that caused it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyError {
    pub context: String,
    pub message: String,
}

impl PolicyError {
    fn new(context: impl Into<String>, message: impl Into<String>) -> Self {
        PolicyError {
            context: context.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.context, self.message)
    }
}

impl std::error::Error for PolicyError {}

// ---------------------------------------------------------------------------
// File format
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    #[serde(default)]
    profiles: BTreeMap<String, ProfileFile>,
    #[serde(default)]
    bindings: Vec<BindingFile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileFile {
    mode: Mode,
    #[serde(default)]
    network: NetworkFile,
    /// Absent: exec policy inactive (every exec allowed), see design §8.1.
    #[serde(default)]
    exec: Option<ExecFile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecFile {
    /// With an `exec` section the default is allowlist mode.
    #[serde(default = "deny")]
    default: Action,
    #[serde(default)]
    allow: Vec<String>,
    #[serde(default)]
    allow_dirs: Vec<String>,
    #[serde(default)]
    allow_unlinked: bool,
    #[serde(default)]
    require_hash: bool,
}

fn deny() -> Action {
    Action::Deny
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct NetworkFile {
    default: Action,
    include: Vec<String>,
    nat64_equivalence: bool,
    deny_raw_sockets: bool,
    allow: Vec<RuleFile>,
    deny: Vec<RuleFile>,
}

impl Default for NetworkFile {
    fn default() -> Self {
        NetworkFile {
            default: Action::Deny,
            include: vec!["cloud-metadata".to_string()],
            nat64_equivalence: true,
            deny_raw_sockets: true,
            allow: Vec::new(),
            deny: Vec::new(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleFile {
    cidr: String,
    #[serde(default)]
    ports: Vec<String>,
    #[serde(default)]
    proto: Vec<Proto>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BindingFile {
    cgroup: String,
    profile: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ListFile {
    name: String,
    #[allow(dead_code)]
    description: String,
    deny: Vec<ListRule>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ListRule {
    cidr: String,
    #[serde(default)]
    ports: Vec<String>,
    #[serde(default)]
    proto: Vec<Proto>,
    #[allow(dead_code)]
    source: String,
    #[serde(default)]
    note: String,
}

// ---------------------------------------------------------------------------
// Validated IR
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortRange {
    pub lo: u16,
    pub hi: u16,
}

impl PortRange {
    pub const ALL: PortRange = PortRange {
        lo: 0,
        hi: u16::MAX,
    };

    fn contains(&self, port: u16) -> bool {
        (self.lo..=self.hi).contains(&port)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    /// Unique within the policy; reported in kernel events.
    pub id: u32,
    pub action: Action,
    /// IPv4 rules are stored IPv4-mapped (`::ffff:a.b.c.d/96+n`).
    pub net: Ipv6Net,
    pub ports: Vec<PortRange>,
    pub proto: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    pub id: u32,
    pub name: String,
    pub mode: Mode,
    pub net_default: Action,
    pub deny_raw_sockets: bool,
    /// In priority order within each action: file order.
    pub rules: Vec<Rule>,
    /// `None`: exec policy inactive for this profile (every exec allowed).
    pub exec: Option<ExecPolicy>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecPathKind {
    /// One executable.
    File,
    /// Every regular file directly inside, resolved at apply time.
    Dir,
}

/// One exec allowlist entry. Paths are resolved to (device, inode) by the
/// sensor at apply time; see docs/design/phase-3.md §4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecAllow {
    pub id: u32,
    pub path: String,
    pub kind: ExecPathKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecPolicy {
    pub default: Action,
    pub allow_unlinked: bool,
    pub allow: Vec<ExecAllow>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    /// Relative to `/sys/fs/cgroup`, always under `rk.slice/`.
    pub cgroup: String,
    pub profile: u32,
}

/// Where a rule id came from, for audit logs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleOrigin {
    pub id: u32,
    pub profile: String,
    pub origin: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub profiles: Vec<Profile>,
    pub bindings: Vec<Binding>,
    pub origins: Vec<RuleOrigin>,
}

impl Policy {
    pub fn profile(&self, id: u32) -> Option<&Profile> {
        self.profiles.iter().find(|p| p.id == id)
    }

    pub fn origin(&self, rule_id: u32) -> Option<&RuleOrigin> {
        self.origins.iter().find(|o| o.id == rule_id)
    }
}

/// Profile name → id allocation that stays stable across reloads, so cgroup
/// bindings never have to change when a policy is re-applied. Ids are never
/// reused within the lifetime of one allocator.
#[derive(Debug, Clone, Default)]
pub struct ProfileIds {
    ids: BTreeMap<String, u32>,
    next: u32,
}

impl ProfileIds {
    pub fn id(&mut self, name: &str) -> Result<u32, PolicyError> {
        if let Some(&id) = self.ids.get(name) {
            return Ok(id);
        }
        if self.next >= MAX_PROFILES {
            return Err(PolicyError::new(
                format!("profile `{name}`"),
                format!("more than {MAX_PROFILES} profiles have been defined"),
            ));
        }
        let id = self.next;
        self.next += 1;
        self.ids.insert(name.to_string(), id);
        Ok(id)
    }
}

// ---------------------------------------------------------------------------
// Parsing and validation
// ---------------------------------------------------------------------------

fn mapped_v4_space() -> Ipv6Net {
    Ipv6Net::new(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0, 0), 96).expect("valid prefix")
}

/// Parses `a.b.c.d/n`, `x::y/n` or a bare address. Host bits must be zero.
pub fn parse_cidr(s: &str) -> Result<Ipv6Net, String> {
    let s = s.trim();
    let net: IpNet = if s.contains('/') {
        s.parse()
            .map_err(|_| format!("`{s}` is not a valid CIDR"))?
    } else {
        s.parse::<IpAddr>()
            .map(IpNet::from)
            .map_err(|_| format!("`{s}` is not a valid address or CIDR"))?
    };
    if net.trunc() != net {
        return Err(format!(
            "`{s}` has host bits set; did you mean `{}`?",
            net.trunc()
        ));
    }
    Ok(match net {
        IpNet::V4(n) => Ipv6Net::new(n.network().to_ipv6_mapped(), 96 + n.prefix_len())
            .map_err(|e| e.to_string())?,
        IpNet::V6(n) => n,
    })
}

fn parse_ports(list: &[String]) -> Result<Vec<PortRange>, String> {
    if list.is_empty() {
        return Ok(vec![PortRange::ALL]);
    }
    list.iter()
        .map(|p| {
            let p = p.trim();
            if p == "*" {
                return Ok(PortRange::ALL);
            }
            let (lo, hi) = match p.split_once('-') {
                Some((lo, hi)) => (lo.trim(), hi.trim()),
                None => (p, p),
            };
            let parse = |v: &str| {
                v.parse::<u16>()
                    .map_err(|_| format!("`{p}` is not a port or port range (0-65535)"))
            };
            let (lo, hi) = (parse(lo)?, parse(hi)?);
            if lo > hi {
                return Err(format!("port range `{p}` is reversed"));
            }
            Ok(PortRange { lo, hi })
        })
        .collect()
}

fn proto_mask(list: &[Proto]) -> u8 {
    if list.is_empty() {
        PROTO_ANY
    } else {
        list.iter().fold(0, |m, p| m | p.mask())
    }
}

/// The `64:ff9b::/96` (RFC 6052) form of an IPv4-mapped prefix.
fn nat64_equivalent(net: Ipv6Net) -> Option<Ipv6Net> {
    if !mapped_v4_space().contains(&net) {
        return None;
    }
    let s = net.network().segments();
    let addr = Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, s[6], s[7]);
    Ipv6Net::new(addr, net.prefix_len()).ok()
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

fn validate_cgroup(path: &str) -> Result<String, String> {
    let path = path.trim().trim_end_matches('/');
    let rest = path
        .strip_prefix(CGROUP_ROOT)
        .and_then(|r| r.strip_prefix('/'))
        .ok_or_else(|| {
            format!("`{path}` must be under `{CGROUP_ROOT}/`, where the hooks are attached")
        })?;
    for segment in rest.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." || !valid_name(segment) {
            return Err(format!("`{path}` has an invalid path segment `{segment}`"));
        }
    }
    Ok(path.to_string())
}

fn builtin_list(name: &str) -> Result<ListFile, String> {
    let text = BUILTIN_LISTS
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, t)| *t)
        .ok_or_else(|| {
            let known: Vec<_> = BUILTIN_LISTS.iter().map(|(n, _)| *n).collect();
            format!("unknown list `{name}` (known: {})", known.join(", "))
        })?;
    let list: ListFile =
        toml::from_str(text).map_err(|e| format!("built-in list `{name}` is invalid: {e}"))?;
    if list.name != name {
        return Err(format!(
            "built-in list `{name}` declares name `{}`",
            list.name
        ));
    }
    Ok(list)
}

/// Parses and validates a policy file. Profile ids come from `ids`, so they
/// stay stable across reloads.
pub fn parse(text: &str, ids: &mut ProfileIds) -> Result<Policy, PolicyError> {
    let file: PolicyFile =
        toml::from_str(text).map_err(|e| PolicyError::new("policy file", e.to_string()))?;

    let mut next_rule = 1u32;
    let mut profiles = Vec::new();
    let mut origins = Vec::new();

    for (name, pf) in &file.profiles {
        let ctx = format!("profile `{name}`");
        if name == QUARANTINE {
            return Err(PolicyError::new(
                &ctx,
                "`quarantine` is a built-in profile and cannot be redefined",
            ));
        }
        if !valid_name(name) {
            return Err(PolicyError::new(
                &ctx,
                "names may use only letters, digits, `-`, `_` and `.` (max 64)",
            ));
        }
        let id = ids.id(name)?;
        let net = &pf.network;
        let mut rules = Vec::new();

        let mut push = |action: Action,
                        cidr: &str,
                        ports: &[String],
                        proto: &[Proto],
                        origin: String,
                        rules: &mut Vec<Rule>|
         -> Result<(), PolicyError> {
            let rctx = format!("{ctx}, {origin}");
            let net_v6 = parse_cidr(cidr).map_err(|m| PolicyError::new(&rctx, m))?;
            let ports = parse_ports(ports).map_err(|m| PolicyError::new(&rctx, m))?;
            let rule = Rule {
                id: next_rule,
                action,
                net: net_v6,
                ports,
                proto: proto_mask(proto),
            };
            origins.push(RuleOrigin {
                id: next_rule,
                profile: name.clone(),
                origin,
            });
            next_rule += 1;
            if action == Action::Deny && pf.network.nat64_equivalence {
                if let Some(nat64) = nat64_equivalent(rule.net) {
                    rules.push(Rule {
                        net: nat64,
                        ..rule.clone()
                    });
                }
            }
            rules.push(rule);
            Ok(())
        };

        let mut seen_lists = BTreeSet::new();
        for list_name in &net.include {
            if !seen_lists.insert(list_name.as_str()) {
                continue;
            }
            let list = builtin_list(list_name).map_err(|m| PolicyError::new(&ctx, m))?;
            for (i, r) in list.deny.iter().enumerate() {
                let label = if r.note.is_empty() {
                    r.cidr.clone()
                } else {
                    format!("{} ({})", r.cidr, r.note)
                };
                push(
                    Action::Deny,
                    &r.cidr,
                    &r.ports,
                    &r.proto,
                    format!("{list_name}[{i}] {label}"),
                    &mut rules,
                )?;
            }
        }
        for (i, r) in net.deny.iter().enumerate() {
            push(
                Action::Deny,
                &r.cidr,
                &r.ports,
                &r.proto,
                format!("network.deny[{i}] {}", r.cidr),
                &mut rules,
            )?;
        }
        for (i, r) in net.allow.iter().enumerate() {
            push(
                Action::Allow,
                &r.cidr,
                &r.ports,
                &r.proto,
                format!("network.allow[{i}] {}", r.cidr),
                &mut rules,
            )?;
        }

        let exec = match &pf.exec {
            None => None,
            Some(ef) => Some(parse_exec(ef, &ctx, name, &mut next_rule, &mut origins)?),
        };

        profiles.push(Profile {
            id,
            name: name.clone(),
            mode: pf.mode,
            net_default: net.default,
            deny_raw_sockets: net.deny_raw_sockets,
            rules,
            exec,
        });
    }

    profiles.push(Profile {
        id: ids.id(QUARANTINE)?,
        name: QUARANTINE.to_string(),
        mode: Mode::Enforce,
        net_default: Action::Deny,
        deny_raw_sockets: true,
        rules: Vec::new(),
        exec: Some(ExecPolicy {
            default: Action::Deny,
            allow_unlinked: false,
            allow: Vec::new(),
        }),
    });

    let mut bindings = Vec::new();
    let mut seen = BTreeSet::new();
    for (i, b) in file.bindings.iter().enumerate() {
        let ctx = format!("bindings[{i}]");
        let cgroup = validate_cgroup(&b.cgroup).map_err(|m| PolicyError::new(&ctx, m))?;
        if !seen.insert(cgroup.clone()) {
            return Err(PolicyError::new(
                &ctx,
                format!("`{cgroup}` is bound more than once"),
            ));
        }
        let profile = profiles
            .iter()
            .find(|p| p.name == b.profile)
            .map(|p| p.id)
            .ok_or_else(|| PolicyError::new(&ctx, format!("unknown profile `{}`", b.profile)))?;
        bindings.push(Binding { cgroup, profile });
    }

    Ok(Policy {
        profiles,
        bindings,
        origins,
    })
}

fn parse_exec(
    ef: &ExecFile,
    ctx: &str,
    profile: &str,
    next_rule: &mut u32,
    origins: &mut Vec<RuleOrigin>,
) -> Result<ExecPolicy, PolicyError> {
    if ef.require_hash {
        return Err(PolicyError::new(
            ctx,
            "exec.require_hash is not supported by this release; the profile is refused \
             rather than run without the hash check (docs/design/phase-3.md §3)",
        ));
    }
    let mut allow = Vec::new();
    for (key, kind, paths) in [
        ("exec.allow", ExecPathKind::File, &ef.allow),
        ("exec.allow_dirs", ExecPathKind::Dir, &ef.allow_dirs),
    ] {
        for (i, path) in paths.iter().enumerate() {
            if !path.starts_with('/') || path.contains('\0') {
                return Err(PolicyError::new(
                    format!("{ctx}, {key}[{i}]"),
                    format!("`{path}` must be an absolute path"),
                ));
            }
            allow.push(ExecAllow {
                id: *next_rule,
                path: path.clone(),
                kind,
            });
            origins.push(RuleOrigin {
                id: *next_rule,
                profile: profile.to_string(),
                origin: format!("{key}[{i}] {path}"),
            });
            *next_rule += 1;
        }
    }
    Ok(ExecPolicy {
        default: ef.default,
        allow_unlinked: ef.allow_unlinked,
        allow,
    })
}

// ---------------------------------------------------------------------------
// Reference semantics
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decision {
    pub action: Action,
    /// 0 when the profile default decided.
    pub rule_id: u32,
}

/// IPv4 addresses are represented IPv4-mapped, as in the kernel.
pub fn normalize(addr: IpAddr) -> Ipv6Addr {
    match addr {
        IpAddr::V4(a) => a.to_ipv6_mapped(),
        IpAddr::V6(a) => a,
    }
}

/// Reference semantics: deny rules win over allow rules; within an action the
/// most specific matching prefix wins, then file order; otherwise the profile
/// default applies. `proto` is one `PROTO_*` bit.
pub fn evaluate(
    policy: &Policy,
    profile: u32,
    addr: IpAddr,
    port: u16,
    proto: u8,
) -> Option<Decision> {
    let prof = policy.profile(profile)?;
    let addr = normalize(addr);
    for action in [Action::Deny, Action::Allow] {
        let best = prof
            .rules
            .iter()
            .enumerate()
            .filter(|(_, r)| {
                r.action == action
                    && r.net.contains(&addr)
                    && r.proto & proto != 0
                    && r.ports.iter().any(|p| p.contains(port))
            })
            .max_by(|(ia, a), (ib, b)| {
                a.net.prefix_len().cmp(&b.net.prefix_len()).then(ib.cmp(ia)) // earlier rule wins a tie
            });
        if let Some((_, r)) = best {
            return Some(Decision {
                action,
                rule_id: r.id,
            });
        }
    }
    Some(Decision {
        action: prof.net_default,
        rule_id: 0,
    })
}

// ---------------------------------------------------------------------------
// Compilation
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompiledRange {
    pub rule_id: u32,
    pub lo: u16,
    pub hi: u16,
    pub proto: u8,
}

impl CompiledRange {
    fn covers(&self, other: &CompiledRange) -> bool {
        self.proto & other.proto == other.proto && self.lo <= other.lo && self.hi >= other.hi
    }
}

/// One LPM trie entry: the key is (slot, profile, prefix); the slot is chosen
/// by the sensor at apply time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub profile: u32,
    pub prefix_len: u8,
    pub addr: [u8; 16],
    /// Most specific first; at most [`MAX_RANGES`].
    pub ranges: Vec<CompiledRange>,
}

impl Entry {
    fn contains(&self, addr: &Ipv6Addr) -> bool {
        Ipv6Net::new(Ipv6Addr::from(self.addr), self.prefix_len)
            .map(|n| n.contains(addr))
            .unwrap_or(false)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompiledProfile {
    pub id: u32,
    pub mode: Mode,
    pub net_default: Action,
    pub flags: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Compiled {
    /// Never 0: the kernel treats generation 0 as "slot never written".
    pub generation: u64,
    pub profiles: Vec<CompiledProfile>,
    pub deny: Vec<Entry>,
    pub allow: Vec<Entry>,
    /// Exec allowlist entries, still as paths: the sensor resolves them.
    pub exec: Vec<CompiledExec>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledExec {
    pub profile: u32,
    pub rule_id: u32,
    pub path: String,
    pub kind: ExecPathKind,
}

/// Compiles a policy into map contents. Each trie entry carries its own
/// ranges followed by those of every covering shorter prefix (flattening), so a
/// single longest-prefix lookup is enough to reproduce [`evaluate`].
pub fn compile(policy: &Policy, generation: u64) -> Result<Compiled, PolicyError> {
    if generation == 0 {
        return Err(PolicyError::new("compile", "generation 0 is reserved"));
    }
    let mut out = Compiled {
        generation,
        profiles: Vec::new(),
        deny: Vec::new(),
        allow: Vec::new(),
        exec: Vec::new(),
    };
    for prof in &policy.profiles {
        out.profiles.push(CompiledProfile {
            id: prof.id,
            mode: prof.mode,
            net_default: prof.net_default,
            flags: profile_flags(prof),
        });
        if let Some(exec) = &prof.exec {
            out.exec.extend(exec.allow.iter().map(|a| CompiledExec {
                profile: prof.id,
                rule_id: a.id,
                path: a.path.clone(),
                kind: a.kind,
            }));
        }
        out.deny.extend(compile_trie(prof, Action::Deny)?);
        out.allow.extend(compile_trie(prof, Action::Allow)?);
    }
    Ok(out)
}

fn profile_flags(prof: &Profile) -> u16 {
    let mut flags = 0;
    if prof.deny_raw_sockets {
        flags |= FLAG_DENY_RAW_SOCKETS;
    }
    match &prof.exec {
        // Exec policy inactive: allow everything, including unlinked files.
        None => flags |= FLAG_EXEC_ALLOW_UNLINKED,
        Some(exec) => {
            if exec.default == Action::Deny {
                flags |= FLAG_EXEC_DENY_DEFAULT;
            }
            if exec.allow_unlinked {
                flags |= FLAG_EXEC_ALLOW_UNLINKED;
            }
        }
    }
    flags
}

fn compile_trie(prof: &Profile, action: Action) -> Result<Vec<Entry>, PolicyError> {
    // Distinct prefixes in first-appearance order, each with its rules in file order.
    let mut groups: Vec<(Ipv6Net, Vec<&Rule>)> = Vec::new();
    for rule in prof.rules.iter().filter(|r| r.action == action) {
        match groups.iter_mut().find(|(n, _)| *n == rule.net) {
            Some((_, rules)) => rules.push(rule),
            None => groups.push((rule.net, vec![rule])),
        }
    }

    let mut entries = Vec::new();
    for (net, own) in &groups {
        let mut ancestors: Vec<&(Ipv6Net, Vec<&Rule>)> = groups
            .iter()
            .filter(|(other, _)| other != net && other.contains(net))
            .collect();
        ancestors.sort_by_key(|(n, _)| std::cmp::Reverse(n.prefix_len()));

        let mut ranges: Vec<CompiledRange> = Vec::new();
        let ordered = own
            .iter()
            .chain(ancestors.iter().flat_map(|(_, rules)| rules.iter()));
        for rule in ordered {
            for p in &rule.ports {
                let r = CompiledRange {
                    rule_id: rule.id,
                    lo: p.lo,
                    hi: p.hi,
                    proto: rule.proto,
                };
                // A range fully covered by an earlier (higher-priority) one can never match first.
                if !ranges.iter().any(|k| k.covers(&r)) {
                    ranges.push(r);
                }
            }
        }
        if ranges.len() > MAX_RANGES {
            return Err(PolicyError::new(
                format!("profile `{}`", prof.name),
                format!(
                    "addresses in {net} are covered by {} distinct {} port/protocol ranges \
                     (including enclosing prefixes); the kernel limit is {MAX_RANGES}. \
                     Merge port lists or split the prefix.",
                    ranges.len(),
                    if action == Action::Deny {
                        "deny"
                    } else {
                        "allow"
                    },
                ),
            ));
        }
        entries.push(Entry {
            profile: prof.id,
            prefix_len: net.prefix_len(),
            addr: net.network().octets(),
            ranges,
        });
    }
    Ok(entries)
}

impl Compiled {
    /// Simulates the kernel decision (`rk_net_verdict` in net.bpf.c).
    pub fn lookup(&self, profile: u32, addr: IpAddr, port: u16, proto: u8) -> Option<Decision> {
        let prof = self.profiles.iter().find(|p| p.id == profile)?;
        let addr = normalize(addr);
        for (action, trie) in [(Action::Deny, &self.deny), (Action::Allow, &self.allow)] {
            let longest = trie
                .iter()
                .filter(|e| e.profile == profile && e.contains(&addr))
                .max_by_key(|e| e.prefix_len);
            if let Some(entry) = longest {
                if let Some(r) = entry
                    .ranges
                    .iter()
                    .find(|r| r.proto & proto != 0 && (r.lo..=r.hi).contains(&port))
                {
                    return Some(Decision {
                        action,
                        rule_id: r.rule_id,
                    });
                }
            }
        }
        Some(Decision {
            action: prof.net_default,
            rule_id: 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::net::Ipv4Addr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn policy(text: &str) -> Policy {
        parse(text, &mut ProfileIds::default()).unwrap()
    }

    fn err(text: &str) -> String {
        parse(text, &mut ProfileIds::default())
            .unwrap_err()
            .to_string()
    }

    const BASIC: &str = r#"
        [profiles.agent]
        mode = "enforce"
        network.default = "deny"

        [[profiles.agent.network.allow]]
        cidr = "10.20.0.0/16"
        ports = ["443", "8000-8100"]
        proto = ["tcp"]

        [[profiles.agent.network.deny]]
        cidr = "10.20.5.0/24"

        [[bindings]]
        cgroup = "rk.slice/agent-1"
        profile = "agent"
    "#;

    #[test]
    fn parses_basic_policy() {
        let p = policy(BASIC);
        assert_eq!(p.profiles.len(), 2); // agent + built-in quarantine
        let prof = &p.profiles[0];
        assert_eq!(prof.mode, Mode::Enforce);
        assert_eq!(prof.net_default, Action::Deny);
        assert!(prof.deny_raw_sockets);
        assert_eq!(
            p.bindings,
            vec![Binding {
                cgroup: "rk.slice/agent-1".into(),
                profile: prof.id
            }]
        );
        // cloud-metadata is included by default.
        assert!(p
            .origins
            .iter()
            .any(|o| o.origin.starts_with("cloud-metadata[0] 169.254.169.254/32")));
    }

    #[test]
    fn deny_beats_allow_and_ports_and_protos_apply() {
        let p = policy(BASIC);
        let id = p.profiles[0].id;
        let d = |a: &str, port, proto| evaluate(&p, id, ip(a), port, proto).unwrap();
        assert_eq!(d("10.20.1.1", 443, PROTO_TCP).action, Action::Allow);
        assert_eq!(d("10.20.1.1", 8050, PROTO_TCP).action, Action::Allow);
        assert_eq!(d("10.20.1.1", 443, PROTO_UDP).action, Action::Deny); // proto
        assert_eq!(d("10.20.1.1", 22, PROTO_TCP).action, Action::Deny); // port
        assert_eq!(d("10.20.5.9", 443, PROTO_TCP).action, Action::Deny); // deny wins
        assert_eq!(
            d("10.20.5.9", 443, PROTO_TCP).rule_id,
            p.origins
                .iter()
                .find(|o| o.origin.starts_with("network.deny[0]"))
                .unwrap()
                .id
        );
        assert_eq!(
            d("8.8.8.8", 53, PROTO_UDP),
            Decision {
                action: Action::Deny,
                rule_id: 0
            }
        );
        assert_eq!(d("169.254.169.254", 80, PROTO_TCP).action, Action::Deny);
    }

    #[test]
    fn ipv4_and_mapped_ipv6_are_the_same_address() {
        let p = policy(BASIC);
        let id = p.profiles[0].id;
        assert_eq!(
            evaluate(&p, id, ip("10.20.5.1"), 1, PROTO_TCP),
            evaluate(&p, id, ip("::ffff:10.20.5.1"), 1, PROTO_TCP)
        );
    }

    #[test]
    fn nat64_equivalent_of_ipv4_deny_rules() {
        let p = policy(BASIC);
        let id = p.profiles[0].id;
        let v4 = evaluate(&p, id, ip("169.254.169.254"), 80, PROTO_TCP).unwrap();
        let nat64 = evaluate(&p, id, ip("64:ff9b::169.254.169.254"), 80, PROTO_TCP).unwrap();
        assert_eq!(v4, nat64);
        assert_eq!(nat64.action, Action::Deny);

        let off = policy(
            r#"
            [profiles.a]
            mode = "enforce"
            network.default = "allow"
            network.nat64_equivalence = false
        "#,
        );
        let d = evaluate(
            &off,
            off.profiles[0].id,
            ip("64:ff9b::169.254.169.254"),
            80,
            PROTO_TCP,
        )
        .unwrap();
        assert_eq!(d.action, Action::Allow);
    }

    #[test]
    fn include_can_only_be_removed_explicitly() {
        let p = policy(
            "[profiles.a]\nmode = \"audit\"\nnetwork.default = \"allow\"\nnetwork.include = []\n",
        );
        assert!(p.profiles[0].rules.is_empty());
    }

    #[test]
    fn rejects_bad_input() {
        assert!(err("[profiles.a]\nmode = \"block\"\n").contains("policy file"));
        assert!(err("[profiles.a]\nmode = \"audit\"\nunknown = 1\n").contains("unknown field"));
        assert!(err(
            "[profiles.a]\nmode = \"audit\"\n[[profiles.a.network.deny]]\ncidr = \"10.0.0.1/8\"\n"
        )
        .contains("did you mean `10.0.0.0/8`"));
        assert!(err(
            "[profiles.a]\nmode = \"audit\"\n[[profiles.a.network.deny]]\ncidr = \"nope\"\n"
        )
        .contains("not a valid"));
        assert!(err("[profiles.a]\nmode = \"audit\"\n[[profiles.a.network.deny]]\ncidr = \"10.0.0.0/8\"\nports = [\"9-1\"]\n")
            .contains("reversed"));
        assert!(
            err("[profiles.a]\nmode = \"audit\"\nnetwork.include = [\"nope\"]\n")
                .contains("unknown list")
        );
        assert!(
            err("[[bindings]]\ncgroup = \"rk.slice/x\"\nprofile = \"missing\"\n")
                .contains("unknown profile")
        );
        assert!(err("[profiles.a]\nmode = \"audit\"\n[[bindings]]\ncgroup = \"system.slice/x\"\nprofile = \"a\"\n")
            .contains("must be under `rk.slice/`"));
        assert!(err("[profiles.a]\nmode = \"audit\"\n[[bindings]]\ncgroup = \"rk.slice/../x\"\nprofile = \"a\"\n")
            .contains("invalid path segment"));
        assert!(err("[profiles.a]\nmode = \"audit\"\n[[bindings]]\ncgroup = \"rk.slice/x\"\nprofile = \"a\"\n[[bindings]]\ncgroup = \"rk.slice/x\"\nprofile = \"a\"\n")
            .contains("bound more than once"));
        assert!(err("[profiles.\"a b\"]\nmode = \"audit\"\n").contains("names may use only"));
    }

    #[test]
    fn profile_ids_are_stable_across_reloads() {
        let mut ids = ProfileIds::default();
        let one = parse("[profiles.b]\nmode = \"audit\"\n", &mut ids).unwrap();
        let two = parse(
            "[profiles.a]\nmode = \"audit\"\n[profiles.b]\nmode = \"audit\"\n",
            &mut ids,
        )
        .unwrap();
        let b1 = one.profiles.iter().find(|p| p.name == "b").unwrap().id;
        let b2 = two.profiles.iter().find(|p| p.name == "b").unwrap().id;
        assert_eq!(b1, b2);
        assert_ne!(two.profiles.iter().find(|p| p.name == "a").unwrap().id, b2);
    }

    #[test]
    fn flattening_keeps_enclosing_deny_rules() {
        // The /16 entry is the longest match for 10.1.2.3, but only the /8 rule
        // matches port 443. Without flattening the kernel would miss it.
        let p = policy(
            r#"
            [profiles.a]
            mode = "enforce"
            network.default = "allow"
            network.include = []
            [[profiles.a.network.deny]]
            cidr = "10.0.0.0/8"
            ports = ["443"]
            [[profiles.a.network.deny]]
            cidr = "10.1.0.0/16"
            ports = ["22"]
        "#,
        );
        let c = compile(&p, 1).unwrap();
        let id = p.profiles[0].id;
        for (addr, port) in [
            ("10.1.2.3", 443),
            ("10.1.2.3", 22),
            ("10.9.9.9", 443),
            ("10.1.2.3", 80),
        ] {
            assert_eq!(
                c.lookup(id, ip(addr), port, PROTO_TCP),
                evaluate(&p, id, ip(addr), port, PROTO_TCP),
                "{addr}:{port}"
            );
        }
        assert_eq!(
            c.lookup(id, ip("10.1.2.3"), 443, PROTO_TCP).unwrap().action,
            Action::Deny
        );
    }

    #[test]
    fn too_many_ranges_is_a_clear_error() {
        let mut text = String::from("[profiles.a]\nmode = \"enforce\"\nnetwork.include = []\n");
        for port in 1..=9 {
            text.push_str(&format!(
                "[[profiles.a.network.allow]]\ncidr = \"10.0.0.0/8\"\nports = [\"{port}\"]\n"
            ));
        }
        let p = policy(&text);
        let e = compile(&p, 1).unwrap_err().to_string();
        assert!(e.contains("kernel limit is 8"), "{e}");
    }

    #[test]
    fn generation_zero_is_rejected() {
        assert!(compile(&policy(BASIC), 0).is_err());
    }

    #[test]
    fn compiled_profiles_carry_mode_default_and_flags() {
        let c = compile(&policy(BASIC), 7).unwrap();
        assert_eq!(c.generation, 7);
        assert_eq!(
            c.profiles[0],
            CompiledProfile {
                id: 0,
                mode: Mode::Enforce,
                net_default: Action::Deny,
                // No exec section: exec policy inactive.
                flags: FLAG_DENY_RAW_SOCKETS | FLAG_EXEC_ALLOW_UNLINKED
            }
        );
        assert_eq!(
            c.profiles[1],
            CompiledProfile {
                id: 1,
                mode: Mode::Enforce,
                net_default: Action::Deny,
                flags: FLAG_DENY_RAW_SOCKETS | FLAG_EXEC_DENY_DEFAULT
            }
        );
        assert!(c.deny.iter().all(|e| e.ranges.len() <= MAX_RANGES));
    }

    const EXEC: &str = r#"
        [profiles.agent]
        mode = "enforce"
        [profiles.agent.exec]
        allow = ["/usr/bin/git", "/bin/sh"]
        allow_dirs = ["/opt/agent/bin"]

        [profiles.loose]
        mode = "audit"
        [profiles.loose.exec]
        default = "allow"
        allow_unlinked = true
    "#;

    #[test]
    fn parses_exec_sections() {
        let p = policy(EXEC);
        let agent = p.profiles.iter().find(|p| p.name == "agent").unwrap();
        let exec = agent.exec.as_ref().unwrap();
        assert_eq!(exec.default, Action::Deny);
        assert_eq!(exec.allow.len(), 3);
        assert_eq!(exec.allow[2].kind, ExecPathKind::Dir);
        assert!(p
            .origins
            .iter()
            .any(|o| o.id == exec.allow[0].id && o.origin == "exec.allow[0] /usr/bin/git"));

        let c = compile(&p, 1).unwrap();
        assert_eq!(c.exec.len(), 3);
        assert!(c.exec.iter().all(|e| e.profile == agent.id));
        let flags = |name: &str| {
            let id = p.profiles.iter().find(|p| p.name == name).unwrap().id;
            c.profiles.iter().find(|cp| cp.id == id).unwrap().flags
        };
        assert_eq!(flags("agent") & FLAG_EXEC_DENY_DEFAULT, FLAG_EXEC_DENY_DEFAULT);
        assert_eq!(flags("agent") & FLAG_EXEC_ALLOW_UNLINKED, 0);
        assert_eq!(flags("loose") & FLAG_EXEC_DENY_DEFAULT, 0);
        assert_eq!(flags("loose") & FLAG_EXEC_ALLOW_UNLINKED, FLAG_EXEC_ALLOW_UNLINKED);
    }

    #[test]
    fn exec_errors_are_clear() {
        assert!(err("[profiles.a]\nmode = \"enforce\"\n[profiles.a.exec]\nallow = [\"bin/sh\"]\n")
            .contains("must be an absolute path"));
        assert!(err("[profiles.a]\nmode = \"enforce\"\n[profiles.a.exec]\nrequire_hash = true\n")
            .contains("not supported by this release"));
        assert!(err("[profiles.a]\nmode = \"enforce\"\n[profiles.a.exec]\nbogus = 1\n")
            .contains("unknown field"));
    }

    #[test]
    fn quarantine_is_built_in_and_reserved() {
        let p = policy("[profiles.a]\nmode = \"audit\"\n");
        let q = p.profiles.iter().find(|p| p.name == QUARANTINE).unwrap();
        assert_eq!(q.mode, Mode::Enforce);
        assert_eq!(q.net_default, Action::Deny);
        assert!(q.rules.is_empty());
        assert_eq!(q.exec.as_ref().unwrap().allow.len(), 0);
        assert!(err("[profiles.quarantine]\nmode = \"audit\"\n").contains("built-in profile"));
        // Its id is stable across reloads like any other profile.
        let mut ids = ProfileIds::default();
        let one = parse("[profiles.a]\nmode = \"audit\"\n", &mut ids).unwrap();
        let two = parse("[profiles.b]\nmode = \"audit\"\n[profiles.a]\nmode = \"audit\"\n", &mut ids).unwrap();
        let qid = |p: &Policy| p.profiles.iter().find(|p| p.name == QUARANTINE).unwrap().id;
        assert_eq!(qid(&one), qid(&two));
    }

    #[test]
    fn builtin_lists_parse_and_cite_sources() {
        for (name, _) in BUILTIN_LISTS {
            let list = builtin_list(name).unwrap();
            assert!(!list.deny.is_empty());
            for r in &list.deny {
                assert!(r.source.starts_with("https://"), "{}", r.cidr);
                parse_cidr(&r.cidr).unwrap();
            }
        }
    }

    // ---- property test: compiled lookup == reference semantics ----

    fn arb_rule() -> impl Strategy<Value = String> {
        (
            prop::bool::ANY,
            0u8..4,
            prop::sample::select(vec![8u8, 12, 16, 20, 24, 28, 32]),
            prop::collection::vec(
                prop::sample::select(vec!["22", "53", "80", "443", "1000-2000", "*"]),
                0..3,
            ),
            prop::collection::vec(
                prop::sample::select(vec!["tcp", "udp", "other", "any"]),
                0..2,
            ),
        )
            .prop_map(|(deny, b, len, ports, protos)| {
                let base = Ipv4Addr::new(10, b, 0, 0);
                let net = ipnet::Ipv4Net::new(base, len).unwrap().trunc();
                let ports: Vec<String> = ports.iter().map(|p| format!("\"{p}\"")).collect();
                let protos: Vec<String> = protos.iter().map(|p| format!("\"{p}\"")).collect();
                format!(
                    "[[profiles.p.network.{}]]\ncidr = \"{net}\"\nports = [{}]\nproto = [{}]\n",
                    if deny { "deny" } else { "allow" },
                    ports.join(", "),
                    protos.join(", ")
                )
            })
    }

    proptest! {
        #[test]
        fn compiled_lookup_matches_reference(
            rules in prop::collection::vec(arb_rule(), 0..6),
            default_deny in prop::bool::ANY,
            queries in prop::collection::vec((0u8..4, 0u8..4, any::<u8>(), prop::sample::select(vec![22u16, 53, 80, 443, 1500, 3000]), prop::sample::select(vec![PROTO_TCP, PROTO_UDP, PROTO_OTHER])), 1..20),
        ) {
            let mut text = format!(
                "[profiles.p]\nmode = \"enforce\"\nnetwork.default = \"{}\"\n",
                if default_deny { "deny" } else { "allow" }
            );
            for r in &rules { text.push_str(r); }
            let p = parse(&text, &mut ProfileIds::default()).unwrap();
            // Over-limit policies are rejected at compile time; nothing to compare.
            if let Ok(c) = compile(&p, 1) {
                let id = p.profiles[0].id;
                for (b, c3, d, port, proto) in queries {
                    let addr = IpAddr::V4(Ipv4Addr::new(10, b, c3, d));
                    prop_assert_eq!(c.lookup(id, addr, port, proto), evaluate(&p, id, addr, port, proto), "{} port {} proto {}", addr, port, proto);
                }
            }
        }
    }
}
