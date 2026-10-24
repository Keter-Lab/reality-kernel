//! `rk init`: write and apply a starter policy that fits this host
//! (docs/design/adoption.md §3.2).
//!
//! The starter profile `agent` is in AUDIT with default deny for network and
//! exec, and protects the user's secret files: nothing is blocked, and every
//! connection, exec and secret read the agent makes is recorded as
//! audit-would-deny. `rk policy suggest` turns those records into an ENFORCE
//! profile.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use rk_agentd::client::{ApplyOutcome, Client};
use toml::{Table, Value};

use crate::doctor;
use crate::toml_out::{self, Comments};

/// Profile name of the starter policy.
pub const PROFILE: &str = "agent";

/// Secret files checked under the agent user's home (docs/design/adoption.md
/// §3.4): path relative to the home directory.
pub const SECRETS: &[&str] = &[
    ".ssh",
    ".aws/credentials",
    ".config/gcloud",
    ".azure",
    ".kube/config",
    ".docker/config.json",
    ".config/gh/hosts.yml",
    ".netrc",
    ".git-credentials",
    ".npmrc",
    ".pypirc",
];

/// A secret that exists on this host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Secret {
    pub path: PathBuf,
    pub dir: bool,
}

/// Who the starter profile is for, and what the host can enforce.
#[derive(Debug, Clone)]
pub struct Starter {
    /// `launchable_by`: `user:NAME` for the invoking user, and `root`
    /// (root can rewrite the policy anyway, so this adds no reach).
    pub principals: Vec<String>,
    /// BPF LSM active: exec and file rules can be enforced.
    pub lsm: bool,
    pub secrets: Vec<Secret>,
}

/// Secrets from [`SECRETS`] that exist under `home`.
pub fn find_secrets(home: &Path) -> Vec<Secret> {
    SECRETS
        .iter()
        .filter_map(|rel| {
            let path = home.join(rel);
            let meta = fs::metadata(&path).ok()?;
            Some(Secret {
                dir: meta.is_dir(),
                path,
            })
        })
        .collect()
}

fn s(v: &str) -> Value {
    Value::String(v.to_string())
}

/// The starter profile's table.
pub fn starter_profile(st: &Starter) -> Table {
    let mut profile = Table::new();
    profile.insert("mode".into(), s("audit"));
    profile.insert(
        "launchable_by".into(),
        Value::Array(st.principals.iter().map(|p| s(p)).collect()),
    );

    let mut network = Table::new();
    network.insert("default".into(), s("deny"));
    if !st.lsm {
        // Without BPF LSM the sensor refuses anything but network rules.
        network.insert("deny_raw_sockets".into(), Value::Boolean(false));
    }
    profile.insert("network".into(), Value::Table(network));

    let mut files = Table::new();
    if st.lsm {
        let mut exec = Table::new();
        exec.insert("default".into(), s("deny"));
        profile.insert("exec".into(), Value::Table(exec));
        let deny: Vec<Value> = st
            .secrets
            .iter()
            .map(|sec| {
                let mut rule = Table::new();
                rule.insert("path".into(), s(&sec.path.to_string_lossy()));
                if sec.dir {
                    rule.insert("subtree".into(), Value::Boolean(true));
                }
                rule.insert("access".into(), Value::Array(vec![s("all")]));
                Value::Table(rule)
            })
            .collect();
        if !deny.is_empty() {
            files.insert("deny".into(), Value::Array(deny));
        }
    } else {
        files.insert("include".into(), Value::Array(Vec::new()));
    }
    if !files.is_empty() {
        profile.insert("files".into(), Value::Table(files));
    }
    profile
}

/// The starter policy file.
pub fn starter_policy(st: &Starter) -> String {
    let what: &[&str] = if st.lsm {
        &[
            "Profile `agent` is in AUDIT: nothing is blocked. Every connection and",
            "exec the agent makes, and every read of a protected secret file, is",
            "recorded as audit-would-deny.",
        ]
    } else {
        &[
            "Profile `agent` is in AUDIT: nothing is blocked. Every connection the",
            "agent makes is recorded as audit-would-deny. BPF LSM is not active on",
            "this host, so the profile is network-only.",
        ]
    };
    let mut lines = vec![
        "Reality Kernel starter policy, written by `rk init` (docs/agents.md).",
        "",
    ];
    lines.extend_from_slice(what);
    lines.extend_from_slice(&[
        "",
        "1. Run your agent under it:  rk run --profile agent -- <agent command>",
        "2. Then turn what it did into an ENFORCE profile, and review it:",
        "     sudo rk policy suggest --profile agent --out agent.toml",
        "     rk policy diff agent.toml",
    ]);
    let mut text = String::new();
    for line in lines {
        text.push_str(toml_out::comment(line).trim_end());
        text.push('\n');
    }
    text.push('\n');
    text.push_str(&toml_out::profile(
        PROFILE,
        &starter_profile(st),
        &Comments::default(),
    ));
    text
}

/// Fails if `text` is not a policy the sensor would accept.
pub fn validate(text: &str) -> Result<()> {
    let policy = rk_policy::net::parse(text, &mut rk_policy::net::ProfileIds::default())
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    rk_policy::net::compile(&policy, 1).map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(())
}

/// Whether the policy file at `path` already defines a profile. A file that
/// does not parse counts as in use: it is never silently replaced.
pub fn defines_profiles(path: &Path) -> Result<bool> {
    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e).with_context(|| format!("read {}", path.display())),
    };
    let table: Table = match toml::from_str(&text) {
        Ok(t) => t,
        Err(_) => return Ok(true),
    };
    Ok(table
        .get("profiles")
        .and_then(Value::as_table)
        .is_some_and(|p| !p.is_empty()))
}

/// `NAME`'s home directory from an `/etc/passwd`-format text.
pub fn home_of(passwd: &str, name: &str) -> Option<PathBuf> {
    passwd.lines().find_map(|line| {
        let fields: Vec<&str> = line.split(':').collect();
        (fields.len() >= 7 && fields[0] == name).then(|| PathBuf::from(fields[5]))
    })
}

fn effective_uid() -> Option<u32> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    status
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .and_then(|rest| rest.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
}

pub struct Options {
    pub policy: PathBuf,
    pub user: Option<String>,
    pub home: Option<PathBuf>,
    pub print: bool,
    pub force: bool,
}

/// `rk init`.
pub fn run(opts: &Options) -> Result<()> {
    let host = doctor::Host::new("/");
    let release = fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
    let report = doctor::run_checks(&host, release.trim());
    if !report.ok {
        let failed: Vec<String> = report
            .checks
            .iter()
            .filter(|c| c.status == doctor::Status::Fail)
            .map(|c| format!("{}: {}", c.name, c.detail))
            .collect();
        bail!(
            "this host cannot run the sensor ({}); see `rk doctor`",
            failed.join("; ")
        );
    }
    let lsm = fs::read_to_string("/sys/kernel/security/lsm")
        .is_ok_and(|l| l.trim().split(',').any(|m| m.trim() == "bpf"));

    let user = opts
        .user
        .clone()
        .or_else(|| std::env::var("SUDO_USER").ok())
        .filter(|u| !u.is_empty() && u != "root");
    let mut principals: Vec<String> = user.iter().map(|u| format!("user:{u}")).collect();
    principals.push("root".to_string());
    let home = match (&opts.home, &user) {
        (Some(h), _) => h.clone(),
        (None, Some(u)) => {
            let passwd = fs::read_to_string("/etc/passwd").context("read /etc/passwd")?;
            home_of(&passwd, u).with_context(|| format!("user `{u}` not found in /etc/passwd"))?
        }
        (None, None) => PathBuf::from("/root"),
    };
    let starter = Starter {
        principals,
        lsm,
        secrets: if lsm { find_secrets(&home) } else { Vec::new() },
    };
    let text = starter_policy(&starter);
    validate(&text).context("internal error: the starter policy does not validate")?;

    if opts.print {
        print!("{text}");
        return Ok(());
    }
    if effective_uid() != Some(0) {
        bail!(
            "rk init writes {} and must run as root (sudo rk init)",
            opts.policy.display()
        );
    }
    if defines_profiles(&opts.policy)? {
        if !opts.force {
            bail!(
                "{} already defines profiles; rk init never replaces a policy in use. \
                 Use `rk init --print` to see the starter, or --force to replace it \
                 (the old file is kept as a backup)",
                opts.policy.display()
            );
        }
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let backup = PathBuf::from(format!("{}.bak.{stamp}", opts.policy.display()));
        fs::copy(&opts.policy, &backup)
            .with_context(|| format!("back up {}", opts.policy.display()))?;
        eprintln!("Saved the previous policy as {}", backup.display());
    }
    if let Some(dir) = opts.policy.parent() {
        fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    }
    let tmp = opts.policy.with_extension("toml.rk-init");
    fs::write(&tmp, &text).with_context(|| format!("write {}", tmp.display()))?;
    fs::rename(&tmp, &opts.policy).with_context(|| format!("replace {}", opts.policy.display()))?;
    println!("Wrote {}", opts.policy.display());
    if !lsm {
        println!("BPF LSM is not active: the profile is network-only (see `rk doctor`).");
    }
    for sec in &starter.secrets {
        println!("Protecting {}", sec.path.display());
    }

    match Client::connect(None) {
        Ok(client) => match client.apply(&text, false)? {
            ApplyOutcome::Applied(rep) => println!(
                "Applied: generation {}, {} profiles",
                rep.generation, rep.profiles
            ),
            ApplyOutcome::DryRun(_) => {}
        },
        Err(e) => eprintln!(
            "Not applied yet: cannot reach rk-sensor ({e:#}). It reads {} when it starts \
             (systemctl start rk-sensor).",
            opts.policy.display()
        ),
    }
    println!(
        "\nNext:\n  rk run --profile {PROFILE} -- <your agent command>\n  \
         sudo rk policy suggest --profile {PROFILE} --out {PROFILE}.toml"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("rk-init-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn starter_with_bpf_lsm_learns_network_exec_and_secrets() {
        let home = scratch("lsm");
        fs::create_dir_all(home.join(".ssh")).unwrap();
        fs::create_dir_all(home.join(".aws")).unwrap();
        fs::write(home.join(".aws/credentials"), "x").unwrap();
        let st = Starter {
            principals: vec!["user:dev".into(), "root".into()],
            lsm: true,
            secrets: find_secrets(&home),
        };
        assert_eq!(st.secrets.len(), 2);
        let text = starter_policy(&st);
        validate(&text).unwrap();
        let t: Table = toml::from_str(&text).unwrap();
        let p = &t["profiles"]["agent"];
        assert_eq!(p["mode"].as_str(), Some("audit"));
        assert_eq!(p["launchable_by"][0].as_str(), Some("user:dev"));
        assert_eq!(p["launchable_by"][1].as_str(), Some("root"));
        assert_eq!(p["network"]["default"].as_str(), Some("deny"));
        assert_eq!(p["exec"]["default"].as_str(), Some("deny"));
        let deny = p["files"]["deny"].as_array().unwrap();
        assert_eq!(deny.len(), 2);
        let ssh = deny
            .iter()
            .find(|r| r["path"].as_str().unwrap().ends_with(".ssh"))
            .unwrap();
        assert_eq!(ssh["subtree"].as_bool(), Some(true));
    }

    #[test]
    fn starter_without_bpf_lsm_is_network_only() {
        let st = Starter {
            principals: vec!["root".into()],
            lsm: false,
            secrets: Vec::new(),
        };
        let text = starter_policy(&st);
        validate(&text).unwrap();
        let t: Table = toml::from_str(&text).unwrap();
        let p = &t["profiles"]["agent"];
        assert!(p.get("exec").is_none());
        assert_eq!(p["network"]["deny_raw_sockets"].as_bool(), Some(false));
        assert_eq!(p["files"]["include"].as_array().map(Vec::len), Some(0));
        assert!(text.contains("network-only"));
    }

    #[test]
    fn a_policy_in_use_is_never_replaced() {
        let dir = scratch("inuse");
        let path = dir.join("policy.toml");
        assert!(!defines_profiles(&path).unwrap());
        fs::write(&path, "# empty\n").unwrap();
        assert!(!defines_profiles(&path).unwrap());
        fs::write(&path, "[profiles.x]\nmode = \"audit\"\n").unwrap();
        assert!(defines_profiles(&path).unwrap());
        fs::write(&path, "not toml [").unwrap();
        assert!(defines_profiles(&path).unwrap());
    }

    #[test]
    fn home_comes_from_passwd() {
        let passwd = "root:x:0:0:root:/root:/bin/bash\ndev:x:1000:1000::/home/dev:/bin/sh\n";
        assert_eq!(home_of(passwd, "dev"), Some(PathBuf::from("/home/dev")));
        assert_eq!(home_of(passwd, "nobody"), None);
    }
}
