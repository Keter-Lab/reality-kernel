//! OCSF 1.9.0 records for kernel decisions (docs/design/phase-9.md §3.2,
//! docs/audit.md).
//!
//! Classes: Network Activity (4001), Process Activity (1007), File System
//! Activity (1001), and Application Error (6008) for lost events. Profiles:
//! `security_control` (action, disposition, policy) and `host` (device,
//! actor). Values without an OCSF attribute go in `unmapped.rk`.

use std::net::IpAddr;

use serde_json::{json, Map, Value};

pub const OCSF_VERSION: &str = "1.9.0";
pub const PRODUCT: &str = "Reality Kernel";
pub const VENDOR: &str = "Keter Labs";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Deny,
    AuditWouldDeny,
}

impl Verdict {
    /// From `enum rk_verdict`.
    pub fn from_abi(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Allow),
            1 => Some(Self::Deny),
            2 => Some(Self::AuditWouldDeny),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::AuditWouldDeny => "audit_would_deny",
        }
    }

    /// OCSF `action_id`, `disposition_id`.
    fn action_disposition(self) -> (u8, u8) {
        match self {
            Self::Allow => (1, 1),
            Self::Deny => (2, 2),
            Self::AuditWouldDeny => (1, 15),
        }
    }
}

/// What the decision was about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Activity<'a> {
    /// `connect()` (`sendmsg: false`) or an unconnected UDP `sendmsg()`.
    Connect {
        addr: IpAddr,
        port: u16,
        /// IPPROTO_*.
        protocol: u8,
        sendmsg: bool,
    },
    /// A raw or packet `socket()`.
    SocketCreate {
        family: u16,
        sock_type: u32,
        protocol: u32,
    },
    /// An exec decision, or (`committed`) the record of an allowed exec.
    Exec {
        path: Option<&'a str>,
        argv: Option<&'a str>,
        dev: u64,
        ino: u64,
        committed: bool,
    },
    /// A file access decided by file policy. `hook` is `enum rk_file_hook`,
    /// `access` the `enum rk_file_access` bits requested.
    File {
        path: Option<&'a str>,
        hook: u16,
        access: u32,
        dev: u64,
        ino: u64,
    },
    /// A self-protection decision. `hook` is `enum rk_tamper_hook`.
    Tamper {
        hook: u16,
        target_tgid: u32,
        detail: u64,
    },
}

/// The acting process. `exe` and `ppid` come from enrichment, which says how
/// it got them in `enrichment` (`exec_record`, `procfs`, `unavailable`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Process<'a> {
    pub pid: u32,
    pub tid: u32,
    pub uid: u32,
    pub gid: u32,
    pub exe: Option<&'a str>,
    pub ppid: Option<u32>,
    pub enrichment: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision<'a> {
    /// Wall-clock time of the decision, milliseconds since the epoch.
    pub time_ms: i64,
    pub activity: Activity<'a>,
    pub verdict: Verdict,
    /// 0 when the profile default decided; `u32::MAX` for a stale heartbeat.
    pub rule_id: u32,
    pub policy_gen: u64,
    pub profile: Option<&'a str>,
    /// Where the rule came from in the policy text.
    pub rule_origin: Option<&'a str>,
    pub cgroup_id: u64,
    pub session: Option<&'a str>,
    pub process: Process<'a>,
    pub hostname: &'a str,
    pub version: &'a str,
}

fn metadata(version: &str) -> Value {
    json!({
        "version": OCSF_VERSION,
        "product": { "name": PRODUCT, "vendor_name": VENDOR, "version": version },
        "profiles": ["security_control", "host"],
        "log_name": "audit",
    })
}

fn device(hostname: &str) -> Value {
    json!({ "hostname": hostname, "type_id": 1, "type": "Server" })
}

/// OCSF class and activity of a record.
struct Class {
    uid: u32,
    name: &'static str,
    category_uid: u32,
    category: &'static str,
    activity_id: u32,
    activity: &'static str,
}

const NETWORK: (u32, &str, u32, &str) = (4001, "Network Activity", 4, "Network Activity");
const PROCESS: (u32, &str, u32, &str) = (1007, "Process Activity", 1, "System Activity");
const FILE: (u32, &str, u32, &str) = (1001, "File System Activity", 1, "System Activity");

fn classify(a: &Activity<'_>) -> Class {
    let ((uid, name, category_uid, category), activity_id, activity) = match a {
        Activity::Connect { sendmsg: false, .. } => (NETWORK, 1, "Open"),
        Activity::Connect { sendmsg: true, .. } => (NETWORK, 6, "Traffic"),
        Activity::SocketCreate { .. } => (NETWORK, 99, "Socket Create"),
        Activity::Exec { .. } => (PROCESS, 1, "Launch"),
        Activity::Tamper { .. } => (PROCESS, 99, "Tamper"),
        Activity::File { hook, .. } => {
            let (id, name) = match hook {
                1 => (14, "Open"),
                2 => (4, "Delete"),
                3 => (5, "Rename"),
                4 => (1, "Create"), // hard link: a new name for the file
                5 => (1, "Create"),
                6 => (6, "Set Attributes"),
                _ => (99, "Other"),
            };
            (FILE, id, name)
        }
    };
    Class {
        uid,
        name,
        category_uid,
        category,
        activity_id,
        activity,
    }
}

fn file_object(path: Option<&str>, executable: bool) -> Value {
    let path = path.unwrap_or("");
    let name = path
        .rsplit('/')
        .next()
        .filter(|n| !n.is_empty())
        .unwrap_or(path);
    let mut f = json!({
        "name": if name.is_empty() { "unknown" } else { name },
        "type_id": if executable { 8 } else { 1 },
        "type": if executable { "Executable File" } else { "Regular File" },
    });
    if path.starts_with('/') {
        f["path"] = json!(path);
    }
    f
}

fn process_object(p: &Process<'_>, session: Option<&str>) -> Value {
    let mut proc_ = json!({
        "pid": p.pid,
        "tid": p.tid,
        "user": { "uid": p.uid.to_string() },
    });
    if let Some(exe) = p.exe {
        proc_["file"] = file_object(Some(exe), true);
        proc_["name"] = json!(exe.rsplit('/').next().unwrap_or(exe));
    }
    if let Some(ppid) = p.ppid {
        proc_["parent_process"] = json!({ "pid": ppid });
    }
    if let Some(s) = session {
        proc_["session"] = json!({ "uid": s });
    }
    proc_
}

fn severity(verdict: Verdict, a: &Activity<'_>) -> (u8, &'static str) {
    match (verdict, a) {
        (Verdict::Allow, _) => (1, "Informational"),
        (_, Activity::Tamper { .. }) => (4, "High"),
        (Verdict::Deny, _) => (3, "Medium"),
        (Verdict::AuditWouldDeny, _) => (2, "Low"),
    }
}

fn file_access_names(access: u32) -> Vec<&'static str> {
    const NAMES: [(u32, &str); 9] = [
        (1, "read"),
        (2, "write"),
        (4, "exec"),
        (8, "create"),
        (16, "delete"),
        (32, "rename"),
        (64, "truncate"),
        (128, "link"),
        (256, "setattr"),
    ];
    NAMES
        .iter()
        .filter(|(bit, _)| access & bit != 0)
        .map(|(_, n)| *n)
        .collect()
}

/// The OCSF record for one decision.
pub fn decision(d: &Decision<'_>) -> Value {
    let class = classify(&d.activity);
    let (action_id, disposition_id) = d.verdict.action_disposition();
    let (severity_id, severity_name) = severity(d.verdict, &d.activity);
    let process = process_object(&d.process, d.session);

    let mut actor = json!({ "process": process, "user": { "uid": d.process.uid.to_string() } });
    if let Some(s) = d.session {
        actor["session"] = json!({ "uid": s });
    }

    let mut policy = json!({ "uid": d.rule_id.to_string(), "version": d.policy_gen.to_string() });
    if let Some(profile) = d.profile {
        policy["name"] = json!(profile);
    }
    if let Some(origin) = d.rule_origin {
        policy["desc"] = json!(origin);
    }

    let mut rk = Map::new();
    rk.insert("verdict".into(), json!(d.verdict.as_str()));
    rk.insert("rule_id".into(), json!(d.rule_id));
    rk.insert("policy_gen".into(), json!(d.policy_gen));
    rk.insert("cgroup_id".into(), json!(d.cgroup_id));
    rk.insert("enrichment".into(), json!(d.process.enrichment));
    rk.insert("gid".into(), json!(d.process.gid));

    let mut r = json!({
        "class_uid": class.uid,
        "class_name": class.name,
        "category_uid": class.category_uid,
        "category_name": class.category,
        "activity_id": class.activity_id,
        "activity_name": class.activity,
        "type_uid": class.uid * 100 + class.activity_id,
        "type_name": format!("{}: {}", class.name, class.activity),
        "time": d.time_ms,
        "severity_id": severity_id,
        "severity": severity_name,
        "action_id": action_id,
        "action": if action_id == 2 { "Denied" } else { "Allowed" },
        "disposition_id": disposition_id,
        "disposition": match disposition_id { 2 => "Blocked", 15 => "Detected", _ => "Allowed" },
        "status_id": if action_id == 2 { 2 } else { 1 },
        "status": if action_id == 2 { "Failure" } else { "Success" },
        "metadata": metadata(d.version),
        "device": device(d.hostname),
        "actor": actor,
        "policy": policy,
    });

    match &d.activity {
        Activity::Connect {
            addr,
            port,
            protocol,
            ..
        } => {
            let ip = match addr {
                IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(*addr),
                v4 => *v4,
            };
            r["dst_endpoint"] = json!({ "ip": ip.to_string(), "port": port });
            r["connection_info"] = json!({
                "protocol_num": protocol,
                "protocol_name": match protocol { 6 => "tcp", 17 => "udp", _ => "other" },
                "direction_id": 2,
                "direction": "Outbound",
                "protocol_ver_id": if ip.is_ipv4() { 4 } else { 6 },
            });
        }
        Activity::SocketCreate {
            family,
            sock_type,
            protocol,
        } => {
            rk.insert(
                "socket".into(),
                json!({ "family": family, "type": sock_type, "protocol": protocol }),
            );
        }
        Activity::Exec {
            path,
            argv,
            dev,
            ino,
            committed,
        } => {
            // The exec'ing task keeps its pid across execve.
            let mut target = json!({ "pid": d.process.pid, "file": file_object(*path, true) });
            if let Some(name) = path.and_then(|p| p.rsplit('/').next()) {
                target["name"] = json!(name);
            }
            if let Some(args) = argv {
                target["cmd_line"] = json!(args);
            }
            r["process"] = target;
            rk.insert("file_dev".into(), json!(dev));
            rk.insert("file_ino".into(), json!(ino));
            rk.insert("committed".into(), json!(committed));
        }
        Activity::File {
            path,
            access,
            dev,
            ino,
            ..
        } => {
            r["file"] = file_object(*path, false);
            rk.insert("access".into(), json!(file_access_names(*access)));
            rk.insert("file_dev".into(), json!(dev));
            rk.insert("file_ino".into(), json!(ino));
        }
        Activity::Tamper {
            hook,
            target_tgid,
            detail,
        } => {
            r["process"] = json!({ "pid": target_tgid });
            rk.insert("tamper_hook".into(), json!(hook));
            rk.insert("tamper_detail".into(), json!(detail));
        }
    }
    r["unmapped"] = json!({ "rk": Value::Object(rk) });
    r
}

/// An Application Error record stating that decision events were lost
/// (docs/design/phase-9.md §3.4, decision 2). `kernel` counts events the
/// kernel could not emit; `channel` those the userspace pipeline dropped.
pub fn loss(time_ms: i64, hostname: &str, version: &str, kernel: u64, channel: u64) -> Value {
    json!({
        "class_uid": 6008,
        "class_name": "Application Error",
        "category_uid": 6,
        "category_name": "Application Activity",
        "activity_id": 1,
        "activity_name": "General Error",
        "type_uid": 600801,
        "type_name": "Application Error: General Error",
        "time": time_ms,
        "severity_id": 4,
        "severity": "High",
        "message": format!("{} decision events lost before reaching the audit log", kernel + channel),
        "metadata": metadata(version),
        "device": device(hostname),
        "unmapped": { "rk": { "lost": { "kernel": kernel, "channel": channel } } },
    })
}

/// The `unmapped.rk` object of a record, if any.
pub fn rk_fields(record: &Value) -> Option<&Map<String, Value>> {
    record.get("unmapped")?.get("rk")?.as_object()
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn sample(activity: Activity<'static>, verdict: Verdict) -> Decision<'static> {
        Decision {
            time_ms: 1_760_000_000_000,
            activity,
            verdict,
            rule_id: 7,
            policy_gen: 3,
            profile: Some("agent"),
            rule_origin: Some("network.deny[0] 10.0.0.0/8"),
            cgroup_id: 4242,
            session: Some("sess-1"),
            process: Process {
                pid: 100,
                tid: 101,
                uid: 1000,
                gid: 1000,
                exe: Some("/usr/bin/python3"),
                ppid: Some(1),
                enrichment: "exec_record",
            },
            hostname: "node-a",
            version: "0.1.0",
        }
    }

    #[test]
    fn deny_and_audit_map_to_ocsf_dispositions() {
        let connect = Activity::Connect {
            addr: "::ffff:10.0.0.5".parse().unwrap(),
            port: 443,
            protocol: 6,
            sendmsg: false,
        };
        let deny = decision(&sample(connect.clone(), Verdict::Deny));
        assert_eq!(
            (deny["action_id"].as_u64(), deny["disposition_id"].as_u64()),
            (Some(2), Some(2))
        );
        assert_eq!(deny["dst_endpoint"]["ip"], "10.0.0.5");
        assert_eq!(deny["policy"]["uid"], "7");
        assert_eq!(deny["type_uid"], 400101);
        let audit = decision(&sample(connect, Verdict::AuditWouldDeny));
        assert_eq!(
            (
                audit["action_id"].as_u64(),
                audit["disposition_id"].as_u64()
            ),
            (Some(1), Some(15))
        );
        assert_eq!(rk_fields(&audit).unwrap()["verdict"], "audit_would_deny");
    }

    #[test]
    fn file_access_bits_are_named() {
        assert_eq!(
            file_access_names(1 | 16 | 256),
            ["read", "delete", "setattr"]
        );
    }
}
