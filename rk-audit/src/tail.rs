//! One-line rendering of audit records for `rk audit tail`.

use std::borrow::Cow;
use std::fmt::Write as _;

use serde_json::Value;

use crate::ocsf::rk_fields;

/// Control lines (segment headers, batch trailers) are not records.
pub fn is_record(v: &Value) -> bool {
    v.get("rk_segment").is_none() && v.get("rk_batch").is_none()
}

/// Whether a record passes the `--verdict` and `--session` filters.
pub fn matches(v: &Value, verdict: Option<&str>, session: Option<&str>) -> bool {
    let rk = rk_fields(v);
    if let Some(want) = verdict {
        let got = rk.and_then(|rk| rk.get("verdict")).and_then(Value::as_str);
        let want = match want {
            "audit" => "audit_would_deny",
            other => other,
        };
        if got != Some(want) {
            return false;
        }
    }
    if let Some(want) = session {
        let got = v.pointer("/actor/session/uid").and_then(Value::as_str);
        if got != Some(want) {
            return false;
        }
    }
    true
}

/// `2026-10-22T12:00:00.123Z` from milliseconds since the epoch (UTC).
pub fn format_time(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let millis = ms.rem_euclid(1000);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // Civil date from days since 1970-01-01 (H. Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

fn str_at<'a>(v: &'a Value, pointer: &str) -> Option<&'a str> {
    v.pointer(pointer).and_then(Value::as_str)
}

/// Characters a terminal acts on rather than shows: C0 and C1 controls
/// (ESC among them), DEL, and the Unicode bidirectional formatting
/// characters, which reorder what is displayed.
pub fn is_unsafe_char(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
        )
}

/// `text` with every [`is_unsafe_char`] written as a visible escape (`\x1b`,
/// `\u{202e}`), for printing text a governed process chose (paths,
/// arguments) to a terminal: otherwise it could move the cursor and redraw
/// its own DENY as an ALLOW.
pub fn escape_control(text: &str) -> Cow<'_, str> {
    if !text.chars().any(is_unsafe_char) {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len() + 8);
    for c in text.chars() {
        if !is_unsafe_char(c) {
            out.push(c);
        } else if (c as u32) < 0x80 {
            let _ = write!(out, "\\x{:02x}", c as u32);
        } else {
            let _ = write!(out, "\\u{{{:x}}}", c as u32);
        }
    }
    Cow::Owned(out)
}

/// A stored JSON line, safe to print to a terminal and still the same JSON
/// value: every [`is_unsafe_char`] inside a string becomes a `\uXXXX`
/// escape. In a valid line the only ones outside a string are tab and
/// carriage return used as whitespace, which become spaces; all of them are
/// in the Basic Multilingual Plane, so four hex digits suffice.
pub fn escape_json_line(line: &str) -> Cow<'_, str> {
    if !line.chars().any(is_unsafe_char) {
        return Cow::Borrowed(line);
    }
    let mut out = String::with_capacity(line.len() + 8);
    for c in line.chars() {
        if !is_unsafe_char(c) {
            out.push(c);
        } else if c == '\t' || c == '\r' {
            out.push(' ');
        } else {
            let _ = write!(out, "\\u{:04x}", c as u32);
        }
    }
    Cow::Owned(out)
}

/// One human-readable line for a record, safe to print to a terminal: see
/// [`escape_control`].
pub fn render(v: &Value) -> String {
    escape_control(&render_raw(v)).into_owned()
}

fn render_raw(v: &Value) -> String {
    let time = v
        .get("time")
        .and_then(Value::as_i64)
        .map(format_time)
        .unwrap_or_default();
    let rk = rk_fields(v);
    if v.get("class_uid").and_then(Value::as_u64) == Some(6008) {
        let msg = v.get("message").and_then(Value::as_str).unwrap_or("error");
        return format!("{time} LOSS   {msg}");
    }
    let verdict = match rk.and_then(|rk| rk.get("verdict")).and_then(Value::as_str) {
        Some("deny") => "DENY ",
        Some("audit_would_deny") => "AUDIT",
        Some("allow") => "ALLOW",
        _ => "?    ",
    };
    let activity = str_at(v, "/activity_name").unwrap_or("?");
    let what = if let Some(ip) = str_at(v, "/dst_endpoint/ip") {
        let port = v
            .pointer("/dst_endpoint/port")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let proto = str_at(v, "/connection_info/protocol_name").unwrap_or("?");
        let host = if ip.contains(':') {
            format!("[{ip}]")
        } else {
            ip.to_string()
        };
        format!("{activity} {host}:{port}/{proto}")
    } else if let Some(path) = str_at(v, "/file/path").or_else(|| str_at(v, "/file/name")) {
        format!("{activity} {path}")
    } else if let Some(path) =
        str_at(v, "/process/file/path").or_else(|| str_at(v, "/process/file/name"))
    {
        format!("{activity} {path}")
    } else {
        activity.to_string()
    };
    let rule = str_at(v, "/policy/uid").unwrap_or("?");
    let profile = str_at(v, "/policy/name").unwrap_or("-");
    let generation = str_at(v, "/policy/version").unwrap_or("?");
    let pid = v
        .pointer("/actor/process/pid")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let exe = str_at(v, "/actor/process/file/path").unwrap_or("?");
    let mut line = format!(
        "{time} {verdict}  {what}  rule {rule} ({profile}) gen {generation}  pid {pid} {exe}"
    );
    if let Some(s) = str_at(v, "/actor/session/uid") {
        line.push_str("  session ");
        line.push_str(s);
    }
    line
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ocsf::{decision, loss, Activity, Decision, Process, Verdict};

    fn record(verdict: Verdict) -> Value {
        decision(&Decision {
            time_ms: 0,
            activity: Activity::Connect {
                addr: "10.0.0.5".parse().unwrap(),
                port: 443,
                protocol: 6,
                sendmsg: false,
            },
            verdict,
            rule_id: 7,
            policy_gen: 3,
            profile: Some("agent"),
            rule_origin: None,
            cgroup_id: 1,
            session: Some("s1"),
            process: Process {
                pid: 100,
                tid: 100,
                uid: 0,
                gid: 0,
                exe: Some("/usr/bin/curl"),
                ppid: None,
                enrichment: "exec_record",
            },
            hostname: "h",
            version: "0",
        })
    }

    #[test]
    fn renders_a_denied_connect() {
        assert_eq!(
            render(&record(Verdict::Deny)),
            "1970-01-01T00:00:00.000Z DENY   Open 10.0.0.5:443/tcp  rule 7 (agent) gen 3  pid 100 /usr/bin/curl  session s1"
        );
        assert!(render(&loss(0, "h", "0", 2, 1)).contains("LOSS   3 decision events lost"));
    }

    #[test]
    fn tail_escapes_terminal_control_sequences() {
        // A governed process names its executable so that printing it
        // erases the line and redraws it as an ALLOW.
        let mut v = record(Verdict::Deny);
        v["actor"]["process"]["file"]["path"] =
            Value::from("/tmp/x\u{1b}[2K\r\u{9b}1A ALLOW \u{7f}\u{202e}fdp.exe");
        let line = render(&v);
        assert!(!line.chars().any(is_unsafe_char), "{line:?}");
        assert!(line.contains("DENY"));
        assert!(
            line.contains("/tmp/x\\x1b[2K\\x0d\\u{9b}1A ALLOW \\x7f\\u{202e}fdp.exe"),
            "{line}"
        );
        assert_eq!(escape_control("plain /usr/bin/curl"), "plain /usr/bin/curl");
        assert!(matches!(escape_control("ok"), Cow::Borrowed(_)));
    }

    #[test]
    fn filters_by_verdict_and_session() {
        let deny = record(Verdict::Deny);
        assert!(matches(&deny, Some("deny"), Some("s1")));
        assert!(!matches(&deny, Some("audit"), None));
        assert!(!matches(&deny, None, Some("s2")));
        assert!(matches(
            &record(Verdict::AuditWouldDeny),
            Some("audit"),
            None
        ));
    }

    #[test]
    fn formats_civil_time() {
        assert_eq!(format_time(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(format_time(951_782_400_123), "2000-02-29T00:00:00.123Z");
        assert_eq!(format_time(1_792_627_200_000), "2026-10-22T00:00:00.000Z");
    }

    /// `--json` output: no character a terminal acts on, and the same JSON
    /// value as stored.
    #[test]
    fn tail_json_escapes_terminal_control_sequences() {
        let stored = "{\"path\":\"/tmp/x\u{202e}gpj.exe\",\"arg\":\"a\u{7f}b\u{9b}c\",\t\"n\":1}";
        let out = escape_json_line(stored);
        assert!(!out.chars().any(is_unsafe_char), "{out}");
        assert!(out.contains("\\u202e") && out.contains("\\u007f") && out.contains("\\u009b"));
        let a: Value = serde_json::from_str(stored).unwrap();
        let b: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(a, b);
        let plain = "{\"n\":1}";
        assert!(matches!(escape_json_line(plain), Cow::Borrowed(s) if s == plain));
    }
}
