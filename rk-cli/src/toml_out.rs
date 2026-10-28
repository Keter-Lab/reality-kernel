//! A small TOML writer for the policies `rk init` and `rk policy suggest`
//! generate (docs/design/adoption.md). Unlike a serializer it controls the
//! layout and can put a comment above an array element or an array-of-tables
//! entry, so a suggested rule can say why it is there.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use toml::{Table, Value};

/// Comments keyed by `dotted.path#index`: shown above element `index` of the
/// array (or array of tables) at that path.
#[derive(Debug, Default)]
pub struct Comments(BTreeMap<String, String>);

impl Comments {
    pub fn add(&mut self, path: &str, index: usize, text: impl Into<String>) {
        self.0.insert(format!("{path}#{index}"), text.into());
    }

    fn get(&self, path: &str, index: usize) -> Option<&str> {
        self.0.get(&format!("{path}#{index}")).map(String::as_str)
    }

    fn any_for(&self, path: &str) -> bool {
        let prefix = format!("{path}#");
        self.0.keys().any(|k| k.starts_with(&prefix))
    }
}

/// A key, bare when it can be, quoted otherwise (a profile name may hold `.`).
pub fn key(k: &str) -> String {
    if !k.is_empty()
        && k.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        k.to_string()
    } else {
        string(k)
    }
}

/// A TOML basic string.
pub fn string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            // Controls (C0, DEL, C1) and bidi overrides: a path from the
            // audit log must not act on the terminal the policy is shown on.
            c if rk_audit::tail::is_unsafe_char(c) => {
                let _ = write!(out, "\\u{:04X}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// One comment line: `# text`, with line breaks flattened and other control
/// characters escaped (TOML refuses them in comments, and a terminal would
/// act on them).
pub fn comment(text: &str) -> String {
    format!(
        "# {}",
        rk_audit::tail::escape_control(&text.replace(['\n', '\r'], " "))
    )
}

fn inline(v: &Value) -> String {
    match v {
        Value::String(s) => string(s),
        Value::Integer(i) => i.to_string(),
        Value::Float(f) => f.to_string(),
        Value::Boolean(b) => b.to_string(),
        Value::Datetime(d) => d.to_string(),
        Value::Array(a) => format!("[{}]", a.iter().map(inline).collect::<Vec<_>>().join(", ")),
        Value::Table(t) => format!(
            "{{ {} }}",
            t.iter()
                .map(|(k, v)| format!("{} = {}", key(k), inline(v)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

fn is_table_array(v: &Value) -> bool {
    matches!(v, Value::Array(a) if !a.is_empty() && a.iter().all(Value::is_table))
}

fn join(path: &str, k: &str) -> String {
    if path.is_empty() {
        key(k)
    } else {
        format!("{path}.{}", key(k))
    }
}

/// Key/value lines of `t` (no sub-tables), arrays with comments one element
/// per line.
fn scalars(out: &mut String, path: &str, t: &Table, comments: &Comments) {
    for (k, v) in t {
        if v.is_table() || is_table_array(v) {
            continue;
        }
        let here = join(path, k);
        match v {
            Value::Array(items) if comments.any_for(&here) => {
                let _ = writeln!(out, "{} = [", key(k));
                for (i, item) in items.iter().enumerate() {
                    if let Some(c) = comments.get(&here, i) {
                        let _ = writeln!(out, "    {}", comment(c));
                    }
                    let _ = writeln!(out, "    {},", inline(item));
                }
                out.push_str("]\n");
            }
            _ => {
                let _ = writeln!(out, "{} = {}", key(k), inline(v));
            }
        }
    }
}

fn has_scalars(t: &Table) -> bool {
    t.values().any(|v| !v.is_table() && !is_table_array(v))
}

/// Sub-tables and arrays of tables of `t`, each under its own header.
fn sections(out: &mut String, path: &str, t: &Table, comments: &Comments) {
    for (k, v) in t {
        let here = join(path, k);
        match v {
            Value::Table(sub) => {
                // A table holding only tables needs no header of its own.
                if has_scalars(sub) || sub.is_empty() {
                    let _ = writeln!(out, "\n[{here}]");
                    scalars(out, &here, sub, comments);
                }
                sections(out, &here, sub, comments);
            }
            v if is_table_array(v) => {
                let Value::Array(items) = v else { continue };
                for (i, item) in items.iter().enumerate() {
                    let Value::Table(entry) = item else { continue };
                    out.push('\n');
                    if let Some(c) = comments.get(&here, i) {
                        let _ = writeln!(out, "{}", comment(c));
                    }
                    let _ = writeln!(out, "[[{here}]]");
                    scalars(out, &here, entry, comments);
                    sections(out, &here, entry, comments);
                }
            }
            _ => {}
        }
    }
}

/// `t` as a TOML document.
pub fn document(t: &Table, comments: &Comments) -> String {
    let mut out = String::new();
    scalars(&mut out, "", t, comments);
    sections(&mut out, "", t, comments);
    out.trim_start_matches('\n').to_string()
}

/// The tables of one profile, `[profiles.NAME]` and below.
pub fn profile(name: &str, t: &Table, comments: &Comments) -> String {
    let mut wrapper = Table::new();
    let mut profiles = Table::new();
    profiles.insert(name.to_string(), Value::Table(t.clone()));
    wrapper.insert("profiles".into(), Value::Table(profiles));
    document(&wrapper, comments)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_valid_toml_that_reads_back_the_same() {
        let text = r#"
            top = 1
            [profiles."a.b"]
            mode = "audit"
            launchable_by = ["user:x"]
            [profiles."a.b".network]
            default = "deny"
            [[profiles."a.b".network.allow]]
            cidr = "127.0.0.0/8"
            ports = ["80", "443"]
            [[profiles."a.b".files.deny]]
            path = "/home/x/q\"uote\\back"
            access = ["all"]
            [[bindings]]
            cgroup = "rk.slice/x"
            profile = "a.b"
        "#;
        let t: Table = toml::from_str(text).unwrap();
        let mut c = Comments::default();
        c.add("profiles.\"a.b\".network.allow", 0, "loopback\nservices");
        let out = document(&t, &c);
        let back: Table = toml::from_str(&out).unwrap();
        assert_eq!(back, t, "{out}");
        assert!(
            out.contains("# loopback services\n[[profiles.\"a.b\".network.allow]]"),
            "{out}"
        );
    }

    #[test]
    fn commented_arrays_go_one_element_per_line() {
        let t: Table = toml::from_str("allow = [\"/bin/sh\", \"/usr/bin/git\"]").unwrap();
        let mut c = Comments::default();
        c.add("allow", 0, "interpreter: allows any script it runs");
        let out = document(&t, &c);
        assert_eq!(
            out,
            "allow = [\n    # interpreter: allows any script it runs\n    \"/bin/sh\",\n    \"/usr/bin/git\",\n]\n"
        );
        assert_eq!(toml::from_str::<Table>(&out).unwrap(), t);
    }

    #[test]
    fn strings_and_keys_are_escaped() {
        assert_eq!(string("a\"b\\c\u{1}"), "\"a\\\"b\\\\c\\u0001\"");
        assert_eq!(string("x\u{1b}\u{9b}\u{202e}"), "\"x\\u001B\\u009B\\u202E\"");
        assert_eq!(comment("a\nb\u{1b}[2J"), "# a b\\x1b[2J");
        assert_eq!(
            toml::from_str::<Table>(&format!("{}\nk = 1\n", comment("\u{7f}\u{9b}")))
                .unwrap()
                .len(),
            1
        );
        assert_eq!(key("agent-1_x"), "agent-1_x");
        assert_eq!(key("a.b"), "\"a.b\"");
    }
}
