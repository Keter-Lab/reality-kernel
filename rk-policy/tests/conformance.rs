//! Policy conformance corpus, userspace side (docs/design/phase-8.md §3.2).
//!
//! Every case in `tests/conformance/*.toml` is checked against the reference
//! evaluator for its `connect` operations. The kernel side is
//! `rk-integration --conformance`, which reads the same files; exec and open
//! operations are kernel-only (network is the domain with a pure-userspace
//! evaluator).

use std::collections::BTreeSet;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;

use rk_policy::net::{self, Action, Mode, ProfileIds, PROTO_TCP, PROTO_UDP};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    name: String,
    description: String,
    #[serde(default)]
    setup: Vec<String>,
    policy: String,
    op: Vec<Op>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Op {
    kind: String,
    target: String,
    #[serde(default)]
    proto: Option<String>,
    #[serde(default)]
    access: Option<String>,
    expect: String,
}

fn corpus() -> Vec<(PathBuf, Case)> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../tests/conformance");
    let mut cases: Vec<(PathBuf, Case)> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "toml"))
        .map(|p| {
            let text = fs::read_to_string(&p).unwrap();
            let case: Case =
                toml::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", p.display()));
            (p, case)
        })
        .collect();
    cases.sort_by(|a, b| a.0.cmp(&b.0));
    cases
}

/// Every case is well formed: unique names, known kinds and verdicts, and the
/// fields each kind needs.
#[test]
fn conformance_corpus_is_well_formed() {
    let cases = corpus();
    assert!(cases.len() >= 10, "corpus unexpectedly small: {}", cases.len());
    let mut names = BTreeSet::new();
    for (path, case) in &cases {
        let file = path.file_stem().unwrap().to_string_lossy();
        assert_eq!(case.name, file, "{}: name must match the file name", path.display());
        assert!(names.insert(case.name.clone()), "duplicate case {}", case.name);
        assert!(!case.description.is_empty(), "{}: needs a description", case.name);
        assert!(!case.op.is_empty(), "{}: needs at least one op", case.name);
        for fixture in &case.setup {
            let (kind, target) = fixture.split_once(':').expect("setup is kind:path");
            assert!(matches!(kind, "exec" | "file"), "{}: setup kind {kind}", case.name);
            assert!(target.starts_with("/run/rk-conf/"), "{}: fixtures live in /run/rk-conf", case.name);
        }
        for op in &case.op {
            assert!(
                matches!(op.expect.as_str(), "allow" | "deny" | "audit"),
                "{}: expect {}",
                case.name,
                op.expect
            );
            match op.kind.as_str() {
                "connect" => {
                    op.target
                        .parse::<SocketAddr>()
                        .unwrap_or_else(|e| panic!("{}: target {}: {e}", case.name, op.target));
                    let proto = op.proto.as_deref().unwrap_or("udp");
                    assert!(matches!(proto, "udp" | "tcp"), "{}: proto {proto}", case.name);
                    // An allowed TCP connect needs a listener; the runner has none.
                    assert!(
                        !(proto == "tcp" && op.expect != "deny"),
                        "{}: tcp ops may only expect deny",
                        case.name
                    );
                }
                "exec" => assert!(op.target.starts_with('/'), "{}: exec path", case.name),
                "open" => assert!(
                    matches!(op.access.as_deref(), Some("r" | "w" | "rw" | "o_trunc")),
                    "{}: open needs access r|w|rw|o_trunc",
                    case.name
                ),
                other => panic!("{}: unknown op kind {other}", case.name),
            }
        }
    }
}

/// The reference evaluator agrees with every `connect` expectation.
#[test]
fn conformance_userspace() {
    let mut checked = 0;
    for (_, case) in corpus() {
        let policy = net::parse(&case.policy, &mut ProfileIds::default())
            .unwrap_or_else(|e| panic!("{}: policy: {e}", case.name));
        let profile = policy
            .profiles
            .iter()
            .find(|p| p.name == "case")
            .unwrap_or_else(|| panic!("{}: no profile named `case`", case.name));
        for op in case.op.iter().filter(|o| o.kind == "connect") {
            let addr: SocketAddr = op.target.parse().unwrap();
            let proto = match op.proto.as_deref().unwrap_or("udp") {
                "tcp" => PROTO_TCP,
                _ => PROTO_UDP,
            };
            let decision = net::evaluate(&policy, profile.id, addr.ip(), addr.port(), proto)
                .unwrap_or_else(|| panic!("{}: profile vanished", case.name));
            let got = match (decision.action, profile.mode) {
                (Action::Allow, _) => "allow",
                (Action::Deny, Mode::Audit) => "audit",
                (Action::Deny, _) => "deny",
            };
            assert_eq!(
                got, op.expect,
                "{}: connect {} ({}) — {}",
                case.name, op.target, decision.rule_id, case.description
            );
            checked += 1;
        }
    }
    assert!(checked >= 15, "only {checked} connect operations checked");
}
