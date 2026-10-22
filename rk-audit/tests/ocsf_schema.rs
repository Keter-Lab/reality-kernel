//! Phase 9 §5: every record the sensor writes is valid OCSF 1.9.0, checked
//! against a vendored subset of the schema (tests/data, generated from
//! schema.ocsf.io): class and category ids, required attributes, known
//! attribute names, enum values, and the same for every nested object.

use rk_audit::ocsf::{decision, loss, Activity, Decision, Process, Verdict};
use serde_json::Value;

fn schema() -> Value {
    serde_json::from_str(include_str!("data/ocsf-1.9.0-subset.json")).unwrap()
}

/// Object type of each nested attribute we emit, by JSON pointer.
const OBJECTS: &[(&str, &str)] = &[
    ("/metadata", "metadata"),
    ("/metadata/product", "product"),
    ("/device", "device"),
    ("/actor", "actor"),
    ("/actor/process", "process"),
    ("/actor/process/file", "file"),
    ("/actor/process/parent_process", "process"),
    ("/actor/process/user", "user"),
    ("/actor/process/session", "session"),
    ("/actor/user", "user"),
    ("/actor/session", "session"),
    ("/process", "process"),
    ("/process/file", "file"),
    ("/file", "file"),
    ("/policy", "policy"),
    ("/dst_endpoint", "network_endpoint"),
];

fn names(v: &Value) -> Vec<&str> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap())
        .collect()
}

fn check_enums(errors: &mut Vec<String>, at: &str, value: &Value, enums: &Value) {
    for (field, allowed) in enums.as_object().unwrap() {
        if let Some(got) = value.get(field) {
            let ok = got.as_u64().is_some_and(|g| {
                allowed
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|a| a.as_u64() == Some(g))
            });
            if !ok {
                errors.push(format!("{at}{field} = {got} is not a defined value"));
            }
        }
    }
}

fn validate(record: &Value, schema: &Value) -> Vec<String> {
    let mut errors = Vec::new();
    let class_uid = record["class_uid"].as_u64().unwrap();
    let Some(class) = schema["classes"].get(class_uid.to_string()) else {
        return vec![format!("class {class_uid} not in the schema subset")];
    };
    if record["category_uid"] != class["category_uid"] {
        errors.push(format!(
            "category_uid {} for class {class_uid}",
            record["category_uid"]
        ));
    }
    let activity = record["activity_id"].as_u64().unwrap();
    if record["type_uid"].as_u64() != Some(class_uid * 100 + activity) {
        errors.push(format!(
            "type_uid {} is not class_uid * 100 + activity_id",
            record["type_uid"]
        ));
    }
    for req in names(&class["required"]) {
        if record.get(req).is_none() {
            errors.push(format!("missing required attribute {req}"));
        }
    }
    let known = names(&class["attributes"]);
    for key in record.as_object().unwrap().keys() {
        if !known.contains(&key.as_str()) {
            errors.push(format!("unknown attribute {key}"));
        }
    }
    check_enums(&mut errors, "", record, &class["enums"]);

    for (pointer, object) in OBJECTS {
        let Some(value) = record.pointer(pointer) else {
            continue;
        };
        let def = &schema["objects"][object];
        let Some(obj) = value.as_object() else {
            errors.push(format!("{pointer} is not an object"));
            continue;
        };
        for req in names(&def["required"]) {
            if !obj.contains_key(req) {
                errors.push(format!("{pointer}: missing required {req}"));
            }
        }
        let one_of = names(&def["at_least_one"]);
        if !one_of.is_empty() && !one_of.iter().any(|k| obj.contains_key(*k)) {
            errors.push(format!("{pointer}: needs at least one of {one_of:?}"));
        }
        let known = names(&def["attributes"]);
        for key in obj.keys() {
            if !known.contains(&key.as_str()) {
                errors.push(format!("{pointer}: unknown attribute {key}"));
            }
        }
        check_enums(&mut errors, &format!("{pointer}/"), value, &def["enums"]);
    }
    errors
}

fn every_kind_of_record() -> Vec<Value> {
    let activities = [
        Activity::Connect {
            addr: "10.0.0.5".parse().unwrap(),
            port: 443,
            protocol: 6,
            sendmsg: false,
        },
        Activity::Connect {
            addr: "2001:db8::1".parse().unwrap(),
            port: 53,
            protocol: 17,
            sendmsg: true,
        },
        Activity::SocketCreate {
            family: 17,
            sock_type: 3,
            protocol: 0,
        },
        Activity::Exec {
            path: Some("/usr/bin/curl"),
            argv: Some("curl example.com"),
            dev: 1,
            ino: 2,
            committed: false,
        },
        Activity::Exec {
            path: None,
            argv: None,
            dev: 1,
            ino: 2,
            committed: true,
        },
        Activity::File {
            path: Some("/etc/shadow"),
            hook: 1,
            access: 1,
            dev: 1,
            ino: 3,
        },
        Activity::File {
            path: Some("secret"),
            hook: 2,
            access: 16,
            dev: 1,
            ino: 3,
        },
        Activity::File {
            path: None,
            hook: 3,
            access: 32,
            dev: 1,
            ino: 3,
        },
        Activity::File {
            path: Some("/a/b"),
            hook: 4,
            access: 128,
            dev: 1,
            ino: 3,
        },
        Activity::File {
            path: Some("/a/c"),
            hook: 5,
            access: 8,
            dev: 1,
            ino: 3,
        },
        Activity::File {
            path: Some("/a/d"),
            hook: 6,
            access: 256,
            dev: 1,
            ino: 3,
        },
        Activity::Tamper {
            hook: 1,
            target_tgid: 77,
            detail: 0,
        },
    ];
    let mut out = Vec::new();
    for activity in activities {
        for verdict in [Verdict::Allow, Verdict::Deny, Verdict::AuditWouldDeny] {
            for (session, exe, ppid) in [
                (Some("s1"), Some("/usr/bin/python3"), Some(1)),
                (None, None, None),
            ] {
                out.push(decision(&Decision {
                    time_ms: 1_760_000_000_000,
                    activity: activity.clone(),
                    verdict,
                    rule_id: 7,
                    policy_gen: 3,
                    profile: Some("agent"),
                    rule_origin: Some("network.deny[0] 10.0.0.0/8"),
                    cgroup_id: 4242,
                    session,
                    process: Process {
                        pid: 100,
                        tid: 101,
                        uid: 1000,
                        gid: 1000,
                        exe,
                        ppid,
                        enrichment: if exe.is_some() {
                            "exec_record"
                        } else {
                            "unavailable"
                        },
                    },
                    hostname: "node-a",
                    version: "0.1.0",
                }));
            }
        }
    }
    out.push(loss(1_760_000_000_000, "node-a", "0.1.0", 5, 2));
    out
}

#[test]
fn ocsf_records_validate() {
    let schema = schema();
    assert_eq!(schema["version"], "1.9.0");
    let mut failures = Vec::new();
    for record in every_kind_of_record() {
        for e in validate(&record, &schema) {
            failures.push(format!(
                "class {} activity {}: {e}",
                record["class_uid"], record["activity_id"]
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn validator_rejects_broken_records() {
    let schema = schema();
    let mut r = every_kind_of_record().remove(0);
    r.as_object_mut().unwrap().remove("severity_id");
    r["disposition_id"] = 1234.into();
    r["made_up"] = 1.into();
    r["device"].as_object_mut().unwrap().remove("type_id");
    let errors = validate(&r, &schema).join("\n");
    for expected in [
        "missing required attribute severity_id",
        "disposition_id = 1234",
        "unknown attribute made_up",
        "/device: missing required type_id",
    ] {
        assert!(errors.contains(expected), "{expected} not in:\n{errors}");
    }
}
