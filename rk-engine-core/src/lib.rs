mod basin_mapper;
mod effect_engine;
mod governor;
mod static_analyser;
mod superposition;
mod unicode;

use lru::LruCache;
use regex::Regex;
use std::num::NonZeroUsize;
use std::sync::{Mutex, OnceLock};

pub use governor::AnalysisResult;

pub const MAX_COMMAND_LEN: usize = 4096;
pub const MAX_INTENT_LEN: usize = 1024;

static FAST_CACHE: OnceLock<Mutex<LruCache<String, bool>>> = OnceLock::new();

fn fast_path_patterns() -> Vec<&'static str> {
    vec![
        r"^(ls|ll|la|dir)\b", r"^cat\b", r"^(head|tail)\b", r"^(less|more|view)\b",
        r"^(wc|wc\s+-[lwc]+)\b", r"^(file|stat|lstat)\b", r"^(find)\b", r"^(tree)\b", r"^(pwd)\b", r"^(du\s|df\s|df\b)",
        r"^(grep|egrep|fgrep|rg|ag|ack)\b", r"^(sed\s+-n|sed\s+.*\bp\b)", r"^(awk)\b(?!.*system\()", r"^(cut|sort|uniq|tr|paste|join)\b",
        r"^(diff|cmp|comm)\b", r"^(strings|xxd|od|hexdump)\b", r"^(jq)\b", r"^(yq)\b", r"^(csvkit|csvstat|csvlook)\b",
        r"^(echo)\b", r"^(printf)\b", r"^(date)\b", r"^(whoami|id|groups|logname)\b", r"^(hostname|uname)\b", r"^(uptime|w)\b", r"^(ps\s|ps\b)",
        r"^(top\s+-b|top\s+-n)", r"^(env|printenv|set\b)", r"^(which|whereis|type)\b", r"^(man|help|info)\b", r"^(history)\b", r"^(lsof\b)",
        r"^(lscpu|lshw|lspci|lsusb|lsblk)\b", r"^(free\b)", r"^(vmstat|iostat|sar)\b", r"^(ulimit\s+-[asSn])", r"^(nproc)\b",
        r"^(curl|wget)\s+https?://[a-zA-Z0-9.-]+/?\s*$", r"^curl\s+.*--version\s*$", r"^curl\s+http://localhost:\d+/health",
        r"^(pip\s+(list|show|freeze))", r"^(npm\s+(list|ls|info|view))", r"^(yarn\s+(list|info))", r"^(apt\s+(list|show|search))", r"^(dpkg\s+-[lL])", r"^(rpm\s+-q)", r"^(brew\s+(list|info|search))", r"^(gem\s+(list|info))",
        r"--version\s*$", r"--help\s*$", r"-h\s*$", r"^(python3?|node|ruby|go|java|php)\s+--version",
        r"^git\s+(status|log|diff|show|branch|tag|remote\s+-v)", r"^git\s+(describe|rev-parse|shortlog|blame|stash\s+list)",
        r"^git\s+(ls-files|ls-tree|cat-file)", r"^git\s+(config\s+--list|config\s+--get)",
        r"^docker\s+(ps|images|inspect|logs|stats\s+--no-stream|info|version)", r"^docker\s+(network|volume)\s+(ls|inspect)",
        r"^(kubectl|k)\s+(get|describe|logs|top)\b", r"^(SELECT\s)", r"^(SHOW\s+(TABLES|DATABASES|COLUMNS|INDEX|STATUS))", r"^(DESCRIBE\s|EXPLAIN\s+SELECT)",
        r"^\\(d|dt|di|l|c)\b", r"^aws\s+\S+\s+(list|describe|get|show)\b", r"^gcloud\s+\S+\s+(list|describe)\b", r"^az\s+\S+\s+(list|show)\b",
    ]
}

fn forced_slow_patterns() -> Vec<&'static str> {
    vec![
        r"\|", r"&&", r";", r";;", r"`", r"\$\(", r"rm\s", r"dd\s", r"mkfs", r"DROP\s", r"DELETE\s+FROM",
        r"chmod", r"chown", r"crontab", r"authorized_keys", r"scp\s", r"rsync\s", r"nc\s", r"ncat\s", r"socat\s", r"openssl\s+s_client",
        r"bash\s+-i", r"python.*-c\s", r"eval\(", r"exec\(", r"\.env", r"\.pem", r"\.key", r"id_rsa", r"/etc/passwd", r"/etc/shadow",
        r"secret", r"credential", r"/proc/.*/environ", r"/proc/.*/mem", r"/etc/sudoers", r"169\.254", r"2852039166", r"0xa9fe", r"\[::ffff:169\.254",
        r"metadata\.google\.internal", r"instance-data", r"localhost", r"127\.0\.0\.1", r"0\.0\.0\.0",
    ]
}

fn truncate(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

pub fn is_fast_path(command: &str) -> bool {
    if command.is_empty() {
        return false;
    }
    let cmd = truncate(command.trim(), MAX_COMMAND_LEN);
    let cache = FAST_CACHE.get_or_init(|| {
        Mutex::new(LruCache::new(NonZeroUsize::new(4096).expect("non zero")))
    });
    if let Ok(mut locked) = cache.lock() {
        if let Some(v) = locked.get(&cmd) {
            return *v;
        }
        let forced = forced_slow_patterns().iter().any(|p| Regex::new(&format!("(?i){p}")).unwrap().is_match(&cmd));
        let mut fast = !forced && fast_path_patterns().iter().any(|p| Regex::new(&format!("(?i){p}")).unwrap().is_match(&cmd));
        if fast && Regex::new(r"(?i)^find\b").unwrap().is_match(&cmd) && cmd.to_lowercase().contains("-exec ") {
            fast = false;
        }
        locked.put(cmd, fast);
        fast
    } else {
        false
    }
}

pub fn analyse(command: &str, prime_intent: &str, n_worlds: usize) -> AnalysisResult {
    let command = truncate(command, MAX_COMMAND_LEN);
    let prime_intent = truncate(prime_intent, MAX_INTENT_LEN);

    let (normalized, unicode_evidence) = unicode::normalize_command(&command);
    if normalized.trim().is_empty() {
        return AnalysisResult {
            verdict: "ALLOW".into(),
            confidence: 0.98,
            evidence: vec![],
            worlds_evaluated: 0,
            worlds_in_basin_b: 0,
            max_divergence: 0.0,
            action_id: "fast-empty".into(),
            proof_hash: "".into(),
        };
    }

    let effect_graph = effect_engine::compute_effect_graph(&normalized, &prime_intent);
    let (mut threat_class, static_floor, static_evidence) =
        static_analyser::evaluate_command_class(&normalized, Some(&unicode_evidence));
    let effect_threat = effect_engine::effect_to_threat_class(effect_graph.worst_effect).to_string();

    let order = ["BENIGN", "MODERATE", "ELEVATED", "CRITICAL"];
    let idx = |v: &str| order.iter().position(|x| *x == v).unwrap_or(0);
    if idx(&effect_threat) > idx(&threat_class) {
        threat_class = effect_threat;
    }

    let mut all_pre_evidence = Vec::new();
    all_pre_evidence.extend(unicode_evidence.clone());
    all_pre_evidence.extend(effect_graph.evidence.clone());
    all_pre_evidence.extend(static_evidence.clone());

    if threat_class == "CRITICAL" {
        let mut basin_summary = serde_json::json!({
            "decision": "BLOCK",
            "max_divergence": 1.0,
            "evidence": all_pre_evidence,
            "worlds_in_B": 1,
        });
        return governor::evaluate(
            &normalized,
            &prime_intent,
            &basin_summary,
            0,
            1.0,
            all_pre_evidence.len(),
        );
    }

    if is_fast_path(&normalized) {
        return AnalysisResult {
            verdict: "ALLOW".into(),
            confidence: 0.98,
            evidence: vec![],
            worlds_evaluated: 0,
            worlds_in_basin_b: 0,
            max_divergence: 0.0,
            action_id: "fast-path".into(),
            proof_hash: "".into(),
        };
    }

    let mut worlds = superposition::spawn_worlds(&normalized, &prime_intent, n_worlds.min(5));
    superposition::run_selection(&mut worlds);
    superposition::mutate_worlds(&mut worlds);

    let alive: Vec<_> = worlds.into_iter().filter(|w| w.alive).collect();
    let delta = effect_engine::effect_to_sandbox_delta(&effect_graph);
    let basin_results: Vec<_> = alive.iter().map(|w| basin_mapper::check_basin(w, &delta)).collect();
    let mut basin_summary = basin_mapper::aggregate_basin_results(&basin_results);

    if let Some(e) = basin_summary.get_mut("evidence").and_then(|v| v.as_array_mut()) {
        for ev in all_pre_evidence.clone() {
            e.push(serde_json::Value::String(ev));
        }
    }

    if effect_graph.effect_divergence > 0.0 {
        let current = basin_summary.get("max_divergence").and_then(|v| v.as_f64()).unwrap_or(0.0);
        basin_summary["max_divergence"] = serde_json::Value::from(current.max(effect_graph.effect_divergence));
    }

    let combined_floor = effect_graph.divergence_floor.max(static_floor);
    governor::evaluate(
        &normalized,
        &prime_intent,
        &basin_summary,
        alive.len(),
        combined_floor,
        all_pre_evidence.len(),
    )
}
