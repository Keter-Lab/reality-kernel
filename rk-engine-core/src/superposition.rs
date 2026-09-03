use crate::effect_engine::compute_effect_graph;
use regex::Regex;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static SPAWN_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Serialize)]
pub struct Hypothesis {
    pub id: &'static str,
    pub label: &'static str,
    pub description: &'static str,
    pub risk_prior: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct World {
    pub world_id: String,
    pub hypothesis: Hypothesis,
    pub command: String,
    pub prime_intent: String,
    pub fitness: f64,
    pub alive: bool,
    pub sim_delta: serde_json::Value,
    pub risk_score: f64,
    pub verdict: String,
}

pub const ELIMINATION_THRESHOLD: f64 = 0.15;
pub const CRITICAL_RISK_THRESHOLD: f64 = 0.80;

pub fn hypotheses() -> Vec<Hypothesis> {
    vec![
        Hypothesis { id: "H_BENIGN", label: "Legitimate task execution", description: "Action serves the user's stated prime intent directly.", risk_prior: 0.05 },
        Hypothesis { id: "H_SCOPE_CREEP", label: "Unintended scope expansion", description: "Action is tangentially related but exceeds the stated scope.", risk_prior: 0.35 },
        Hypothesis { id: "H_INJECTION", label: "Prompt injection hijack", description: "Action was injected by adversarial content in the environment.", risk_prior: 0.75 },
        Hypothesis { id: "H_EXFIL", label: "Data exfiltration attempt", description: "Action attempts to read/send sensitive data outside authorised scope.", risk_prior: 0.85 },
        Hypothesis { id: "H_DESTROY", label: "Destructive / irreversible action", description: "Action will permanently alter or destroy resources.", risk_prior: 0.95 },
    ]
}

pub fn spawn_worlds(command: &str, prime_intent: &str, n: usize) -> Vec<World> {
    let hs = hypotheses();
    hs.into_iter().take(n).map(|h| {
        let ctr = SPAWN_COUNTER.fetch_add(1, Ordering::Relaxed) + 1;
        let ts = now_secs();
        let seed = format!("{}:{}:{}:{}", h.id, command, ts, ctr);
        let mut hasher = Sha256::new();
        hasher.update(seed.as_bytes());
        let wid = hex::encode(hasher.finalize())[..12].to_string();
        let risk = initial_risk(command, &h);
        World {
            world_id: wid,
            hypothesis: h,
            command: command.to_string(),
            prime_intent: prime_intent.to_string(),
            fitness: 1.0,
            alive: true,
            sim_delta: serde_json::json!({}),
            risk_score: risk,
            verdict: "PENDING".to_string(),
        }
    }).collect()
}

pub fn initial_risk(command: &str, hypothesis: &Hypothesis) -> f64 {
    let base = hypothesis.risk_prior;
    let graph = compute_effect_graph(command, "");
    let cmd_signal = graph.divergence_floor;
    if cmd_signal == 0.0 { return round3(base); }
    let headroom = 1.0 - base;
    round3((base + headroom * cmd_signal).min(1.0))
}

fn tokenise(text: &str) -> HashSet<String> {
    let stops = hs(&["the","a","an","to","in","on","of","and","or","for","with","my","it","is","this","that","all","me","please","can","you","i","we"]);
    Regex::new(r"\b\w+\b").unwrap().find_iter(&text.to_lowercase()).map(|m| m.as_str().to_string()).filter(|t| !stops.contains(t)).collect()
}

fn classify_ops(tokens: &HashSet<String>) -> HashSet<String> {
    let mut map: HashMap<&str, HashSet<String>> = HashMap::new();
    map.insert("READ", hs(&["read","show","list","display","cat","view","get","fetch","check","inspect","ls","find","search","grep","summarise","summarize","describe","print","log","logs","status","tail","head"]));
    map.insert("WRITE", hs(&["write","create","update","edit","modify","save","append","insert","add","set","configure","change"]));
    map.insert("DELETE", hs(&["delete","remove","clean","tidy","purge","wipe","drop","truncate","rm","erase","clear"]));
    map.insert("EXECUTE", hs(&["run","execute","start","launch","deploy","migrate","install","build","compile","test","script","bash","python","sh"]));
    map.insert("NETWORK", hs(&["send","upload","post","transfer","sync","curl","wget","nc","connect","tunnel","forward","export","push"]));
    map.into_iter().filter_map(|(k, v)| if !tokens.is_disjoint(&v) { Some(k.to_string()) } else { None }).collect()
}

fn classify_scope(tokens: &HashSet<String>) -> HashSet<String> {
    let mut map: HashMap<&str, HashSet<String>> = HashMap::new();
    map.insert("LOGS", hs(&["log","logs","error","app","access","audit"]));
    map.insert("DB", hs(&["database","db","table","record","migration","sql","postgres","mysql","sqlite"]));
    map.insert("CONFIG", hs(&["config","configuration","settings","env","environment","server","json","yaml","ini"]));
    map.insert("CODE", hs(&["code","script","file","directory","folder","src","source","git","repo","build"]));
    map.insert("CRED", hs(&["credential","credentials","secret","key","token","password","auth","pem","rsa","ssh","api_key"]));
    map.insert("NET", hs(&["network","server","connectivity","connection","host","ping","port","socket","tunnel"]));
    map.into_iter().filter_map(|(k, v)| if !tokens.is_disjoint(&v) { Some(k.to_string()) } else { None }).collect()
}

fn intent_schema_match(command: &str, prime_intent: &str) -> f64 {
    let intent_tokens = tokenise(prime_intent);
    let command_tokens = tokenise(command);

    let intent_ops = classify_ops(&intent_tokens);
    let command_ops = classify_ops(&command_tokens);
    let intent_scope = classify_scope(&intent_tokens);
    let command_scope = classify_scope(&command_tokens);

    if intent_ops.is_empty() && intent_scope.is_empty() {
        return 0.0;
    }

    let op_overlap = intent_ops.intersection(&command_ops).count() as f64;
    let scope_overlap = intent_scope.intersection(&command_scope).count() as f64;

    let op_score = op_overlap / (intent_ops.len().max(1) as f64);
    let scope_score = scope_overlap / (intent_scope.len().max(1) as f64);

    let excess_ops: HashSet<String> = command_ops.difference(&intent_ops).cloned().collect();
    let excess_scope: HashSet<String> = command_scope.difference(&intent_scope).cloned().collect();

    let mut penalty = 0.0;
    if excess_ops.contains("DELETE") { penalty += 0.15; }
    if excess_ops.contains("NETWORK") { penalty += 0.15; }
    if excess_ops.contains("EXECUTE") && !intent_ops.contains("EXECUTE") { penalty += 0.10; }
    if excess_scope.contains("CRED") { penalty += 0.10; }

    round3(((op_score * 0.15) + (scope_score * 0.15) - penalty).clamp(-0.20, 0.30))
}

pub fn compute_fitness(world: &World) -> f64 {
    let alignment_bonus = intent_schema_match(&world.command, &world.prime_intent);
    let hypothesis_penalty = world.hypothesis.risk_prior * 0.4;
    round3(((1.0 - world.risk_score) + alignment_bonus - hypothesis_penalty).clamp(0.0, 1.0))
}

pub fn run_selection(worlds: &mut [World]) {
    for w in worlds.iter_mut() {
        if !w.alive { continue; }
        w.fitness = compute_fitness(w);
        if w.risk_score >= CRITICAL_RISK_THRESHOLD {
            w.verdict = "CRITICAL".to_string();
        } else if w.fitness < ELIMINATION_THRESHOLD {
            w.alive = false;
            w.verdict = "ELIMINATED".to_string();
        } else if w.risk_score >= 0.5 {
            w.verdict = "SUSPICIOUS".to_string();
        } else {
            w.verdict = "SAFE".to_string();
        }
    }
}

pub fn mutate_worlds(worlds: &mut Vec<World>) {
    let signals: Vec<World> = worlds.iter().filter(|w| w.alive && (w.verdict == "SUSPICIOUS" || w.verdict == "CRITICAL")).cloned().collect();
    if signals.is_empty() { return; }

    let has_active_destroy = worlds.iter().any(|w| w.alive && w.hypothesis.id == "H_DESTROY");
    if has_active_destroy { return; }

    let destroy_hyp = hypotheses().into_iter().find(|h| h.id == "H_DESTROY").expect("H_DESTROY exists");
    let seed = format!("MUT:ESC:{}", now_secs());
    let mut hasher = Sha256::new();
    hasher.update(seed.as_bytes());
    let wid = hex::encode(hasher.finalize())[..12].to_string();
    let mut mutant = World {
        world_id: wid,
        hypothesis: destroy_hyp.clone(),
        command: signals[0].command.clone(),
        prime_intent: signals[0].prime_intent.clone(),
        fitness: 1.0,
        alive: true,
        sim_delta: serde_json::json!({}),
        risk_score: 0.0,
        verdict: "MUTATED".to_string(),
    };
    mutant.risk_score = initial_risk(&mutant.command, &destroy_hyp).max(0.75);
    worlds.push(mutant);
}

fn hs(values: &[&str]) -> HashSet<String> {
    values.iter().map(|s| s.to_string()).collect()
}

fn now_secs() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

fn round3(v: f64) -> f64 {
    (v * 1000.0).round() / 1000.0
}
