use ipnet::IpNet;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeastAgencyPolicy {
    pub allowed_tools: Option<Vec<String>>,
    pub allowed_egress: Option<Vec<String>>,
    pub read_only_paths: Option<Vec<String>>,
}

pub fn verify_least_agency_policy(
    command: &str,
    policy: Option<&LeastAgencyPolicy>,
    scopes: &[String],
) -> Option<String> {
    if command.trim().is_empty() {
        return None;
    }

    if !scopes.is_empty() {
        let mut allowed_bins = std::collections::BTreeSet::new();
        for scope in scopes {
            for b in scope_bins(scope) {
                allowed_bins.insert(b.to_string());
            }
        }
        if !allowed_bins.is_empty() {
            for b in extract_binaries(command) {
                if !allowed_bins.contains(&b) {
                    return Some(format!(
                        "ScopeViolation: Binary '{}' is not allowed by token scopes: {:?}.",
                        b, scopes
                    ));
                }
            }
        }
    }

    if let Some(policy) = policy {
        if let Some(tools) = &policy.allowed_tools {
            let allowed_tools_lower: Vec<String> = tools.iter().map(|t| t.to_lowercase()).collect();
            for b in extract_binaries(command) {
                if !allowed_tools_lower.iter().any(|t| t == &b || glob_match(t, &b)) {
                    return Some(format!(
                        "PolicyViolation: Binary '{}' is not in allowed_tools list.",
                        b
                    ));
                }
            }
        }

        if let Some(egress) = &policy.allowed_egress {
            for d in extract_domains(command) {
                let mut matched = false;
                for pattern in egress {
                    if domain_matches(&d, pattern) || cidr_matches(&d, pattern) {
                        matched = true;
                        break;
                    }
                }
                if !matched {
                    return Some(format!(
                        "PolicyViolation: Outbound network request to '{}' is not in allowed_egress list.",
                        d
                    ));
                }
            }
        }
    }

    None
}

fn scope_bins(scope: &str) -> &'static [&'static str] {
    match scope {
        "fs:read" => &["ls", "ll", "la", "dir", "cat", "head", "tail", "less", "more", "view", "wc", "file", "stat", "find", "tree", "pwd", "du", "df"],
        "sys:info" => &["echo", "printf", "date", "whoami", "id", "groups", "hostname", "uname", "uptime", "w", "ps", "top", "env", "printenv", "set", "which", "whereis", "type", "man", "help", "info", "history", "lsof", "free", "nproc"],
        "git" => &["git"],
        "network" => &["ping", "traceroute", "tracepath", "mtr", "nslookup", "dig", "host", "whois", "netstat", "ss", "ip", "ifconfig", "curl", "wget"],
        _ => &[],
    }
}

fn extract_binaries(command: &str) -> Vec<String> {
    let splitter = Regex::new(r";|&&|\|\||\|").unwrap();
    let mut binaries = Vec::new();
    for part in splitter.split(command) {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue;
        }
        let subparts: Vec<&str> = trimmed.split_whitespace().collect();
        for token in subparts {
            if token.contains('=') && !token.starts_with('-') {
                continue;
            }
            let mut bin_name = token.rsplit('/').next().unwrap_or(token).rsplit('\\').next().unwrap_or(token).to_string();
            bin_name = bin_name.replace(['"', '\'', '`', '(', ')'], "");
            if !bin_name.is_empty() {
                binaries.push(bin_name.to_lowercase());
            }
            break;
        }
    }
    binaries
}

fn extract_domains(command: &str) -> Vec<String> {
    let mut domains = Vec::new();
    for cap in Regex::new(r"https?://([a-zA-Z0-9][a-zA-Z0-9.\-]*)").unwrap().captures_iter(command) {
        domains.push(cap[1].to_lowercase());
    }

    for cap in Regex::new(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b").unwrap().captures_iter(command) {
        let ip = cap[1].to_string();
        if ip != "127.0.0.1" && ip != "0.0.0.0" && ip != "255.255.255.255" {
            domains.push(ip);
        }
    }

    for word in command.split_whitespace() {
        let word = word.trim().to_lowercase();
        if word.contains('.') && !word.chars().any(|c| "/:\\'\"()$*".contains(c)) && word.chars().any(|c| c.is_ascii_alphabetic()) {
            domains.push(word);
        }
    }

    domains.sort();
    domains.dedup();
    domains
}

fn domain_matches(domain: &str, pattern: &str) -> bool {
    let p = pattern.to_lowercase();
    if let Some(suffix) = p.strip_prefix("*.") {
        domain == suffix || domain.ends_with(&format!(".{suffix}"))
    } else {
        domain == p
    }
}

fn cidr_matches(domain_or_ip: &str, pattern: &str) -> bool {
    let Ok(net) = pattern.parse::<IpNet>() else { return false; };
    let Ok(ip) = domain_or_ip.parse::<IpAddr>() else { return false; };
    net.contains(&ip)
}

fn glob_match(pattern: &str, text: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    let escaped = regex::escape(pattern).replace("\\*", ".*");
    let re = Regex::new(&format!("^{escaped}$")).unwrap();
    re.is_match(text)
}
