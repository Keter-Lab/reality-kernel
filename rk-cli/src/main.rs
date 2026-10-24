use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use rk_agentd::client::{ApplyOutcome, Client};
use rk_agentd::protocol::{AgentStatusInfo, DaemonStatus};
use std::collections::VecDeque;
use std::fs;
use std::io::{Read as _, Seek as _, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

mod doctor;
mod init;
mod suggest;
mod toml_out;

#[derive(Parser, Debug)]
#[command(
    name = "rk",
    version,
    about = "Reality Kernel operations and agent CLI"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Launch a governed agent under a profile
    Run {
        /// Profile to govern the agent under
        #[arg(long)]
        profile: String,
        /// Session id for audit and attestation linkage
        #[arg(long, env = "RK_SESSION_ID")]
        session: Option<String>,
        /// Command and arguments to execute
        #[arg(last = true, required = true)]
        cmd: Vec<String>,
    },
    /// Policy management commands
    Policy {
        #[command(subcommand)]
        command: PolicyCommands,
    },
    /// Query daemon status, active policy, running agents, and capabilities
    Status {
        /// Emit machine-readable JSON output
        #[arg(long)]
        json: bool,
    },
    /// Check the host: kernel features, mounts, lockdown, the sensor (docs/install.md)
    #[command(alias = "preflight")]
    Doctor {
        /// Emit machine-readable JSON output
        #[arg(long)]
        json: bool,
    },
    /// Write and apply a starter policy in AUDIT that fits this host
    /// (docs/agents.md)
    Init {
        /// Policy file to write
        #[arg(long, default_value = "/etc/rk/policy.toml")]
        policy: PathBuf,
        /// User the agent runs as (default: $SUDO_USER, else root)
        #[arg(long)]
        user: Option<String>,
        /// Home directory to look for secret files in (default: the user's)
        #[arg(long)]
        home: Option<PathBuf>,
        /// Print the starter policy and change nothing
        #[arg(long)]
        print: bool,
        /// Replace a policy that already defines profiles (a backup is kept)
        #[arg(long)]
        force: bool,
    },
    /// Read and verify the tamper-evident audit log (docs/audit.md)
    Audit {
        #[command(subcommand)]
        command: AuditCommands,
    },
}

#[derive(Subcommand, Debug)]
enum AuditCommands {
    /// Print audit records, oldest first
    Tail {
        /// Audit log directory
        #[arg(long, default_value = rk_audit::DEFAULT_DIR)]
        dir: PathBuf,
        /// Keep printing records as they are written
        #[arg(short, long)]
        follow: bool,
        /// Print the OCSF JSON lines instead of one summary line per record
        #[arg(long)]
        json: bool,
        /// Only this verdict (`audit` means audit-would-deny)
        #[arg(long, value_parser = ["deny", "audit", "allow"])]
        verdict: Option<String>,
        /// Only decisions of this agent session
        #[arg(long)]
        session: Option<String>,
        /// Records to print before following; 0 prints all
        #[arg(short = 'n', long, default_value_t = 20)]
        lines: usize,
    },
    /// Verify the hash chain and the batch signatures
    Verify {
        /// Audit log directory
        #[arg(long, default_value = rk_audit::DEFAULT_DIR)]
        dir: PathBuf,
        /// Require this signing key: hex public key, or a file holding it
        /// (e.g. /var/lib/rk/audit.key.pub)
        #[arg(long)]
        pubkey: Option<String>,
        /// Emit machine-readable JSON output
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand, Debug)]
enum PolicyCommands {
    /// Apply a policy file atomically
    Apply {
        /// Path to policy TOML file
        file: PathBuf,
        /// Validate and report changes without touching the kernel
        #[arg(long)]
        dry_run: bool,
    },
    /// Show differences between a policy file and the active policy
    Diff {
        /// Path to policy TOML file
        file: PathBuf,
    },
    /// Re-apply the previous policy
    Rollback,
    /// Suggest an ENFORCE profile from what the audit log shows the profile's
    /// agents did. Prints a complete policy; applies nothing
    Suggest {
        /// Profile to suggest rules for
        #[arg(long)]
        profile: String,
        /// Policy file holding the profile
        #[arg(long, default_value = "/etc/rk/policy.toml")]
        policy: PathBuf,
        /// Audit log directory
        #[arg(long, default_value = rk_audit::DEFAULT_DIR)]
        dir: PathBuf,
        /// Require this signing key (default: /var/lib/rk/audit.key.pub if present)
        #[arg(long)]
        pubkey: Option<String>,
        /// Use a log that does not verify (the output says so)
        #[arg(long)]
        no_verify: bool,
        /// Only records from the last 30s, 15m, 2h, 1d, ...
        #[arg(long)]
        since: Option<String>,
        /// Also look for executables in this directory (and four levels below)
        #[arg(long)]
        search: Vec<PathBuf>,
        /// Write the suggestion here instead of stdout
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Commands::Run {
            profile,
            session,
            cmd,
        } => run_agent(&profile, session.as_deref(), &cmd),
        Commands::Policy { command } => match run_policy(command) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("rk policy error: {e:#}");
                ExitCode::FAILURE
            }
        },
        Commands::Status { json } => match run_status(json) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("rk status error: {e:#}");
                ExitCode::FAILURE
            }
        },
        Commands::Doctor { json } => match doctor::run(json) {
            Ok(true) => ExitCode::SUCCESS,
            Ok(false) => ExitCode::from(2),
            Err(err) => {
                eprintln!("doctor error: {err:#}");
                ExitCode::from(1)
            }
        },
        Commands::Init {
            policy,
            user,
            home,
            print,
            force,
        } => match init::run(&init::Options {
            policy,
            user,
            home,
            print,
            force,
        }) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("rk init: {e:#}");
                ExitCode::FAILURE
            }
        },
        Commands::Audit {
            command:
                AuditCommands::Tail {
                    dir,
                    follow,
                    json,
                    verdict,
                    session,
                    lines,
                },
        } => match run_audit_tail(
            &dir,
            follow,
            json,
            verdict.as_deref(),
            session.as_deref(),
            lines,
        ) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("rk audit tail: {e:#}");
                ExitCode::FAILURE
            }
        },
        Commands::Audit {
            command: AuditCommands::Verify { dir, pubkey, json },
        } => match run_audit_verify(&dir, pubkey.as_deref(), json) {
            Ok(true) => ExitCode::SUCCESS,
            Ok(false) => ExitCode::from(2),
            Err(e) => {
                eprintln!("rk audit verify: {e:#}");
                ExitCode::FAILURE
            }
        },
    }
}

/// The output line for one audit log line, if it is a record that passes
/// the filters.
fn audit_line(
    line: &str,
    json: bool,
    verdict: Option<&str>,
    session: Option<&str>,
) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(line).ok()?;
    if !rk_audit::tail::is_record(&v) || !rk_audit::tail::matches(&v, verdict, session) {
        return None;
    }
    Some(if json {
        line.to_string()
    } else {
        rk_audit::tail::render(&v)
    })
}

/// Complete lines appended to `path` since `offset`; a partial last line is
/// kept in `partial` until its newline arrives.
fn read_new_lines(path: &Path, offset: &mut u64, partial: &mut String) -> Result<Vec<String>> {
    let mut f = fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    f.seek(SeekFrom::Start(*offset))?;
    let mut chunk = String::new();
    *offset += f.read_to_string(&mut chunk)? as u64;
    partial.push_str(&chunk);
    let Some(end) = partial.rfind('\n') else {
        return Ok(Vec::new());
    };
    let complete: Vec<String> = partial[..end].lines().map(str::to_string).collect();
    partial.drain(..=end);
    Ok(complete)
}

fn run_audit_tail(
    dir: &Path,
    follow: bool,
    json: bool,
    verdict: Option<&str>,
    session: Option<&str>,
    lines: usize,
) -> Result<()> {
    let segments = rk_audit::chain::segments(dir)?;
    // Newest segments first, until enough records are collected.
    let mut shown: VecDeque<String> = VecDeque::new();
    for seg in segments.iter().rev() {
        let text = fs::read_to_string(seg).with_context(|| format!("read {}", seg.display()))?;
        let found: Vec<String> = text
            .lines()
            .filter_map(|l| audit_line(l, json, verdict, session))
            .collect();
        for line in found.into_iter().rev() {
            shown.push_front(line);
        }
        if lines > 0 && shown.len() >= lines {
            break;
        }
    }
    while lines > 0 && shown.len() > lines {
        shown.pop_front();
    }
    for line in &shown {
        println!("{line}");
    }
    if !follow {
        return Ok(());
    }
    let mut current = segments.last().cloned();
    let mut offset = current
        .as_deref()
        .and_then(|p| fs::metadata(p).ok())
        .map_or(0, |m| m.len());
    let mut partial = String::new();
    loop {
        std::thread::sleep(Duration::from_millis(500));
        let newest = rk_audit::chain::segments(dir)?.last().cloned();
        let emit = |path: &Path, offset: &mut u64, partial: &mut String| -> Result<()> {
            for l in read_new_lines(path, offset, partial)? {
                if let Some(out) = audit_line(&l, json, verdict, session) {
                    println!("{out}");
                }
            }
            Ok(())
        };
        if newest != current {
            // Finish the old segment, then start the new one from its top.
            if let Some(p) = &current {
                emit(p.as_path(), &mut offset, &mut partial)?;
            }
            current = newest;
            offset = 0;
            partial.clear();
        }
        if let Some(p) = &current {
            emit(p.as_path(), &mut offset, &mut partial)?;
        }
    }
}

/// An audit public key given as hex, or as a file holding it.
pub(crate) fn read_public_key(p: &str) -> Result<[u8; 32]> {
    let text = if Path::new(p).is_file() {
        fs::read_to_string(p).with_context(|| format!("read {p}"))?
    } else {
        p.to_string()
    };
    rk_audit::key::parse_public_key(&text)
}

fn run_audit_verify(dir: &Path, pubkey: Option<&str>, json: bool) -> Result<bool> {
    let pinned = pubkey.map(read_public_key).transpose()?;
    let r = rk_audit::chain::verify_dir(dir, pinned)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&r)?);
        return Ok(r.ok());
    }
    println!(
        "audit log {}: {} segments, {} batches, {} records ({} recovered batches)",
        dir.display(),
        r.segments,
        r.batches,
        r.records,
        r.recovered_batches
    );
    if let (Some(first), Some(head), Some(hash)) = (r.first_seq, r.head_seq, &r.head_hash) {
        println!(
            "chain: batches {first}..{}, head {}, signed by {}",
            head.saturating_sub(1),
            &hash[..16.min(hash.len())],
            r.key_ids.join(", ")
        );
    }
    if r.unsealed_tail > 0 {
        println!("open batch: {} records not sealed yet", r.unsealed_tail);
    }
    for w in &r.warnings {
        println!("warning: {w}");
    }
    if r.ok() {
        println!("VERIFIED");
    } else {
        println!("FAILED: {} problem(s)", r.problems.len());
        for p in &r.problems {
            println!("  {} line {}: {}", p.segment, p.line, p.what);
        }
    }
    Ok(r.ok())
}

fn run_agent(profile: &str, session: Option<&str>, cmd: &[String]) -> ExitCode {
    let client = match Client::connect(None) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("rk run: failed to connect to rk-sensor daemon: {e:#}");
            return ExitCode::FAILURE;
        }
    };

    let env = std::env::vars().collect::<Vec<_>>();
    let cwd_buf = std::env::current_dir().ok();
    let cwd_str = cwd_buf.as_deref().and_then(|p| p.to_str());
    match client.run(profile, session, cwd_str, cmd, &env) {
        Ok(code) => ExitCode::from(u8::try_from(code).unwrap_or(1)),
        Err(e) => {
            eprintln!("rk run error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run_policy(command: PolicyCommands) -> Result<()> {
    // Reads the policy file and the audit log; needs no daemon.
    if let PolicyCommands::Suggest {
        profile,
        policy,
        dir,
        pubkey,
        no_verify,
        since,
        search,
        out,
    } = command
    {
        return suggest::run(&suggest::Options {
            profile,
            policy,
            dir,
            pubkey,
            no_verify,
            since,
            search,
            out,
        });
    }
    let client = Client::connect(None)
        .context("failed to connect to rk-sensor daemon (is rk-sensor running?)")?;

    match command {
        PolicyCommands::Apply { file, dry_run } => {
            let text = fs::read_to_string(&file)
                .with_context(|| format!("failed to read policy file {}", file.display()))?;
            match client.apply(&text, dry_run)? {
                ApplyOutcome::Applied(rep) => {
                    println!(
                        "Policy applied: generation {}, {} profiles, {} bindings",
                        rep.generation, rep.profiles, rep.bindings
                    );
                    if !rep.skipped_files.is_empty() {
                        eprintln!(
                            "Warning: skipped built-in file rules on this host: {:?}",
                            rep.skipped_files
                        );
                    }
                }
                ApplyOutcome::DryRun(dr) => {
                    println!(
                        "Dry run: generation {}, {} profiles, {} cgroups to create",
                        dr.generation,
                        dr.profiles,
                        dr.cgroups_to_create.len()
                    );
                    if !dr.diff.is_empty() {
                        println!("Changes:");
                        for line in &dr.diff {
                            println!("  {line}");
                        }
                    } else {
                        println!("No changes against active policy.");
                    }
                }
            }
        }
        PolicyCommands::Diff { file } => {
            let text = fs::read_to_string(&file)
                .with_context(|| format!("failed to read policy file {}", file.display()))?;
            let diff = client.diff(&text)?;
            if diff.is_empty() {
                println!("No changes against active policy.");
            } else {
                for line in &diff {
                    println!("{line}");
                }
            }
        }
        PolicyCommands::Rollback => {
            let rep = client.rollback()?;
            println!(
                "Policy rolled back: generation {}, {} profiles, {} bindings",
                rep.generation, rep.profiles, rep.bindings
            );
        }
        PolicyCommands::Suggest { .. } => unreachable!("handled before connecting"),
    }
    Ok(())
}

fn run_status(as_json: bool) -> Result<()> {
    let client = Client::connect(None)
        .context("failed to connect to rk-sensor daemon (is rk-sensor running?)")?;
    let status = client.status()?;

    if as_json {
        println!("{}", serde_json::to_string_pretty(&status)?);
    } else {
        print_human_status(&status);
    }
    Ok(())
}

fn print_human_status(status: &DaemonStatus) {
    println!("Reality Kernel daemon status");
    println!(
        "  health     : {}",
        if status.health {
            "healthy"
        } else {
            "unhealthy"
        }
    );
    println!("  generation : {}", status.generation);
    println!("  containers : {} (Kubernetes)", status.containers);
    let (decisions, pipeline): (Vec<_>, Vec<_>) = status
        .counters
        .iter()
        .partition(|(k, _)| k.starts_with("decisions."));
    if !pipeline.is_empty() {
        let line: Vec<String> = pipeline.iter().map(|(k, v)| format!("{k}={v}")).collect();
        println!("  pipeline   : {}", line.join(" "));
    }
    let decided: Vec<String> = decisions
        .iter()
        .filter(|(_, v)| **v > 0)
        .map(|(k, v)| format!("{}={v}", k.trim_start_matches("decisions.")))
        .collect();
    if !decided.is_empty() {
        println!("  decisions  : {}", decided.join(" "));
    }
    println!(
        "  profiles   : {}",
        if status.active_profiles.is_empty() {
            "(none)".into()
        } else {
            status.active_profiles.join(", ")
        }
    );
    println!();
    println!("Running agents ({}):", status.agents.len());
    if status.agents.is_empty() {
        println!("  (none)");
    } else {
        for a in &status.agents {
            print_agent_status(a);
        }
    }
    println!();
    println!("Capabilities:");
    for cap in &status.capabilities {
        println!(
            "  - {:22} {:3}  {}",
            cap.name,
            if cap.ok { "yes" } else { "no" },
            cap.detail
        );
    }
}

fn print_agent_status(a: &AgentStatusInfo) {
    println!("  - Agent {} (pid {}):", a.agent_id, a.pid);
    println!("    profile      : {}", a.profile);
    if let Some(ref sess) = a.session_id {
        println!("    session      : {}", sess);
    }
    println!("    cgroup       : {} (id {})", a.cgroup_rel, a.cgroup_id);
    println!("    privilege checks:");
    println!(
        "      unprivileged user   : {} (uid={}, gid={})",
        yes_no(a.privilege_checks.unprivileged_user),
        a.privilege_checks.caller_uid,
        a.privilege_checks.caller_gid
    );
    println!(
        "      no_new_privs        : {}",
        yes_no(a.privilege_checks.no_new_privs)
    );
    println!(
        "      empty capabilities  : {}",
        yes_no(a.privilege_checks.empty_capabilities)
    );
    println!(
        "      no cgroup delegation: {}",
        yes_no(a.privilege_checks.cgroup_not_delegated)
    );
}

fn yes_no(v: bool) -> &'static str {
    if v {
        "yes"
    } else {
        "no"
    }
}
