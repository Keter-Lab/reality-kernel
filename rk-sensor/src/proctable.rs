//! Process table for audit enrichment (docs/design/phase-9.md §3.7; deferred
//! from Phase 7, decision 4).
//!
//! A bounded LRU keyed by tgid, filled from the exec records the kernel emits
//! for every governed exec. A decision event for a process the table has not
//! seen (a forked child, or a process older than the sensor) falls back to
//! procfs, which is off the hot path because decisions are rare. Enrichment is
//! best-effort and says where it came from; the decision itself always comes
//! from the kernel record.
//!
//! A tgid can be reused once its process exits, so each entry keeps the
//! process's start time (`/proc/<pid>/stat` field 22, boot-based like the
//! event timestamps). An entry names a decision's process only if it can be
//! the process that held the tgid at the decision; otherwise the record says
//! `unavailable` rather than naming another process's executable. Start times
//! have clock-tick granularity (usually 10 ms).

use std::fs;
use std::num::NonZeroUsize;
use std::path::PathBuf;

use lru::LruCache;

pub const DEFAULT_CAPACITY: usize = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    ExecRecord,
    Procfs,
    Unavailable,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ExecRecord => "exec_record",
            Self::Procfs => "procfs",
            Self::Unavailable => "unavailable",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcInfo {
    pub exe: Option<String>,
    pub ppid: Option<u32>,
    pub source: Source,
}

impl ProcInfo {
    fn unavailable() -> Self {
        Self {
            exe: None,
            ppid: None,
            source: Source::Unavailable,
        }
    }
}

#[derive(Debug, Clone)]
struct Entry {
    exe: String,
    ppid: Option<u32>,
    source: Source,
    /// procfs was already asked for the parent.
    ppid_tried: bool,
    /// Start time in clock ticks since boot; `None` when it could not be
    /// read for this process.
    start: Option<u64>,
}

/// What `/proc/<pid>/stat` says about a live process.
struct Stat {
    ppid: Option<u32>,
    start: Option<u64>,
}

pub struct ProcTable {
    cache: LruCache<u32, Entry>,
    proc_root: PathBuf,
    ns_per_tick: u64,
}

/// Parent pid (field 4) from the contents of `/proc/<pid>/stat`.
pub fn parse_ppid(stat: &str) -> Option<u32> {
    // comm (field 2) may contain spaces and ')': fields resume after the last ')'.
    let rest = &stat[stat.rfind(')')? + 1..];
    rest.split_whitespace().nth(1)?.parse().ok()
}

/// Start time (field 22, clock ticks since boot) from `/proc/<pid>/stat`.
pub fn parse_starttime(stat: &str) -> Option<u64> {
    let rest = &stat[stat.rfind(')')? + 1..];
    rest.split_whitespace().nth(19)?.parse().ok()
}

impl ProcTable {
    pub fn new(capacity: usize, proc_root: impl Into<PathBuf>) -> Self {
        let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
        let hz = if hz > 0 { hz as u64 } else { 100 };
        Self {
            cache: LruCache::new(NonZeroUsize::new(capacity.max(1)).expect("non-zero")),
            proc_root: proc_root.into(),
            ns_per_tick: 1_000_000_000 / hz,
        }
    }

    pub fn len(&self) -> usize {
        self.cache.len()
    }

    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }

    /// Boot-based nanoseconds of a start time in clock ticks.
    fn start_ns(&self, ticks: u64) -> u64 {
        ticks.saturating_mul(self.ns_per_tick)
    }

    /// `None` when the process is gone.
    fn read_stat(&self, tgid: u32) -> Option<Stat> {
        let stat = fs::read_to_string(self.proc_root.join(tgid.to_string()).join("stat")).ok()?;
        Some(Stat {
            ppid: parse_ppid(&stat),
            start: parse_starttime(&stat),
        })
    }

    /// Records the executable of a committed exec at `ts_ns` (the event's
    /// boot-based timestamp). A new exec replaces what the table knew about
    /// the tgid. The start time is read now; if the tgid already belongs to a
    /// process started after the exec, it is left unknown.
    pub fn record_exec(&mut self, tgid: u32, exe: String, ts_ns: u64) {
        let start = self
            .read_stat(tgid)
            .and_then(|s| s.start)
            .filter(|&s| self.start_ns(s) <= ts_ns);
        self.cache.put(
            tgid,
            Entry {
                exe,
                ppid: None,
                source: Source::ExecRecord,
                ppid_tried: false,
                start,
            },
        );
    }

    /// What is known about the process `tgid` that made a decision at
    /// `ts_ns`, asking procfs on a miss.
    pub fn lookup(&mut self, tgid: u32, ts_ns: u64) -> ProcInfo {
        if tgid == 0 {
            return ProcInfo::unavailable();
        }
        let live = self.read_stat(tgid);
        // The live process, if any, made the decision when it already
        // existed then: a tgid has one process at a time.
        let live_decided = live
            .as_ref()
            .is_some_and(|s| s.start.is_none_or(|c| self.start_ns(c) <= ts_ns));

        if let Some(e) = self.cache.get(&tgid).cloned() {
            let live_start = live.as_ref().and_then(|s| s.start);
            let same_as_live = match (e.start, live_start) {
                (Some(a), Some(b)) => a == b,
                _ => live.is_some(),
            };
            let usable = match &live {
                // The entry must be the live process's.
                Some(_) if live_decided => same_as_live,
                // A process started after the decision holds the tgid: the
                // entry must be an earlier one that existed at the decision.
                Some(_) => {
                    matches!((e.start, live_start), (Some(a), Some(b)) if a != b && self.start_ns(a) <= ts_ns)
                }
                // Exited: usable unless known to have started too late.
                None => e.start.is_none_or(|a| self.start_ns(a) <= ts_ns),
            };
            if usable {
                let ppid = if e.ppid_tried {
                    e.ppid
                } else {
                    let ppid = live
                        .as_ref()
                        .filter(|_| same_as_live)
                        .and_then(|s| s.ppid);
                    if let Some(entry) = self.cache.get_mut(&tgid) {
                        entry.ppid = ppid;
                        entry.ppid_tried = true;
                    }
                    ppid
                };
                return ProcInfo {
                    exe: Some(e.exe),
                    ppid,
                    source: e.source,
                };
            }
        }

        // procfs only for the process that made the decision. Not cached
        // when there is none: the tgid may be reused.
        let Some(stat) = live.filter(|_| live_decided) else {
            return ProcInfo::unavailable();
        };
        let dir = self.proc_root.join(tgid.to_string());
        let Ok(exe) = fs::read_link(dir.join("exe")) else {
            return ProcInfo::unavailable();
        };
        let entry = Entry {
            exe: exe.to_string_lossy().into_owned(),
            ppid: stat.ppid,
            source: Source::Procfs,
            ppid_tried: true,
            start: stat.start,
        };
        let info = ProcInfo {
            exe: Some(entry.exe.clone()),
            ppid: entry.ppid,
            source: Source::Procfs,
        };
        self.cache.put(tgid, entry);
        info
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fake procfs with one process.
    fn fake_proc(name: &str, pid: u32, exe: &str, ppid: u32) -> PathBuf {
        let root = std::env::temp_dir().join(format!("rk-proc-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let dir = root.join(pid.to_string());
        fs::create_dir_all(&dir).unwrap();
        std::os::unix::fs::symlink(exe, dir.join("exe")).unwrap();
        fs::write(
            dir.join("stat"),
            format!("{pid} (my (odd) comm) S {ppid} 1 1 0 -1"),
        )
        .unwrap();
        root
    }

    #[test]
    fn ppid_is_parsed_after_the_last_paren() {
        assert_eq!(parse_ppid("42 (a) b) R 7 42 42"), Some(7));
        assert_eq!(parse_ppid("garbage"), None);
    }

    #[test]
    fn exec_records_fill_the_table_and_procfs_adds_the_parent() {
        let root = fake_proc("exec", 50, "/usr/bin/python3", 1);
        let mut t = ProcTable::new(8, &root);
        t.record_exec(50, "/opt/agent/bin/run".into(), 0);
        let info = t.lookup(50, 0);
        assert_eq!(info.source, Source::ExecRecord);
        assert_eq!(info.exe.as_deref(), Some("/opt/agent/bin/run"));
        assert_eq!(info.ppid, Some(1));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn misses_fall_back_to_procfs_and_exited_processes_are_unavailable() {
        let root = fake_proc("miss", 60, "/usr/bin/curl", 59);
        let mut t = ProcTable::new(8, &root);
        let info = t.lookup(60, 0);
        assert_eq!(
            info,
            ProcInfo {
                exe: Some("/usr/bin/curl".into()),
                ppid: Some(59),
                source: Source::Procfs,
            }
        );
        assert_eq!(t.lookup(61, 0).source, Source::Unavailable);
        assert_eq!(t.len(), 1, "unavailable lookups are not cached");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn the_table_is_bounded() {
        let mut t = ProcTable::new(3, "/nonexistent");
        for pid in 1..=10 {
            t.record_exec(pid, format!("/bin/p{pid}"), 0);
        }
        assert_eq!(t.len(), 3);
        assert_eq!(t.lookup(10, 0).exe.as_deref(), Some("/bin/p10"));
        assert_eq!(t.lookup(1, 0).source, Source::Unavailable);
    }

    /// Replaces the fake process `pid` under `root` (a new process reusing
    /// the pid): its executable and start time in clock ticks.
    fn set_proc(root: &std::path::Path, pid: u32, exe: &str, start: u64) {
        let dir = root.join(pid.to_string());
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        std::os::unix::fs::symlink(exe, dir.join("exe")).unwrap();
        let fill = ["0"; 17].join(" ");
        fs::write(dir.join("stat"), format!("{pid} (x) S 1 {fill} {start} 0 0")).unwrap();
    }

    #[test]
    fn starttime_is_field_22() {
        let fill = ["0"; 17].join(" ");
        assert_eq!(parse_starttime(&format!("7 (a) b) S 1 {fill} 4242 0")), Some(4242));
        assert_eq!(parse_starttime("7 (a) S 1 1 1"), None);
    }

    /// After pid reuse, a decision is never attributed to the executable of
    /// the process that held the pid before.
    #[test]
    fn pid_reuse_is_not_misattributed() {
        let root = std::env::temp_dir().join(format!("rk-proc-{}-reuse", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let mut t = ProcTable::new(8, &root);
        let at = |ticks: u64| ticks * t.ns_per_tick;
        let (t100, t150, t250, t300) = (at(100), at(150), at(250), at(300));

        // Process A (started at tick 100) execs /old.
        set_proc(&root, 70, "/old", 100);
        t.record_exec(70, "/old".into(), t150);
        assert_eq!(t.lookup(70, t150).exe.as_deref(), Some("/old"));

        // A exits; B (started at tick 200, no exec of its own) reuses the pid.
        set_proc(&root, 70, "/usr/bin/new", 200);
        // A decision from before B started is still A's.
        assert_eq!(t.lookup(70, t150).exe.as_deref(), Some("/old"));
        // A decision after B started is B's, read from procfs, never A's.
        let info = t.lookup(70, t250);
        assert_eq!(info.exe.as_deref(), Some("/usr/bin/new"));
        assert_eq!(info.source, Source::Procfs);

        // B exits too and C starts at tick 300. A decision made between them
        // (B's, at tick 250) is B's from the table; one before tick 200 with
        // no matching entry is unknown, not C's.
        set_proc(&root, 70, "/usr/bin/third", 300);
        assert_eq!(t.lookup(70, t250).exe.as_deref(), Some("/usr/bin/new"));
        let mut fresh = ProcTable::new(8, &root);
        assert_eq!(fresh.lookup(70, t100).source, Source::Unavailable);
        assert_eq!(fresh.len(), 0);

        // The pid is free again: an entry known to start after the
        // decision is not used.
        fs::remove_dir_all(root.join("70")).unwrap();
        assert_eq!(t.lookup(70, t150).source, Source::Unavailable);
        assert_eq!(t.lookup(70, t300).exe.as_deref(), Some("/usr/bin/new"));
        let _ = fs::remove_dir_all(&root);
    }
}
