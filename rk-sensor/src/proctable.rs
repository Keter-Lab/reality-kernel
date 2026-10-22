//! Process table for audit enrichment (docs/design/phase-9.md §3.7; deferred
//! from Phase 7, decision 4).
//!
//! A bounded LRU keyed by tgid, filled from the exec records the kernel emits
//! for every governed exec. A decision event for a process the table has not
//! seen (a forked child, or a process older than the sensor) falls back to
//! procfs, which is off the hot path because decisions are rare. Enrichment is
//! best-effort and says where it came from; the decision itself always comes
//! from the kernel record.

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

#[derive(Debug, Clone)]
struct Entry {
    exe: String,
    ppid: Option<u32>,
    source: Source,
    /// procfs was already asked for the parent.
    ppid_tried: bool,
}

pub struct ProcTable {
    cache: LruCache<u32, Entry>,
    proc_root: PathBuf,
}

/// Parent pid (field 4) from the contents of `/proc/<pid>/stat`.
pub fn parse_ppid(stat: &str) -> Option<u32> {
    // comm (field 2) may contain spaces and ')': fields resume after the last ')'.
    let rest = &stat[stat.rfind(')')? + 1..];
    rest.split_whitespace().nth(1)?.parse().ok()
}

impl ProcTable {
    pub fn new(capacity: usize, proc_root: impl Into<PathBuf>) -> Self {
        Self {
            cache: LruCache::new(NonZeroUsize::new(capacity.max(1)).expect("non-zero")),
            proc_root: proc_root.into(),
        }
    }

    pub fn len(&self) -> usize {
        self.cache.len()
    }

    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }

    /// Records the executable of a committed exec. A new exec replaces what
    /// the table knew about the tgid, so pid reuse corrects itself on exec.
    pub fn record_exec(&mut self, tgid: u32, exe: String) {
        self.cache.put(
            tgid,
            Entry {
                exe,
                ppid: None,
                source: Source::ExecRecord,
                ppid_tried: false,
            },
        );
    }

    fn read_ppid(&self, tgid: u32) -> Option<u32> {
        let stat = fs::read_to_string(self.proc_root.join(tgid.to_string()).join("stat")).ok()?;
        parse_ppid(&stat)
    }

    /// What is known about `tgid`, asking procfs on a miss.
    pub fn lookup(&mut self, tgid: u32) -> ProcInfo {
        if tgid == 0 {
            return ProcInfo {
                exe: None,
                ppid: None,
                source: Source::Unavailable,
            };
        }
        let needs_ppid = self.cache.get(&tgid).map(|e| !e.ppid_tried);
        if needs_ppid == Some(true) {
            let ppid = self.read_ppid(tgid);
            if let Some(e) = self.cache.get_mut(&tgid) {
                e.ppid = ppid;
                e.ppid_tried = true;
            }
        }
        if let Some(e) = self.cache.get(&tgid) {
            return ProcInfo {
                exe: Some(e.exe.clone()),
                ppid: e.ppid,
                source: e.source,
            };
        }
        let dir = self.proc_root.join(tgid.to_string());
        let Ok(exe) = fs::read_link(dir.join("exe")) else {
            // Exited already. Not cached: the pid may be reused.
            return ProcInfo {
                exe: None,
                ppid: None,
                source: Source::Unavailable,
            };
        };
        let entry = Entry {
            exe: exe.to_string_lossy().into_owned(),
            ppid: self.read_ppid(tgid),
            source: Source::Procfs,
            ppid_tried: true,
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
        t.record_exec(50, "/opt/agent/bin/run".into());
        let info = t.lookup(50);
        assert_eq!(info.source, Source::ExecRecord);
        assert_eq!(info.exe.as_deref(), Some("/opt/agent/bin/run"));
        assert_eq!(info.ppid, Some(1));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn misses_fall_back_to_procfs_and_exited_processes_are_unavailable() {
        let root = fake_proc("miss", 60, "/usr/bin/curl", 59);
        let mut t = ProcTable::new(8, &root);
        let info = t.lookup(60);
        assert_eq!(
            info,
            ProcInfo {
                exe: Some("/usr/bin/curl".into()),
                ppid: Some(59),
                source: Source::Procfs,
            }
        );
        assert_eq!(t.lookup(61).source, Source::Unavailable);
        assert_eq!(t.len(), 1, "unavailable lookups are not cached");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn the_table_is_bounded() {
        let mut t = ProcTable::new(3, "/nonexistent");
        for pid in 1..=10 {
            t.record_exec(pid, format!("/bin/p{pid}"));
        }
        assert_eq!(t.len(), 3);
        assert_eq!(t.lookup(10).exe.as_deref(), Some("/bin/p10"));
        assert_eq!(t.lookup(1).source, Source::Unavailable);
    }
}
