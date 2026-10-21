//! Socket peer authentication and authorisation helpers.

use std::collections::BTreeSet;
use std::ffi::CStr;
use std::os::unix::io::RawFd;

use anyhow::{bail, Context, Result};
use rk_policy::net::{Principal, Profile};

/// Peer process credentials read via `SO_PEERCRED`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCred {
    pub pid: i32,
    pub uid: u32,
    pub gid: u32,
}

/// Retrieve the caller's credentials from a connected Unix domain socket.
pub fn get_peer_cred(sock: RawFd) -> Result<PeerCred> {
    unsafe {
        let mut ucred: libc::ucred = std::mem::zeroed();
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        let res = libc::getsockopt(
            sock,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut ucred as *mut _ as *mut libc::c_void,
            &mut len,
        );
        if res != 0 {
            return Err(std::io::Error::last_os_error()).context("getsockopt(SO_PEERCRED) failed");
        }
        Ok(PeerCred {
            pid: ucred.pid,
            uid: ucred.uid,
            gid: ucred.gid,
        })
    }
}

/// Resolves user and group membership for a given `uid` and `gid`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserIdentity {
    pub uid: u32,
    pub gid: u32,
    pub username: Option<String>,
    pub group_names: BTreeSet<String>,
    pub gids: BTreeSet<u32>,
}

impl UserIdentity {
    pub fn from_cred(cred: &PeerCred) -> Self {
        let mut group_names = BTreeSet::new();
        let mut gids = BTreeSet::new();
        gids.insert(cred.gid);

        let username = get_username_and_groups(cred.uid, cred.gid, &mut group_names, &mut gids);

        Self {
            uid: cred.uid,
            gid: cred.gid,
            username,
            group_names,
            gids,
        }
    }
}

/// Query system database for username and supplementary groups.
fn get_username_and_groups(
    uid: u32,
    primary_gid: u32,
    out_group_names: &mut BTreeSet<String>,
    out_gids: &mut BTreeSet<u32>,
) -> Option<String> {
    unsafe {
        let mut pwd: libc::passwd = std::mem::zeroed();
        let mut buf = vec![0; 4096];
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        if libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr(), buf.len(), &mut result) != 0
            || result.is_null()
        {
            return None;
        }

        let username = CStr::from_ptr(pwd.pw_name).to_string_lossy().to_string();

        // Primary group name
        let mut grp: libc::group = std::mem::zeroed();
        let mut grp_result: *mut libc::group = std::ptr::null_mut();
        let mut grp_buf = vec![0; 4096];
        if libc::getgrgid_r(
            primary_gid,
            &mut grp,
            grp_buf.as_mut_ptr(),
            grp_buf.len(),
            &mut grp_result,
        ) == 0
            && !grp_result.is_null()
        {
            out_group_names.insert(CStr::from_ptr(grp.gr_name).to_string_lossy().to_string());
        }

        // Supplementary groups
        let mut ngroups: libc::c_int = 64;
        let mut groups = vec![0 as libc::gid_t; ngroups as usize];
        if libc::getgrouplist(
            pwd.pw_name,
            primary_gid as libc::gid_t,
            groups.as_mut_ptr(),
            &mut ngroups,
        ) == -1
        {
            groups.resize(ngroups as usize, 0);
            libc::getgrouplist(
                pwd.pw_name,
                primary_gid as libc::gid_t,
                groups.as_mut_ptr(),
                &mut ngroups,
            );
        }

        for &gid in groups.iter().take(ngroups as usize) {
            out_gids.insert(gid);
            if libc::getgrgid_r(
                gid,
                &mut grp,
                grp_buf.as_mut_ptr(),
                grp_buf.len(),
                &mut grp_result,
            ) == 0
                && !grp_result.is_null()
            {
                out_group_names.insert(CStr::from_ptr(grp.gr_name).to_string_lossy().to_string());
            }
        }

        Some(username)
    }
}

/// Checks whether `cred` is authorised to manage policy (apply, diff, rollback).
///
/// Authorised if `uid == 0` (root) or the user belongs to the `rk` group.
pub fn check_policy_admin(cred: &PeerCred) -> Result<()> {
    if cred.uid == 0 {
        return Ok(());
    }
    let id = UserIdentity::from_cred(cred);
    if id.group_names.contains("rk") {
        return Ok(());
    }
    bail!(
        "caller uid {} is not authorised to manage policy (must be root or in group rk)",
        cred.uid
    )
}

/// Checks whether `cred` is authorised to launch an agent under `profile`.
///
/// Matches against `profile.launchable_by`. If `launchable_by` is empty (e.g. quarantine),
/// it is always rejected.
pub fn check_launchable_by(cred: &PeerCred, profile: &Profile) -> Result<()> {
    if profile.launchable_by.is_empty() {
        bail!(
            "profile `{}` cannot be launched (launchable_by is empty)",
            profile.name
        );
    }

    let id = UserIdentity::from_cred(cred);

    for principal in &profile.launchable_by {
        let matches = match principal {
            Principal::User(name) => {
                if name == "root" && cred.uid == 0 {
                    true
                } else {
                    id.username.as_deref() == Some(name.as_str())
                }
            }
            Principal::Uid(u) => cred.uid == *u,
            Principal::Gid(g) => id.gids.contains(g),
            Principal::Group(name) => id.group_names.contains(name.as_str()),
        };
        if matches {
            return Ok(());
        }
    }

    bail!(
        "caller uid {} is not authorised to launch profile `{}`",
        cred.uid,
        profile.name
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rk_policy::net::{Action, Mode};

    fn test_profile(name: &str, principals: Vec<Principal>) -> Profile {
        Profile {
            id: 1,
            name: name.into(),
            mode: Mode::Enforce,
            net_default: Action::Deny,
            deny_raw_sockets: true,
            rules: Vec::new(),
            exec: None,
            files: rk_policy::net::FilePolicy {
                rules: Vec::new(),
                protect_exec_allowlist: false,
            },
            launchable_by: principals,
        }
    }

    #[test]
    fn policy_admin_permits_root_and_rejects_unprivileged() {
        let root_cred = PeerCred {
            pid: 1,
            uid: 0,
            gid: 0,
        };
        assert!(check_policy_admin(&root_cred).is_ok());

        // An arbitrary unprivileged uid not in group rk
        let unpriv_cred = PeerCred {
            pid: 9999,
            uid: 65534, // nobody
            gid: 65534,
        };
        assert!(check_policy_admin(&unpriv_cred).is_err());
    }

    #[test]
    fn launchable_by_authorisation() {
        let root_cred = PeerCred {
            pid: 1,
            uid: 0,
            gid: 0,
        };
        let user_cred = PeerCred {
            pid: 1234,
            uid: 1000,
            gid: 1000,
        };

        // Default: root only
        let default_prof = test_profile("default", vec![Principal::User("root".into())]);
        assert!(check_launchable_by(&root_cred, &default_prof).is_ok());
        assert!(check_launchable_by(&user_cred, &default_prof).is_err());

        // Numeric UID match
        let uid_prof = test_profile("dev", vec![Principal::Uid(1000)]);
        assert!(check_launchable_by(&user_cred, &uid_prof).is_ok());
        assert!(check_launchable_by(&root_cred, &uid_prof).is_err());

        // Numeric GID match
        let gid_prof = test_profile("team", vec![Principal::Gid(1000)]);
        assert!(check_launchable_by(&user_cred, &gid_prof).is_ok());

        // Quarantine: empty launchable_by -> nobody may launch
        let q_prof = test_profile("quarantine", Vec::new());
        assert!(check_launchable_by(&root_cred, &q_prof).is_err());
        assert!(check_launchable_by(&user_cred, &q_prof).is_err());
    }
}
