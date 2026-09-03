use anyhow::{Context, Result};
use aya::programs::{CgroupAttachMode, CgroupSockAddr, Lsm, TracePoint};
use aya::{Btf, Ebpf};

pub struct LoadedProbes {
    pub ebpf: Ebpf,
    pub attached_hooks: Vec<String>,
}

pub fn load_and_attach() -> Result<LoadedProbes> {
    let object_path = std::env::var("RK_EBPF_OBJECT")
        .unwrap_or_else(|_| "target/bpfel-unknown-none/debug/rk-ebpf-probes".to_string());
    let object_bytes = std::fs::read(&object_path)
        .with_context(|| format!("failed to read eBPF object at {object_path}"))?;
    let mut ebpf = Ebpf::load(&object_bytes)
        .context("failed to load eBPF object bytes")?;

    let mut attached = Vec::new();
    let cgroup = std::fs::File::open("/sys/fs/cgroup")
        .context("failed to open /sys/fs/cgroup")?;

    {
        let tp: &mut TracePoint = ebpf
            .program_mut("exec_enter_execve")
            .context("missing exec_enter_execve program")?
            .try_into()
            .context("exec_enter_execve type conversion failed")?;
        tp.load().context("load exec_enter_execve failed")?;
        tp.attach("syscalls", "sys_enter_execve")
            .context("attach sys_enter_execve failed")?;
        attached.push("tracepoint/syscalls/sys_enter_execve".to_string());
    }

    {
        let tp: &mut TracePoint = ebpf
            .program_mut("exec_enter_execveat")
            .context("missing exec_enter_execveat program")?
            .try_into()
            .context("exec_enter_execveat type conversion failed")?;
        tp.load().context("load exec_enter_execveat failed")?;
        tp.attach("syscalls", "sys_enter_execveat")
            .context("attach sys_enter_execveat failed")?;
        attached.push("tracepoint/syscalls/sys_enter_execveat".to_string());
    }

    let file_lsm_attached = {
        let lsm: &mut Lsm = ebpf
            .program_mut("rk_lsm_file_open")
            .context("missing rk_lsm_file_open program")?
            .try_into()
            .context("rk_lsm_file_open type conversion failed")?;

        let btf = Btf::from_sys_fs().context("failed to load kernel BTF from /sys/kernel/btf/vmlinux")?;
        lsm.load("file_open", &btf)
            .context("load rk_lsm_file_open failed")?;
        match lsm.attach() {
            Ok(_) => {
                attached.push("lsm/file_open".to_string());
                true
            }
            Err(err) => {
                tracing::warn!("LSM attach failed, using fallback openat tracepoint: {err}");
                false
            }
        }
    };

    if !file_lsm_attached {
        let tp: &mut TracePoint = ebpf
            .program_mut("openat_enter")
            .context("missing openat_enter fallback program")?
            .try_into()
            .context("openat_enter type conversion failed")?;
        tp.load().context("load openat_enter failed")?;
        tp.attach("syscalls", "sys_enter_openat")
            .context("attach sys_enter_openat fallback failed")?;
        attached.push("tracepoint/syscalls/sys_enter_openat (fallback)".to_string());
    }

    {
        let tp: &mut TracePoint = ebpf
            .program_mut("unlinkat_enter")
            .context("missing unlinkat_enter program")?
            .try_into()
            .context("unlinkat_enter type conversion failed")?;
        tp.load().context("load unlinkat_enter failed")?;
        tp.attach("syscalls", "sys_enter_unlinkat")
            .context("attach sys_enter_unlinkat failed")?;
        attached.push("tracepoint/syscalls/sys_enter_unlinkat".to_string());
    }

    {
        let connect4: &mut CgroupSockAddr = ebpf
            .program_mut("rk_connect4")
            .context("missing rk_connect4 program")?
            .try_into()
            .context("rk_connect4 type conversion failed")?;
        connect4.load().context("load rk_connect4 failed")?;
        connect4
            .attach(&cgroup, CgroupAttachMode::Single)
            .context("attach cgroup/connect4 failed")?;
        attached.push("cgroup/connect4".to_string());
    }

    {
        let connect6: &mut CgroupSockAddr = ebpf
            .program_mut("rk_connect6")
            .context("missing rk_connect6 program")?
            .try_into()
            .context("rk_connect6 type conversion failed")?;
        connect6.load().context("load rk_connect6 failed")?;
        connect6
            .attach(&cgroup, CgroupAttachMode::Single)
            .context("attach cgroup/connect6 failed")?;
        attached.push("cgroup/connect6".to_string());
    }

    Ok(LoadedProbes {
        ebpf,
        attached_hooks: attached,
    })
}
