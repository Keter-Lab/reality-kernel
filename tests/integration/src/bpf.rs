//! Embedded BPF bytecode access for rk-integration.

#[cfg(feature = "embedded-bpf")]
mod embedded {
    pub static RK_BPF: &[u8] =
        aya::include_bytes_aligned!(concat!(env!("RK_BPF_DIR"), "/rk.bpf.o"));
    pub static RK_EMITFAIL: &[u8] =
        aya::include_bytes_aligned!(concat!(env!("RK_BPF_DIR"), "/rk_emitfail.bpf.o"));
}

pub fn rk_bpf_bytes() -> Option<&'static [u8]> {
    #[cfg(feature = "embedded-bpf")]
    {
        Some(embedded::RK_BPF)
    }
    #[cfg(not(feature = "embedded-bpf"))]
    {
        None
    }
}

pub fn rk_emitfail_bytes() -> Option<&'static [u8]> {
    #[cfg(feature = "embedded-bpf")]
    {
        Some(embedded::RK_EMITFAIL)
    }
    #[cfg(not(feature = "embedded-bpf"))]
    {
        None
    }
}
