#![cfg_attr(target_arch = "bpf", no_std)]
#![cfg_attr(target_arch = "bpf", no_main)]

#[cfg(target_arch = "bpf")]
mod exec_probe;
#[cfg(target_arch = "bpf")]
mod file_probe;
#[cfg(target_arch = "bpf")]
mod maps;
#[cfg(target_arch = "bpf")]
mod net_probe;
#[cfg(target_arch = "bpf")]
mod unlink_probe;
#[cfg(target_arch = "bpf")]
mod util;

#[cfg(target_arch = "bpf")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[cfg(not(target_arch = "bpf"))]
fn main() {
    // Host-target stub so `cargo check --workspace` passes in CI/local environments.
}
