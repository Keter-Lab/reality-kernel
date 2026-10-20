//! With the `embedded-bpf` feature, points `RK_BPF_DIR` at the objects built by
//! `make -C rk-bpf ARCH=<arch>` so tests/integration can embed them with `include_bytes!`.

use std::env;
use std::path::PathBuf;

const OBJECTS: [&str; 2] = ["rk.bpf.o", "rk_emitfail.bpf.o"];

fn main() {
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_EMBEDDED_BPF");
    if env::var_os("CARGO_FEATURE_EMBEDDED_BPF").is_none() {
        return;
    }

    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").expect("CARGO_CFG_TARGET_ARCH");
    let bpf_arch = match target_arch.as_str() {
        "x86_64" => "x86",
        "aarch64" => "arm64",
        other => panic!("embedded-bpf: unsupported target arch `{other}`"),
    };

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let dir = manifest_dir.join("../../rk-bpf/build").join(bpf_arch);
    for object in OBJECTS {
        let path = dir.join(object);
        println!("cargo:rerun-if-changed={}", path.display());
        if !path.is_file() {
            panic!(
                "embedded-bpf: missing {}; run `make -C rk-bpf ARCH={bpf_arch}` first",
                path.display()
            );
        }
    }
    let dir = dir.canonicalize().expect("canonicalize rk-bpf build dir");
    println!("cargo:rustc-env=RK_BPF_DIR={}", dir.display());
}
