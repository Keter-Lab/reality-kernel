//! Generates the ABI bindings from `rk-bpf/include/rk_abi.h` at build time, so the
//! Rust layout can never drift from the C header.

use std::env;
use std::path::PathBuf;

use bindgen::callbacks::{DeriveInfo, ParseCallbacks, TypeKind};

/// Adds `Pod`/`Zeroable` to every ABI struct. `derive(Pod)` refuses to compile a
/// struct with implicit padding, which enforces the padding-free ABI rule.
#[derive(Debug)]
struct PodDerives;

impl ParseCallbacks for PodDerives {
    fn add_derives(&self, info: &DeriveInfo<'_>) -> Vec<String> {
        if matches!(info.kind, TypeKind::Struct) && info.name.starts_with("rk_") {
            vec!["bytemuck::Pod".into(), "bytemuck::Zeroable".into()]
        } else {
            Vec::new()
        }
    }
}

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let include_dir = manifest_dir.join("../rk-bpf/include");
    let header = include_dir.join("rk_abi.h");
    println!("cargo:rerun-if-changed={}", header.display());

    let wrapper = "\
typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
#include \"rk_abi.h\"
";

    let bindings = bindgen::Builder::default()
        .header_contents("rk_abi_wrapper.h", wrapper)
        .clang_arg(format!("-I{}", include_dir.display()))
        .clang_arg("-DRK_ABI_TYPES_PROVIDED")
        .use_core()
        .allowlist_type("rk_.*")
        .allowlist_var("RK_.*")
        .constified_enum_module("rk_.*")
        .derive_debug(true)
        .derive_default(false)
        .derive_partialeq(true)
        .derive_eq(true)
        .layout_tests(true)
        .parse_callbacks(Box::new(PodDerives))
        .generate()
        .expect("bindgen failed to process rk-bpf/include/rk_abi.h");

    let out = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR")).join("rk_abi.rs");
    bindings
        .write_to_file(&out)
        .expect("failed to write generated ABI bindings");
}
