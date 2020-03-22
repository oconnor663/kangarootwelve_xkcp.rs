use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    // TODO: Re-targeting this to "generic32" is not trivial. Different header
    // files get imported, and the size/alignment of structs changes. A lot of
    // implementation details will need to depend on the target word size.
    let build_target = "generic64";

    let manifest_dir: PathBuf = env::var("CARGO_MANIFEST_DIR").unwrap().into();
    let k12_dir = manifest_dir.join("XKCP-K12");
    let build_dir = k12_dir.join(format!("bin/{}", build_target));
    let build_status = Command::new("make")
        .arg(format!("{}/libk12.a", build_target))
        .current_dir(&k12_dir)
        .status()
        .unwrap();
    assert!(build_status.success());
    println!("cargo:rustc-link-search={}", build_dir.to_str().unwrap());
    println!("cargo:rustc-link-lib=static=k12");

    // Note that because this build relies on Make, it's not good at noticing
    // changes. In general you'll need to `cargo clean` whenever you change
    // something.
}
