use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let k12_target = match env::var("CARGO_CFG_TARGET_POINTER_WIDTH").unwrap().as_str() {
        "64" => "generic64",
        "32" => "generic32",
        x => panic!("unexpected target pointer width: {}", x),
    };
    println!("cargo:rustc-cfg=k12_target=\"{}\"", k12_target);

    let manifest_dir: PathBuf = env::var("CARGO_MANIFEST_DIR").unwrap().into();
    let k12_dir = manifest_dir.join("XKCP-K12");
    let build_dir = k12_dir.join(format!("bin/{}", k12_target));
    let build_status = Command::new("make")
        .arg(format!("{}/libk12.a", k12_target))
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
