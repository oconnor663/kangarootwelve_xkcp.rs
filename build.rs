//! NOTE: This build does *not* use the upstream makefile system. Instead, it
//! executes the C compiler directly, via the `cc` crate. That avoids taking
//! build dependencies on make and xsltproc, which would be problematic on
//! Windows. However, it does mean that we'll need to be careful to track build
//! changes when we re-vendor upstream code.

use std::env;
use std::path::PathBuf;

enum Implementation {
    Optimized64,
    Optimized64NoAsm, // Note that Optimized64NoAsm uses the same bindings as Optimized64.
    Plain64,
    Inplace32BI,
}

fn generate_bindings(implementation: &Implementation) {
    let arch_arg = match implementation {
        Implementation::Optimized64
        | Implementation::Optimized64NoAsm
        | Implementation::Plain64 => "-m64",
        Implementation::Inplace32BI => "-m32",
    };
    let include_dir = match implementation {
        Implementation::Optimized64 | Implementation::Optimized64NoAsm => {
            "XKCP-K12/lib/Optimized64"
        }
        Implementation::Plain64 => "XKCP-K12/lib/Plain64",
        Implementation::Inplace32BI => "XKCP-K12/lib/Inplace32BI",
    };
    let bindings = bindgen::Builder::default()
        .header("XKCP-K12/lib/KangarooTwelve.h")
        .clang_arg(arch_arg)
        .clang_arg(format!("-I{}", include_dir))
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("failed to generate KangarooTwelve bindings");
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap()).join("bindings.rs");
    bindings
        .write_to_file(out_path)
        .expect("failed to write KangarooTwelve bindings");
}

fn main() {
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    let target_pointer_width = env::var("CARGO_CFG_TARGET_POINTER_WIDTH").unwrap();
    let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap(); // e.g. "msvc" on Windows
    let target_is_little_endian = match env::var("CARGO_CFG_TARGET_ENDIAN").unwrap().as_str() {
        "little" => true,
        "big" => false,
        e @ _ => panic!("unexpected endianness: {}", e),
    };

    let target_implementation = if target_arch == "x86_64" {
        if target_os != "windows" {
            Implementation::Optimized64
        } else {
            // The current assembly implementation doesn't include a Windows
            // assembler syntax version.
            Implementation::Optimized64NoAsm
        }
    } else if target_pointer_width == "64" {
        Implementation::Plain64
    } else if target_pointer_width == "32" {
        Implementation::Inplace32BI
    } else {
        panic!("unsupported target pointer width: {}", target_pointer_width);
    };

    // Configure the base_build, which might be used for multiple different
    // compilation steps below.
    let mut base_build = cc::Build::new();
    base_build.include("XKCP-K12/lib");
    // brg_endian.h tries to detect the target endianness, but it fails on e.g.
    // mips. Cargo knows better, so we explicitly set the preprocessor
    // variables that brg_endian.h looks for.
    if target_is_little_endian {
        base_build.define("LITTLE_ENDIAN", "1");
    } else {
        base_build.define("BIG_ENDIAN", "1");
    }
    match &target_implementation {
        Implementation::Optimized64 | Implementation::Optimized64NoAsm => {
            // These two targets share headers.
            base_build.include("XKCP-K12/lib/Optimized64");
        }
        Implementation::Plain64 => {
            base_build.include("XKCP-K12/lib/Plain64");
        }
        Implementation::Inplace32BI => {
            base_build.include("XKCP-K12/lib/Inplace32BI");
        }
    }
    if let Implementation::Optimized64NoAsm = &target_implementation {
        // Since Optimized64 and Optimized64NoAsm use the same header file,
        // KeccakP-1600-runtimeDispatch.c relies on this preprocessor var to
        // distinguish them.
        base_build.define("KeccakP1600_noAssembly", "1");
    }
    let base_build = base_build; // immutable from here on

    let mut portable_build = base_build.clone();
    let c_files = [
        "KangarooTwelve.c",
        "KangarooTwelve-threading.c",
        "KT-threadpool.c",
        "KT-threadpool-pthread.c",
        "KT-threadpool-sequential.c",
    ];
    for c_file in c_files {
        portable_build.file(format!("XKCP-K12/lib/{}", c_file));
    }

    match &target_implementation {
        Implementation::Optimized64 | Implementation::Optimized64NoAsm => {
            portable_build.file("XKCP-K12/lib/Optimized64/KeccakP-1600-opt64.c");
            portable_build.file("XKCP-K12/lib/Optimized64/KeccakP-1600-runtimeDispatch.c");

            let mut ssse3_build = base_build.clone();
            if target_env != "msvc" {
                ssse3_build.flag("-mssse3");
            }
            ssse3_build.file("XKCP-K12/lib/Optimized64/KeccakP-1600-timesN-SSSE3.c");
            ssse3_build.compile("k12_ssse3");

            let mut avx2_build = base_build.clone();
            if target_env == "msvc" {
                avx2_build.flag("/arch:AVX2");
            } else {
                avx2_build.flag("-mavx2");
            }
            avx2_build.file("XKCP-K12/lib/Optimized64/KeccakP-1600-timesN-AVX2.c");
            avx2_build.compile("k12_avx2");

            let mut avx512_build = base_build.clone();
            if target_env == "msvc" {
                avx2_build.flag("/arch:AVX512");
            } else {
                avx512_build.flag("-mavx512f");
                avx512_build.flag("-mavx512vl");
            }
            avx512_build.file("XKCP-K12/lib/Optimized64/KeccakP-1600-timesN-AVX512.c");
            // For the non-asm build we add another file below.

            if let Implementation::Optimized64 = &target_implementation {
                let mut asm_build = base_build.clone();
                asm_build.file("XKCP-K12/lib/Optimized64/KeccakP-1600-AVX2.s");
                asm_build.file("XKCP-K12/lib/Optimized64/KeccakP-1600-AVX512.s");
                if target_os == "macos" {
                    // see https://github.com/XKCP/K12/blob/b4f434574c501b1088468180feeeaab6117341e4/support/Build/ToTargetMakefile.xsl#L178
                    asm_build.flag("-xassembler-with-cpp");
                    asm_build.flag("-Wa,-defsym,macOS=1");
                }
                asm_build.compile("k12_asm");
            } else {
                avx512_build.file("XKCP-K12/lib/Optimized64/KeccakP-1600-AVX512-plainC.c");
            }

            avx512_build.compile("k12_avx512");
        }
        Implementation::Plain64 => {
            portable_build.file("XKCP-K12/lib/Optimized64/KeccakP-1600-opt64.c");
            portable_build.file("XKCP-K12/lib/Plain64/KeccakP-1600-plain64.c");
        }
        Implementation::Inplace32BI => {
            portable_build.file("XKCP-K12/lib/Inplace32BI/KeccakP-1600-inplace32BI.c");
        }
    }

    portable_build.compile("k12");

    generate_bindings(&target_implementation);
}
