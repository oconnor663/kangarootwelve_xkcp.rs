use std::env;

fn main() {
    let mut build = cc::Build::new();
    build.include("XKCP-K12/lib");
    build.file("XKCP-K12/lib/KangarooTwelve.c");

    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let k12_target;
    if target_arch == "x86_64" {
        k12_target = "generic64";
        build.include("XKCP-K12/lib/Optimized64");
        build.file("XKCP-K12/lib/Optimized64/KeccakP-1600-opt64.c");
        build.file("XKCP-K12/lib/Optimized64/KeccakP-1600-AVX2.s");
        build.file("XKCP-K12/lib/Optimized64/KeccakP-1600-AVX512.s");

        let mut ssse3_build = cc::Build::new();
        ssse3_build.flag("-mssse3");
        ssse3_build.file("XKCP-K12/lib/Optimized64/KeccakP-1600-timesN-SSSE3.c");
        ssse3_build.compile("k12_ssse3");
        ssse3_build.compile("k12_ssse3");

        let mut avx2_build = cc::Build::new();
        avx2_build.flag("-mavx2");
        avx2_build.file("XKCP-K12/lib/Optimized64/KeccakP-1600-timesN-AVX2.c");
        avx2_build.compile("k12_avx2");

        let mut avx512_build = cc::Build::new();
        avx512_build.flag("-mavx512f");
        avx512_build.flag("-mavx512vl");
        avx512_build.file("XKCP-K12/lib/Optimized64/KeccakP-1600-timesN-AVX512.c");
        avx512_build.compile("k12_avx512");
    } else {
        k12_target = "generic32";
        build.include("XKCP-K12/lib/Inplace32BI");
        build.file("XKCP-K12/lib/Inplace32BI/KeccakP-1600-inplace32BI.c");
        // The 32-bit code includes a switch with intentional fallthrough.
        build.flag("-Wno-implicit-fallthrough");
        // The 32-bit code has some unused variables.
        build.flag("-Wno-unused-variable");
    }
    println!("cargo:rustc-cfg=k12_target=\"{}\"", k12_target);

    // brg_endian.h tries to detect the target endianness, but it fails on e.g.
    // mips. Cargo knows better, so we explicitly set the preprocessor
    // variables that brg_endian.h looks for.
    match env::var("CARGO_CFG_TARGET_ENDIAN").unwrap().as_str() {
        "little" => {
            build.define("LITTLE_ENDIAN", "1");
        }
        "big" => {
            build.define("BIG_ENDIAN", "1");
        }
        s => panic!("unexpected target endianness: {}", s),
    }

    build.compile("k12");
}
