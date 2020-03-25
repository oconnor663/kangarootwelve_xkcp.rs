use std::env;

fn main() {
    let mut build = cc::Build::new();
    build.include("XKCP-K12/lib");
    build.file("XKCP-K12/lib/KangarooTwelve.c");
    let k12_target;
    match env::var("CARGO_CFG_TARGET_POINTER_WIDTH").unwrap().as_str() {
        "64" => {
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

            k12_target = "generic64";
        }
        "32" => {
            build.include("XKCP-K12/lib/Inplace32BI");
            build.file("XKCP-K12/lib/Inplace32BI/KeccakP-1600-inplace32BI.c");
            // The 32-bit code includes a switch with intentional fallthrough.
            build.flag("-Wno-implicit-fallthrough");
            k12_target = "generic32";
        }
        x => panic!("unexpected target pointer width: {}", x),
    };
    build.compile("k12");
    println!("cargo:rustc-cfg=k12_target=\"{}\"", k12_target);
}
