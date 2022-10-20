#! /usr/bin/env bash

set -v -e -u -o pipefail

cd "$(dirname "$BASH_SOURCE")"

bindgen XKCP-K12/lib/KangarooTwelve.h --whitelist-function=KangarooTwelve_{Initialize,Update,Final,Squeeze} --size_t-is-usize -- -m64 -I XKCP-K12/lib/Optimized64 > src/ffi_optimized64.rs
bindgen XKCP-K12/lib/KangarooTwelve.h --whitelist-function=KangarooTwelve_{Initialize,Update,Final,Squeeze} --size_t-is-usize -- -m64 -I XKCP-K12/lib/Plain64 > src/ffi_plain64.rs
bindgen XKCP-K12/lib/KangarooTwelve.h --whitelist-function=KangarooTwelve_{Initialize,Update,Final,Squeeze} --size_t-is-usize -- -m32 -I XKCP-K12/lib/Inplace32BI > src/ffi_inplace32bi.rs
