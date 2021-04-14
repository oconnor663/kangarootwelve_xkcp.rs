#! /usr/bin/env bash

set -e -u -o pipefail

here="$(dirname "$BASH_SOURCE")"

generate() {
  bindgen \
    "$here/../XKCP-K12/lib/KangarooTwelve.h" \
    --whitelist-function=KangarooTwelve_{Initialize,Update,Final,Squeeze} \
    --size_t-is-usize \
    -- \
    -m"$1" \
    -I "$2" \
    > "$3"
}

generate 64 "$here/../XKCP-K12/lib/Optimized64" "$here/ffi_optimized64.rs"
generate 64 "$here/../XKCP-K12/lib/Plain64"     "$here/ffi_plain64.rs"
generate 32 "$here/../XKCP-K12/lib/Inplace32BI" "$here/ffi_inplace32bi.rs"
