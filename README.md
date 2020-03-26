# kangarootwelve-xkcp.rs [![Actions Status](https://github.com/oconnor663/kangarootwelve-xkcp.rs/workflows/tests/badge.svg)](https://github.com/oconnor663/kangarootwelve-xkcp.rs/actions)

A Rust wrapper around the [eXtended Keccak Code Package
implementation](https://github.com/XKCP/K12) of the
[KangarooTwelve](https://keccak.team/kangarootwelve.html) cryptographic
hash function. That implementation includes SSSE3, AVX2, and AVX-512
optimizations, and it detects processor support at runtime. The `k12sum`
sub-crate provides a command line interface.

## Building

`cargo install k12sum`

This crate currently builds SIMD optimizations only on x86\_64 Linux.
Windows and macOS are supported, but they build the slower "generic32"
implementation. This should be fixable in a future version.

## License

The Rust wrapping code in this project is released into the public
domain via [CC0](https://creativecommons.org/publicdomain/zero/1.0/).
Vendored [XKCP](https://github.com/XKCP/XKCP) code is covered by a
[mixture of
licenses](https://github.com/XKCP/XKCP#under-which-license-is-the-xkcp-distributed).
