A Rust wrapper around the [eXtended Keccak Code Package
implementation](https://github.com/XKCP/K12) of the
[KangarooTwelve](https://keccak.team/kangarootwelve.html) cryptographic
hash function. That implementation includes SSSE3, AVX2, and AVX-512
optimizations, and it detects processor support at runtime. The `k12sum`
sub-crate provides a command line interface.
