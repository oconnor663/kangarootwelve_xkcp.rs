# kangarootwelve-xkcp [![Actions Status](https://github.com/oconnor663/kangarootwelve-xkcp/workflows/tests/badge.svg)](https://github.com/oconnor663/kangarootwelve-xkcp/actions)

A Rust wrapper around the [eXtended Keccak Code Package
implementation](https://github.com/XKCP/K12) of the
[KangarooTwelve](https://keccak.team/kangarootwelve.html) cryptographic
hash function. That implementation includes SSSE3, AVX2, and AVX-512
optimizations, and it detects processor support at runtime. The `k12sum`
sub-crate (coming soon) provides a command line interface.

## Building

[As with XKCP
upstream](https://github.com/XKCP/XKCP#how-can-i-build-the-xkcp), the
following tools are needed:

- GCC
- GNU make
- xsltproc
  - **Important!** You probably don't have this one, which will lead to
    a confusing build error. Install it first with `apt-get install
    xsltproc` or similar.

This crate is currently tested only on Linux. Building on macOS or
Windows might work, with the dependencies listed above. But if you try
it and run into trouble, please open an issue.

## License

The Rust wrapping code in this project is released into the public
domain via [CC0](https://creativecommons.org/publicdomain/zero/1.0/).
Vendored [XKCP](https://github.com/XKCP/XKCP) code is covered by a
[mixture of
licenses](https://github.com/XKCP/XKCP#under-which-license-is-the-xkcp-distributed).
