# kangarootwelve_xkcp.rs [![Actions Status](https://github.com/oconnor663/kangarootwelve_xkcp.rs/workflows/tests/badge.svg)](https://github.com/oconnor663/kangarootwelve_xkcp.rs/actions) [![docs.rs](https://docs.rs/kangarootwelve_xkcp/badge.svg)](https://docs.rs/kangarootwelve_xkcp) [![crates.io](https://img.shields.io/crates/v/kangarootwelve_xkcp.svg)](https://crates.io/crates/kangarootwelve_xkcp)

A Rust wrapper around the [eXtended Keccak Code Package
implementation](https://github.com/XKCP/K12) of the
[KangarooTwelve](https://keccak.team/kangarootwelve.html) cryptographic
hash function. That implementation includes SSSE3, AVX2, and AVX-512
optimizations, and it detects processor support at runtime. The `k12sum`
sub-crate provides a command line interface.

This package wraps C code via FFI, so you have to have a C compiler
installed to build it.

## Usage

### The `k12sum` command line utility

`k12sum` hashes files or data from standard input using KangarooTwelve.
Prebuilt binaries are available for Linux, Windows, and macOS (requiring
the [unidentified developer
workaround](https://support.apple.com/guide/mac-help/open-a-mac-app-from-an-unidentified-developer-mh40616/mac))
on the [releases page](https://github.com/oconnor663/kangarootwelve_xkcp.rs/releases).

To build `k12sum` yourself:

1. Make sure you have a working C compiler. On Linux and macOS, you can
   run `gcc --version` to check that GCC (or Clang pretending to be GCC)
   is installed. On Windows, if you don't already have Visual Studio
   installed, you can install the [C++ Build Tools for Visual Studio
   2019](https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2019).
2. [Install Rust and Cargo.](https://doc.rust-lang.org/cargo/getting-started/installation.html)
3. Run `cargo install k12sum`.

If `rustup` didn't configure your `PATH` for you, you might need to go
looking for the installed binary in e.g. `~/.cargo/bin`. You can test
out how fast KangarooTwelve is on your machine by creating a big file
and hashing it, for example as follows:

```bash
# Create a 1 GB file.
head -c 1000000000 /dev/zero > /tmp/bigfile
# Hash it with SHA-256.
time openssl sha256 /tmp/bigfile
# Hash it with KangarooTwelve.
time k12sum /tmp/bigfile
```

### The `kangarootwelve_xkcp` Rust crate

To use KangarooTwelve from Rust code, add a dependency on the
`kangarootwelve_xkcp` crate to your `Cargo.toml`. Here's an example of
hashing some bytes:

```rust
// Hash an input all at once.
let hash1 = kangarootwelve_xkcp::hash(b"foobarbaz");

// Hash an input incrementally.
let mut hasher = kangarootwelve_xkcp::Hasher::new();
hasher.update(b"foo");
hasher.update(b"bar");
hasher.update(b"baz");
let hash2 = hasher.finalize();
assert_eq!(hash1, hash2);

// Extended output. OutputReader also implements Read.
let mut hasher = kangarootwelve_xkcp::Hasher::new();
hasher.update(b"foobarbaz");
let mut output_reader = hasher.finalize_xof();
let mut output = [0; 1000];
output_reader.squeeze(&mut output);
assert_eq!(&output[..32], hash1.as_bytes());

// Print a hash as hex.
println!("{}", hash1.to_hex());
```

## License

The Rust wrapping code in this project is released into the public
domain via [CC0](https://creativecommons.org/publicdomain/zero/1.0/).
Vendored [XKCP](https://github.com/XKCP/XKCP) code is covered by a
[mixture of
licenses](https://github.com/XKCP/XKCP#under-which-license-is-the-xkcp-distributed).
