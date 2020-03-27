# kangarootwelve_xkcp.rs [![Actions Status](https://github.com/oconnor663/kangarootwelve_xkcp.rs/workflows/tests/badge.svg)](https://github.com/oconnor663/kangarootwelve_xkcp.rs/actions)

A Rust wrapper around the [eXtended Keccak Code Package
implementation](https://github.com/XKCP/K12) of the
[KangarooTwelve](https://keccak.team/kangarootwelve.html) cryptographic
hash function. That implementation includes SSSE3, AVX2, and AVX-512
optimizations, and it detects processor support at runtime. The `k12sum`
sub-crate provides a command line interface.

## Usage

### `k12sum`

The `k12sum` command line utility allows you to hash files and data from
standard input using KangarooTwelve. To install it, first [install Rust
and Cargo](https://doc.rust-lang.org/cargo/getting-started/installation.html),
and then run:

```bash
cargo install k12sum
```

If `rustup` didn't configure your `PATH` for you, you might need to go
looking for the installed binary in e.g. `~/.cargo/bin`. You can test
out how fast KangarooTwelve is on your machine (but see the
[Performance](#performance) section below) by creating a big file and
hashing it, for example as follows:

```bash
# Create a 1 GB file.
head -c 1000000000 /dev/zero > /tmp/bigfile
# Hash it with SHA-256.
time openssl sha256 /tmp/bigfile
# Hash it with KangarooTwelve.
time k12sum /tmp/bigfile
```

### The `kangarootwelve_xkcp` crate

To use KangarooTwelve from Rust code, add a dependency on the
`kangarootwelve_xkcp` crate to your `Cargo.toml`. Here's an example of
hashing some input bytes:

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
# #[cfg(feature = "std")] {
let mut hasher = kangarootwelve_xkcp::Hasher::new();
hasher.update(b"foobarbaz");
let mut output_reader = hasher.finalize_xof();
let mut output = [0; 1000];
output_reader.squeeze(&mut output);
assert_eq!(&output[..32], hash1.as_bytes());
```

## Performance

This crate currently builds SIMD optimizations only on x86\_64 Linux.
Windows and macOS are supported, but they build the slower "generic32"
implementation. If you're using this crate to compare benchmarks of
different hash functions, you'll need to do it on x86\_64 Linux. This
might change in a future version.

## License

The Rust wrapping code in this project is released into the public
domain via [CC0](https://creativecommons.org/publicdomain/zero/1.0/).
Vendored [XKCP](https://github.com/XKCP/XKCP) code is covered by a
[mixture of
licenses](https://github.com/XKCP/XKCP#under-which-license-is-the-xkcp-distributed).
