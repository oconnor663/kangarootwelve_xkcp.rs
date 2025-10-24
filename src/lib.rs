//! A Rust wrapper around the [eXtended Keccak Code Package
//! implementation](https://github.com/XKCP/K12) of the
//! [KangarooTwelve](https://keccak.team/kangarootwelve.html) cryptographic
//! hash function.
//!
//! # Examples
//!
//! ```
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Hash an input all at once.
//! let hash1 = kangarootwelve_xkcp::hash(b"foobarbaz");
//!
//! // Hash an input incrementally.
//! let mut hasher = kangarootwelve_xkcp::Hasher::new();
//! hasher.update(b"foo");
//! hasher.update(b"bar");
//! hasher.update(b"baz");
//! let hash2 = hasher.finalize();
//! assert_eq!(hash1, hash2);
//!
//! // Extended output. OutputReader also implements Read.
//! let mut hasher = kangarootwelve_xkcp::Hasher::new();
//! hasher.update(b"foobarbaz");
//! let mut output_reader = hasher.finalize_xof();
//! let mut output = [0; 1000];
//! output_reader.squeeze(&mut output);
//! assert_eq!(&output[..32], hash1.as_bytes());
//!
//! // Print a hash as hex.
//! println!("{}", hash1.to_hex());
//! # Ok(())
//! # }
//! ```

// ffi_generic32.rs and ffi_generic64.rs are almost exactly the output from
// bindgen. However, we need to manually insert some extra padding (see the XXX
// comments), to work around https://github.com/rust-lang/rust-bindgen/issues/1753.
// Be careful to preserve this tweak when regenerating these files, until that
// issue is fixed.
#[cfg(k12_bindings = "optimized64")]
#[path = "ffi_optimized64.rs"]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
mod ffi;
#[cfg(k12_bindings = "plain64")]
#[path = "ffi_plain64.rs"]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
mod ffi;
#[cfg(k12_bindings = "inplace32bi")]
#[path = "ffi_inplace32bi.rs"]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
mod ffi;

#[cfg(test)]
mod test;

use arrayvec::ArrayString;
use std::fmt;
use std::mem::MaybeUninit;

/// The number of bytes hashed or output per block.
pub const RATE: usize = 168; // (1600 - 256) / 8

/// Hash a slice of bytes all at once. For multiple writes, the optional
/// customization string, or extended output bytes, see [`Hasher`].
///
/// [`Hasher`]: struct.Hasher.html
pub fn hash(input: &[u8]) -> Hash {
    let mut hasher = Hasher::new();
    hasher.update(input);
    hasher.finalize()
}

/// An incremental hash state that can accept any number of writes.
///
/// # Examples
///
/// ```
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// // Hash an input incrementally.
/// let mut hasher = kangarootwelve_xkcp::Hasher::new();
/// hasher.update(b"foo");
/// hasher.update(b"bar");
/// hasher.update(b"baz");
/// assert_eq!(hasher.finalize(), kangarootwelve_xkcp::hash(b"foobarbaz"));
///
/// // Extended output. OutputReader also implements Read and Seek.
/// let mut hasher = kangarootwelve_xkcp::Hasher::new();
/// hasher.update(b"foobarbaz");
/// let mut output = [0; 1000];
/// let mut output_reader = hasher.finalize_xof();
/// output_reader.squeeze(&mut output);
/// assert_eq!(&output[..32], kangarootwelve_xkcp::hash(b"foobarbaz").as_bytes());
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct Hasher(ffi::KangarooTwelve_Instance);

impl Hasher {
    /// Construct a new `Hasher` for the regular hash function.
    pub fn new() -> Self {
        let mut inner = MaybeUninit::uninit();
        let inner = unsafe {
            let ret = ffi::KangarooTwelve_Initialize(inner.as_mut_ptr(), 128, 0);
            debug_assert_eq!(0, ret);
            inner.assume_init()
        };
        // These asserts help check that our struct definitions agree with C.
        debug_assert_eq!(0, inner.fixedOutputLength);
        debug_assert_eq!(0, inner.blockNumber);
        debug_assert_eq!(0, inner.queueAbsorbedLen);
        debug_assert_eq!(inner.phase, 1);
        debug_assert_eq!(0, inner.finalNode.byteIOIndex);
        debug_assert_eq!(0, inner.finalNode.squeezing);
        Self(inner)
    }

    /// Add input bytes to the hash state. You can call this any number of
    /// times, until the `Hasher` is finalized.
    pub fn update(&mut self, input: &[u8]) {
        assert_eq!(self.0.phase, 1, "this instance has already been finalized");
        unsafe {
            let ret = ffi::KangarooTwelve_Update(&mut self.0, input.as_ptr(), input.len());
            debug_assert_eq!(0, ret);
        }
    }

    /// Finalize the hash state and return the [`Hash`](struct.Hash.html) of
    /// the input. This method is equivalent to
    /// [`finalize_custom`](#method.finalize_custom) with an empty
    /// customization string.
    ///
    /// You can only finalize a `Hasher` once. Additional calls to any of the
    /// finalize methods will panic.
    pub fn finalize(&mut self) -> Hash {
        self.finalize_custom(&[])
    }

    /// Finalize the hash state using the given customization string and return
    /// the [`Hash`](struct.Hash.html) of the input.
    ///
    /// You can only finalize a `Hasher` once. Additional calls to any of the
    /// finalize methods will panic.
    pub fn finalize_custom(&mut self, customization: &[u8]) -> Hash {
        assert_eq!(self.0.phase, 1, "this instance has already been finalized");
        let mut bytes = [0; 32];
        unsafe {
            let ret = ffi::KangarooTwelve_Final(
                &mut self.0,
                std::ptr::null_mut(),
                customization.as_ptr(),
                customization.len(),
            );
            debug_assert_eq!(0, ret);
            let ret = ffi::KangarooTwelve_Squeeze(&mut self.0, bytes.as_mut_ptr(), bytes.len());
            debug_assert_eq!(0, ret);
        }
        bytes.into()
    }

    /// Finalize the hash state and return an [`OutputReader`], which can
    /// supply any number of output bytes. This method is equivalent to
    /// [`finalize_custom_xof`](#method.finalize_custom_xof) with an empty
    /// customization string.
    ///
    /// You can only finalize a `Hasher` once. Additional calls to any of the
    /// finalize methods will panic.
    ///
    /// [`OutputReader`]: struct.OutputReader.html
    pub fn finalize_xof(&mut self) -> OutputReader {
        self.finalize_custom_xof(&[])
    }

    /// Finalize the hash state and return an [`OutputReader`], which can
    /// supply any number of output bytes.
    ///
    /// You can only finalize a `Hasher` once. Additional calls to any of the
    /// finalize methods will panic.
    ///
    /// [`OutputReader`]: struct.OutputReader.html
    pub fn finalize_custom_xof(&mut self, customization: &[u8]) -> OutputReader {
        assert_eq!(self.0.phase, 1, "this instance has already been finalized");
        unsafe {
            let ret = ffi::KangarooTwelve_Final(
                &mut self.0,
                std::ptr::null_mut(),
                customization.as_ptr(),
                customization.len(),
            );
            debug_assert_eq!(0, ret);
        }
        OutputReader(self.0)
    }
}

impl Default for Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for Hasher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Hasher").finish()
    }
}

/// An output of the default size, 32 bytes, which provides constant-time
/// equality checking.
///
/// `Hash` implements [`From`] and [`Into`] for `[u8; 32]`, and it provides an
/// explicit [`as_bytes`] method returning `&[u8; 32]`. However, byte arrays
/// and slices don't provide constant-time equality checking, which is often a
/// security requirement in software that handles private data. `Hash` doesn't
/// implement [`Deref`] or [`AsRef`], to avoid situations where a type
/// conversion happens implicitly and the constant-time property is
/// accidentally lost.
///
/// `Hash` provides the [`to_hex`] method for converting to hexadecimal. It
/// doesn't directly support converting from hexadecimal, but here's an example
/// of doing that with the [`hex`] crate:
///
/// ```
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # use kangarootwelve_xkcp::Hash;
/// use std::convert::TryInto;
///
/// let hash_hex = "d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24";
/// let hash_bytes = hex::decode(hash_hex)?;
/// let hash_array: [u8; 32] = hash_bytes[..].try_into()?;
/// let hash: Hash = hash_array.into();
/// # Ok(())
/// # }
/// ```
///
/// [`From`]: https://doc.rust-lang.org/std/convert/trait.From.html
/// [`Into`]: https://doc.rust-lang.org/std/convert/trait.Into.html
/// [`as_bytes`]: #method.as_bytes
/// [`Deref`]: https://doc.rust-lang.org/stable/std/ops/trait.Deref.html
/// [`AsRef`]: https://doc.rust-lang.org/std/convert/trait.AsRef.html
/// [`to_hex`]: #method.to_hex
/// [`hex`]: https://crates.io/crates/hex
#[derive(Clone, Copy, Hash)]
pub struct Hash([u8; 32]);

impl Hash {
    /// The bytes of the `Hash`. Note that byte arrays don't provide
    /// constant-time equality checking, so if  you need to compare hashes,
    /// prefer the `Hash` type.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The hexadecimal encoding of the `Hash`. The returned [`ArrayString`] is
    /// a fixed size and doesn't allocate memory on the heap. Note that
    /// [`ArrayString`] doesn't provide constant-time equality checking, so if
    /// you need to compare hashes, prefer the `Hash` type.
    ///
    /// [`ArrayString`]: https://docs.rs/arrayvec/0.5.1/arrayvec/struct.ArrayString.html
    pub fn to_hex(&self) -> ArrayString<[u8; 2 * 32]> {
        let mut s = ArrayString::new();
        let table = b"0123456789abcdef";
        for &b in self.0.iter() {
            s.push(table[(b >> 4) as usize] as char);
            s.push(table[(b & 0xf) as usize] as char);
        }
        s
    }
}

impl From<[u8; 32]> for Hash {
    #[inline]
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl From<Hash> for [u8; 32] {
    #[inline]
    fn from(hash: Hash) -> Self {
        hash.0
    }
}

/// This implementation is constant-time.
impl PartialEq for Hash {
    #[inline]
    fn eq(&self, other: &Hash) -> bool {
        constant_time_eq::constant_time_eq_32(&self.0, &other.0)
    }
}

/// This implementation is constant-time.
impl PartialEq<[u8; 32]> for Hash {
    #[inline]
    fn eq(&self, other: &[u8; 32]) -> bool {
        constant_time_eq::constant_time_eq_32(&self.0, other)
    }
}

impl Eq for Hash {}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Hash({})", self.to_hex())
    }
}

/// An incremental reader for extended output, returned by
/// [`Hasher::finalize_xof`](struct.Hasher.html#method.finalize_xof) and
/// [`Hasher::finalize_custom_xof`](struct.Hasher.html#method.finalize_custom_xof).
#[derive(Clone)]
pub struct OutputReader(ffi::KangarooTwelve_Instance);

impl OutputReader {
    /// Fill a buffer with output bytes and advance the position of the
    /// `OutputReader`. This is equivalent to [`Read::read`], except that it
    /// doesn't return a `Result`. Both methods always fill the entire buffer.
    ///
    /// [`Read::read`]: #method.read
    pub fn squeeze(&mut self, buf: &mut [u8]) {
        debug_assert_eq!(self.0.phase, 3, "this instance has not yet been finalized");
        unsafe {
            let ret = ffi::KangarooTwelve_Squeeze(&mut self.0, buf.as_mut_ptr(), buf.len());
            debug_assert_eq!(0, ret);
        }
    }
}

// Don't derive(Debug), because the state may be secret.
impl fmt::Debug for OutputReader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "OutputReader {{ ... }}")
    }
}

impl std::io::Read for OutputReader {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.squeeze(buf);
        Ok(buf.len())
    }
}
