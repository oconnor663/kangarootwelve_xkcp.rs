// ffi_generic32.rs and ffi_generic64.rs are almost exactly the output from
// bindgen. However, we need to manually insert some extra padding (see the XXX
// comments), to work around https://github.com/rust-lang/rust-bindgen/issues/1753.
// Be careful to preserve this tweak when regenerating these files, until that
// issue is fixed.
#[cfg(k12_target = "generic64")]
#[path = "ffi_generic64.rs"]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
mod ffi;
#[cfg(k12_target = "generic32")]
#[path = "ffi_generic32.rs"]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
mod ffi;

#[cfg(test)]
mod test;

use arrayvec::ArrayString;
use std::fmt;
use std::mem::MaybeUninit;

pub const RATE: usize = 168; // (1600 - 256) / 8

pub fn hash(input: &[u8]) -> Hash {
    let mut hasher = Hasher::new();
    hasher.update(input);
    hasher.finalize()
}

#[derive(Clone)]
pub struct Hasher(ffi::KangarooTwelve_Instance);

impl Hasher {
    pub fn new() -> Self {
        let mut inner = MaybeUninit::uninit();
        let inner = unsafe {
            let ret = ffi::KangarooTwelve_Initialize(inner.as_mut_ptr(), 0);
            debug_assert_eq!(0, ret);
            inner.assume_init()
        };
        // These asserts help check that our struct definitions agree with C.
        debug_assert_eq!(0, inner.fixedOutputLength);
        debug_assert_eq!(0, inner.blockNumber);
        debug_assert_eq!(0, inner.queueAbsorbedLen);
        debug_assert_eq!(ffi::KCP_Phases_ABSORBING, inner.phase);
        // Go ahead and use these three so that they're not dead code.
        debug_assert!(ffi::KCP_Phases_NOT_INITIALIZED != inner.phase);
        debug_assert!(ffi::KCP_Phases_FINAL != inner.phase);
        debug_assert!(ffi::KCP_Phases_SQUEEZING != inner.phase);
        debug_assert_eq!(1600 - 256, inner.finalNode.rate);
        debug_assert_eq!(0, inner.finalNode.byteIOIndex);
        debug_assert_eq!(0, inner.finalNode.squeezing);
        Self(inner)
    }

    pub fn update(&mut self, input: &[u8]) {
        assert_eq!(
            ffi::KCP_Phases_ABSORBING,
            self.0.phase,
            "this instance has already been finalized"
        );
        unsafe {
            let ret = ffi::KangarooTwelve_Update(&mut self.0, input.as_ptr(), input.len());
            debug_assert_eq!(0, ret);
        }
    }

    pub fn finalize(&mut self) -> Hash {
        self.finalize_custom(&[])
    }

    pub fn finalize_custom(&mut self, customization: &[u8]) -> Hash {
        assert_eq!(
            ffi::KCP_Phases_ABSORBING,
            self.0.phase,
            "this instance has already been finalized"
        );
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

    pub fn finalize_xof(&mut self) -> OutputReader {
        self.finalize_custom_xof(&[])
    }

    pub fn finalize_custom_xof(&mut self, customization: &[u8]) -> OutputReader {
        assert_eq!(
            ffi::KCP_Phases_ABSORBING,
            self.0.phase,
            "this instance has already been finalized"
        );
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
        debug_assert_eq!(
            ffi::KCP_Phases_SQUEEZING,
            self.0.phase,
            "this instance has not yet been finalized"
        );
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
