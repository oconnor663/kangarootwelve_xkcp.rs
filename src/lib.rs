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

#[allow(dead_code)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
mod ffi {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

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
pub struct Hasher {
    instance: ffi::KangarooTwelve_Instance,
    #[cfg(feature = "rayon")]
    _pool: Option<Box<threadpool::RayonKTThreadPool>>,
}

// SAFETY: `KangarooTwelve_Instance` contains raw pointers, so we need to explicitly declare `Send`
// and `Sync`. All mutation is done through `&mut self` methods.
unsafe impl Send for Hasher {}
unsafe impl Sync for Hasher {}

impl Hasher {
    /// Construct a single-threaded KangarooTwelve `Hasher`.
    pub fn new() -> Self {
        let mut instance = MaybeUninit::uninit();
        let instance = unsafe {
            let ret = ffi::KangarooTwelve_Initialize(instance.as_mut_ptr(), 128, 0);
            debug_assert_eq!(0, ret);
            instance.assume_init()
        };
        // These asserts help check that our struct definitions agree with C.
        debug_assert_eq!(0, instance.fixedOutputLength);
        debug_assert_eq!(0, instance.blockNumber);
        debug_assert_eq!(0, instance.queueAbsorbedLen);
        debug_assert_eq!(instance.phase, 1);
        debug_assert_eq!(0, instance.finalNode.byteIOIndex);
        debug_assert_eq!(0, instance.finalNode.squeezing);
        Self {
            instance,
            #[cfg(feature = "rayon")]
            _pool: None,
        }
    }

    /// Construct a multithreaded KangarooTwelve `Hasher`.
    #[cfg(feature = "rayon")]
    pub fn new_rayon() -> Self {
        // Currently `thread_count` isn't used by the implementation, other than to check that it's
        // greater than 1. It would be a good idea for reviewers to verify this when revendoring
        // from upstream.
        let thread_count = 2;
        let pool = Box::new(threadpool::RayonKTThreadPool::new());
        let mut instance = MaybeUninit::uninit();
        let instance = unsafe {
            let ret = ffi::KangarooTwelve_Initialize_Threaded(
                instance.as_mut_ptr(),
                128,
                0,
                &threadpool::RAYON_THREADPOOL_API as *const _ as *const _,
                &*pool as *const _ as *const _ as *mut _,
                thread_count,
            );
            debug_assert_eq!(0, ret);
            instance.assume_init()
        };
        // These asserts help check that our struct definitions agree with C.
        debug_assert_eq!(0, instance.fixedOutputLength);
        debug_assert_eq!(0, instance.blockNumber);
        debug_assert_eq!(0, instance.queueAbsorbedLen);
        debug_assert_eq!(instance.phase, 1);
        debug_assert_eq!(0, instance.finalNode.byteIOIndex);
        debug_assert_eq!(0, instance.finalNode.squeezing);
        Self {
            instance,
            #[cfg(feature = "rayon")]
            _pool: Some(pool),
        }
    }

    /// Add input bytes to the hash state. You can call this any number of
    /// times, until the `Hasher` is finalized.
    pub fn update(&mut self, input: &[u8]) {
        assert_eq!(
            self.instance.phase, 1,
            "this instance has already been finalized"
        );
        unsafe {
            let ret = ffi::KangarooTwelve_Update(&mut self.instance, input.as_ptr(), input.len());
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
        assert_eq!(
            self.instance.phase, 1,
            "this instance has already been finalized"
        );
        let mut bytes = [0; 32];
        unsafe {
            let ret = ffi::KangarooTwelve_Final(
                &mut self.instance,
                std::ptr::null_mut(),
                customization.as_ptr(),
                customization.len(),
            );
            debug_assert_eq!(0, ret);
            let ret =
                ffi::KangarooTwelve_Squeeze(&mut self.instance, bytes.as_mut_ptr(), bytes.len());
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
        assert_eq!(
            self.instance.phase, 1,
            "this instance has already been finalized"
        );
        unsafe {
            let ret = ffi::KangarooTwelve_Final(
                &mut self.instance,
                std::ptr::null_mut(),
                customization.as_ptr(),
                customization.len(),
            );
            debug_assert_eq!(0, ret);
        }
        OutputReader(self.instance)
    }
}

impl Clone for Hasher {
    fn clone(&self) -> Self {
        #[cfg(feature = "rayon")]
        let pool = Box::new(threadpool::RayonKTThreadPool::new());
        #[allow(unused_mut)]
        let mut instance = self.instance;
        #[cfg(feature = "rayon")]
        {
            // The `threadpool_api` pointer is static, so it's still valid, but the
            // `threadpool_handle` pointer needs to point to the new pool.
            instance.threadpool_handle = (&*pool) as *const _ as *const _ as *mut _;
        }
        Self {
            instance,
            #[cfg(feature = "rayon")]
            _pool: Some(pool),
        }
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
    pub fn to_hex(&self) -> ArrayString<64> {
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

// SAFETY: Same as `Hasher` above.
unsafe impl Send for OutputReader {}
unsafe impl Sync for OutputReader {}

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

/// This threadpool implementation is a thin wrapper around `rayon::ParallelIterator`, which
/// collects jobs through `submit` and runs them all in parallel when `wait_all` is called. Note
/// that this approach should not be vulnerable to deadlocks, even if the hasher itself is
/// instantiated in a Rayon thread pool of size 1. See `test_rayon_small_pool`.
#[cfg(feature = "rayon")]
mod threadpool {
    use rayon::prelude::*;
    use std::ffi::{c_int, c_void};

    struct WorkItem {
        work_fn: Option<unsafe extern "C" fn(*mut c_void)>,
        work_data: *mut c_void,
    }

    // SAFETY: `WorkItem` is a task that C code is deliberately running on another thread, so it
    // had *better* be `Send`.
    unsafe impl Send for WorkItem {}

    pub struct RayonKTThreadPool {
        work_items: Vec<WorkItem>,
    }

    impl RayonKTThreadPool {
        pub fn new() -> Self {
            Self {
                work_items: Vec::new(),
            }
        }
    }

    pub static RAYON_THREADPOOL_API: crate::ffi::KT_ThreadPool_API =
        crate::ffi::KT_ThreadPool_API {
            min_input_size_for_threading: 1 << 21, // 2 MiB, consistent with upstream
            submit: Some(rayon_submit),
            wait_all: Some(rayon_wait_all),
            // These two functions aren't needed by the implementation.
            create: None,
            destroy: None,
        };

    unsafe extern "C" fn rayon_submit(
        pool: *mut c_void,
        work_fn: Option<unsafe extern "C" fn(*mut c_void)>,
        work_data: *mut c_void,
    ) -> c_int {
        let pool = unsafe { &mut *(pool as *mut RayonKTThreadPool) };
        pool.work_items.push(WorkItem { work_fn, work_data });
        0
    }

    unsafe extern "C" fn rayon_wait_all(pool: *mut c_void) {
        let pool = unsafe { &mut *(pool as *mut RayonKTThreadPool) };
        // Clearing the work items `Vec` with a drop guard is the panic-safe way to do it. Panics
        // here at this FFI boundary would be UB in any case, but we might as well do it right.
        struct ClearGuard<'a, T>(&'a mut Vec<T>);
        impl<T> Drop for ClearGuard<'_, T> {
            fn drop(&mut self) {
                self.0.clear();
            }
        }
        let guard = ClearGuard(&mut pool.work_items);
        guard.0.par_iter_mut().for_each(|item| unsafe {
            item.work_fn.unwrap_unchecked()(item.work_data);
        });
    }
}
