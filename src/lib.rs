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

use std::fmt;
use std::mem::MaybeUninit;

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
            let ret =
                ffi::KangarooTwelve_Update(&mut self.0, input.as_ptr(), input.len() as ffi::size_t);
            debug_assert_eq!(0, ret);
        }
    }

    pub fn finalize(&mut self, output: &mut [u8]) {
        self.finalize_custom(&[], output);
    }

    pub fn finalize_custom(&mut self, customization: &[u8], output: &mut [u8]) {
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
                customization.len() as ffi::size_t,
            );
            debug_assert_eq!(0, ret);
            let ret = ffi::KangarooTwelve_Squeeze(
                &mut self.0,
                output.as_mut_ptr(),
                output.len() as ffi::size_t,
            );
            debug_assert_eq!(0, ret);
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    #[should_panic]
    fn test_update_after_finalize_panics() {
        let mut hasher = Hasher::new();
        hasher.finalize(&mut []);
        hasher.update(&[]);
    }

    #[test]
    #[should_panic]
    fn test_finalize_twice_panics() {
        let mut hasher = Hasher::new();
        hasher.finalize(&mut []);
        hasher.finalize(&mut []);
    }

    fn fill_pattern(buf: &mut [u8]) {
        // repeating the pattern 0x00, 0x01, 0x02, ..., 0xFA as many times as necessary
        for i in 0..buf.len() {
            buf[i] = (i % 251) as u8;
        }
    }

    fn k12_hex(input: &[u8], customization: &[u8], num_output_bytes: usize) -> String {
        let mut hasher = Hasher::new();
        hasher.update(input);
        let mut output = vec![0; num_output_bytes];
        hasher.finalize_custom(customization, &mut output);

        // Also check that doing the same hash in two steps gives the same answer.
        let mut hasher2 = Hasher::new();
        hasher2.update(&input[..input.len() / 2]);
        hasher2.update(&input[input.len() / 2..]);
        let mut output2 = vec![0; num_output_bytes];
        hasher2.finalize_custom(customization, &mut output2);
        assert_eq!(output, output2);

        hex::encode(output)
    }

    // from https://eprint.iacr.org/2016/770.pdf
    #[test]
    fn test_vector_01() {
        // KangarooTwelve(M=empty, C=empty, 32 bytes):
        let expected = "1ac2d450fc3b4205d19da7bfca1b37513c0803577ac7167f06fe2ce1f0ef39e5";
        assert_eq!(expected, k12_hex(&[], &[], 32));
    }

    #[test]
    fn test_vector_02() {
        // KangarooTwelve(M=empty, C=empty, 64 bytes):
        let expected = "1ac2d450fc3b4205d19da7bfca1b37513c0803577ac7167f06fe2ce1f0ef39e54269c056b8c82e48276038b6d292966cc07a3d4645272e31ff38508139eb0a71";
        assert_eq!(expected, k12_hex(&[], &[], 64));
    }

    #[test]
    fn test_vector_03() {
        // KangarooTwelve(M=empty, C=empty, 10032 bytes), last 32 bytes:
        let expected = "e8dc563642f7228c84684c898405d3a834799158c079b12880277a1d28e2ff6d";
        let out = k12_hex(&[], &[], 10032);
        assert_eq!(expected, &out[out.len() - 64..]);
    }

    #[test]
    fn test_vector_04() {
        // KangarooTwelve(M=pattern 0x00 to 0xFA for 17^0 bytes, C=empty, 32 bytes):
        let expected = "2bda92450e8b147f8a7cb629e784a058efca7cf7d8218e02d345dfaa65244a1f";
        let mut input = [0];
        fill_pattern(&mut input);
        assert_eq!(expected, k12_hex(&input, &[], 32));
    }

    #[test]
    fn test_vector_05() {
        // KangarooTwelve(M=pattern 0x00 to 0xFA for 17^1 bytes, C=empty, 32 bytes):
        let expected = "6bf75fa2239198db4772e36478f8e19b0f371205f6a9a93a273f51df37122888";
        let mut input = vec![0; 17];
        fill_pattern(&mut input);
        assert_eq!(expected, k12_hex(&input, &[], 32));
    }

    #[test]
    fn test_vector_06() {
        // KangarooTwelve(M=pattern 0x00 to 0xFA for 17^2 bytes, C=empty, 32 bytes):
        let expected = "0c315ebcdedbf61426de7dcf8fb725d1e74675d7f5327a5067f367b108ecb67c";
        let mut input = vec![0; 17 * 17];
        fill_pattern(&mut input);
        assert_eq!(expected, k12_hex(&input, &[], 32));
    }

    #[test]
    fn test_vector_07() {
        // KangarooTwelve(M=pattern 0x00 to 0xFA for 17^3 bytes, C=empty, 32 bytes):
        let expected = "cb552e2ec77d9910701d578b457ddf772c12e322e4ee7fe417f92c758f0d59d0";
        let mut input = vec![0; 17 * 17 * 17];
        fill_pattern(&mut input);
        assert_eq!(expected, k12_hex(&input, &[], 32));
    }

    #[test]
    fn test_vector_08() {
        // KangarooTwelve(M=pattern 0x00 to 0xFA for 17^4 bytes, C=empty, 32 bytes):
        let expected = "8701045e22205345ff4dda05555cbb5c3af1a771c2b89baef37db43d9998b9fe";
        let mut input = vec![0; 17 * 17 * 17 * 17];
        fill_pattern(&mut input);
        assert_eq!(expected, k12_hex(&input, &[], 32));
    }

    #[test]
    fn test_vector_09() {
        // KangarooTwelve(M=pattern 0x00 to 0xFA for 17^5 bytes, C=empty, 32 bytes):
        let expected = "844d610933b1b9963cbdeb5ae3b6b05cc7cbd67ceedf883eb678a0a8e0371682";
        let mut input = vec![0; 17 * 17 * 17 * 17 * 17];
        fill_pattern(&mut input);
        assert_eq!(expected, k12_hex(&input, &[], 32));
    }

    #[test]
    fn test_vector_10() {
        // KangarooTwelve(M=pattern 0x00 to 0xFA for 17^6 bytes, C=empty, 32 bytes):
        let expected = "3c390782a8a4e89fa6367f72feaaf13255c8d95878481d3cd8ce85f58e880af8";
        let mut input = vec![0; 17 * 17 * 17 * 17 * 17 * 17];
        fill_pattern(&mut input);
        assert_eq!(expected, k12_hex(&input, &[], 32));
    }

    #[test]
    fn test_vector_11() {
        // KangarooTwelve(M=0 times byte 0xFF, C=pattern 0x00 to 0xFA for 41^0 bytes, 32 bytes):
        let expected = "fab658db63e94a246188bf7af69a133045f46ee984c56e3c3328caaf1aa1a583";
        let mut customization = [0];
        fill_pattern(&mut customization);
        assert_eq!(expected, k12_hex(&[], &customization, 32));
    }

    #[test]
    fn test_vector_12() {
        // KangarooTwelve(M=1 times byte 0xFF, C=pattern 0x00 to 0xFA for 41^1 bytes, 32 bytes):
        let expected = "d848c5068ced736f4462159b9867fd4c20b808acc3d5bc48e0b06ba0a3762ec4";
        let input = [0xff];
        let mut customization = vec![0; 41];
        fill_pattern(&mut customization);
        assert_eq!(expected, k12_hex(&input, &customization, 32));
    }

    #[test]
    fn test_vector_13() {
        // KangarooTwelve(M=3 times byte 0xFF, C=pattern 0x00 to 0xFA for 41^2 bytes, 32 bytes):
        let expected = "c389e5009ae57120854c2e8c64670ac01358cf4c1baf89447a724234dc7ced74";
        let input = [0xff; 3];
        let mut customization = vec![0; 41 * 41];
        fill_pattern(&mut customization);
        assert_eq!(expected, k12_hex(&input, &customization, 32));
    }

    #[test]
    fn test_vector_14() {
        // KangarooTwelve(M=7 times byte 0xFF, C=pattern 0x00 to 0xFA for 41^3 bytes, 32 bytes):
        let expected = "75d2f86a2e644566726b4fbcfc5657b9dbcf070c7b0dca06450ab291d7443bcf";
        let input = [0xff; 7];
        let mut customization = vec![0; 41 * 41 * 41];
        fill_pattern(&mut customization);
        assert_eq!(expected, k12_hex(&input, &customization, 32));
    }
}
