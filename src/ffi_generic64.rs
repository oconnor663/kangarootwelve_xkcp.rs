/* automatically generated by rust-bindgen */

pub type size_t = ::std::os::raw::c_ulong;
#[repr(C)]
#[derive(Copy, Clone)]
pub struct KeccakWidth1600_12rounds_SpongeInstanceStruct {
    pub state: [::std::os::raw::c_uchar; 200usize],
    pub rate: ::std::os::raw::c_uint,
    pub byteIOIndex: ::std::os::raw::c_uint,
    pub squeezing: ::std::os::raw::c_int,
}
#[test]
fn bindgen_test_layout_KeccakWidth1600_12rounds_SpongeInstanceStruct() {
    assert_eq!(
        ::std::mem::size_of::<KeccakWidth1600_12rounds_SpongeInstanceStruct>(),
        212usize,
        concat!(
            "Size of: ",
            stringify!(KeccakWidth1600_12rounds_SpongeInstanceStruct)
        )
    );
    assert_eq!(
        ::std::mem::align_of::<KeccakWidth1600_12rounds_SpongeInstanceStruct>(),
        4usize,
        concat!(
            "Alignment of ",
            stringify!(KeccakWidth1600_12rounds_SpongeInstanceStruct)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<KeccakWidth1600_12rounds_SpongeInstanceStruct>())).state
                as *const _ as usize
        },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(KeccakWidth1600_12rounds_SpongeInstanceStruct),
            "::",
            stringify!(state)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<KeccakWidth1600_12rounds_SpongeInstanceStruct>())).rate
                as *const _ as usize
        },
        200usize,
        concat!(
            "Offset of field: ",
            stringify!(KeccakWidth1600_12rounds_SpongeInstanceStruct),
            "::",
            stringify!(rate)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<KeccakWidth1600_12rounds_SpongeInstanceStruct>())).byteIOIndex
                as *const _ as usize
        },
        204usize,
        concat!(
            "Offset of field: ",
            stringify!(KeccakWidth1600_12rounds_SpongeInstanceStruct),
            "::",
            stringify!(byteIOIndex)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<KeccakWidth1600_12rounds_SpongeInstanceStruct>())).squeezing
                as *const _ as usize
        },
        208usize,
        concat!(
            "Offset of field: ",
            stringify!(KeccakWidth1600_12rounds_SpongeInstanceStruct),
            "::",
            stringify!(squeezing)
        )
    );
}
pub type KeccakWidth1600_12rounds_SpongeInstance = KeccakWidth1600_12rounds_SpongeInstanceStruct;
pub const KCP_Phases_NOT_INITIALIZED: KCP_Phases = 0;
pub const KCP_Phases_ABSORBING: KCP_Phases = 1;
pub const KCP_Phases_FINAL: KCP_Phases = 2;
pub const KCP_Phases_SQUEEZING: KCP_Phases = 3;
pub type KCP_Phases = u32;
pub use self::KCP_Phases as KangarooTwelve_Phases;
#[repr(C)]
#[repr(align(64))]
#[derive(Copy, Clone)]
pub struct KangarooTwelve_Instance {
    pub queueNode: KeccakWidth1600_12rounds_SpongeInstance,
    pub finalNode: KeccakWidth1600_12rounds_SpongeInstance,
    pub fixedOutputLength: size_t,
    pub blockNumber: size_t,
    pub queueAbsorbedLen: ::std::os::raw::c_uint,
    pub phase: KangarooTwelve_Phases,
}
#[test]
fn bindgen_test_layout_KangarooTwelve_Instance() {
    assert_eq!(
        ::std::mem::size_of::<KangarooTwelve_Instance>(),
        512usize,
        concat!("Size of: ", stringify!(KangarooTwelve_Instance))
    );
    assert_eq!(
        ::std::mem::align_of::<KangarooTwelve_Instance>(),
        64usize,
        concat!("Alignment of ", stringify!(KangarooTwelve_Instance))
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<KangarooTwelve_Instance>())).queueNode as *const _ as usize
        },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(KangarooTwelve_Instance),
            "::",
            stringify!(queueNode)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<KangarooTwelve_Instance>())).finalNode as *const _ as usize
        },
        256usize,
        concat!(
            "Offset of field: ",
            stringify!(KangarooTwelve_Instance),
            "::",
            stringify!(finalNode)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<KangarooTwelve_Instance>())).fixedOutputLength as *const _
                as usize
        },
        472usize,
        concat!(
            "Offset of field: ",
            stringify!(KangarooTwelve_Instance),
            "::",
            stringify!(fixedOutputLength)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<KangarooTwelve_Instance>())).blockNumber as *const _ as usize
        },
        480usize,
        concat!(
            "Offset of field: ",
            stringify!(KangarooTwelve_Instance),
            "::",
            stringify!(blockNumber)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<KangarooTwelve_Instance>())).queueAbsorbedLen as *const _
                as usize
        },
        488usize,
        concat!(
            "Offset of field: ",
            stringify!(KangarooTwelve_Instance),
            "::",
            stringify!(queueAbsorbedLen)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<KangarooTwelve_Instance>())).phase as *const _ as usize },
        492usize,
        concat!(
            "Offset of field: ",
            stringify!(KangarooTwelve_Instance),
            "::",
            stringify!(phase)
        )
    );
}
extern "C" {
    #[doc = " Function to initialize a KangarooTwelve instance."]
    #[doc = " @param  ktInstance      Pointer to the instance to be initialized."]
    #[doc = " @param  outputByteLen   The desired number of output bytes,"]
    #[doc = "                         or 0 for an arbitrarily-long output."]
    #[doc = " @return 0 if successful, 1 otherwise."]
    pub fn KangarooTwelve_Initialize(
        ktInstance: *mut KangarooTwelve_Instance,
        outputByteLen: size_t,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    #[doc = " Function to give input data to be absorbed."]
    #[doc = " @param  ktInstance      Pointer to the instance initialized by KangarooTwelve_Initialize()."]
    #[doc = " @param  input           Pointer to the input message data (M)."]
    #[doc = " @param  inputByteLen    The number of bytes provided in the input message data."]
    #[doc = " @return 0 if successful, 1 otherwise."]
    pub fn KangarooTwelve_Update(
        ktInstance: *mut KangarooTwelve_Instance,
        input: *const ::std::os::raw::c_uchar,
        inputByteLen: size_t,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    #[doc = " Function to call after all the input message has been input, and to get"]
    #[doc = " output bytes if the length was specified when calling KangarooTwelve_Initialize()."]
    #[doc = " @param  ktInstance      Pointer to the hash instance initialized by KangarooTwelve_Initialize()."]
    #[doc = " If @a outputByteLen was not 0 in the call to KangarooTwelve_Initialize(), the number of"]
    #[doc = "     output bytes is equal to @a outputByteLen."]
    #[doc = " If @a outputByteLen was 0 in the call to KangarooTwelve_Initialize(), the output bytes"]
    #[doc = "     must be extracted using the KangarooTwelve_Squeeze() function."]
    #[doc = " @param  output          Pointer to the buffer where to store the output data."]
    #[doc = " @param  customization   Pointer to the customization string (C)."]
    #[doc = " @param  customByteLen   The length of the customization string in bytes."]
    #[doc = " @return 0 if successful, 1 otherwise."]
    pub fn KangarooTwelve_Final(
        ktInstance: *mut KangarooTwelve_Instance,
        output: *mut ::std::os::raw::c_uchar,
        customization: *const ::std::os::raw::c_uchar,
        customByteLen: size_t,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    #[doc = " Function to squeeze output data."]
    #[doc = " @param  ktInstance     Pointer to the hash instance initialized by KangarooTwelve_Initialize()."]
    #[doc = " @param  data           Pointer to the buffer where to store the output data."]
    #[doc = " @param  outputByteLen  The number of output bytes desired."]
    #[doc = " @pre    KangarooTwelve_Final() must have been already called."]
    #[doc = " @return 0 if successful, 1 otherwise."]
    pub fn KangarooTwelve_Squeeze(
        ktInstance: *mut KangarooTwelve_Instance,
        output: *mut ::std::os::raw::c_uchar,
        outputByteLen: size_t,
    ) -> ::std::os::raw::c_int;
}
