// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use vmm_sys_util::fam::{FamStruct, FamStructWrapper};

use x86_64::bindings::*;

/// Maximum number of CPUID entries that can be returned by a call to KVM ioctls.
///
/// See arch/x86/include/asm/kvm_host.h
pub const KVM_MAX_CPUID_ENTRIES: usize = 80;

/// Maximum number of MSRs KVM supports (See arch/x86/kvm/x86.c).
pub const KVM_MAX_MSR_ENTRIES: usize = 256;

// Implement the FamStruct trait for kvm_cpuid2.
generate_fam_struct_impl!(
    kvm_cpuid2,
    kvm_cpuid_entry2,
    entries,
    u32,
    nent,
    KVM_MAX_CPUID_ENTRIES
);

// Implement the PartialEq trait for kvm_cpuid2.
//
// Note:
// This PartialEq implementation should not be used directly, instead FamStructWrapper
// should be used. FamStructWrapper<T> provides us with an PartialEq implementation,
// and it will determine the entire contents of the entries array. But requires
// type T to implement `Default + FamStruct + PartialEq`, so we implement PartialEq here
// and only need to determine the header field.
impl PartialEq for kvm_cpuid2 {
    fn eq(&self, other: &kvm_cpuid2) -> bool {
        // No need to call entries's eq, FamStructWrapper's PartialEq will do it for you
        self.nent == other.nent && self.padding == other.padding
    }
}

/// Wrapper over the `kvm_cpuid2` structure.
///
/// The `kvm_cpuid2` structure contains a flexible array member. For details check the
/// [KVM API](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt)
/// documentation on `kvm_cpuid2`. To provide safe access to
/// the array elements, this type is implemented using
/// [FamStructWrapper](../vmm_sys_util/fam/struct.FamStructWrapper.html).
pub type CpuId = FamStructWrapper<kvm_cpuid2>;

// Implement the FamStruct trait for kvm_msrs.
generate_fam_struct_impl!(
    kvm_msrs,
    kvm_msr_entry,
    entries,
    u32,
    nmsrs,
    KVM_MAX_MSR_ENTRIES
);

// Implement the PartialEq trait for kvm_msrs.
impl PartialEq for kvm_msrs {
    fn eq(&self, other: &kvm_msrs) -> bool {
        // No need to call entries's eq, FamStructWrapper's PartialEq will do it for you
        self.nmsrs == other.nmsrs && self.pad == other.pad
    }
}

/// Wrapper over the `kvm_msrs` structure.
///
/// The `kvm_msrs` structure contains a flexible array member. For details check the
/// [KVM API](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt)
/// documentation on `kvm_msrs`. To provide safe access to
/// the array elements, this type is implemented using
/// [FamStructWrapper](../vmm_sys_util/fam/struct.FamStructWrapper.html).
pub type Msrs = FamStructWrapper<kvm_msrs>;

// Implement the FamStruct trait for kvm_msr_list.
generate_fam_struct_impl!(kvm_msr_list, u32, indices, u32, nmsrs, KVM_MAX_MSR_ENTRIES);

// Implement the PartialEq trait for kvm_msr_list.
impl PartialEq for kvm_msr_list {
    fn eq(&self, other: &kvm_msr_list) -> bool {
        // No need to call entries's eq, FamStructWrapper's PartialEq will do it for you
        self.nmsrs == other.nmsrs
    }
}

/// Wrapper over the `kvm_msr_list` structure.
///
/// The `kvm_msr_list` structure contains a flexible array member. For details check the
/// [KVM API](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt)
/// documentation on `kvm_msr_list`. To provide safe access to
/// the array elements, this type is implemented using
/// [FamStructWrapper](../vmm_sys_util/fam/struct.FamStructWrapper.html).
pub type MsrList = FamStructWrapper<kvm_msr_list>;

/// Helper structure to treat post-5.17 [`kvm_xsave`] as a FamStruct.
///
/// See also: [`Xsave`].
#[repr(C)]
#[derive(Debug, Default)]
pub struct kvm_xsave2 {
    /// The length, in bytes, of the FAM in [`kvm_xsave`].
    ///
    /// Note that `KVM_CHECK_EXTENSION(KVM_CAP_XSAVE2)` returns the size of the entire
    /// `kvm_xsave` structure, e.g. the sum of header and FAM. Thus, this `len` field
    /// is equal to `KVM_CHECK_EXTENSION(KVM_CAP_XSAVE2) - 4096`.
    pub len: usize,
    pub xsave: kvm_xsave,
}

// SAFETY:
// - `kvm_xsave2` is a POD
// - `kvm_xsave2` contains a flexible array member as its final field, due to `kvm_xsave` containing
//    one, and being `repr(C)`
// - `Entry` is a POD
unsafe impl FamStruct for kvm_xsave2 {
    type Entry = __u32;

    fn len(&self) -> usize {
        self.len
    }

    unsafe fn set_len(&mut self, len: usize) {
        self.len = len;
    }

    fn max_len() -> usize {
        __u32::MAX as usize
    }

    fn as_slice(&self) -> &[<Self as FamStruct>::Entry] {
        let len = self.len();
        // SAFETY: By the invariants that the caller of `set_len` has to uphold, `len` matches
        // the actual in-memory length of the FAM
        unsafe { self.xsave.extra.as_slice(len) }
    }

    fn as_mut_slice(&mut self) -> &mut [<Self as FamStruct>::Entry] {
        let len = self.len();
        // SAFETY: By the invariants that the caller of `set_len` has to uphold, `len` matches
        // the actual in-memory length of the FAM
        unsafe { self.xsave.extra.as_mut_slice(len) }
    }
}

/// Wrapper over the post-5.17 [`kvm_xsave`] structure.
///
/// In linux 5.17, kvm_xsave got turned into a FamStruct by adding the flexible "extra" member
/// to its definition. However, unlike all other such structs, it does not contain a "length"
/// field. Instead, the length of the flexible array member has to be determined by querying
/// the [`KVM_CAP_XSAVE2`] capability. This requires access to a VM file descriptor, and thus
/// cannot happen in the [`FamStruct::len`] trait method. To work around this, we define a wrapper
/// struct that caches the length of a previous `KVM_CHECK_EXTENSION(KVM_CAP_XSAVE2)` call,
/// and implement [`FamStruct`] for this wrapper. Then in kvm-ioctls, we can expose a function
/// that first queries `KVM_CAP_XSAVE2`, then invokes [`KVM_GET_XSAVE2`] to retrives the `kvm_xsave`
/// structure, and finally combine them into the [`kvm_xsave2`] helper structure to be managed as a
/// `FamStruct`.
pub type Xsave = FamStructWrapper<kvm_xsave2>;

#[cfg(test)]
mod tests {
    use super::{CpuId, MsrList, Msrs, Xsave};
    use x86_64::bindings::kvm_cpuid_entry2;

    use vmm_sys_util::fam::FamStruct;

    #[test]
    fn test_cpuid_eq() {
        let entries = &[kvm_cpuid_entry2::default(); 2];
        let mut wrapper = CpuId::from_entries(entries).unwrap();
        assert_eq!(wrapper.as_slice().len(), 2);

        let mut wrapper2 = wrapper.clone();
        assert!(wrapper == wrapper2);

        wrapper.as_mut_slice()[1].index = 1;
        assert!(wrapper != wrapper2);
        wrapper2.as_mut_slice()[1].index = 1;
        assert!(wrapper == wrapper2);
    }
    #[test]
    fn test_msrs_eq() {
        let mut wrapper = Msrs::new(2).unwrap();
        assert_eq!(wrapper.as_slice().len(), 2);

        let mut wrapper2 = wrapper.clone();
        assert!(wrapper == wrapper2);
        // SAFETY: We are not modifying the `nmsrs` field
        unsafe {
            wrapper.as_mut_fam_struct().pad = 1;
        }
        assert!(wrapper != wrapper2);
        // SAFETY: We are not modifying the `nmsrs` field
        unsafe {
            wrapper2.as_mut_fam_struct().pad = 1;
        }
        assert!(wrapper == wrapper2);

        wrapper.as_mut_slice()[1].data = 1;
        assert!(wrapper != wrapper2);
        assert!(wrapper.as_slice() != wrapper2.as_slice());
        wrapper2.as_mut_slice()[1].data = 1;
        assert!(wrapper == wrapper2);
        assert!(wrapper.as_slice() == wrapper2.as_slice());
    }
    #[test]
    fn test_msrs_list_eq() {
        let mut wrapper = MsrList::new(1).unwrap();
        assert_eq!(wrapper.as_slice().len(), 1);

        let mut wrapper2 = wrapper.clone();
        assert!(wrapper == wrapper2);

        wrapper.as_mut_slice()[0] = 1;
        assert!(wrapper != wrapper2);
        wrapper2.as_mut_slice()[0] = 1;
        assert!(wrapper == wrapper2);
    }
    #[test]
    fn test_xsave() {
        let wrapper = Xsave::new(1).unwrap();
        assert_eq!(wrapper.as_slice().len(), 1);
        assert_eq!(wrapper.as_fam_struct_ref().len(), 1);
        assert_eq!(wrapper.as_fam_struct_ref().len, 1);
    }
}
