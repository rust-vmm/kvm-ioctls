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

#[cfg(test)]
mod tests {
    use super::{CpuId, MsrList, Msrs};
    use x86_64::bindings::kvm_cpuid_entry2;

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

        wrapper.as_mut_fam_struct().pad = 1;
        assert!(wrapper != wrapper2);
        wrapper2.as_mut_fam_struct().pad = 1;
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
}
