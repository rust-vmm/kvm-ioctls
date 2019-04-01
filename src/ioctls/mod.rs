// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::io;
use std::mem::size_of;
use std::os::unix::io::AsRawFd;
use std::ptr::null_mut;
use std::result;
use MAX_KVM_CPUID_ENTRIES;
use MAX_KVM_MSR_ENTRIES;

use kvm_bindings::kvm_run;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use kvm_bindings::{__IncompleteArrayField, kvm_cpuid2, kvm_cpuid_entry2, kvm_msr_list};

/// Helper for dealing with KVM api structures
pub mod common;
/// Wrappers over KVM device ioctls.
pub mod device;
/// Wrappers over KVM system ioctls.
pub mod system;
/// Wrappers over KVM VCPU ioctls.
pub mod vcpu;
/// Wrappers over KVM Virtual Machine ioctls.
pub mod vm;

use self::common::kvm_vec::{KvmArray, KvmVec};

/// A specialized `Result` type for KVM ioctls.
///
/// This typedef is generally used to avoid writing out io::Error directly and
/// is otherwise a direct mapping to Result.
pub type Result<T> = result::Result<T, io::Error>;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
impl KvmArray for kvm_cpuid2 {
    type Entry = kvm_cpuid_entry2;

    fn len(&self) -> usize {
        self.nent as usize
    }

    fn set_len(&mut self, len: usize) {
        self.nent = len as u32;
    }

    fn max_len() -> usize {
        MAX_KVM_CPUID_ENTRIES
    }

    fn entries(&self) -> &__IncompleteArrayField<kvm_cpuid_entry2> {
        &self.entries
    }

    fn entries_mut(&mut self) -> &mut __IncompleteArrayField<kvm_cpuid_entry2> {
        &mut self.entries
    }
}

/// Wrapper for `kvm_cpuid2`.
///
/// The `kvm_cpuid2` structure has a zero sized array. For details check the
/// [KVM API](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt)
/// documentation on `kvm_cpuid2`. To provide safe access to
/// the array elements, this type is implemented using
/// [KvmVec](struct.KvmVec.html).
///
/// # Example
/// ```rust
/// extern crate kvm_bindings;
/// use kvm_bindings::kvm_cpuid_entry2;
///
/// use kvm_ioctls::{CpuId, Kvm, MAX_KVM_CPUID_ENTRIES};
/// let kvm = Kvm::new().unwrap();
/// // get the supported cpuid from KVM
/// let mut cpuid = kvm.get_supported_cpuid(MAX_KVM_CPUID_ENTRIES).unwrap();
/// // remove extended cache topology leafs
/// cpuid.retain(|entry| {
///     return entry.function != 0x8000_001d;
/// });
/// // add largest extended fn entry
/// cpuid.push(kvm_cpuid_entry2 {
///     function: 0x8000_0000,
///     index: 0,
///     flags: 0,
///     eax: 0x8000_001f,
///     ebx: 0,
///     ecx: 0,
///     edx: 0,
///     padding: [0, 0, 0]}
/// );
/// // edit features info leaf
/// for entry in cpuid.as_mut_entries_slice().iter_mut() {
///     match entry.function {
///         0x1 => {
///             entry.eax = 0;
///         }
///         _ => { }
///     }
/// }
/// ```
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub type CpuId = KvmVec<kvm_cpuid2>;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
impl KvmArray for kvm_msr_list {
    type Entry = u32;

    fn len(&self) -> usize {
        self.nmsrs as usize
    }

    fn set_len(&mut self, len: usize) {
        self.nmsrs = len as u32;
    }

    fn max_len() -> usize {
        MAX_KVM_MSR_ENTRIES as usize
    }

    fn entries(&self) -> &__IncompleteArrayField<u32> {
        &self.indices
    }

    fn entries_mut(&mut self) -> &mut __IncompleteArrayField<u32> {
        &mut self.indices
    }
}

/// Wrapper for `kvm_msr_list`.
///
/// The `kvm_msr_list` structure has a zero sized array. For details check the
/// [KVM API](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt)
/// documentation on `kvm_msr_list`. To provide safe access to
/// the array elements, this type is implemented using
/// [KvmVec](struct.KvmVec.html).
///
/// # Example
/// ```rust
/// use kvm_ioctls::{Kvm};
///
/// let kvm = Kvm::new().unwrap();
/// // get the msr index list from KVM
/// let mut msr_index_list = kvm.get_msr_index_list().unwrap();
/// // get indexes as u32 slice
/// let indexes = msr_index_list.as_entries_slice();
/// ```
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub type MsrList = KvmVec<kvm_msr_list>;

/// Safe wrapper over the `kvm_run` struct.
///
/// The wrapper is needed for sending the pointer to `kvm_run` between
/// threads as raw pointers do not implement `Send` and `Sync`.
pub struct KvmRunWrapper {
    kvm_run_ptr: *mut u8,
}

// Send and Sync aren't automatically inherited for the raw address pointer.
// Accessing that pointer is only done through the stateless interface which
// allows the object to be shared by multiple threads without a decrease in
// safety.
unsafe impl Send for KvmRunWrapper {}
unsafe impl Sync for KvmRunWrapper {}

impl KvmRunWrapper {
    /// Maps the first `size` bytes of the given `fd`.
    ///
    /// # Arguments
    /// * `fd` - File descriptor to mmap from.
    /// * `size` - Size of memory region in bytes.
    pub fn mmap_from_fd(fd: &AsRawFd, size: usize) -> Result<KvmRunWrapper> {
        // This is safe because we are creating a mapping in a place not already used by any other
        // area in this process.
        let addr = unsafe {
            libc::mmap(
                null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd.as_raw_fd(),
                0,
            )
        };
        if addr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }

        Ok(KvmRunWrapper {
            kvm_run_ptr: addr as *mut u8,
        })
    }

    /// Returns a mutable reference to `kvm_run`.
    ///
    #[allow(clippy::mut_from_ref)]
    pub fn as_mut_ref(&self) -> &mut kvm_run {
        // Safe because we know we mapped enough memory to hold the kvm_run struct because the
        // kernel told us how large it was.
        #[allow(clippy::cast_ptr_alignment)]
        unsafe {
            &mut *(self.kvm_run_ptr as *mut kvm_run)
        }
    }
}
