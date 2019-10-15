// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::io;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use std::mem::size_of;
use std::os::unix::io::AsRawFd;
use std::ptr::null_mut;
use std::result;

use kvm_bindings::kvm_run;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use kvm_bindings::{kvm_cpuid2, kvm_cpuid_entry2};
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use vmm_sys_util::fam::{FamStruct, FamStructWrapper};

/// Wrappers over KVM device ioctls.
pub mod device;
/// Wrappers over KVM system ioctls.
pub mod system;
/// Wrappers over KVM VCPU ioctls.
pub mod vcpu;
/// Wrappers over KVM Virtual Machine ioctls.
pub mod vm;

/// A specialized `Result` type for KVM ioctls.
///
/// This typedef is generally used to avoid writing out io::Error directly and
/// is otherwise a direct mapping to Result.
pub type Result<T> = result::Result<T, io::Error>;

// Returns a `Vec<T>` with a size in bytes at least as large as `size_in_bytes`.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn vec_with_size_in_bytes<T: Default>(size_in_bytes: usize) -> Vec<T> {
    let rounded_size = (size_in_bytes + size_of::<T>() - 1) / size_of::<T>();
    let mut v = Vec::with_capacity(rounded_size);
    for _ in 0..rounded_size {
        v.push(T::default())
    }
    v
}

// The kvm API has many structs that resemble the following `Foo` structure:
//
// ```
// #[repr(C)]
// struct Foo {
//    some_data: u32
//    entries: __IncompleteArrayField<__u32>,
// }
// ```
//
// In order to allocate such a structure, `size_of::<Foo>()` would be too small because it would not
// include any space for `entries`. To make the allocation large enough while still being aligned
// for `Foo`, a `Vec<Foo>` is created. Only the first element of `Vec<Foo>` would actually be used
// as a `Foo`. The remaining memory in the `Vec<Foo>` is for `entries`, which must be contiguous
// with `Foo`. This function is used to make the `Vec<Foo>` with enough space for `count` entries.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn vec_with_array_field<T: Default, F>(count: usize) -> Vec<T> {
    let element_space = count * size_of::<F>();
    let vec_size_bytes = size_of::<T>() + element_space;
    vec_with_size_in_bytes(vec_size_bytes)
}

/// Maximum number of CPUID entries that can be returned by a call to KVM ioctls.
///
/// This value is taken from Linux Kernel v4.14.13 (arch/x86/include/asm/kvm_host.h).
/// It can be used for calls to [get_supported_cpuid](struct.Kvm.html#method.get_supported_cpuid) and
/// [get_emulated_cpuid](struct.Kvm.html#method.get_emulated_cpuid).
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub const MAX_KVM_CPUID_ENTRIES: usize = 80;

/// Maximum number of MSRs KVM supports (See arch/x86/kvm/x86.c).
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub const KVM_MAX_MSR_ENTRIES: usize = 256;

// We can't implement FamStruct directly for kvm_cpuid2.
// We would get an "impl doesn't use types inside crate" error.
// We have to create a shadow structure as a workaround.
#[derive(Default)]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub struct KvmCpuId(kvm_cpuid2);

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
impl Clone for KvmCpuId {
    fn clone(&self) -> Self {
        let KvmCpuId(cpuid) = self;
        KvmCpuId(kvm_cpuid2 {
            nent: cpuid.nent,
            padding: cpuid.padding,
            entries: cpuid.entries.clone(),
        })
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
unsafe impl FamStruct for KvmCpuId {
    type Entry = kvm_cpuid_entry2;

    fn len(&self) -> usize {
        let KvmCpuId(cpuid) = self;
        cpuid.nent as usize
    }

    fn set_len(&mut self, len: usize) {
        let KvmCpuId(cpuid) = self;
        cpuid.nent = len as u32;
    }

    fn max_len() -> usize {
        MAX_KVM_CPUID_ENTRIES
    }

    fn as_slice(&self) -> &[Self::Entry] {
        let len = self.len();
        let KvmCpuId(cpuid) = self;
        // This is safe because the provided length is correct.
        unsafe { cpuid.entries.as_slice(len) }
    }

    fn as_mut_slice(&mut self) -> &mut [Self::Entry] {
        let len = self.len();
        let KvmCpuId(cpuid) = self;
        // This is safe because the provided length is correct.
        unsafe { cpuid.entries.as_mut_slice(len) }
    }
}

/// Wrapper over the `kvm_cpuid2` structure.
///
/// The `kvm_cpuid2` structure contains a flexible array member. For details check the
/// [KVM API](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt)
/// documentation on `kvm_cpuid2`. To provide safe access to
/// the array elements, this type is implemented using
/// [FamStructWrapper](../vmm_sys_util/fam/struct.FamStructWrapper.html).
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub type CpuId = FamStructWrapper<KvmCpuId>;

/// Safe wrapper over the `kvm_run` struct.
///
/// The wrapper is needed for sending the pointer to `kvm_run` between
/// threads as raw pointers do not implement `Send` and `Sync`.
pub struct KvmRunWrapper {
    kvm_run_ptr: *mut u8,
    // This field is need so we can `munmap` the memory mapped to hold `kvm_run`.
    mmap_size: usize,
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
            mmap_size: size,
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

impl Drop for KvmRunWrapper {
    fn drop(&mut self) {
        // This is safe because we mmap the area at kvm_run_ptr ourselves,
        // and nobody else is holding a reference to it.
        unsafe {
            libc::munmap(self.kvm_run_ptr as *mut libc::c_void, self.mmap_size);
        }
    }
}
