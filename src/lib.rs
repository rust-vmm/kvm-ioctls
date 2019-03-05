// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.
#![allow(unused)]
#![deny(missing_docs)]

//! A safe wrapper around the kernel's KVM interface.

extern crate kvm_bindings;
extern crate libc;

#[macro_use]
mod sys_ioctl;
#[macro_use]
mod kvm_ioctls;
mod cap;

use kvm_bindings::*;
use libc::{open, O_CLOEXEC, O_RDWR};
use std::fs::File;
use std::mem::size_of;
use std::os::raw::{c_char, c_ulong};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::{io, result};

pub use self::cap::Cap;
use self::kvm_ioctls::*;
use self::sys_ioctl::*;

/// Wrapper over possible Kvm Result.
pub type Result<T> = result::Result<T, io::Error>;

/// Taken from Linux Kernel v4.14.13 (arch/x86/include/asm/kvm_host.h)
pub const MAX_KVM_CPUID_ENTRIES: usize = 80;

// Returns a `Vec<T>` with a size in bytes at least as large as `size_in_bytes`.
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
fn vec_with_array_field<T: Default, F>(count: usize) -> Vec<T> {
    let element_space = count * size_of::<F>();
    let vec_size_bytes = size_of::<T>() + element_space;
    vec_with_size_in_bytes(vec_size_bytes)
}

/// A wrapper around opening and using `/dev/kvm`.
///
/// The handle is used to issue system ioctls.
pub struct Kvm {
    kvm: File,
}

impl Kvm {
    /// Opens `/dev/kvm/` and returns a `Kvm` object on success.
    ///
    #[allow(clippy::new_ret_no_self)]
    pub fn new() -> Result<Self> {
        // Open `/dev/kvm` using `O_CLOEXEC` flag.
        let fd = Self::open_with_cloexec(true)?;
        // Safe because we verify that ret is valid and we own the fd.
        Ok(unsafe { Self::new_with_fd_number(fd) })
    }

    /// Creates a new Kvm object assuming `fd` represents an existing open file descriptor
    /// associated with `/dev/kvm`.
    ///
    /// # Arguments
    ///
    /// * `fd` - File descriptor for `/dev/kvm`.
    ///
    pub unsafe fn new_with_fd_number(fd: RawFd) -> Self {
        Kvm {
            kvm: File::from_raw_fd(fd),
        }
    }

    /// Opens `/dev/kvm` and returns the fd number on success.
    ///
    /// # Arguments
    ///
    /// * `close_on_exec`: If true opens `/dev/kvm` using the `O_CLOEXEC` flag.
    ///
    pub fn open_with_cloexec(close_on_exec: bool) -> Result<RawFd> {
        let open_flags = O_RDWR | if close_on_exec { O_CLOEXEC } else { 0 };
        // Safe because we give a constant nul-terminated string and verify the result.
        let ret = unsafe { open("/dev/kvm\0".as_ptr() as *const c_char, open_flags) };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(ret)
        }
    }

    /// Returns the KVM API version.
    ///
    /// See the documentation for `KVM_GET_API_VERSION`.
    pub fn get_api_version(&self) -> i32 {
        // Safe because we know that our file is a KVM fd and that the request is one of the ones
        // defined by kernel.
        unsafe { ioctl(self, KVM_GET_API_VERSION()) }
    }

    /// Query the availability of a particular kvm capability.
    ///
    /// See the documentation for `KVM_CHECK_EXTENSION`.
    /// Returns 0 if the capability is not available and > 0 otherwise.
    ///
    fn check_extension_int(&self, c: Cap) -> i32 {
        // Safe because we know that our file is a KVM fd and that the extension is one of the ones
        // defined by kernel.
        unsafe { ioctl_with_val(self, KVM_CHECK_EXTENSION(), c as c_ulong) }
    }

    /// Checks if a particular `Cap` is available.
    ///
    /// According to the KVM API doc, `KVM_CHECK_EXTENSION` returns "0 if unsupported; 1 (or some
    /// other positive integer) if supported.
    ///
    /// # Arguments
    ///
    /// * `c` - KVM capability.
    ///
    pub fn check_extension(&self, c: Cap) -> bool {
        self.check_extension_int(c) >= 1
    }

    /// Gets the size of the mmap required to use vcpu's `kvm_run` structure.
    ///
    /// See the documentation for `KVM_GET_VCPU_MMAP_SIZE`.
    ///
    pub fn get_vcpu_mmap_size(&self) -> Result<usize> {
        // Safe because we know that our file is a KVM fd and we verify the return result.
        let res = unsafe { ioctl(self, KVM_GET_VCPU_MMAP_SIZE()) };
        if res > 0 {
            Ok(res as usize)
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// Gets the recommended number of VCPUs per VM.
    ///
    /// See the documentation for `KVM_CAP_NR_VCPUS`.
    /// Default to 4 when `KVM_CAP_NR_VCPUS` is not implemented.
    pub fn get_nr_vcpus(&self) -> usize {
        let x = self.check_extension_int(Cap::NrVcpus);
        if x > 0 {
            x as usize
        } else {
            4
        }
    }

    /// Gets the maximum allowed memory slots per VM.
    ///
    /// KVM reports the number of available memory slots (`KVM_CAP_NR_MEMSLOTS`)
    /// using the extension interface.  Both x86 and s390 implement this, ARM
    /// and powerpc do not yet enable it.
    /// Default to 32 when `KVM_CAP_NR_MEMSLOTS` is not implemented.
    ///
    pub fn get_nr_memslots(&self) -> usize {
        let x = self.check_extension_int(Cap::NrMemslots);
        if x > 0 {
            x as usize
        } else {
            32
        }
    }

    /// Gets the recommended maximum number of VCPUs per VM.
    ///
    /// See the documentation for `KVM_CAP_MAX_VCPUS`.
    /// Default to `KVM_CAP_NR_VCPUS` when `KVM_CAP_MAX_VCPUS` is not implemented.
    ///
    pub fn get_max_vcpus(&self) -> usize {
        match self.check_extension_int(Cap::MaxVcpus) {
            0 => self.get_nr_vcpus(),
            x => x as usize,
        }
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn get_cpuid(&self, kind: u64, max_entries_count: usize) -> Result<CpuId> {
        let mut cpuid = CpuId::new(max_entries_count);

        let ret = unsafe {
            // ioctl is unsafe. The kernel is trusted not to write beyond the bounds of the memory
            // allocated for the struct. The limit is read from nent, which is set to the allocated
            // size(max_entries_count) above.
            ioctl_with_mut_ptr(self, kind, cpuid.as_mut_ptr())
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(cpuid)
    }

    /// X86 specific call to get the system emulated CPUID values.
    ///
    /// See the documentation for KVM_GET_EMULATED_CPUID.
    ///
    /// # Arguments
    ///
    /// * `max_entries_count` - Maximum number of CPUID entries. This function can return less than
    ///                         this when the hardware does not support so many CPUID entries.
    ///
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn get_emulated_cpuid(&self, max_entries_count: usize) -> Result<CpuId> {
        self.get_cpuid(KVM_GET_EMULATED_CPUID(), max_entries_count)
    }

    /// X86 specific call to get the system supported CPUID values.
    ///
    /// See the documentation for KVM_GET_SUPPORTED_CPUID.
    ///
    /// # Arguments
    ///
    /// * `max_entries_count` - Maximum number of CPUID entries. This function can return less than
    ///                         this when the hardware does not support so many CPUID entries.
    ///
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn get_supported_cpuid(&self, max_entries_count: usize) -> Result<CpuId> {
        self.get_cpuid(KVM_GET_SUPPORTED_CPUID(), max_entries_count)
    }

    /// X86 specific call to get list of supported MSRS
    ///
    /// See the documentation for KVM_GET_MSR_INDEX_LIST.
    ///
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn get_msr_index_list(&self) -> Result<Vec<u32>> {
        const MAX_KVM_MSR_ENTRIES: usize = 256;

        let mut msr_list = vec_with_array_field::<kvm_msr_list, u32>(MAX_KVM_MSR_ENTRIES);
        msr_list[0].nmsrs = MAX_KVM_MSR_ENTRIES as u32;

        let ret = unsafe {
            // ioctl is unsafe. The kernel is trusted not to write beyond the bounds of the memory
            // allocated for the struct. The limit is read from nmsrs, which is set to the allocated
            // size (MAX_KVM_MSR_ENTRIES) above.
            ioctl_with_mut_ref(self, KVM_GET_MSR_INDEX_LIST(), &mut msr_list[0])
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut nmsrs = msr_list[0].nmsrs;

        // Mapping the unsized array to a slice is unsafe because the length isn't known.  Using
        // the length we originally allocated with eliminates the possibility of overflow.
        let indices: &[u32] = unsafe {
            if nmsrs > MAX_KVM_MSR_ENTRIES as u32 {
                nmsrs = MAX_KVM_MSR_ENTRIES as u32;
            }
            msr_list[0].indices.as_slice(nmsrs as usize)
        };

        Ok(indices.to_vec())
    }

    /// Creates a VM fd using the KVM fd.
    ///
    /// See the documentation for `KVM_CREATE_VM`.
    /// A call to this function will also initialize the size of the vcpu mmap area using the
    /// `KVM_GET_VCPU_MMAP_SIZE` ioctl.
    ///
    pub fn create_vm(&self) -> Result<VmFd> {
        // Safe because we know kvm is a real kvm fd as this module is the only one that can make
        // Kvm objects.
        let ret = unsafe { ioctl(&self.kvm, KVM_CREATE_VM()) };
        if ret >= 0 {
            // Safe because we verify the value of ret and we are the owners of the fd.
            let vm_file = unsafe { File::from_raw_fd(ret) };
            let run_mmap_size = self.get_vcpu_mmap_size()?;
            Ok(VmFd {
                vm: vm_file,
                run_size: run_mmap_size,
            })
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

impl AsRawFd for Kvm {
    fn as_raw_fd(&self) -> RawFd {
        self.kvm.as_raw_fd()
    }
}

/// A wrapper around creating and using a VM.
pub struct VmFd {
    vm: File,
    run_size: usize,
}

/// Wrapper for `kvm_cpuid2` which has a zero length array at the end.
/// Hides the zero length array behind a bounds check.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub struct CpuId {
    /// Wrapper over `kvm_cpuid2` from which we only use the first element.
    kvm_cpuid: Vec<kvm_cpuid2>,
    // Number of `kvm_cpuid_entry2` structs at the end of kvm_cpuid2.
    allocated_len: usize,
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
impl Clone for CpuId {
    fn clone(&self) -> Self {
        let mut kvm_cpuid = Vec::with_capacity(self.kvm_cpuid.len());
        for _ in 0..self.kvm_cpuid.len() {
            kvm_cpuid.push(kvm_cpuid2::default());
        }

        let num_bytes = self.kvm_cpuid.len() * size_of::<kvm_cpuid2>();

        let src_byte_slice =
            unsafe { std::slice::from_raw_parts(self.kvm_cpuid.as_ptr() as *const u8, num_bytes) };

        let dst_byte_slice =
            unsafe { std::slice::from_raw_parts_mut(kvm_cpuid.as_mut_ptr() as *mut u8, num_bytes) };

        dst_byte_slice.copy_from_slice(src_byte_slice);

        CpuId {
            kvm_cpuid,
            allocated_len: self.allocated_len,
        }
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
impl CpuId {
    /// Creates a new `CpuId` structure that can contain at most `array_len` KVM CPUID entries.
    ///
    /// # Arguments
    ///
    /// * `array_len` - Maximum number of CPUID entries.
    ///
    pub fn new(array_len: usize) -> CpuId {
        let mut kvm_cpuid = vec_with_array_field::<kvm_cpuid2, kvm_cpuid_entry2>(array_len);
        kvm_cpuid[0].nent = array_len as u32;

        CpuId {
            kvm_cpuid,
            allocated_len: array_len,
        }
    }

    /// Get the mutable entries slice so they can be modified before passing to the VCPU.
    ///
    pub fn mut_entries_slice(&mut self) -> &mut [kvm_cpuid_entry2] {
        // Mapping the unsized array to a slice is unsafe because the length isn't known.  Using
        // the length we originally allocated with eliminates the possibility of overflow.
        if self.kvm_cpuid[0].nent as usize > self.allocated_len {
            self.kvm_cpuid[0].nent = self.allocated_len as u32;
        }
        let nent = self.kvm_cpuid[0].nent as usize;
        unsafe { self.kvm_cpuid[0].entries.as_mut_slice(nent) }
    }

    /// Get a  pointer so it can be passed to the kernel. Using this pointer is unsafe.
    ///
    pub fn as_ptr(&self) -> *const kvm_cpuid2 {
        &self.kvm_cpuid[0]
    }

    /// Get a mutable pointer so it can be passed to the kernel. Using this pointer is unsafe.
    ///
    pub fn as_mut_ptr(&mut self) -> *mut kvm_cpuid2 {
        &mut self.kvm_cpuid[0]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    impl PartialEq for CpuId {
        fn eq(&self, other: &CpuId) -> bool {
            let entries: &[kvm_cpuid_entry2] =
                unsafe { self.kvm_cpuid[0].entries.as_slice(self.allocated_len) };
            let other_entries: &[kvm_cpuid_entry2] =
                unsafe { self.kvm_cpuid[0].entries.as_slice(other.allocated_len) };
            self.allocated_len == other.allocated_len && entries == other_entries
        }
    }

    #[test]
    fn test_kvm_new() {
        Kvm::new().unwrap();
    }

    #[test]
    fn test_kvm_api_version() {
        let kvm = Kvm::new().unwrap();
        assert_eq!(kvm.get_api_version(), 12);
        assert!(kvm.check_extension(Cap::UserMemory));
    }

    #[test]
    fn test_kvm_getters() {
        let kvm = Kvm::new().unwrap();

        // vCPU related getters
        let nr_vcpus = kvm.get_nr_vcpus();
        assert!(nr_vcpus >= 4);

        assert!(kvm.get_max_vcpus() >= nr_vcpus);

        // Memory related getters
        assert!(kvm.get_vcpu_mmap_size().unwrap() > 0);
        assert!(kvm.get_nr_memslots() >= 32);
    }

    #[test]
    fn test_create_vm() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();

        assert_eq!(vm.run_size, kvm.get_vcpu_mmap_size().unwrap());
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[test]
    fn test_get_supported_cpuid() {
        let kvm = Kvm::new().unwrap();
        let mut cpuid = kvm.get_supported_cpuid(MAX_KVM_CPUID_ENTRIES).unwrap();
        let cpuid_entries = cpuid.mut_entries_slice();
        assert!(cpuid_entries.len() > 0);
        assert!(cpuid_entries.len() <= MAX_KVM_CPUID_ENTRIES);
    }

    #[test]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn test_get_emulated_cpuid() {
        let kvm = Kvm::new().unwrap();
        let mut cpuid = kvm.get_emulated_cpuid(MAX_KVM_CPUID_ENTRIES).unwrap();
        let cpuid_entries = cpuid.mut_entries_slice();
        assert!(cpuid_entries.len() > 0);
        assert!(cpuid_entries.len() <= MAX_KVM_CPUID_ENTRIES);
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[test]
    fn test_cpuid_clone() {
        let kvm = Kvm::new().unwrap();
        let cpuid_1 = kvm.get_supported_cpuid(MAX_KVM_CPUID_ENTRIES).unwrap();
        let mut cpuid_2 = cpuid_1.clone();
        assert!(cpuid_1 == cpuid_2);
        cpuid_2 = unsafe { std::mem::zeroed() };
        assert!(cpuid_1 != cpuid_2);
    }

    #[test]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn get_msr_index_list() {
        let kvm = Kvm::new().unwrap();
        let msr_list = kvm.get_msr_index_list().unwrap();
        assert!(msr_list.len() >= 2);
    }

}
