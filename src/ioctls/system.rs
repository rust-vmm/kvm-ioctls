// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.
use libc::{open, O_CLOEXEC, O_RDWR};
use std::ffi::CStr;
use std::fs::File;
use std::os::raw::{c_char, c_ulong};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};

use crate::cap::Cap;
use crate::ioctls::vm::{new_vmfd, VmFd};
use crate::ioctls::Result;
use crate::kvm_ioctls::*;
#[cfg(target_arch = "aarch64")]
use kvm_bindings::KVM_VM_TYPE_ARM_IPA_SIZE_MASK;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use kvm_bindings::{CpuId, MsrList, Msrs, KVM_MAX_CPUID_ENTRIES, KVM_MAX_MSR_ENTRIES};
use vmm_sys_util::errno;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use vmm_sys_util::ioctl::ioctl_with_mut_ptr;
use vmm_sys_util::ioctl::{ioctl, ioctl_with_val};

/// Wrapper over KVM system ioctls.
#[derive(Debug)]
pub struct Kvm {
    kvm: File,
}

impl Kvm {
    /// Opens `/dev/kvm` and returns a `Kvm` object on success.
    ///
    /// # Example
    ///
    /// ```
    /// use kvm_ioctls::Kvm;
    /// let kvm = Kvm::new().unwrap();
    /// ```
    #[allow(clippy::new_ret_no_self)]
    pub fn new() -> Result<Self> {
        // Open `/dev/kvm` using `O_CLOEXEC` flag.
        let fd = Self::open_with_cloexec(true)?;
        // SAFETY: Safe because we verify that the fd is valid in `open_with_cloexec` and we own
        // the fd.
        Ok(unsafe { Self::from_raw_fd(fd) })
    }

    /// Opens the KVM device at `kvm_path` and returns a `Kvm` object on success.
    ///
    /// # Arguments
    ///
    /// * `kvm_path`: path to the KVM device. Usually it is `/dev/kvm`.
    ///
    /// # Example
    ///
    /// ```
    /// use kvm_ioctls::Kvm;
    /// use std::ffi::CString;
    /// let kvm_path = CString::new("/dev/kvm").unwrap();
    /// let kvm = Kvm::new_with_path(&kvm_path).unwrap();
    /// ```
    #[allow(clippy::new_ret_no_self)]
    pub fn new_with_path<P>(kvm_path: P) -> Result<Self>
    where
        P: AsRef<CStr>,
    {
        // Open `kvm_path` using `O_CLOEXEC` flag.
        let fd = Self::open_with_cloexec_at(kvm_path, true)?;
        // SAFETY: Safe because we verify that the fd is valid in `open_with_cloexec_at`
        // and we own the fd.
        Ok(unsafe { Self::from_raw_fd(fd) })
    }

    /// Opens `/dev/kvm` and returns the fd number on success.
    ///
    /// One usecase for this method is opening `/dev/kvm` before exec-ing into a
    /// process with seccomp filters enabled that blacklist the `sys_open` syscall.
    /// For this usecase `open_with_cloexec` must be called with the `close_on_exec`
    /// parameter set to false.
    ///
    /// # Arguments
    ///
    /// * `close_on_exec`: If true opens `/dev/kvm` using the `O_CLOEXEC` flag.
    ///
    /// # Example
    ///
    /// ```
    /// # use kvm_ioctls::Kvm;
    /// # use std::os::unix::io::FromRawFd;
    /// let kvm_fd = Kvm::open_with_cloexec(false).unwrap();
    /// // The `kvm_fd` can now be passed to another process where we can use
    /// // `from_raw_fd` for creating a `Kvm` object:
    /// let kvm = unsafe { Kvm::from_raw_fd(kvm_fd) };
    /// ```
    pub fn open_with_cloexec(close_on_exec: bool) -> Result<RawFd> {
        // SAFETY: Safe because we give a constant nul-terminated string.
        let kvm_path = unsafe { CStr::from_bytes_with_nul_unchecked(b"/dev/kvm\0") };
        Self::open_with_cloexec_at(kvm_path, close_on_exec)
    }

    /// Opens the KVM device at `kvm_path` and returns the fd number on success.
    /// Same as [open_with_cloexec()](struct.Kvm.html#method.open_with_cloexec)
    /// except this method opens `kvm_path` instead of `/dev/kvm`.
    ///
    /// # Arguments
    ///
    /// * `kvm_path`: path to the KVM device. Usually it is `/dev/kvm`.
    /// * `close_on_exec`: If true opens `kvm_path` using the `O_CLOEXEC` flag.
    ///
    /// # Example
    ///
    /// ```
    /// # use kvm_ioctls::Kvm;
    /// # use std::ffi::CString;
    /// # use std::os::unix::io::FromRawFd;
    /// let kvm_path = CString::new("/dev/kvm").unwrap();
    /// let kvm_fd = Kvm::open_with_cloexec_at(kvm_path, false).unwrap();
    /// // The `kvm_fd` can now be passed to another process where we can use
    /// // `from_raw_fd` for creating a `Kvm` object:
    /// let kvm = unsafe { Kvm::from_raw_fd(kvm_fd) };
    /// ```
    pub fn open_with_cloexec_at<P>(path: P, close_on_exec: bool) -> Result<RawFd>
    where
        P: AsRef<CStr>,
    {
        let open_flags = O_RDWR | if close_on_exec { O_CLOEXEC } else { 0 };
        // SAFETY: Safe because we verify the result.
        let ret = unsafe { open(path.as_ref().as_ptr() as *const c_char, open_flags) };
        if ret < 0 {
            Err(errno::Error::last())
        } else {
            Ok(ret)
        }
    }

    /// Returns the KVM API version.
    ///
    /// See the documentation for `KVM_GET_API_VERSION`.
    ///
    /// # Example
    ///
    /// ```
    /// # use kvm_ioctls::Kvm;
    /// let kvm = Kvm::new().unwrap();
    /// assert_eq!(kvm.get_api_version(), 12);
    /// ```
    pub fn get_api_version(&self) -> i32 {
        // SAFETY: Safe because we know that our file is a KVM fd and that the request is one of
        // the ones defined by kernel.
        unsafe { ioctl(self, KVM_GET_API_VERSION()) }
    }

    /// AArch64 specific call to get the host Intermediate Physical Address space limit.
    ///
    /// Returns 0 if the capability is not available and an integer >= 32 otherwise.
    #[cfg(target_arch = "aarch64")]
    pub fn get_host_ipa_limit(&self) -> i32 {
        self.check_extension_int(Cap::ArmVmIPASize)
    }

    /// AArch64 specific call to get the number of supported hardware breakpoints.
    ///
    /// Returns 0 if the capability is not available and a positive integer otherwise.
    #[cfg(target_arch = "aarch64")]
    pub fn get_guest_debug_hw_bps(&self) -> i32 {
        self.check_extension_int(Cap::DebugHwBps)
    }

    /// AArch64 specific call to get the number of supported hardware watchpoints.
    ///
    /// Returns 0 if the capability is not available and a positive integer otherwise.
    #[cfg(target_arch = "aarch64")]
    pub fn get_guest_debug_hw_wps(&self) -> i32 {
        self.check_extension_int(Cap::DebugHwWps)
    }

    /// Wrapper over `KVM_CHECK_EXTENSION`.
    ///
    /// Returns 0 if the capability is not available and a positive integer otherwise.
    /// See the documentation for `KVM_CHECK_EXTENSION`.
    ///
    /// # Arguments
    ///
    /// * `c` - KVM capability to check in a form of a raw integer.
    ///
    /// # Example
    ///
    /// ```
    /// # use kvm_ioctls::Kvm;
    /// # use std::os::raw::c_ulong;
    /// use kvm_ioctls::Cap;
    ///
    /// let kvm = Kvm::new().unwrap();
    /// assert!(kvm.check_extension_raw(Cap::MaxVcpuId as c_ulong) > 0);
    /// ```
    pub fn check_extension_raw(&self, c: c_ulong) -> i32 {
        // SAFETY: Safe because we know that our file is a KVM fd.
        // If `c` is not a known kernel extension, kernel will return 0.
        unsafe { ioctl_with_val(self, KVM_CHECK_EXTENSION(), c) }
    }

    /// Wrapper over `KVM_CHECK_EXTENSION`.
    ///
    /// Returns 0 if the capability is not available and a positive integer otherwise.
    /// See the documentation for `KVM_CHECK_EXTENSION`.
    ///
    /// # Arguments
    ///
    /// * `c` - KVM capability to check.
    ///
    /// # Example
    ///
    /// ```
    /// # use kvm_ioctls::Kvm;
    /// use kvm_ioctls::Cap;
    ///
    /// let kvm = Kvm::new().unwrap();
    /// assert!(kvm.check_extension_int(Cap::MaxVcpuId) > 0);
    /// ```
    pub fn check_extension_int(&self, c: Cap) -> i32 {
        self.check_extension_raw(c as c_ulong)
    }

    /// Checks if a particular `Cap` is available.
    ///
    /// Returns true if the capability is supported and false otherwise.
    /// See the documentation for `KVM_CHECK_EXTENSION`.
    ///
    /// # Arguments
    ///
    /// * `c` - KVM capability to check.
    ///
    /// # Example
    ///
    /// ```
    /// # use kvm_ioctls::Kvm;
    /// use kvm_ioctls::Cap;
    ///
    /// let kvm = Kvm::new().unwrap();
    /// // Check if `KVM_CAP_USER_MEMORY` is supported.
    /// assert!(kvm.check_extension(Cap::UserMemory));
    /// ```
    pub fn check_extension(&self, c: Cap) -> bool {
        self.check_extension_int(c) > 0
    }

    ///  Returns the size of the memory mapping required to use the vcpu's `kvm_run` structure.
    ///
    /// See the documentation for `KVM_GET_VCPU_MMAP_SIZE`.
    ///
    /// # Example
    ///
    /// ```
    /// # use kvm_ioctls::Kvm;
    /// let kvm = Kvm::new().unwrap();
    /// assert!(kvm.get_vcpu_mmap_size().unwrap() > 0);
    /// ```
    pub fn get_vcpu_mmap_size(&self) -> Result<usize> {
        // SAFETY: Safe because we know that our file is a KVM fd and we verify the return result.
        let res = unsafe { ioctl(self, KVM_GET_VCPU_MMAP_SIZE()) };
        if res > 0 {
            Ok(res as usize)
        } else {
            Err(errno::Error::last())
        }
    }

    /// Gets the recommended number of VCPUs per VM.
    ///
    /// See the documentation for `KVM_CAP_NR_VCPUS`.
    /// Default to 4 when `KVM_CAP_NR_VCPUS` is not implemented.
    ///
    /// # Example
    ///
    /// ```
    /// # use kvm_ioctls::Kvm;
    /// let kvm = Kvm::new().unwrap();
    /// // We expect the number of vCPUs to be > 0 as per KVM API documentation.
    /// assert!(kvm.get_nr_vcpus() > 0);
    /// ```
    pub fn get_nr_vcpus(&self) -> usize {
        let x = self.check_extension_int(Cap::NrVcpus);
        if x > 0 {
            x as usize
        } else {
            4
        }
    }

    /// Returns the maximum allowed memory slots per VM.
    ///
    /// KVM reports the number of available memory slots (`KVM_CAP_NR_MEMSLOTS`)
    /// using the extension interface.  Both x86 and s390 implement this, ARM
    /// and powerpc do not yet enable it.
    /// Default to 32 when `KVM_CAP_NR_MEMSLOTS` is not implemented.
    ///
    /// # Example
    ///
    /// ```
    /// # use kvm_ioctls::Kvm;
    /// let kvm = Kvm::new().unwrap();
    /// assert!(kvm.get_nr_memslots() > 0);
    /// ```
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
    /// Returns [get_nr_vcpus()](struct.Kvm.html#method.get_nr_vcpus) when
    /// `KVM_CAP_MAX_VCPUS` is not implemented.
    ///
    /// # Example
    ///
    /// ```
    /// # use kvm_ioctls::Kvm;
    /// let kvm = Kvm::new().unwrap();
    /// assert!(kvm.get_max_vcpus() > 0);
    /// ```
    pub fn get_max_vcpus(&self) -> usize {
        match self.check_extension_int(Cap::MaxVcpus) {
            0 => self.get_nr_vcpus(),
            x => x as usize,
        }
    }

    /// Gets the Maximum VCPU ID per VM.
    ///
    /// See the documentation for `KVM_CAP_MAX_VCPU_ID`
    /// Returns [get_max_vcpus()](struct.Kvm.html#method.get_max_vcpus) when
    /// `KVM_CAP_MAX_VCPU_ID` is not implemented
    ///
    /// # Example
    ///
    /// ```
    /// # use kvm_ioctls::Kvm;
    /// let kvm = Kvm::new().unwrap();
    /// assert!(kvm.get_max_vcpu_id() > 0);
    /// ```
    pub fn get_max_vcpu_id(&self) -> usize {
        match self.check_extension_int(Cap::MaxVcpuId) {
            0 => self.get_max_vcpus(),
            x => x as usize,
        }
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn get_cpuid(&self, kind: u64, num_entries: usize) -> Result<CpuId> {
        if num_entries > KVM_MAX_CPUID_ENTRIES {
            // Returns the same error the underlying `ioctl` would have sent.
            return Err(errno::Error::new(libc::ENOMEM));
        }

        let mut cpuid = CpuId::new(num_entries).map_err(|_| errno::Error::new(libc::ENOMEM))?;
        // SAFETY: The kernel is trusted not to write beyond the bounds of the memory
        // allocated for the struct. The limit is read from nent, which is set to the allocated
        // size(num_entries) above.
        let ret = unsafe { ioctl_with_mut_ptr(self, kind, cpuid.as_mut_fam_struct_ptr()) };
        if ret < 0 {
            return Err(errno::Error::last());
        }

        Ok(cpuid)
    }

    /// X86 specific call to get the system emulated CPUID values.
    ///
    /// See the documentation for `KVM_GET_EMULATED_CPUID`.
    ///
    /// # Arguments
    ///
    /// * `num_entries` - Maximum number of CPUID entries. This function can return less than
    ///                         this when the hardware does not support so many CPUID entries.
    ///
    /// Returns Error `errno::Error(libc::ENOMEM)` when the input `num_entries` is greater than
    /// `KVM_MAX_CPUID_ENTRIES`.
    ///
    /// # Example
    ///
    /// ```
    /// extern crate kvm_bindings;
    /// use kvm_bindings::KVM_MAX_CPUID_ENTRIES;
    /// use kvm_ioctls::Kvm;
    ///
    /// let kvm = Kvm::new().unwrap();
    /// let mut cpuid = kvm.get_emulated_cpuid(KVM_MAX_CPUID_ENTRIES).unwrap();
    /// let cpuid_entries = cpuid.as_mut_slice();
    /// assert!(cpuid_entries.len() <= KVM_MAX_CPUID_ENTRIES);
    /// ```
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn get_emulated_cpuid(&self, num_entries: usize) -> Result<CpuId> {
        self.get_cpuid(KVM_GET_EMULATED_CPUID(), num_entries)
    }

    /// X86 specific call to get the system supported CPUID values.
    ///
    /// See the documentation for `KVM_GET_SUPPORTED_CPUID`.
    ///
    /// # Arguments
    ///
    /// * `num_entries` - Maximum number of CPUID entries. This function can return less than
    ///                         this when the hardware does not support so many CPUID entries.
    ///
    /// Returns Error `errno::Error(libc::ENOMEM)` when the input `num_entries` is greater than
    /// `KVM_MAX_CPUID_ENTRIES`.
    ///
    /// # Example
    ///
    /// ```
    /// extern crate kvm_bindings;
    /// use kvm_bindings::KVM_MAX_CPUID_ENTRIES;
    /// use kvm_ioctls::Kvm;
    ///
    /// let kvm = Kvm::new().unwrap();
    /// let mut cpuid = kvm.get_supported_cpuid(KVM_MAX_CPUID_ENTRIES).unwrap();
    /// let cpuid_entries = cpuid.as_mut_slice();
    /// assert!(cpuid_entries.len() <= KVM_MAX_CPUID_ENTRIES);
    /// ```
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn get_supported_cpuid(&self, num_entries: usize) -> Result<CpuId> {
        self.get_cpuid(KVM_GET_SUPPORTED_CPUID(), num_entries)
    }

    /// X86 specific call to get list of supported MSRS
    ///
    /// See the documentation for `KVM_GET_MSR_INDEX_LIST`.
    ///
    /// # Example
    ///
    /// ```
    /// use kvm_ioctls::Kvm;
    ///
    /// let kvm = Kvm::new().unwrap();
    /// let msr_index_list = kvm.get_msr_index_list().unwrap();
    /// ```
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn get_msr_index_list(&self) -> Result<MsrList> {
        let mut msr_list =
            MsrList::new(KVM_MAX_MSR_ENTRIES).map_err(|_| errno::Error::new(libc::ENOMEM))?;

        // SAFETY: The kernel is trusted not to write beyond the bounds of the memory
        // allocated for the struct. The limit is read from nmsrs, which is set to the allocated
        // size (KVM_MAX_MSR_ENTRIES) above.
        let ret = unsafe {
            ioctl_with_mut_ptr(
                self,
                KVM_GET_MSR_INDEX_LIST(),
                msr_list.as_mut_fam_struct_ptr(),
            )
        };
        if ret < 0 {
            return Err(errno::Error::last());
        }

        // The ioctl will also update the internal `nmsrs` with the actual count.
        Ok(msr_list)
    }

    /// X86 specific call to get a list of MSRs that can be passed to the KVM_GET_MSRS system ioctl.
    ///
    /// See the documentation for `KVM_GET_MSR_FEATURE_INDEX_LIST`.
    ///
    /// # Example
    ///
    /// ```
    /// use kvm_bindings::{kvm_msr_entry, Msrs};
    /// use kvm_ioctls::Kvm;
    ///
    /// let kvm = Kvm::new().unwrap();
    /// let msr_feature_index_list = kvm.get_msr_feature_index_list().unwrap();
    /// ```
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn get_msr_feature_index_list(&self) -> Result<MsrList> {
        let mut msr_list =
            MsrList::new(KVM_MAX_MSR_ENTRIES).map_err(|_| errno::Error::new(libc::ENOMEM))?;

        // SAFETY: The kernel is trusted not to write beyond the bounds of the memory
        // allocated for the struct. The limit is read from nmsrs, which is set to the allocated
        // size (KVM_MAX_MSR_ENTRIES) above.
        let ret = unsafe {
            ioctl_with_mut_ptr(
                self,
                KVM_GET_MSR_FEATURE_INDEX_LIST(),
                msr_list.as_mut_fam_struct_ptr(),
            )
        };
        if ret < 0 {
            return Err(errno::Error::last());
        }

        Ok(msr_list)
    }

    /// X86 specific call to read the values of MSR-based features that are available for the VM.
    /// As opposed to `VcpuFd::get_msrs()`, this call returns all the MSRs supported by the
    /// system, similar to `get_supported_cpuid()` for CPUID.
    ///
    /// See the documentation for `KVM_GET_MSRS`.
    ///
    /// # Arguments
    ///
    /// * `msrs`  - MSRs (input/output). For details check the `kvm_msrs` structure in the
    ///             [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    ///
    /// # Example
    ///
    /// ```
    /// use kvm_bindings::{kvm_msr_entry, Msrs};
    /// use kvm_ioctls::Kvm;
    ///
    /// let kvm = Kvm::new().unwrap();
    /// let msr_feature_index_list = kvm.get_msr_feature_index_list().unwrap();
    /// let mut msrs = Msrs::from_entries(
    ///     &msr_feature_index_list
    ///         .as_slice()
    ///         .iter()
    ///         .map(|&idx| kvm_msr_entry {
    ///             index: idx,
    ///             ..Default::default()
    ///         })
    ///         .collect::<Vec<_>>(),
    /// )
    /// .unwrap();
    /// let ret = kvm.get_msrs(&mut msrs).unwrap();
    /// ```
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn get_msrs(&self, msrs: &mut Msrs) -> Result<usize> {
        // SAFETY: Here we trust the kernel not to read past the end of the kvm_msrs struct.
        let ret = unsafe { ioctl_with_mut_ptr(self, KVM_GET_MSRS(), msrs.as_mut_fam_struct_ptr()) };
        if ret < 0 {
            return Err(errno::Error::last());
        }
        Ok(ret as usize)
    }

    /// Creates a VM fd using the KVM fd.
    ///
    /// See the documentation for `KVM_CREATE_VM`.
    /// A call to this function will also initialize the size of the vcpu mmap area using the
    /// `KVM_GET_VCPU_MMAP_SIZE` ioctl.
    ///
    /// # Example
    ///
    /// ```
    /// # use kvm_ioctls::Kvm;
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// // Check that the VM mmap size is the same reported by `KVM_GET_VCPU_MMAP_SIZE`.
    /// assert!(vm.run_size() == kvm.get_vcpu_mmap_size().unwrap());
    /// ```
    #[cfg(not(any(target_arch = "aarch64")))]
    pub fn create_vm(&self) -> Result<VmFd> {
        self.create_vm_with_type(0) // Create using default VM type
    }

    /// AArch64 specific create_vm to create a VM fd using the KVM fd using the host's maximum IPA size.
    ///
    /// See the arm64 section of KVM documentation for `KVM_CREATE_VM`.
    /// A call to this function will also initialize the size of the vcpu mmap area using the
    /// `KVM_GET_VCPU_MMAP_SIZE` ioctl.
    ///
    /// # Example
    ///
    /// ```
    /// # use kvm_ioctls::Kvm;
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// // Check that the VM mmap size is the same reported by `KVM_GET_VCPU_MMAP_SIZE`.
    /// assert!(vm.run_size() == kvm.get_vcpu_mmap_size().unwrap());
    /// ```
    #[cfg(target_arch = "aarch64")]
    pub fn create_vm(&self) -> Result<VmFd> {
        let mut ipa_size = 0; // Create using default VM type
        if self.check_extension(Cap::ArmVmIPASize) {
            ipa_size = self.get_host_ipa_limit();
        }
        self.create_vm_with_type(ipa_size as u64)
    }

    /// AArch64 specific function to create a VM fd using the KVM fd with flexible IPA size.
    ///
    /// See the arm64 section of KVM documentation for `KVM_CREATE_VM`.
    /// A call to this function will also initialize the size of the vcpu mmap area using the
    /// `KVM_GET_VCPU_MMAP_SIZE` ioctl.
    ///
    /// Note: `Cap::ArmVmIPASize` should be checked using `check_extension` before calling
    /// this function to determine if the host machine supports the IPA size capability.
    ///
    /// # Arguments
    ///
    /// * `ipa_size` - Guest VM IPA size, 32 <= ipa_size <= Host_IPA_Limit.
    ///                The value of `Host_IPA_Limit` may be different between hardware
    ///                implementations and can be extracted by calling `get_host_ipa_limit`.
    ///                Possible values can be found in documentation of registers `TCR_EL2`
    ///                and `VTCR_EL2`.
    ///
    /// # Example
    ///
    /// ```
    /// # use kvm_ioctls::{Kvm, Cap};
    /// let kvm = Kvm::new().unwrap();
    /// // Check if the ArmVmIPASize cap is supported.
    /// if kvm.check_extension(Cap::ArmVmIPASize) {
    ///     let host_ipa_limit = kvm.get_host_ipa_limit();
    ///     let vm = kvm.create_vm_with_ipa_size(host_ipa_limit as u32).unwrap();
    ///     // Check that the VM mmap size is the same reported by `KVM_GET_VCPU_MMAP_SIZE`.
    ///     assert!(vm.run_size() == kvm.get_vcpu_mmap_size().unwrap());
    /// }
    /// ```
    #[cfg(target_arch = "aarch64")]
    pub fn create_vm_with_ipa_size(&self, ipa_size: u32) -> Result<VmFd> {
        self.create_vm_with_type((ipa_size & KVM_VM_TYPE_ARM_IPA_SIZE_MASK).into())
    }

    /// Creates a VM fd using the KVM fd of a specific type.
    ///
    /// See the documentation for `KVM_CREATE_VM`.
    /// A call to this function will also initialize the size of the vcpu mmap area using the
    /// `KVM_GET_VCPU_MMAP_SIZE` ioctl.
    ///
    /// * `vm_type` - Platform and architecture specific platform VM type. A value of 0 is the equivalent
    ///               to using the default VM type.
    /// # Example
    ///
    /// ```
    /// # use kvm_ioctls::Kvm;
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm_with_type(0).unwrap();
    /// // Check that the VM mmap size is the same reported by `KVM_GET_VCPU_MMAP_SIZE`.
    /// assert!(vm.run_size() == kvm.get_vcpu_mmap_size().unwrap());
    /// ```
    pub fn create_vm_with_type(&self, vm_type: u64) -> Result<VmFd> {
        // SAFETY: Safe because we know `self.kvm` is a real KVM fd as this module is the only one
        // that create Kvm objects.
        let ret = unsafe { ioctl_with_val(&self.kvm, KVM_CREATE_VM(), vm_type) };
        if ret >= 0 {
            // SAFETY: Safe because we verify the value of ret and we are the owners of the fd.
            let vm_file = unsafe { File::from_raw_fd(ret) };
            let run_mmap_size = self.get_vcpu_mmap_size()?;
            Ok(new_vmfd(vm_file, run_mmap_size))
        } else {
            Err(errno::Error::last())
        }
    }

    /// Creates a VmFd object from a VM RawFd.
    ///
    /// # Arguments
    ///
    /// * `fd` - the RawFd used for creating the VmFd object.
    ///
    /// # Safety
    ///
    /// This function is unsafe as the primitives currently returned have the contract that
    /// they are the sole owner of the file descriptor they are wrapping. Usage of this function
    /// could accidentally allow violating this contract which can cause memory unsafety in code
    /// that relies on it being true.
    ///
    /// The caller of this method must make sure the fd is valid and nothing else uses it.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # use std::os::unix::io::AsRawFd;
    /// # use kvm_ioctls::Kvm;
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let rawfd = unsafe { libc::dup(vm.as_raw_fd()) };
    /// assert!(rawfd >= 0);
    /// let vm = unsafe { kvm.create_vmfd_from_rawfd(rawfd).unwrap() };
    /// ```
    pub unsafe fn create_vmfd_from_rawfd(&self, fd: RawFd) -> Result<VmFd> {
        let run_mmap_size = self.get_vcpu_mmap_size()?;
        Ok(new_vmfd(File::from_raw_fd(fd), run_mmap_size))
    }

    /// Issues platform-specific memory encryption commands to manage encrypted VMs if
    /// the platform supports creating those encrypted VMs.
    ///
    /// Currently, this ioctl is used for issuing Secure Encrypted Virtualization
    /// (SEV) commands on AMD Processors.
    ///
    /// See the documentation for `KVM_MEMORY_ENCRYPT_OP` in the
    /// [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    ///
    /// For SEV-specific functionality, prefer safe wrapper:
    /// - [`encrypt_op_sev`](Self::encrypt_op_sev)
    ///
    /// # Safety
    ///
    /// This function is unsafe because there is no guarantee `T` is valid in this context, how
    /// much data kernel will read from memory and where it will write data on error.
    ///
    /// # Arguments
    ///
    /// * `fd` - the RawFd to be operated on. (`VmFd`, `VcpuFd`, etc.)
    /// * `op` - an opaque platform specific structure.
    ///
    /// # Example
    #[cfg_attr(has_sev, doc = "```rust")]
    #[cfg_attr(not(has_sev), doc = "```rust,no_run")]
    /// # extern crate kvm_ioctls;
    /// # extern crate kvm_bindings;
    /// use kvm_bindings::bindings::kvm_sev_cmd;
    /// # use kvm_ioctls::Kvm;
    ///
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    ///
    /// // Initialize the SEV platform context.
    /// let mut init: kvm_sev_cmd = Default::default();
    /// unsafe { kvm.encrypt_op(&vm, &mut init).unwrap() };
    /// ```
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub unsafe fn encrypt_op<T>(&self, fd: &impl AsRawFd, op: *mut T) -> Result<()> {
        let ret = ioctl_with_mut_ptr(fd, KVM_MEMORY_ENCRYPT_OP(), op);
        if ret == 0 {
            Ok(())
        } else {
            Err(errno::Error::last())
        }
    }

    /// Issue common lifecycle events of SEV guests, such as launching, running, snapshotting,
    /// migrating and decommissioning via `KVM_MEMORY_ENCRYPT_OP` ioctl.
    ///
    /// Kernel documentation states that this ioctl can be used for testing whether SEV is enabled
    /// by sending `NULL`. To do that, pass [`std::ptr::null_mut`](std::ptr::null_mut) to [`encrypt_op`](Self::encrypt_op).
    ///
    /// See the documentation for Secure Encrypted Virtualization (SEV).
    ///
    /// # Arguments
    ///
    /// * `fd` - the RawFd to be operated on. (`VmFd`, `VcpuFd`, etc.)
    /// * `op` - SEV-specific structure. For details check the
    ///         [Secure Encrypted Virtualization (SEV) doc](https://www.kernel.org/doc/Documentation/virtual/kvm/amd-memory-encryption.rst).
    ///
    /// # Example
    #[cfg_attr(has_sev, doc = "```rust")]
    #[cfg_attr(not(has_sev), doc = "```rust,no_run")]
    /// # extern crate kvm_ioctls;
    /// # extern crate kvm_bindings;
    /// # use std::{os::raw::c_void, ptr::null_mut};
    /// use kvm_bindings::bindings::kvm_sev_cmd;
    /// # use kvm_ioctls::Kvm;
    ///
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    ///
    /// // Check whether SEV is enabled, optional.
    /// assert!(unsafe { kvm.encrypt_op(&vm, null_mut() as *mut c_void) }.is_ok());
    ///
    /// // Initialize the SEV platform context.
    /// let mut init: kvm_sev_cmd = Default::default();
    /// kvm.encrypt_op_sev(&vm, &mut init).unwrap();
    /// ```
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn encrypt_op_sev(
        &self,
        fd: &impl AsRawFd,
        op: &mut kvm_bindings::kvm_sev_cmd,
    ) -> Result<()> {
        // SAFETY: Safe because we know that kernel will only read the correct amount of memory
        // from our pointer and we know where it will write it (op.error).
        unsafe { self.encrypt_op(fd, op) }
    }
}

impl AsRawFd for Kvm {
    fn as_raw_fd(&self) -> RawFd {
        self.kvm.as_raw_fd()
    }
}

impl FromRawFd for Kvm {
    /// Creates a new Kvm object assuming `fd` represents an existing open file descriptor
    /// associated with `/dev/kvm`.
    ///
    /// For usage examples check [open_with_cloexec()](struct.Kvm.html#method.open_with_cloexec).
    ///
    /// # Arguments
    ///
    /// * `fd` - File descriptor for `/dev/kvm`.
    ///
    /// # Safety
    ///
    /// This function is unsafe as the primitives currently returned have the contract that
    /// they are the sole owner of the file descriptor they are wrapping. Usage of this function
    /// could accidentally allow violating this contract which can cause memory unsafety in code
    /// that relies on it being true.
    ///
    /// The caller of this method must make sure the fd is valid and nothing else uses it.
    ///
    /// # Example
    ///
    /// ```
    /// # use kvm_ioctls::Kvm;
    /// # use std::os::unix::io::FromRawFd;
    /// let kvm_fd = Kvm::open_with_cloexec(true).unwrap();
    /// // Safe because we verify that the fd is valid in `open_with_cloexec` and we own the fd.
    /// let kvm = unsafe { Kvm::from_raw_fd(kvm_fd) };
    /// ```
    unsafe fn from_raw_fd(fd: RawFd) -> Self {
        Kvm {
            kvm: File::from_raw_fd(fd),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks)]
    use super::*;
    use libc::{fcntl, FD_CLOEXEC, F_GETFD};
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    use vmm_sys_util::fam::FamStruct;

    #[test]
    fn test_kvm_new() {
        Kvm::new().unwrap();
    }

    #[test]
    fn test_kvm_new_with_path() {
        let kvm_path = unsafe { CStr::from_bytes_with_nul_unchecked(b"/dev/kvm\0") };
        Kvm::new_with_path(kvm_path).unwrap();
    }

    #[test]
    fn test_open_with_cloexec() {
        let fd = Kvm::open_with_cloexec(false).unwrap();
        let flags = unsafe { fcntl(fd, F_GETFD, 0) };
        assert_eq!(flags & FD_CLOEXEC, 0);
        let fd = Kvm::open_with_cloexec(true).unwrap();
        let flags = unsafe { fcntl(fd, F_GETFD, 0) };
        assert_eq!(flags & FD_CLOEXEC, FD_CLOEXEC);
    }

    #[test]
    fn test_open_with_cloexec_at() {
        let kvm_path = std::ffi::CString::new("/dev/kvm").unwrap();
        let fd = Kvm::open_with_cloexec_at(&kvm_path, false).unwrap();
        let flags = unsafe { fcntl(fd, F_GETFD, 0) };
        assert_eq!(flags & FD_CLOEXEC, 0);
        let fd = Kvm::open_with_cloexec_at(&kvm_path, true).unwrap();
        let flags = unsafe { fcntl(fd, F_GETFD, 0) };
        assert_eq!(flags & FD_CLOEXEC, FD_CLOEXEC);
    }

    #[test]
    fn test_kvm_api_version() {
        let kvm = Kvm::new().unwrap();
        assert_eq!(kvm.get_api_version(), 12);
        assert!(kvm.check_extension(Cap::UserMemory));
    }

    #[test]
    fn test_kvm_check_extension() {
        let kvm = Kvm::new().unwrap();
        // unsupported extension will return 0
        assert_eq!(kvm.check_extension_raw(696969), 0);
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn test_get_host_ipa_limit() {
        let kvm = Kvm::new().unwrap();
        let host_ipa_limit = kvm.get_host_ipa_limit();

        if host_ipa_limit > 0 {
            assert!(host_ipa_limit >= 32);
        } else {
            // if unsupported, the return value should be 0.
            assert_eq!(host_ipa_limit, 0);
        }
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn test_guest_debug_hw_capacity() {
        let kvm = Kvm::new().unwrap();
        // The number of supported breakpoints and watchpoints may vary on
        // different platforms.
        // It could be 0 if no supported, or any positive integer otherwise.
        assert!(kvm.get_guest_debug_hw_bps() >= 0);
        assert!(kvm.get_guest_debug_hw_wps() >= 0);
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

        // Test create_vmfd_from_rawfd()
        let rawfd = unsafe { libc::dup(vm.as_raw_fd()) };
        assert!(rawfd >= 0);
        let vm = unsafe { kvm.create_vmfd_from_rawfd(rawfd).unwrap() };

        assert_eq!(vm.run_size(), kvm.get_vcpu_mmap_size().unwrap());
    }

    #[test]
    fn test_create_vm_with_type() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm_with_type(0).unwrap();

        // Test create_vmfd_from_rawfd()
        let rawfd = unsafe { libc::dup(vm.as_raw_fd()) };
        assert!(rawfd >= 0);
        let vm = unsafe { kvm.create_vmfd_from_rawfd(rawfd).unwrap() };

        assert_eq!(vm.run_size(), kvm.get_vcpu_mmap_size().unwrap());
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn test_create_vm_with_ipa_size() {
        let kvm = Kvm::new().unwrap();
        if kvm.check_extension(Cap::ArmVmIPASize) {
            let host_ipa_limit = kvm.get_host_ipa_limit();
            // Here we test with the maximum value that the host supports to both test the
            // discoverability of supported IPA sizes and likely some other values than 40.
            kvm.create_vm_with_ipa_size(host_ipa_limit as u32).unwrap();
            // Test invalid input values
            // Case 1: IPA size is smaller than 32.
            assert!(kvm.create_vm_with_ipa_size(31).is_err());
            // Case 2: IPA size is bigger than Host_IPA_Limit.
            assert!(kvm
                .create_vm_with_ipa_size((host_ipa_limit + 1) as u32)
                .is_err());
        } else {
            // Unsupported, we can't provide an IPA size. Only KVM type=0 works.
            assert!(kvm.create_vm_with_type(0).is_err());
        }
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[test]
    fn test_get_supported_cpuid() {
        let kvm = Kvm::new().unwrap();
        let mut cpuid = kvm.get_supported_cpuid(KVM_MAX_CPUID_ENTRIES).unwrap();
        let cpuid_entries = cpuid.as_mut_slice();
        assert!(!cpuid_entries.is_empty());
        assert!(cpuid_entries.len() <= KVM_MAX_CPUID_ENTRIES);

        // Test case for more than MAX entries
        let cpuid_err = kvm.get_emulated_cpuid(KVM_MAX_CPUID_ENTRIES + 1_usize);
        assert!(cpuid_err.is_err());
    }

    #[test]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn test_get_emulated_cpuid() {
        let kvm = Kvm::new().unwrap();
        let mut cpuid = kvm.get_emulated_cpuid(KVM_MAX_CPUID_ENTRIES).unwrap();
        let cpuid_entries = cpuid.as_mut_slice();
        assert!(!cpuid_entries.is_empty());
        assert!(cpuid_entries.len() <= KVM_MAX_CPUID_ENTRIES);

        // Test case for more than MAX entries
        let cpuid_err = kvm.get_emulated_cpuid(KVM_MAX_CPUID_ENTRIES + 1_usize);
        assert!(cpuid_err.is_err());
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[test]
    fn test_cpuid_clone() {
        let kvm = Kvm::new().unwrap();

        // Test from_raw_fd()
        let rawfd = unsafe { libc::dup(kvm.as_raw_fd()) };
        assert!(rawfd >= 0);
        let kvm = unsafe { Kvm::from_raw_fd(rawfd) };

        let cpuid_1 = kvm.get_supported_cpuid(KVM_MAX_CPUID_ENTRIES).unwrap();
        let _ = CpuId::new(cpuid_1.as_fam_struct_ref().len()).unwrap();
    }

    #[test]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn get_msr_index_list() {
        let kvm = Kvm::new().unwrap();
        let msr_list = kvm.get_msr_index_list().unwrap();
        assert!(msr_list.as_slice().len() >= 2);
    }

    #[test]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn get_msr_feature_index_list() {
        let kvm = Kvm::new().unwrap();
        let msr_feature_index_list = kvm.get_msr_feature_index_list().unwrap();
        assert!(!msr_feature_index_list.as_slice().is_empty());
    }

    #[test]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn get_msrs() {
        use kvm_bindings::kvm_msr_entry;

        let kvm = Kvm::new().unwrap();
        let mut msrs = Msrs::from_entries(&[
            kvm_msr_entry {
                index: 0x0000010a, // MSR_IA32_ARCH_CAPABILITIES
                ..Default::default()
            },
            kvm_msr_entry {
                index: 0x00000345, // MSR_IA32_PERF_CAPABILITIES
                ..Default::default()
            },
        ])
        .unwrap();
        let nmsrs = kvm.get_msrs(&mut msrs).unwrap();

        assert_eq!(nmsrs, 2);
    }

    #[test]
    fn test_bad_kvm_fd() {
        let badf_errno = libc::EBADF;

        let faulty_kvm = Kvm {
            kvm: unsafe { File::from_raw_fd(-2) },
        };

        assert_eq!(
            faulty_kvm.get_vcpu_mmap_size().unwrap_err().errno(),
            badf_errno
        );
        assert_eq!(faulty_kvm.get_nr_vcpus(), 4);
        assert_eq!(faulty_kvm.get_nr_memslots(), 32);
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            assert_eq!(
                faulty_kvm.get_emulated_cpuid(4).err().unwrap().errno(),
                badf_errno
            );
            assert_eq!(
                faulty_kvm.get_supported_cpuid(4).err().unwrap().errno(),
                badf_errno
            );

            assert_eq!(
                faulty_kvm.get_msr_index_list().err().unwrap().errno(),
                badf_errno
            );
        }
        assert_eq!(faulty_kvm.create_vm().err().unwrap().errno(), badf_errno);
    }

    #[test]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[cfg_attr(not(has_sev), ignore)]
    fn test_encrypt_op_sev() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();

        let mut init: kvm_bindings::kvm_sev_cmd = Default::default();
        assert!(kvm.encrypt_op_sev(&vm, &mut init).is_ok());
    }
}
