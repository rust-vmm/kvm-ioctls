// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use ioctls::Result;
use kvm_bindings::*;
use std::fs::File;
use std::io;
use std::os::raw::{c_ulong, c_void};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};

use ioctls::device::new_device;
use ioctls::device::DeviceFd;
use ioctls::vcpu::new_vcpu;
use ioctls::vcpu::VcpuFd;
use ioctls::KvmRunWrapper;
use kvm_ioctls::*;
use sys_ioctl::*;

/// An address either in programmable I/O space or in memory mapped I/O space.
pub enum IoEventAddress {
    /// Representation of an programmable I/O address.
    Pio(u64),
    /// Representation of an memory mapped I/O address.
    Mmio(u64),
}

/// Used in `VmFd::register_ioevent` to indicate that no datamatch is requested.
pub struct NoDatamatch;
impl Into<u64> for NoDatamatch {
    fn into(self) -> u64 {
        0
    }
}

/// A wrapper around creating and using a VM.
pub struct VmFd {
    vm: File,
    run_size: usize,
}

impl VmFd {
    /// Creates/modifies a guest physical memory slot.
    ///
    /// See the documentation for `KVM_SET_USER_MEMORY_REGION`.
    ///
    pub fn set_user_memory_region(
        &self,
        user_memory_region: kvm_userspace_memory_region,
    ) -> Result<()> {
        let ret =
            unsafe { ioctl_with_ref(self, KVM_SET_USER_MEMORY_REGION(), &user_memory_region) };
        if ret == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// Sets the address of the three-page region in the VM's address space.
    ///
    /// See the documentation on the `KVM_SET_TSS_ADDR` ioctl.
    ///
    /// # Arguments
    ///
    /// * `offset` - Physical address of a three-page region in the guest's physical address space.
    ///
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn set_tss_address(&self, offset: usize) -> Result<()> {
        // Safe because we know that our file is a VM fd and we verify the return result.
        let ret = unsafe { ioctl_with_val(self, KVM_SET_TSS_ADDR(), offset as c_ulong) };
        if ret == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// Creates an in-kernel interrupt controller.
    ///
    /// See the documentation for `KVM_CREATE_IRQCHIP`.
    ///
    #[cfg(any(
        target_arch = "x86",
        target_arch = "x86_64",
        target_arch = "arm",
        target_arch = "aarch64"
    ))]
    pub fn create_irq_chip(&self) -> Result<()> {
        // Safe because we know that our file is a VM fd and we verify the return result.
        let ret = unsafe { ioctl(self, KVM_CREATE_IRQCHIP()) };
        if ret == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// Creates a PIT as per the `KVM_CREATE_PIT2` ioctl.
    ///
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn create_pit2(&self, pit_config: kvm_pit_config) -> Result<()> {
        // Safe because we know that our file is a VM fd, we know the kernel will only read the
        // correct amount of memory from our pointer, and we verify the return result.
        let ret = unsafe { ioctl_with_ref(self, KVM_CREATE_PIT2(), &pit_config) };
        if ret == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// Registers an event to be signaled whenever a certain address is written to.
    ///
    /// # Arguments
    ///
    /// * `fd` - FD which will be signaled. When signaling, the usual `vmexit` to userspace
    ///           is prevented.
    /// * `addr` - Address being written to.
    /// * `datamatch` - Limits signaling `fd` to only the cases where the value being written is
    ///                 equal to this parameter. The size of `datamatch` is important and it must
    ///                 match the expected size of the guest's write.
    ///
    pub fn register_ioevent<T: Into<u64>>(
        &self,
        fd: RawFd,
        addr: &IoEventAddress,
        datamatch: T,
    ) -> Result<()> {
        let mut flags = 0;
        if std::mem::size_of::<T>() > 0 {
            flags |= 1 << kvm_ioeventfd_flag_nr_datamatch
        }
        if let IoEventAddress::Pio(_) = *addr {
            flags |= 1 << kvm_ioeventfd_flag_nr_pio
        }

        let ioeventfd = kvm_ioeventfd {
            datamatch: datamatch.into(),
            len: std::mem::size_of::<T>() as u32,
            addr: match addr {
                IoEventAddress::Pio(ref p) => *p as u64,
                IoEventAddress::Mmio(ref m) => *m,
            },
            fd,
            flags,
            ..Default::default()
        };
        // Safe because we know that our file is a VM fd, we know the kernel will only read the
        // correct amount of memory from our pointer, and we verify the return result.
        let ret = unsafe { ioctl_with_ref(self, KVM_IOEVENTFD(), &ioeventfd) };
        if ret == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// Gets the bitmap of pages dirtied since the last call of this function.
    ///
    /// Leverages the dirty page logging feature in KVM. As a side-effect, this also resets the
    /// bitmap inside the kernel.
    ///
    /// # Arguments
    ///
    /// * `slot` - Guest memory slot identifier.
    /// * `memory_size` - Size of the memory region.
    ///
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn get_dirty_log(&self, slot: u32, memory_size: usize) -> Result<Vec<u64>> {
        // Compute the length of the bitmap needed for all dirty pages in one memory slot.
        // One memory page is 4KiB (4096 bits) and `KVM_GET_DIRTY_LOG` returns one dirty bit for
        // each page.
        let page_size = 4 << 10;

        let div_round_up = |dividend, divisor| (dividend + divisor - 1) / divisor;
        // For ease of access we are saving the bitmap in a u64 vector. We are using ceil to
        // make sure we count all dirty pages even when `mem_size` is not a multiple of
        // page_size * 64.
        let bitmap_size = div_round_up(memory_size, page_size * 64);
        let mut bitmap = vec![0; bitmap_size];
        let b_data = bitmap.as_mut_ptr() as *mut c_void;
        let dirtylog = kvm_dirty_log {
            slot,
            padding1: 0,
            __bindgen_anon_1: kvm_dirty_log__bindgen_ty_1 {
                dirty_bitmap: b_data,
            },
        };
        // Safe because we know that our file is a VM fd, and we know that the amount of memory
        // we allocated for the bitmap is at least one bit per page.
        let ret = unsafe { ioctl_with_ref(self, KVM_GET_DIRTY_LOG(), &dirtylog) };
        if ret == 0 {
            Ok(bitmap)
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// Registers an event that will, when signaled, trigger the `gsi` IRQ.
    ///
    /// # Arguments
    ///
    /// * `fd` - Event to be signaled.
    /// * `gsi` - IRQ to be triggered.
    ///
    #[cfg(any(
        target_arch = "x86",
        target_arch = "x86_64",
        target_arch = "arm",
        target_arch = "aarch64"
    ))]
    pub fn register_irqfd(&self, fd: RawFd, gsi: u32) -> Result<()> {
        let irqfd = kvm_irqfd {
            fd: fd as u32,
            gsi,
            ..Default::default()
        };
        // Safe because we know that our file is a VM fd, we know the kernel will only read the
        // correct amount of memory from our pointer, and we verify the return result.
        let ret = unsafe { ioctl_with_ref(self, KVM_IRQFD(), &irqfd) };
        if ret == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// Creates a new KVM vCPU fd.
    ///
    /// # Arguments
    ///
    /// * `id` - The CPU number between [0, max vs).
    ///
    /// # Errors
    /// Returns an error when the VM fd is invalid or the vCPU memory cannot be mapped correctly.
    ///
    pub fn create_vcpu(&self, id: u8) -> Result<VcpuFd> {
        // Safe because we know that vm is a VM fd and we verify the return result.
        #[allow(clippy::cast_lossless)]
        let vcpu_fd = unsafe { ioctl_with_val(&self.vm, KVM_CREATE_VCPU(), id as c_ulong) };
        if vcpu_fd < 0 {
            return Err(io::Error::last_os_error());
        }

        // Wrap the vCPU now in case the following ? returns early. This is safe because we verified
        // the value of the fd and we own the fd.
        let vcpu = unsafe { File::from_raw_fd(vcpu_fd) };

        let kvm_run_ptr = KvmRunWrapper::mmap_from_fd(&vcpu, self.run_size)?;

        Ok(new_vcpu(vcpu, kvm_run_ptr))
    }

    /// Creates an emulated device in the kernel.
    pub fn create_device(&self, device: &mut kvm_create_device) -> Result<DeviceFd> {
        let ret = unsafe { ioctl_with_ref(self, KVM_CREATE_DEVICE(), device) };
        if ret == 0 {
            Ok((new_device(unsafe { File::from_raw_fd(device.fd as i32) })))
        } else {
            return Err(io::Error::last_os_error());
        }
    }

    /// This queries the kernel for the preferred target CPU type.
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    pub fn get_preferred_target(&self, kvi: &mut kvm_vcpu_init) -> Result<()> {
        // The ioctl is safe because we allocated the struct and we know the
        // kernel will write exactly the size of the struct.
        let ret = unsafe { ioctl_with_mut_ref(self, KVM_ARM_PREFERRED_TARGET(), kvi) };
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Get the `kvm_run` size.
    pub fn get_run_size(&self) -> usize {
        self.run_size
    }
}

/// Helper function to create a new `VmFd`.
///
/// This should not be exported as a public function because the preferred way is to use
/// `create_vm` from `Kvm`. The function cannot be part of the `VmFd` implementation because
/// then it would be exported with the public `VmFd` interface.
pub fn new_vmfd(vm: File, run_size: usize) -> VmFd {
    VmFd { vm, run_size }
}

impl AsRawFd for VmFd {
    fn as_raw_fd(&self) -> RawFd {
        self.vm.as_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use {Cap, Kvm, MAX_KVM_CPUID_ENTRIES};

    use libc::{eventfd, EFD_NONBLOCK};

    #[test]
    fn test_set_invalid_memory() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let invalid_mem_region = kvm_userspace_memory_region {
            slot: 0,
            guest_phys_addr: 0,
            memory_size: 0,
            userspace_addr: 0,
            flags: 0,
        };
        assert!(vm.set_user_memory_region(invalid_mem_region).is_err());
    }

    #[test]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn test_set_tss_address() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        assert!(vm.set_tss_address(0xfffb_d000).is_ok());
    }

    #[test]
    #[cfg(any(
        target_arch = "x86",
        target_arch = "x86_64",
        target_arch = "arm",
        target_arch = "aarch64"
    ))]
    fn test_create_irq_chip() {
        let kvm = Kvm::new().unwrap();
        assert!(kvm.check_extension(Cap::Irqchip));
        let vm = kvm.create_vm().unwrap();
        if cfg!(any(target_arch = "x86", target_arch = "x86_64")) {
            assert!(vm.create_irq_chip().is_ok());
        } else if cfg!(any(target_arch = "arm", target_arch = "aarch64")) {
            // On arm, we expect this to fail as the irq chip needs to be created after the vcpus.
            assert!(vm.create_irq_chip().is_err());
        }
    }

    #[test]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn test_create_pit2() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        assert!(vm.create_pit2(kvm_pit_config::default()).is_ok());
    }

    #[test]
    fn test_register_ioevent() {
        assert_eq!(std::mem::size_of::<NoDatamatch>(), 0);

        let kvm = Kvm::new().unwrap();
        let vm_fd = kvm.create_vm().unwrap();
        let evtfd = unsafe { eventfd(0, EFD_NONBLOCK) };
        assert!(vm_fd
            .register_ioevent(evtfd, &IoEventAddress::Pio(0xf4), NoDatamatch)
            .is_ok());
        assert!(vm_fd
            .register_ioevent(evtfd, &IoEventAddress::Mmio(0x1000), NoDatamatch)
            .is_ok());
        assert!(vm_fd
            .register_ioevent(evtfd, &IoEventAddress::Pio(0xc1), 0x7fu8)
            .is_ok());
        assert!(vm_fd
            .register_ioevent(evtfd, &IoEventAddress::Pio(0xc2), 0x1337u16)
            .is_ok());
        assert!(vm_fd
            .register_ioevent(evtfd, &IoEventAddress::Pio(0xc4), 0xdead_beefu32)
            .is_ok());
        assert!(vm_fd
            .register_ioevent(evtfd, &IoEventAddress::Pio(0xc8), 0xdead_beef_dead_beefu64)
            .is_ok());
    }

    #[test]
    #[cfg(any(
        target_arch = "x86",
        target_arch = "x86_64",
        target_arch = "arm",
        target_arch = "aarch64"
    ))]
    fn test_register_irqfd() {
        let kvm = Kvm::new().unwrap();
        let vm_fd = kvm.create_vm().unwrap();
        let evtfd1 = unsafe { eventfd(0, EFD_NONBLOCK) };
        let evtfd2 = unsafe { eventfd(0, EFD_NONBLOCK) };
        let evtfd3 = unsafe { eventfd(0, EFD_NONBLOCK) };
        if cfg!(any(target_arch = "x86", target_arch = "x86_64")) {
            assert!(vm_fd.register_irqfd(evtfd1, 4).is_ok());
            assert!(vm_fd.register_irqfd(evtfd2, 8).is_ok());
            assert!(vm_fd.register_irqfd(evtfd3, 4).is_ok());
        }

        // On aarch64, this fails because setting up the interrupt controller is mandatory before
        // registering any IRQ.
        // On x86_64 this fails as the event fd was already matched with a GSI.
        assert!(vm_fd.register_irqfd(evtfd3, 4).is_err());
        assert!(vm_fd.register_irqfd(evtfd3, 5).is_err());
    }

    fn get_raw_errno<T>(result: super::Result<T>) -> i32 {
        result.err().unwrap().raw_os_error().unwrap()
    }

    #[test]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn test_faulty_vm_fd() {
        let badf_errno = libc::EBADF;

        let faulty_vm_fd = VmFd {
            vm: unsafe { File::from_raw_fd(-1) },
            run_size: 0,
        };

        let invalid_mem_region = kvm_userspace_memory_region {
            slot: 0,
            guest_phys_addr: 0,
            memory_size: 0,
            userspace_addr: 0,
            flags: 0,
        };

        assert_eq!(
            get_raw_errno(faulty_vm_fd.set_user_memory_region(invalid_mem_region)),
            badf_errno
        );
        assert_eq!(get_raw_errno(faulty_vm_fd.set_tss_address(0)), badf_errno);
        assert_eq!(get_raw_errno(faulty_vm_fd.create_irq_chip()), badf_errno);
        assert_eq!(
            get_raw_errno(faulty_vm_fd.create_pit2(kvm_pit_config::default())),
            badf_errno
        );
        let event_fd = unsafe { eventfd(0, EFD_NONBLOCK) };
        assert_eq!(
            get_raw_errno(faulty_vm_fd.register_ioevent(event_fd, &IoEventAddress::Pio(0), 0u64)),
            badf_errno
        );
        assert_eq!(
            get_raw_errno(faulty_vm_fd.register_irqfd(event_fd, 0)),
            badf_errno
        );

        assert_eq!(get_raw_errno(faulty_vm_fd.create_vcpu(0)), badf_errno);

        assert_eq!(get_raw_errno(faulty_vm_fd.get_dirty_log(0, 0)), badf_errno);
    }

    #[test]
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    fn test_get_preferred_target() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let mut kvi: kvm_bindings::kvm_vcpu_init = kvm_bindings::kvm_vcpu_init::default();
        assert!(vm.get_preferred_target(&mut kvi).is_ok());
    }
}
