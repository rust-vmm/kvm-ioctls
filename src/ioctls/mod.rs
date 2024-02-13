// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::mem::size_of;
use std::os::unix::io::AsRawFd;
use std::ptr::null_mut;

use kvm_bindings::{
    kvm_coalesced_mmio, kvm_coalesced_mmio_ring, kvm_run, KVM_COALESCED_MMIO_PAGE_OFFSET,
};
use vmm_sys_util::errno;

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
/// This typedef is generally used to avoid writing out errno::Error directly and
/// is otherwise a direct mapping to Result.
pub type Result<T> = std::result::Result<T, errno::Error>;

/// A wrapper around the coalesced MMIO ring page.
#[derive(Debug)]
pub(crate) struct KvmCoalescedIoRing {
    addr: *mut kvm_coalesced_mmio_ring,
    page_size: usize,
}

impl KvmCoalescedIoRing {
    /// Maps the coalesced MMIO ring from the vCPU file descriptor.
    pub(crate) fn mmap_from_fd<F: AsRawFd>(fd: &F) -> Result<Self> {
        // SAFETY: We trust the sysconf libc function and we're calling it
        // with a correct parameter.
        let page_size = match unsafe { libc::sysconf(libc::_SC_PAGESIZE) } {
            -1 => return Err(errno::Error::last()),
            ps => ps as usize,
        };

        let offset = KVM_COALESCED_MMIO_PAGE_OFFSET * page_size as u32;
        // SAFETY: KVM guarantees that there is a page at offset
        // KVM_COALESCED_MMIO_PAGE_OFFSET * PAGE_SIZE if the appropriate
        // capability is available. If it is not, the call will simply
        // fail.
        let addr = unsafe {
            libc::mmap(
                null_mut(),
                page_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd.as_raw_fd(),
                offset.into(),
            )
        };
        if addr == libc::MAP_FAILED {
            return Err(errno::Error::last());
        }
        Ok(Self {
            addr: addr.cast(),
            page_size,
        })
    }

    /// Compute the size of the MMIO ring.
    /// Taken from [include/uapi/linux/kvm.h](https://elixir.bootlin.com/linux/v6.6/source/include/uapi/linux/kvm.h#L562)
    const fn ring_max(&self) -> usize {
        (self.page_size - size_of::<kvm_coalesced_mmio_ring>()) / size_of::<kvm_coalesced_mmio>()
    }

    /// Gets a mutable reference to the ring
    fn ring_mut(&mut self) -> &mut kvm_coalesced_mmio_ring {
        // SAFETY: We have a `&mut self` and the pointer is private, so this
        // access is exclusive.
        unsafe { &mut *self.addr }
    }

    /// Reads a single entry from the MMIO ring.
    ///
    /// # Returns
    ///
    /// An entry from the MMIO ring buffer, or [`None`] if the ring is empty.
    pub(crate) fn read_entry(&mut self) -> Option<kvm_coalesced_mmio> {
        let ring_max = self.ring_max();

        let ring = self.ring_mut();
        if ring.first == ring.last {
            return None;
        }

        let entries = ring.coalesced_mmio.as_ptr();
        // SAFETY: `ring.first` is an `u32` coming from mapped memory filled
        // by the kernel, so we trust it. `entries` is a pointer coming from
        // mmap(), so pointer arithmetic cannot overflow. We have a `&mut self`,
        // so nobody else has access to the contents of the pointer.
        let elem = unsafe { entries.add(ring.first as usize).read() };
        ring.first = (ring.first + 1) % ring_max as u32;

        Some(elem)
    }
}

impl Drop for KvmCoalescedIoRing {
    fn drop(&mut self) {
        // SAFETY: This is safe because we mmap the page ourselves, and nobody
        // else is holding a reference to it.
        unsafe {
            libc::munmap(self.addr.cast(), self.page_size);
        }
    }
}

// SAFETY: See safety comments about [`KvmRunWrapper`].
unsafe impl Send for KvmCoalescedIoRing {}
// SAFETY: See safety comments about [`KvmRunWrapper`].
unsafe impl Sync for KvmCoalescedIoRing {}

/// Safe wrapper over the `kvm_run` struct.
///
/// The wrapper is needed for sending the pointer to `kvm_run` between
/// threads as raw pointers do not implement `Send` and `Sync`.
#[derive(Debug)]
pub struct KvmRunWrapper {
    kvm_run_ptr: *mut u8,
    // This field is need so we can `munmap` the memory mapped to hold `kvm_run`.
    mmap_size: usize,
}

// SAFETY: Send and Sync aren't automatically inherited for the raw address pointer.
// Accessing that pointer is only done through the stateless interface which
// allows the object to be shared by multiple threads without a decrease in
// safety.
unsafe impl Send for KvmRunWrapper {}
// SAFETY: See above.
unsafe impl Sync for KvmRunWrapper {}

impl KvmRunWrapper {
    /// Maps the first `size` bytes of the given `fd`.
    ///
    /// # Arguments
    /// * `fd` - File descriptor to mmap from.
    /// * `size` - Size of memory region in bytes.
    pub fn mmap_from_fd<F: AsRawFd>(fd: &F, size: usize) -> Result<KvmRunWrapper> {
        // SAFETY: This is safe because we are creating a mapping in a place not already used by
        // any other area in this process.
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
            return Err(errno::Error::last());
        }

        Ok(KvmRunWrapper {
            kvm_run_ptr: addr as *mut u8,
            mmap_size: size,
        })
    }

    /// Returns a mutable reference to `kvm_run`.
    pub fn as_mut_ref(&mut self) -> &mut kvm_run {
        #[allow(clippy::cast_ptr_alignment)]
        // SAFETY: Safe because we know we mapped enough memory to hold the kvm_run struct because
        // the kernel told us how large it was.
        unsafe {
            &mut *(self.kvm_run_ptr as *mut kvm_run)
        }
    }
}

impl AsRef<kvm_run> for KvmRunWrapper {
    fn as_ref(&self) -> &kvm_run {
        // SAFETY: Safe because we know we mapped enough memory to hold the kvm_run struct because
        // the kernel told us how large it was.
        unsafe { &*(self.kvm_run_ptr as *const kvm_run) }
    }
}

impl Drop for KvmRunWrapper {
    fn drop(&mut self) {
        // SAFETY: This is safe because we mmap the area at kvm_run_ptr ourselves,
        // and nobody else is holding a reference to it.
        unsafe {
            libc::munmap(self.kvm_run_ptr as *mut libc::c_void, self.mmap_size);
        }
    }
}
