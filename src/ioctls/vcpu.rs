// Copyright © 2024 Institute of Software, CAS. All rights reserved.
//
// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use kvm_bindings::*;
use libc::EINVAL;
use std::fs::File;
use std::os::unix::io::{AsRawFd, RawFd};

use crate::ioctls::{KvmCoalescedIoRing, KvmRunWrapper, Result};
use crate::kvm_ioctls::*;
use vmm_sys_util::errno;
use vmm_sys_util::ioctl::{ioctl, ioctl_with_mut_ref, ioctl_with_ref};
#[cfg(target_arch = "x86_64")]
use vmm_sys_util::ioctl::{ioctl_with_mut_ptr, ioctl_with_ptr, ioctl_with_val};

/// Helper method to obtain the size of the register through its id
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
pub fn reg_size(reg_id: u64) -> usize {
    2_usize.pow(((reg_id & KVM_REG_SIZE_MASK) >> KVM_REG_SIZE_SHIFT) as u32)
}

/// Information about a [`VcpuExit`] triggered by an Hypercall (`KVM_EXIT_HYPERCALL`).
#[derive(Debug)]
pub struct HypercallExit<'a> {
    /// The hypercall number.
    pub nr: u64,
    /// The arguments for the hypercall.
    pub args: [u64; 6],
    /// The return code to be indicated to the guest.
    pub ret: &'a mut u64,
    /// Whether the hypercall was executed in long mode.
    pub longmode: u32,
}

/// Information about a [`VcpuExit`] triggered by an MSR read (`KVM_EXIT_X86_RDMSR`).
#[derive(Debug)]
pub struct ReadMsrExit<'a> {
    /// Must be set to 1 by the the user if the read access should fail. This
    /// will inject a #GP fault into the guest when the VCPU is executed
    /// again.
    pub error: &'a mut u8,
    /// The reason for this exit.
    pub reason: MsrExitReason,
    /// The MSR the guest wants to read.
    pub index: u32,
    /// The data to be supplied by the user as the MSR Contents to the guest.
    pub data: &'a mut u64,
}

/// Information about a [`VcpuExit`] triggered by an MSR write (`KVM_EXIT_X86_WRMSR`).
#[derive(Debug)]
pub struct WriteMsrExit<'a> {
    /// Must be set to 1 by the the user if the write access should fail. This
    /// will inject a #GP fault into the guest when the VCPU is executed
    /// again.
    pub error: &'a mut u8,
    /// The reason for this exit.
    pub reason: MsrExitReason,
    /// The MSR the guest wants to write.
    pub index: u32,
    /// The data the guest wants to write into the MSR.
    pub data: u64,
}

bitflags::bitflags! {
    /// The reason for a [`VcpuExit::X86Rdmsr`] or[`VcpuExit::X86Wrmsr`]. This
    /// is also used when enabling
    /// [`Cap::X86UserSpaceMsr`](crate::Cap::X86UserSpaceMsr) to specify which
    /// reasons should be forwarded to the user via those exits.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct MsrExitReason: u32 {
        /// Corresponds to [`KVM_MSR_EXIT_REASON_UNKNOWN`]. The exit was
        /// triggered by an access to an MSR that is unknown to KVM.
        const Unknown = KVM_MSR_EXIT_REASON_UNKNOWN;
        /// Corresponds to [`KVM_MSR_EXIT_REASON_INVAL`]. The exit was
        /// triggered by an access to an invalid MSR or to reserved bits.
        const Inval = KVM_MSR_EXIT_REASON_INVAL;
        /// Corresponds to [`KVM_MSR_EXIT_REASON_FILTER`]. The exit was
        /// triggered by an access to a filtered MSR.
        const Filter = KVM_MSR_EXIT_REASON_FILTER;
    }
}

/// Reasons for vCPU exits.
///
/// The exit reasons are mapped to the `KVM_EXIT_*` defines in the
/// [Linux KVM header](https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/kvm.h).
#[derive(Debug)]
pub enum VcpuExit<'a> {
    /// An out port instruction was run on the given port with the given data.
    IoOut(u16 /* port */, &'a [u8] /* data */),
    /// An in port instruction was run on the given port.
    ///
    /// The given slice should be filled in before [run()](struct.VcpuFd.html#method.run)
    /// is called again.
    IoIn(u16 /* port */, &'a mut [u8] /* data */),
    /// A read instruction was run against the given MMIO address.
    ///
    /// The given slice should be filled in before [run()](struct.VcpuFd.html#method.run)
    /// is called again.
    MmioRead(u64 /* address */, &'a mut [u8]),
    /// A write instruction was run against the given MMIO address with the given data.
    MmioWrite(u64 /* address */, &'a [u8]),
    /// Corresponds to KVM_EXIT_UNKNOWN.
    Unknown,
    /// Corresponds to KVM_EXIT_EXCEPTION.
    Exception,
    /// Corresponds to KVM_EXIT_HYPERCALL.
    Hypercall(HypercallExit<'a>),
    /// Corresponds to KVM_EXIT_DEBUG.
    ///
    /// Provides architecture specific information for the debug event.
    Debug(kvm_debug_exit_arch),
    /// Corresponds to KVM_EXIT_HLT.
    Hlt,
    /// Corresponds to KVM_EXIT_IRQ_WINDOW_OPEN.
    IrqWindowOpen,
    /// Corresponds to KVM_EXIT_SHUTDOWN.
    Shutdown,
    /// Corresponds to KVM_EXIT_FAIL_ENTRY.
    FailEntry(
        u64, /* hardware_entry_failure_reason */
        u32, /* cpu */
    ),
    /// Corresponds to KVM_EXIT_INTR.
    Intr,
    /// Corresponds to KVM_EXIT_SET_TPR.
    SetTpr,
    /// Corresponds to KVM_EXIT_TPR_ACCESS.
    TprAccess,
    /// Corresponds to KVM_EXIT_S390_SIEIC.
    S390Sieic,
    /// Corresponds to KVM_EXIT_S390_RESET.
    S390Reset,
    /// Corresponds to KVM_EXIT_DCR.
    Dcr,
    /// Corresponds to KVM_EXIT_NMI.
    Nmi,
    /// Corresponds to KVM_EXIT_INTERNAL_ERROR.
    InternalError,
    /// Corresponds to KVM_EXIT_OSI.
    Osi,
    /// Corresponds to KVM_EXIT_PAPR_HCALL.
    PaprHcall,
    /// Corresponds to KVM_EXIT_S390_UCONTROL.
    S390Ucontrol,
    /// Corresponds to KVM_EXIT_WATCHDOG.
    Watchdog,
    /// Corresponds to KVM_EXIT_S390_TSCH.
    S390Tsch,
    /// Corresponds to KVM_EXIT_EPR.
    Epr,
    /// Corresponds to KVM_EXIT_SYSTEM_EVENT.
    SystemEvent(u32 /* type */, &'a [u64] /* data */),
    /// Corresponds to KVM_EXIT_S390_STSI.
    S390Stsi,
    /// Corresponds to KVM_EXIT_IOAPIC_EOI.
    IoapicEoi(u8 /* vector */),
    /// Corresponds to KVM_EXIT_HYPERV.
    Hyperv,
    /// Corresponds to KVM_EXIT_X86_RDMSR.
    X86Rdmsr(ReadMsrExit<'a>),
    /// Corresponds to KVM_EXIT_X86_WRMSR.
    X86Wrmsr(WriteMsrExit<'a>),
    /// Corresponds to KVM_EXIT_MEMORY_FAULT.
    MemoryFault {
        /// flags
        flags: u64,
        /// gpa
        gpa: u64,
        /// size
        size: u64,
    },
    /// Corresponds to an exit reason that is unknown from the current version
    /// of the kvm-ioctls crate. Let the consumer decide about what to do with
    /// it.
    Unsupported(u32),
}

/// Wrapper over KVM vCPU ioctls.
#[derive(Debug)]
pub struct VcpuFd {
    vcpu: File,
    kvm_run_ptr: KvmRunWrapper,
    /// A pointer to the coalesced MMIO page
    coalesced_mmio_ring: Option<KvmCoalescedIoRing>,
}

/// KVM Sync Registers used to tell KVM which registers to sync
#[repr(u32)]
#[derive(Debug, Copy, Clone)]
#[cfg(target_arch = "x86_64")]
pub enum SyncReg {
    /// General purpose registers,
    Register = KVM_SYNC_X86_REGS,

    /// System registers
    SystemRegister = KVM_SYNC_X86_SREGS,

    /// CPU events
    VcpuEvents = KVM_SYNC_X86_EVENTS,
}

impl VcpuFd {
    /// Returns the vCPU general purpose registers.
    ///
    /// The registers are returned in a `kvm_regs` structure as defined in the
    /// [KVM API documentation](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    /// See documentation for `KVM_GET_REGS`.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # use kvm_ioctls::Kvm;
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    /// let regs = vcpu.get_regs().unwrap();
    /// ```
    #[cfg(not(any(target_arch = "aarch64", target_arch = "riscv64")))]
    pub fn get_regs(&self) -> Result<kvm_regs> {
        let mut regs = kvm_regs::default();
        // SAFETY: Safe because we know that our file is a vCPU fd, we know the kernel will only
        // read the correct amount of memory from our pointer, and we verify the return result.
        let ret = unsafe { ioctl_with_mut_ref(self, KVM_GET_REGS(), &mut regs) };
        if ret != 0 {
            return Err(errno::Error::last());
        }
        Ok(regs)
    }

    /// Sets a specified piece of cpu configuration and/or state.
    ///
    /// See the documentation for `KVM_SET_DEVICE_ATTR` in
    /// [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt)
    /// # Arguments
    ///
    /// * `device_attr` - The cpu attribute to be set.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # extern crate kvm_bindings;
    /// # use kvm_ioctls::Kvm;
    /// # use kvm_bindings::{
    ///    KVM_ARM_VCPU_PMU_V3_CTRL, KVM_ARM_VCPU_PMU_V3_INIT
    /// };
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    ///
    /// let dist_attr = kvm_bindings::kvm_device_attr {
    ///     group: KVM_ARM_VCPU_PMU_V3_CTRL,
    ///     attr: u64::from(KVM_ARM_VCPU_PMU_V3_INIT),
    ///     addr: 0x0,
    ///     flags: 0,
    /// };
    ///
    /// if (vcpu.has_device_attr(&dist_attr).is_ok()) {
    ///     vcpu.set_device_attr(&dist_attr).unwrap();
    /// }
    /// ```
    #[cfg(target_arch = "aarch64")]
    pub fn set_device_attr(&self, device_attr: &kvm_device_attr) -> Result<()> {
        // SAFETY: Safe because we call this with a Vcpu fd and we trust the kernel.
        let ret = unsafe { ioctl_with_ref(self, KVM_SET_DEVICE_ATTR(), device_attr) };
        if ret != 0 {
            return Err(errno::Error::last());
        }
        Ok(())
    }

    /// Tests whether a cpu supports a particular attribute.
    ///
    /// See the documentation for `KVM_HAS_DEVICE_ATTR` in
    /// [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt)
    /// # Arguments
    ///
    /// * `device_attr` - The cpu attribute to be tested. `addr` field is ignored.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # extern crate kvm_bindings;
    /// # use kvm_ioctls::Kvm;
    /// # use kvm_bindings::{
    ///    KVM_ARM_VCPU_PMU_V3_CTRL, KVM_ARM_VCPU_PMU_V3_INIT
    /// };
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    ///
    /// let dist_attr = kvm_bindings::kvm_device_attr {
    ///     group: KVM_ARM_VCPU_PMU_V3_CTRL,
    ///     attr: u64::from(KVM_ARM_VCPU_PMU_V3_INIT),
    ///     addr: 0x0,
    ///     flags: 0,
    /// };
    ///
    /// vcpu.has_device_attr(&dist_attr);
    /// ```
    #[cfg(target_arch = "aarch64")]
    pub fn has_device_attr(&self, device_attr: &kvm_device_attr) -> Result<()> {
        // SAFETY: Safe because we call this with a Vcpu fd and we trust the kernel.
        let ret = unsafe { ioctl_with_ref(self, KVM_HAS_DEVICE_ATTR(), device_attr) };
        if ret != 0 {
            return Err(errno::Error::last());
        }
        Ok(())
    }

    /// Sets the vCPU general purpose registers using the `KVM_SET_REGS` ioctl.
    ///
    /// # Arguments
    ///
    /// * `regs` - general purpose registers. For details check the `kvm_regs` structure in the
    ///             [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # use kvm_ioctls::Kvm;
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    ///
    /// // Get the current vCPU registers.
    /// let mut regs = vcpu.get_regs().unwrap();
    /// // Set a new value for the Instruction Pointer.
    /// regs.rip = 0x100;
    /// vcpu.set_regs(&regs).unwrap();
    /// ```
    #[cfg(not(any(target_arch = "aarch64", target_arch = "riscv64")))]
    pub fn set_regs(&self, regs: &kvm_regs) -> Result<()> {
        // SAFETY: Safe because we know that our file is a vCPU fd, we know the kernel will only
        // read the correct amount of memory from our pointer, and we verify the return result.
        let ret = unsafe { ioctl_with_ref(self, KVM_SET_REGS(), regs) };
        if ret != 0 {
            return Err(errno::Error::last());
        }
        Ok(())
    }

    /// Returns the vCPU special registers.
    ///
    /// The registers are returned in a `kvm_sregs` structure as defined in the
    /// [KVM API documentation](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    /// See documentation for `KVM_GET_SREGS`.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # use kvm_ioctls::Kvm;
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    /// let sregs = vcpu.get_sregs().unwrap();
    /// ```
    #[cfg(target_arch = "x86_64")]
    pub fn get_sregs(&self) -> Result<kvm_sregs> {
        let mut regs = kvm_sregs::default();
        // SAFETY: Safe because we know that our file is a vCPU fd, we know the kernel will only
        // write the correct amount of memory to our pointer, and we verify the return result.
        let ret = unsafe { ioctl_with_mut_ref(self, KVM_GET_SREGS(), &mut regs) };
        if ret != 0 {
            return Err(errno::Error::last());
        }
        Ok(regs)
    }

    /// Sets the vCPU special registers using the `KVM_SET_SREGS` ioctl.
    ///
    /// # Arguments
    ///
    /// * `sregs` - Special registers. For details check the `kvm_sregs` structure in the
    ///             [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # use kvm_ioctls::Kvm;
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    ///
    /// let mut sregs = vcpu.get_sregs().unwrap();
    /// // Update the code segment (cs).
    /// sregs.cs.base = 0;
    /// sregs.cs.selector = 0;
    /// vcpu.set_sregs(&sregs).unwrap();
    /// ```
    #[cfg(target_arch = "x86_64")]
    pub fn set_sregs(&self, sregs: &kvm_sregs) -> Result<()> {
        // SAFETY: Safe because we know that our file is a vCPU fd, we know the kernel will only
        // read the correct amount of memory from our pointer, and we verify the return result.
        let ret = unsafe { ioctl_with_ref(self, KVM_SET_SREGS(), sregs) };
        if ret != 0 {
            return Err(errno::Error::last());
        }
        Ok(())
    }

    /// Returns the floating point state (FPU) from the vCPU.
    ///
    /// The state is returned in a `kvm_fpu` structure as defined in the
    /// [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    /// See the documentation for `KVM_GET_FPU`.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # use kvm_ioctls::Kvm;
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    /// #[cfg(target_arch = "x86_64")]
    /// let fpu = vcpu.get_fpu().unwrap();
    /// ```
    #[cfg(target_arch = "x86_64")]
    pub fn get_fpu(&self) -> Result<kvm_fpu> {
        let mut fpu = kvm_fpu::default();
        // SAFETY: Here we trust the kernel not to read past the end of the kvm_fpu struct.
        let ret = unsafe { ioctl_with_mut_ref(self, KVM_GET_FPU(), &mut fpu) };
        if ret != 0 {
            return Err(errno::Error::last());
        }
        Ok(fpu)
    }

    /// Set the floating point state (FPU) of a vCPU using the `KVM_SET_FPU` ioct.
    ///
    /// # Arguments
    ///
    /// * `fpu` - FPU configuration. For details check the `kvm_fpu` structure in the
    ///           [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # extern crate kvm_bindings;
    /// # use kvm_ioctls::Kvm;
    /// # use kvm_bindings::kvm_fpu;
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    /// #[cfg(target_arch = "x86_64")]
    /// {
    ///     let KVM_FPU_CWD: u16 = 0x37f;
    ///     let fpu = kvm_fpu {
    ///         fcw: KVM_FPU_CWD,
    ///         ..Default::default()
    ///     };
    ///     vcpu.set_fpu(&fpu).unwrap();
    /// }
    /// ```
    #[cfg(target_arch = "x86_64")]
    pub fn set_fpu(&self, fpu: &kvm_fpu) -> Result<()> {
        // SAFETY: Here we trust the kernel not to read past the end of the kvm_fpu struct.
        let ret = unsafe { ioctl_with_ref(self, KVM_SET_FPU(), fpu) };
        if ret < 0 {
            return Err(errno::Error::last());
        }
        Ok(())
    }

    /// X86 specific call to setup the CPUID registers.
    ///
    /// See the documentation for `KVM_SET_CPUID2`.
    ///
    /// # Arguments
    ///
    /// * `cpuid` - CPUID registers.
    ///
    /// # Example
    ///
    ///  ```rust
    /// # extern crate kvm_ioctls;
    /// # extern crate kvm_bindings;
    /// # use kvm_bindings::KVM_MAX_CPUID_ENTRIES;
    /// # use kvm_ioctls::Kvm;
    /// let kvm = Kvm::new().unwrap();
    /// let mut kvm_cpuid = kvm.get_supported_cpuid(KVM_MAX_CPUID_ENTRIES).unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    ///
    /// // Update the CPUID entries to disable the EPB feature.
    /// const ECX_EPB_SHIFT: u32 = 3;
    /// {
    ///     let entries = kvm_cpuid.as_mut_slice();
    ///     for entry in entries.iter_mut() {
    ///         match entry.function {
    ///             6 => entry.ecx &= !(1 << ECX_EPB_SHIFT),
    ///             _ => (),
    ///         }
    ///     }
    /// }
    ///
    /// vcpu.set_cpuid2(&kvm_cpuid).unwrap();
    /// ```
    ///
    #[cfg(target_arch = "x86_64")]
    pub fn set_cpuid2(&self, cpuid: &CpuId) -> Result<()> {
        // SAFETY: Here we trust the kernel not to read past the end of the kvm_cpuid2 struct.
        let ret = unsafe { ioctl_with_ptr(self, KVM_SET_CPUID2(), cpuid.as_fam_struct_ptr()) };
        if ret < 0 {
            return Err(errno::Error::last());
        }
        Ok(())
    }

    /// X86 specific call to retrieve the CPUID registers.
    ///
    /// It requires knowledge of how many `kvm_cpuid_entry2` entries there are to get.
    /// See the documentation for `KVM_GET_CPUID2` in the
    /// [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    ///
    /// # Arguments
    ///
    /// * `num_entries` - Number of CPUID entries to be read.
    ///
    /// # Example
    ///
    ///  ```rust
    /// # extern crate kvm_ioctls;
    /// # extern crate kvm_bindings;
    /// # use kvm_bindings::KVM_MAX_CPUID_ENTRIES;
    /// # use kvm_ioctls::Kvm;
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    /// let cpuid = vcpu.get_cpuid2(KVM_MAX_CPUID_ENTRIES).unwrap();
    /// ```
    ///
    #[cfg(target_arch = "x86_64")]
    pub fn get_cpuid2(&self, num_entries: usize) -> Result<CpuId> {
        if num_entries > KVM_MAX_CPUID_ENTRIES {
            // Returns the same error the underlying `ioctl` would have sent.
            return Err(errno::Error::new(libc::ENOMEM));
        }

        let mut cpuid = CpuId::new(num_entries).map_err(|_| errno::Error::new(libc::ENOMEM))?;
        let ret =
            // SAFETY: Here we trust the kernel not to read past the end of the kvm_cpuid2 struct.
            unsafe { ioctl_with_mut_ptr(self, KVM_GET_CPUID2(), cpuid.as_mut_fam_struct_ptr()) };
        if ret != 0 {
            return Err(errno::Error::last());
        }
        Ok(cpuid)
    }

    ///
    /// See the documentation for `KVM_ENABLE_CAP`.
    ///
    /// # Arguments
    ///
    /// * kvm_enable_cap - KVM capability structure. For details check the `kvm_enable_cap`
    ///                    structure in the
    ///                    [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    ///
    /// # Example
    ///
    ///  ```rust
    /// # extern crate kvm_ioctls;
    /// # extern crate kvm_bindings;
    /// # use kvm_bindings::{kvm_enable_cap, KVM_MAX_CPUID_ENTRIES, KVM_CAP_HYPERV_SYNIC, KVM_CAP_SPLIT_IRQCHIP};
    /// # use kvm_ioctls::{Kvm, Cap};
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let mut cap: kvm_enable_cap = Default::default();
    /// if cfg!(target_arch = "x86_64") {
    ///     // KVM_CAP_HYPERV_SYNIC needs KVM_CAP_SPLIT_IRQCHIP enabled
    ///     cap.cap = KVM_CAP_SPLIT_IRQCHIP;
    ///     cap.args[0] = 24;
    ///     vm.enable_cap(&cap).unwrap();
    ///
    ///     let vcpu = vm.create_vcpu(0).unwrap();
    ///     if kvm.check_extension(Cap::HypervSynic) {
    ///         let mut cap: kvm_enable_cap = Default::default();
    ///         cap.cap = KVM_CAP_HYPERV_SYNIC;
    ///         vcpu.enable_cap(&cap).unwrap();
    ///     }
    /// }
    /// ```
    ///
    #[cfg(target_arch = "x86_64")]
    pub fn enable_cap(&self, cap: &kvm_enable_cap) -> Result<()> {
        // SAFETY: The ioctl is safe because we allocated the struct and we know the
        // kernel will write exactly the size of the struct.
        let ret = unsafe { ioctl_with_ref(self, KVM_ENABLE_CAP(), cap) };
        if ret == 0 {
            Ok(())
        } else {
            Err(errno::Error::last())
        }
    }

    /// Returns the state of the LAPIC (Local Advanced Programmable Interrupt Controller).
    ///
    /// The state is returned in a `kvm_lapic_state` structure as defined in the
    /// [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    /// See the documentation for `KVM_GET_LAPIC`.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # use kvm_ioctls::Kvm;
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// // For `get_lapic` to work, you first need to create a IRQ chip before creating the vCPU.
    /// vm.create_irq_chip().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    /// let lapic = vcpu.get_lapic().unwrap();
    /// ```
    #[cfg(target_arch = "x86_64")]
    pub fn get_lapic(&self) -> Result<kvm_lapic_state> {
        let mut klapic = kvm_lapic_state::default();

        // SAFETY: The ioctl is unsafe unless you trust the kernel not to write past the end of the
        // local_apic struct.
        let ret = unsafe { ioctl_with_mut_ref(self, KVM_GET_LAPIC(), &mut klapic) };
        if ret < 0 {
            return Err(errno::Error::last());
        }
        Ok(klapic)
    }

    /// Sets the state of the LAPIC (Local Advanced Programmable Interrupt Controller).
    ///
    /// See the documentation for `KVM_SET_LAPIC`.
    ///
    /// # Arguments
    ///
    /// * `klapic` - LAPIC state. For details check the `kvm_lapic_state` structure in the
    ///             [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # use kvm_ioctls::Kvm;
    /// use std::io::Write;
    ///
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// // For `get_lapic` to work, you first need to create a IRQ chip before creating the vCPU.
    /// vm.create_irq_chip().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    /// let mut lapic = vcpu.get_lapic().unwrap();
    ///
    /// // Write to APIC_ICR offset the value 2.
    /// let apic_icr_offset = 0x300;
    /// let write_value: &[u8] = &[2, 0, 0, 0];
    /// let mut apic_icr_slice =
    ///     unsafe { &mut *(&mut lapic.regs[apic_icr_offset..] as *mut [i8] as *mut [u8]) };
    /// apic_icr_slice.write(write_value).unwrap();
    ///
    /// // Update the value of LAPIC.
    /// vcpu.set_lapic(&lapic).unwrap();
    /// ```
    #[cfg(target_arch = "x86_64")]
    pub fn set_lapic(&self, klapic: &kvm_lapic_state) -> Result<()> {
        // SAFETY: The ioctl is safe because the kernel will only read from the klapic struct.
        let ret = unsafe { ioctl_with_ref(self, KVM_SET_LAPIC(), klapic) };
        if ret < 0 {
            return Err(errno::Error::last());
        }
        Ok(())
    }

    /// Returns the model-specific registers (MSR) for this vCPU.
    ///
    /// It emulates `KVM_GET_MSRS` ioctl's behavior by returning the number of MSRs
    /// successfully read upon success or the last error number in case of failure.
    /// The MSRs are returned in the `msr` method argument.
    ///
    /// # Arguments
    ///
    /// * `msrs`  - MSRs (input/output). For details check the `kvm_msrs` structure in the
    ///             [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # extern crate kvm_bindings;
    /// # use kvm_ioctls::Kvm;
    /// # use kvm_bindings::{kvm_msr_entry, Msrs};
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    /// // Configure the struct to say which entries we want to get.
    /// let mut msrs = Msrs::from_entries(&[
    ///     kvm_msr_entry {
    ///         index: 0x0000_0174,
    ///         ..Default::default()
    ///     },
    ///     kvm_msr_entry {
    ///         index: 0x0000_0175,
    ///         ..Default::default()
    ///     },
    /// ])
    /// .unwrap();
    /// let read = vcpu.get_msrs(&mut msrs).unwrap();
    /// assert_eq!(read, 2);
    /// ```
    #[cfg(target_arch = "x86_64")]
    pub fn get_msrs(&self, msrs: &mut Msrs) -> Result<usize> {
        // SAFETY: Here we trust the kernel not to read past the end of the kvm_msrs struct.
        let ret = unsafe { ioctl_with_mut_ptr(self, KVM_GET_MSRS(), msrs.as_mut_fam_struct_ptr()) };
        if ret < 0 {
            return Err(errno::Error::last());
        }
        Ok(ret as usize)
    }

    /// Setup the model-specific registers (MSR) for this vCPU.
    /// Returns the number of MSR entries actually written.
    ///
    /// See the documentation for `KVM_SET_MSRS`.
    ///
    /// # Arguments
    ///
    /// * `msrs` - MSRs. For details check the `kvm_msrs` structure in the
    ///            [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # extern crate kvm_bindings;
    /// # use kvm_ioctls::Kvm;
    /// # use kvm_bindings::{kvm_msr_entry, Msrs};
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    ///
    /// // Configure the entries we want to set.
    /// let mut msrs = Msrs::from_entries(&[kvm_msr_entry {
    ///     index: 0x0000_0174,
    ///     ..Default::default()
    /// }])
    /// .unwrap();
    /// let written = vcpu.set_msrs(&msrs).unwrap();
    /// assert_eq!(written, 1);
    /// ```
    #[cfg(target_arch = "x86_64")]
    pub fn set_msrs(&self, msrs: &Msrs) -> Result<usize> {
        // SAFETY: Here we trust the kernel not to read past the end of the kvm_msrs struct.
        let ret = unsafe { ioctl_with_ptr(self, KVM_SET_MSRS(), msrs.as_fam_struct_ptr()) };
        // KVM_SET_MSRS actually returns the number of msr entries written.
        if ret < 0 {
            return Err(errno::Error::last());
        }
        Ok(ret as usize)
    }

    /// Returns the vcpu's current "multiprocessing state".
    ///
    /// See the documentation for `KVM_GET_MP_STATE` in the
    /// [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    ///
    /// # Arguments
    ///
    /// * `kvm_mp_state` - multiprocessing state to be read.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # use kvm_ioctls::Kvm;
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    /// let mp_state = vcpu.get_mp_state().unwrap();
    /// ```
    #[cfg(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64",
        target_arch = "s390x"
    ))]
    pub fn get_mp_state(&self) -> Result<kvm_mp_state> {
        let mut mp_state = Default::default();
        // SAFETY: Here we trust the kernel not to read past the end of the kvm_mp_state struct.
        let ret = unsafe { ioctl_with_mut_ref(self, KVM_GET_MP_STATE(), &mut mp_state) };
        if ret != 0 {
            return Err(errno::Error::last());
        }
        Ok(mp_state)
    }

    /// Sets the vcpu's current "multiprocessing state".
    ///
    /// See the documentation for `KVM_SET_MP_STATE` in the
    /// [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    ///
    /// # Arguments
    ///
    /// * `kvm_mp_state` - multiprocessing state to be written.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # use kvm_ioctls::Kvm;
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    /// let mp_state = Default::default();
    /// // Your `mp_state` manipulation here.
    /// vcpu.set_mp_state(mp_state).unwrap();
    /// ```
    #[cfg(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64",
        target_arch = "s390x"
    ))]
    pub fn set_mp_state(&self, mp_state: kvm_mp_state) -> Result<()> {
        // SAFETY: Here we trust the kernel not to read past the end of the kvm_mp_state struct.
        let ret = unsafe { ioctl_with_ref(self, KVM_SET_MP_STATE(), &mp_state) };
        if ret != 0 {
            return Err(errno::Error::last());
        }
        Ok(())
    }

    /// X86 specific call that returns the vcpu's current "xsave struct".
    ///
    /// See the documentation for `KVM_GET_XSAVE` in the
    /// [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    ///
    /// # Arguments
    ///
    /// * `kvm_xsave` - xsave struct to be read.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # use kvm_ioctls::Kvm;
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    /// let xsave = vcpu.get_xsave().unwrap();
    /// ```
    #[cfg(target_arch = "x86_64")]
    pub fn get_xsave(&self) -> Result<kvm_xsave> {
        let mut xsave = Default::default();
        // SAFETY: Here we trust the kernel not to read past the end of the kvm_xsave struct.
        let ret = unsafe { ioctl_with_mut_ref(self, KVM_GET_XSAVE(), &mut xsave) };
        if ret != 0 {
            return Err(errno::Error::last());
        }
        Ok(xsave)
    }

    /// X86 specific call that sets the vcpu's current "xsave struct".
    ///
    /// See the documentation for `KVM_SET_XSAVE` in the
    /// [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    ///
    /// # Arguments
    ///
    /// * `kvm_xsave` - xsave struct to be written.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # use kvm_ioctls::Kvm;
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    /// let xsave = Default::default();
    /// // Your `xsave` manipulation here.
    /// vcpu.set_xsave(&xsave).unwrap();
    /// ```
    #[cfg(target_arch = "x86_64")]
    pub fn set_xsave(&self, xsave: &kvm_xsave) -> Result<()> {
        // SAFETY: Here we trust the kernel not to read past the end of the kvm_xsave struct.
        let ret = unsafe { ioctl_with_ref(self, KVM_SET_XSAVE(), xsave) };
        if ret != 0 {
            return Err(errno::Error::last());
        }
        Ok(())
    }

    /// X86 specific call that returns the vcpu's current "xcrs".
    ///
    /// See the documentation for `KVM_GET_XCRS` in the
    /// [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    ///
    /// # Arguments
    ///
    /// * `kvm_xcrs` - xcrs to be read.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # use kvm_ioctls::Kvm;
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    /// let xcrs = vcpu.get_xcrs().unwrap();
    /// ```
    #[cfg(target_arch = "x86_64")]
    pub fn get_xcrs(&self) -> Result<kvm_xcrs> {
        let mut xcrs = Default::default();
        // SAFETY: Here we trust the kernel not to read past the end of the kvm_xcrs struct.
        let ret = unsafe { ioctl_with_mut_ref(self, KVM_GET_XCRS(), &mut xcrs) };
        if ret != 0 {
            return Err(errno::Error::last());
        }
        Ok(xcrs)
    }

    /// X86 specific call that sets the vcpu's current "xcrs".
    ///
    /// See the documentation for `KVM_SET_XCRS` in the
    /// [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    ///
    /// # Arguments
    ///
    /// * `kvm_xcrs` - xcrs to be written.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # use kvm_ioctls::Kvm;
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    /// let xcrs = Default::default();
    /// // Your `xcrs` manipulation here.
    /// vcpu.set_xcrs(&xcrs).unwrap();
    /// ```
    #[cfg(target_arch = "x86_64")]
    pub fn set_xcrs(&self, xcrs: &kvm_xcrs) -> Result<()> {
        // SAFETY: Here we trust the kernel not to read past the end of the kvm_xcrs struct.
        let ret = unsafe { ioctl_with_ref(self, KVM_SET_XCRS(), xcrs) };
        if ret != 0 {
            return Err(errno::Error::last());
        }
        Ok(())
    }

    /// X86 specific call that returns the vcpu's current "debug registers".
    ///
    /// See the documentation for `KVM_GET_DEBUGREGS` in the
    /// [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    ///
    /// # Arguments
    ///
    /// * `kvm_debugregs` - debug registers to be read.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # use kvm_ioctls::Kvm;
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    /// let debug_regs = vcpu.get_debug_regs().unwrap();
    /// ```
    #[cfg(target_arch = "x86_64")]
    pub fn get_debug_regs(&self) -> Result<kvm_debugregs> {
        let mut debug_regs = Default::default();
        // SAFETY: Here we trust the kernel not to read past the end of the kvm_debugregs struct.
        let ret = unsafe { ioctl_with_mut_ref(self, KVM_GET_DEBUGREGS(), &mut debug_regs) };
        if ret != 0 {
            return Err(errno::Error::last());
        }
        Ok(debug_regs)
    }

    /// X86 specific call that sets the vcpu's current "debug registers".
    ///
    /// See the documentation for `KVM_SET_DEBUGREGS` in the
    /// [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    ///
    /// # Arguments
    ///
    /// * `kvm_debugregs` - debug registers to be written.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # use kvm_ioctls::Kvm;
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    /// let debug_regs = Default::default();
    /// // Your `debug_regs` manipulation here.
    /// vcpu.set_debug_regs(&debug_regs).unwrap();
    /// ```
    #[cfg(target_arch = "x86_64")]
    pub fn set_debug_regs(&self, debug_regs: &kvm_debugregs) -> Result<()> {
        // SAFETY: Here we trust the kernel not to read past the end of the kvm_debugregs struct.
        let ret = unsafe { ioctl_with_ref(self, KVM_SET_DEBUGREGS(), debug_regs) };
        if ret != 0 {
            return Err(errno::Error::last());
        }
        Ok(())
    }

    /// Returns currently pending exceptions, interrupts, and NMIs as well as related
    /// states of the vcpu.
    ///
    /// See the documentation for `KVM_GET_VCPU_EVENTS` in the
    /// [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    ///
    /// # Arguments
    ///
    /// * `kvm_vcpu_events` - vcpu events to be read.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # use kvm_ioctls::{Kvm, Cap};
    /// let kvm = Kvm::new().unwrap();
    /// if kvm.check_extension(Cap::VcpuEvents) {
    ///     let vm = kvm.create_vm().unwrap();
    ///     let vcpu = vm.create_vcpu(0).unwrap();
    ///     let vcpu_events = vcpu.get_vcpu_events().unwrap();
    /// }
    /// ```
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    pub fn get_vcpu_events(&self) -> Result<kvm_vcpu_events> {
        let mut vcpu_events = Default::default();
        // SAFETY: Here we trust the kernel not to read past the end of the kvm_vcpu_events struct.
        let ret = unsafe { ioctl_with_mut_ref(self, KVM_GET_VCPU_EVENTS(), &mut vcpu_events) };
        if ret != 0 {
            return Err(errno::Error::last());
        }
        Ok(vcpu_events)
    }

    /// Sets pending exceptions, interrupts, and NMIs as well as related states of the vcpu.
    ///
    /// See the documentation for `KVM_SET_VCPU_EVENTS` in the
    /// [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    ///
    /// # Arguments
    ///
    /// * `kvm_vcpu_events` - vcpu events to be written.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # use kvm_ioctls::{Kvm, Cap};
    /// let kvm = Kvm::new().unwrap();
    /// if kvm.check_extension(Cap::VcpuEvents) {
    ///     let vm = kvm.create_vm().unwrap();
    ///     let vcpu = vm.create_vcpu(0).unwrap();
    ///     let vcpu_events = Default::default();
    ///     // Your `vcpu_events` manipulation here.
    ///     vcpu.set_vcpu_events(&vcpu_events).unwrap();
    /// }
    /// ```
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    pub fn set_vcpu_events(&self, vcpu_events: &kvm_vcpu_events) -> Result<()> {
        // SAFETY: Here we trust the kernel not to read past the end of the kvm_vcpu_events struct.
        let ret = unsafe { ioctl_with_ref(self, KVM_SET_VCPU_EVENTS(), vcpu_events) };
        if ret != 0 {
            return Err(errno::Error::last());
        }
        Ok(())
    }

    /// Sets the type of CPU to be exposed to the guest and optional features.
    ///
    /// This initializes an ARM vCPU to the specified type with the specified features
    /// and resets the values of all of its registers to defaults. See the documentation for
    /// `KVM_ARM_VCPU_INIT`.
    ///
    /// # Arguments
    ///
    /// * `kvi` - information about preferred CPU target type and recommended features for it.
    ///           For details check the `kvm_vcpu_init` structure in the
    ///           [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    ///
    /// # Example
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # extern crate kvm_bindings;
    /// # use kvm_ioctls::Kvm;
    /// use kvm_bindings::kvm_vcpu_init;
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    ///
    /// let mut kvi = kvm_vcpu_init::default();
    /// vm.get_preferred_target(&mut kvi).unwrap();
    /// vcpu.vcpu_init(&kvi).unwrap();
    /// ```
    #[cfg(target_arch = "aarch64")]
    pub fn vcpu_init(&self, kvi: &kvm_vcpu_init) -> Result<()> {
        // SAFETY: This is safe because we allocated the struct and we know the kernel will read
        // exactly the size of the struct.
        let ret = unsafe { ioctl_with_ref(self, KVM_ARM_VCPU_INIT(), kvi) };
        if ret < 0 {
            return Err(errno::Error::last());
        }
        Ok(())
    }

    /// Finalizes the configuration of the specified vcpu feature.
    ///
    /// The vcpu must already have been initialised, enabling the affected feature,
    /// by means of a successful KVM_ARM_VCPU_INIT call with the appropriate flag set
    /// in features[].
    ///
    /// For affected vcpu features, this is a mandatory step that must be performed before
    /// the vcpu is fully usable.
    ///
    /// Between KVM_ARM_VCPU_INIT and KVM_ARM_VCPU_FINALIZE, the feature may be configured
    /// by use of ioctls such as KVM_SET_ONE_REG. The exact configuration that should be
    /// performaned and how to do it are feature-dependent.
    ///
    /// Other calls that depend on a particular feature being finalized, such as KVM_RUN,
    /// KVM_GET_REG_LIST, KVM_GET_ONE_REG and KVM_SET_ONE_REG, will fail with -EPERM unless
    /// the feature has already been finalized by means of a KVM_ARM_VCPU_FINALIZE call.
    ///
    /// See KVM_ARM_VCPU_INIT for details of vcpu features that require finalization using this ioctl.
    /// [KVM_ARM_VCPU_FINALIZE](https://www.kernel.org/doc/html/latest/virt/kvm/api.html#kvm-arm-vcpu-finalize).
    ///
    /// # Arguments
    ///
    /// * `feature` - vCPU features that needs to be finalized.
    ///
    /// # Example
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # extern crate kvm_bindings;
    /// # use kvm_ioctls::Kvm;
    /// use std::arch::is_aarch64_feature_detected;
    ///
    /// use kvm_bindings::{kvm_vcpu_init, KVM_ARM_VCPU_SVE};
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    ///
    /// let mut kvi = kvm_vcpu_init::default();
    /// vm.get_preferred_target(&mut kvi).unwrap();
    /// kvi.features[0] |= 1 << KVM_ARM_VCPU_SVE;
    /// if is_aarch64_feature_detected!("sve2") || is_aarch64_feature_detected!("sve") {
    ///     vcpu.vcpu_init(&kvi).unwrap();
    ///     let feature = KVM_ARM_VCPU_SVE as i32;
    ///     vcpu.vcpu_finalize(&feature).unwrap();
    /// }
    /// ```
    #[cfg(target_arch = "aarch64")]
    pub fn vcpu_finalize(&self, feature: &std::os::raw::c_int) -> Result<()> {
        // SAFETY: This is safe because we know the kernel will only read this
        // parameter to select the correct finalization case in KVM.
        let ret = unsafe { ioctl_with_ref(self, KVM_ARM_VCPU_FINALIZE(), feature) };
        if ret < 0 {
            return Err(errno::Error::last());
        }
        Ok(())
    }

    /// Returns the guest registers that are supported for the
    /// KVM_GET_ONE_REG/KVM_SET_ONE_REG calls.
    ///
    /// # Arguments
    ///
    /// * `reg_list`  - list of registers (input/output). For details check the `kvm_reg_list`
    ///                 structure in the
    ///                 [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # extern crate kvm_bindings;
    /// # use kvm_ioctls::Kvm;
    /// # use kvm_bindings::RegList;
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    ///
    /// // KVM_GET_REG_LIST on Aarch64 demands that the vcpus be initialized.
    /// #[cfg(target_arch = "aarch64")]
    /// {
    ///     let mut kvi = kvm_bindings::kvm_vcpu_init::default();
    ///     vm.get_preferred_target(&mut kvi).unwrap();
    ///     vcpu.vcpu_init(&kvi).expect("Cannot initialize vcpu");
    ///
    ///     let mut reg_list = RegList::new(500).unwrap();
    ///     vcpu.get_reg_list(&mut reg_list).unwrap();
    ///     assert!(reg_list.as_fam_struct_ref().n > 0);
    /// }
    /// ```
    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
    pub fn get_reg_list(&self, reg_list: &mut RegList) -> Result<()> {
        let ret =
            // SAFETY: This is safe because we allocated the struct and we trust the kernel will read
            // exactly the size of the struct.
            unsafe { ioctl_with_mut_ref(self, KVM_GET_REG_LIST(), reg_list.as_mut_fam_struct()) };
        if ret < 0 {
            return Err(errno::Error::last());
        }
        Ok(())
    }

    /// Sets processor-specific debug registers and configures the vcpu for handling
    /// certain guest debug events using the `KVM_SET_GUEST_DEBUG` ioctl.
    ///
    /// # Arguments
    ///
    /// * `debug_struct` - control bitfields and debug registers, depending on the specific architecture.
    ///             For details check the `kvm_guest_debug` structure in the
    ///             [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # extern crate kvm_bindings;
    /// # use kvm_ioctls::Kvm;
    /// # use kvm_bindings::{
    /// #     KVM_GUESTDBG_ENABLE, KVM_GUESTDBG_USE_SW_BP, kvm_guest_debug_arch, kvm_guest_debug
    /// # };
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    ///
    /// #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    /// {
    ///     let debug_struct = kvm_guest_debug {
    ///         // Configure the vcpu so that a KVM_DEBUG_EXIT would be generated
    ///         // when encountering a software breakpoint during execution
    ///         control: KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP,
    ///         pad: 0,
    ///         // Reset all arch-specific debug registers
    ///         arch: Default::default(),
    ///     };
    ///
    ///     vcpu.set_guest_debug(&debug_struct).unwrap();
    /// }
    /// ```
    #[cfg(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "s390x",
        target_arch = "powerpc"
    ))]
    pub fn set_guest_debug(&self, debug_struct: &kvm_guest_debug) -> Result<()> {
        // SAFETY: Safe because we allocated the structure and we trust the kernel.
        let ret = unsafe { ioctl_with_ref(self, KVM_SET_GUEST_DEBUG(), debug_struct) };
        if ret < 0 {
            return Err(errno::Error::last());
        }
        Ok(())
    }

    /// Sets the value of one register for this vCPU.
    ///
    /// The id of the register is encoded as specified in the kernel documentation
    /// for `KVM_SET_ONE_REG`.
    ///
    /// # Arguments
    ///
    /// * `reg_id` - ID of the register for which we are setting the value.
    /// * `data` - byte slice where the register value will be written to.
    ///
    /// # Note
    ///
    /// `data` should be equal or bigger then the register size
    /// oterwise function will return EINVAL error
    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
    pub fn set_one_reg(&self, reg_id: u64, data: &[u8]) -> Result<usize> {
        let reg_size = reg_size(reg_id);
        if data.len() < reg_size {
            return Err(errno::Error::new(libc::EINVAL));
        }
        let onereg = kvm_one_reg {
            id: reg_id,
            addr: data.as_ptr() as u64,
        };
        // SAFETY: This is safe because we allocated the struct and we know the kernel will read
        // exactly the size of the struct.
        let ret = unsafe { ioctl_with_ref(self, KVM_SET_ONE_REG(), &onereg) };
        if ret < 0 {
            return Err(errno::Error::last());
        }
        Ok(reg_size)
    }

    /// Writes the value of the specified vCPU register into provided buffer.
    ///
    /// The id of the register is encoded as specified in the kernel documentation
    /// for `KVM_GET_ONE_REG`.
    ///
    /// # Arguments
    ///
    /// * `reg_id` - ID of the register.
    /// * `data` - byte slice where the register value will be written to.
    /// # Note
    ///
    /// `data` should be equal or bigger then the register size
    /// oterwise function will return EINVAL error
    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
    pub fn get_one_reg(&self, reg_id: u64, data: &mut [u8]) -> Result<usize> {
        let reg_size = reg_size(reg_id);
        if data.len() < reg_size {
            return Err(errno::Error::new(libc::EINVAL));
        }
        let mut onereg = kvm_one_reg {
            id: reg_id,
            addr: data.as_ptr() as u64,
        };
        // SAFETY: This is safe because we allocated the struct and we know the kernel will read
        // exactly the size of the struct.
        let ret = unsafe { ioctl_with_mut_ref(self, KVM_GET_ONE_REG(), &mut onereg) };
        if ret < 0 {
            return Err(errno::Error::last());
        }
        Ok(reg_size)
    }

    /// Notify the guest about the vCPU being paused.
    ///
    /// See the documentation for `KVM_KVMCLOCK_CTRL` in the
    /// [KVM API documentation](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    #[cfg(target_arch = "x86_64")]
    pub fn kvmclock_ctrl(&self) -> Result<()> {
        // SAFETY: Safe because we know that our file is a KVM fd and that the request
        // is one of the ones defined by kernel.
        let ret = unsafe { ioctl(self, KVM_KVMCLOCK_CTRL()) };
        if ret != 0 {
            return Err(errno::Error::last());
        }
        Ok(())
    }

    /// Triggers the running of the current virtual CPU returning an exit reason.
    ///
    /// See documentation for `KVM_RUN`.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # extern crate kvm_bindings;
    /// # use std::io::Write;
    /// # use std::ptr::null_mut;
    /// # use std::slice;
    /// # use kvm_ioctls::{Kvm, VcpuExit};
    /// # use kvm_bindings::{kvm_userspace_memory_region, KVM_MEM_LOG_DIRTY_PAGES};
    /// # let kvm = Kvm::new().unwrap();
    /// # let vm = kvm.create_vm().unwrap();
    /// // This is a dummy example for running on x86 based on https://lwn.net/Articles/658511/.
    /// #[cfg(target_arch = "x86_64")]
    /// {
    ///     let mem_size = 0x4000;
    ///     let guest_addr: u64 = 0x1000;
    ///     let load_addr: *mut u8 = unsafe {
    ///         libc::mmap(
    ///             null_mut(),
    ///             mem_size,
    ///             libc::PROT_READ | libc::PROT_WRITE,
    ///             libc::MAP_ANONYMOUS | libc::MAP_SHARED | libc::MAP_NORESERVE,
    ///             -1,
    ///             0,
    ///         ) as *mut u8
    ///     };
    ///
    ///     let mem_region = kvm_userspace_memory_region {
    ///         slot: 0,
    ///         guest_phys_addr: guest_addr,
    ///         memory_size: mem_size as u64,
    ///         userspace_addr: load_addr as u64,
    ///         flags: 0,
    ///     };
    ///     unsafe { vm.set_user_memory_region(mem_region).unwrap() };
    ///
    ///     // Dummy x86 code that just calls halt.
    ///     let x86_code = [0xf4 /* hlt */];
    ///
    ///     // Write the code in the guest memory. This will generate a dirty page.
    ///     unsafe {
    ///         let mut slice = slice::from_raw_parts_mut(load_addr, mem_size);
    ///         slice.write(&x86_code).unwrap();
    ///     }
    ///
    ///     let mut vcpu_fd = vm.create_vcpu(0).unwrap();
    ///
    ///     let mut vcpu_sregs = vcpu_fd.get_sregs().unwrap();
    ///     vcpu_sregs.cs.base = 0;
    ///     vcpu_sregs.cs.selector = 0;
    ///     vcpu_fd.set_sregs(&vcpu_sregs).unwrap();
    ///
    ///     let mut vcpu_regs = vcpu_fd.get_regs().unwrap();
    ///     // Set the Instruction Pointer to the guest address where we loaded the code.
    ///     vcpu_regs.rip = guest_addr;
    ///     vcpu_regs.rax = 2;
    ///     vcpu_regs.rbx = 3;
    ///     vcpu_regs.rflags = 2;
    ///     vcpu_fd.set_regs(&vcpu_regs).unwrap();
    ///
    ///     loop {
    ///         match vcpu_fd.run().expect("run failed") {
    ///             VcpuExit::Hlt => {
    ///                 break;
    ///             }
    ///             exit_reason => panic!("unexpected exit reason: {:?}", exit_reason),
    ///         }
    ///     }
    /// }
    /// ```
    pub fn run(&mut self) -> Result<VcpuExit> {
        // SAFETY: Safe because we know that our file is a vCPU fd and we verify the return result.
        let ret = unsafe { ioctl(self, KVM_RUN()) };
        if ret == 0 {
            let run = self.kvm_run_ptr.as_mut_ref();
            match run.exit_reason {
                // make sure you treat all possible exit reasons from include/uapi/linux/kvm.h corresponding
                // when upgrading to a different kernel version
                KVM_EXIT_UNKNOWN => Ok(VcpuExit::Unknown),
                KVM_EXIT_EXCEPTION => Ok(VcpuExit::Exception),
                KVM_EXIT_IO => {
                    let run_start = run as *mut kvm_run as *mut u8;
                    // SAFETY: Safe because the exit_reason (which comes from the kernel) told us
                    // which union field to use.
                    let io = unsafe { run.__bindgen_anon_1.io };
                    let port = io.port;
                    let data_size = io.count as usize * io.size as usize;
                    // SAFETY: The data_offset is defined by the kernel to be some number of bytes
                    // into the kvm_run stucture, which we have fully mmap'd.
                    let data_ptr = unsafe { run_start.offset(io.data_offset as isize) };
                    let data_slice =
                        // SAFETY: The slice's lifetime is limited to the lifetime of this vCPU, which is equal
                        // to the mmap of the `kvm_run` struct that this is slicing from.
                        unsafe { std::slice::from_raw_parts_mut::<u8>(data_ptr, data_size) };
                    match u32::from(io.direction) {
                        KVM_EXIT_IO_IN => Ok(VcpuExit::IoIn(port, data_slice)),
                        KVM_EXIT_IO_OUT => Ok(VcpuExit::IoOut(port, data_slice)),
                        _ => Err(errno::Error::new(EINVAL)),
                    }
                }
                KVM_EXIT_HYPERCALL => {
                    // SAFETY: Safe because the exit_reason (which comes from the kernel) told us
                    // which union field to use.
                    let hypercall = unsafe { &mut run.__bindgen_anon_1.hypercall };
                    Ok(VcpuExit::Hypercall(HypercallExit {
                        nr: hypercall.nr,
                        args: hypercall.args,
                        ret: &mut hypercall.ret,
                        // SAFETY: Safe because the exit_reason (which comes from the kernel) told us
                        // which union field to use.
                        longmode: unsafe { hypercall.__bindgen_anon_1.longmode },
                    }))
                }
                KVM_EXIT_DEBUG => {
                    // SAFETY: Safe because the exit_reason (which comes from the kernel) told us
                    // which union field to use.
                    let debug = unsafe { run.__bindgen_anon_1.debug };
                    Ok(VcpuExit::Debug(debug.arch))
                }
                KVM_EXIT_HLT => Ok(VcpuExit::Hlt),
                KVM_EXIT_MMIO => {
                    // SAFETY: Safe because the exit_reason (which comes from the kernel) told us
                    // which union field to use.
                    let mmio = unsafe { &mut run.__bindgen_anon_1.mmio };
                    let addr = mmio.phys_addr;
                    let len = mmio.len as usize;
                    let data_slice = &mut mmio.data[..len];
                    if mmio.is_write != 0 {
                        Ok(VcpuExit::MmioWrite(addr, data_slice))
                    } else {
                        Ok(VcpuExit::MmioRead(addr, data_slice))
                    }
                }
                KVM_EXIT_X86_RDMSR => {
                    // SAFETY: Safe because the exit_reason (which comes from the kernel) told us
                    // which union field to use.
                    let msr = unsafe { &mut run.__bindgen_anon_1.msr };
                    let exit = ReadMsrExit {
                        error: &mut msr.error,
                        reason: MsrExitReason::from_bits_truncate(msr.reason),
                        index: msr.index,
                        data: &mut msr.data,
                    };
                    Ok(VcpuExit::X86Rdmsr(exit))
                }
                KVM_EXIT_X86_WRMSR => {
                    // SAFETY: Safe because the exit_reason (which comes from the kernel) told us
                    // which union field to use.
                    let msr = unsafe { &mut run.__bindgen_anon_1.msr };
                    let exit = WriteMsrExit {
                        error: &mut msr.error,
                        reason: MsrExitReason::from_bits_truncate(msr.reason),
                        index: msr.index,
                        data: msr.data,
                    };
                    Ok(VcpuExit::X86Wrmsr(exit))
                }
                KVM_EXIT_IRQ_WINDOW_OPEN => Ok(VcpuExit::IrqWindowOpen),
                KVM_EXIT_SHUTDOWN => Ok(VcpuExit::Shutdown),
                KVM_EXIT_FAIL_ENTRY => {
                    // SAFETY: Safe because the exit_reason (which comes from the kernel) told us
                    // which union field to use.
                    let fail_entry = unsafe { &mut run.__bindgen_anon_1.fail_entry };
                    Ok(VcpuExit::FailEntry(
                        fail_entry.hardware_entry_failure_reason,
                        fail_entry.cpu,
                    ))
                }
                KVM_EXIT_INTR => Ok(VcpuExit::Intr),
                KVM_EXIT_SET_TPR => Ok(VcpuExit::SetTpr),
                KVM_EXIT_TPR_ACCESS => Ok(VcpuExit::TprAccess),
                KVM_EXIT_S390_SIEIC => Ok(VcpuExit::S390Sieic),
                KVM_EXIT_S390_RESET => Ok(VcpuExit::S390Reset),
                KVM_EXIT_DCR => Ok(VcpuExit::Dcr),
                KVM_EXIT_NMI => Ok(VcpuExit::Nmi),
                KVM_EXIT_INTERNAL_ERROR => Ok(VcpuExit::InternalError),
                KVM_EXIT_OSI => Ok(VcpuExit::Osi),
                KVM_EXIT_PAPR_HCALL => Ok(VcpuExit::PaprHcall),
                KVM_EXIT_S390_UCONTROL => Ok(VcpuExit::S390Ucontrol),
                KVM_EXIT_WATCHDOG => Ok(VcpuExit::Watchdog),
                KVM_EXIT_S390_TSCH => Ok(VcpuExit::S390Tsch),
                KVM_EXIT_EPR => Ok(VcpuExit::Epr),
                KVM_EXIT_SYSTEM_EVENT => {
                    // SAFETY: Safe because the exit_reason (which comes from the kernel) told us
                    // which union field to use.
                    let system_event = unsafe { &mut run.__bindgen_anon_1.system_event };
                    let ndata = system_event.ndata;
                    // SAFETY: Safe because we only populate with valid data (based on ndata)
                    let data = unsafe { &system_event.__bindgen_anon_1.data[0..ndata as usize] };
                    Ok(VcpuExit::SystemEvent(system_event.type_, data))
                }
                KVM_EXIT_S390_STSI => Ok(VcpuExit::S390Stsi),
                KVM_EXIT_IOAPIC_EOI => {
                    // SAFETY: Safe because the exit_reason (which comes from the kernel) told us
                    // which union field to use.
                    let eoi = unsafe { &mut run.__bindgen_anon_1.eoi };
                    Ok(VcpuExit::IoapicEoi(eoi.vector))
                }
                KVM_EXIT_HYPERV => Ok(VcpuExit::Hyperv),
                r => Ok(VcpuExit::Unsupported(r)),
            }
        } else {
            let errno = errno::Error::last();
            let run = self.kvm_run_ptr.as_mut_ref();
            // From https://docs.kernel.org/virt/kvm/api.html#kvm-run :
            //
            // KVM_EXIT_MEMORY_FAULT is unique among all KVM exit reasons in that it accompanies
            // a return code of ‘-1’, not ‘0’! errno will always be set to EFAULT or EHWPOISON
            // when KVM exits with KVM_EXIT_MEMORY_FAULT, userspace should assume kvm_run.exit_reason
            // is stale/undefined for all other error numbers.
            if ret == -1
                && (errno == errno::Error::new(libc::EFAULT)
                    || errno == errno::Error::new(libc::EHWPOISON))
                && run.exit_reason == KVM_EXIT_MEMORY_FAULT
            {
                // SAFETY: Safe because the exit_reason (which comes from the kernel) told us
                // which union field to use.
                let fault = unsafe { &mut run.__bindgen_anon_1.memory_fault };
                Ok(VcpuExit::MemoryFault {
                    flags: fault.flags,
                    gpa: fault.gpa,
                    size: fault.size,
                })
            } else {
                Err(errno)
            }
        }
    }

    /// Returns a mutable reference to the kvm_run structure
    pub fn get_kvm_run(&mut self) -> &mut kvm_run {
        self.kvm_run_ptr.as_mut_ref()
    }

    /// Sets the `immediate_exit` flag on the `kvm_run` struct associated with this vCPU to `val`.
    pub fn set_kvm_immediate_exit(&mut self, val: u8) {
        let kvm_run = self.kvm_run_ptr.as_mut_ref();
        kvm_run.immediate_exit = val;
    }

    /// Returns the vCPU TSC frequency in KHz or an error if the host has unstable TSC.
    ///
    /// # Example
    ///
    ///  ```rust
    /// # extern crate kvm_ioctls;
    /// # use kvm_ioctls::Kvm;
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    /// let tsc_khz = vcpu.get_tsc_khz().unwrap();
    /// ```
    ///
    #[cfg(target_arch = "x86_64")]
    pub fn get_tsc_khz(&self) -> Result<u32> {
        // SAFETY:  Safe because we know that our file is a KVM fd and that the request is one of
        // the ones defined by kernel.
        let ret = unsafe { ioctl(self, KVM_GET_TSC_KHZ()) };
        if ret >= 0 {
            Ok(ret as u32)
        } else {
            Err(errno::Error::new(ret))
        }
    }

    /// Sets the specified vCPU TSC frequency.
    ///
    /// # Arguments
    ///
    /// * `freq` - The frequency unit is KHz as per the KVM API documentation
    ///   for `KVM_SET_TSC_KHZ`.
    ///
    /// # Example
    ///
    ///  ```rust
    /// # extern crate kvm_ioctls;
    /// # use kvm_ioctls::{Cap, Kvm};
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    /// if kvm.check_extension(Cap::GetTscKhz) && kvm.check_extension(Cap::TscControl) {
    ///     vcpu.set_tsc_khz(1000).unwrap();
    /// }
    /// ```
    ///
    #[cfg(target_arch = "x86_64")]
    pub fn set_tsc_khz(&self, freq: u32) -> Result<()> {
        // SAFETY: Safe because we know that our file is a KVM fd and that the request is one of
        // the ones defined by kernel.
        let ret = unsafe { ioctl_with_val(self, KVM_SET_TSC_KHZ(), freq as u64) };
        if ret < 0 {
            Err(errno::Error::last())
        } else {
            Ok(())
        }
    }

    /// Translates a virtual address according to the vCPU's current address translation mode.
    ///
    /// The physical address is returned in a `kvm_translation` structure as defined in the
    /// [KVM API documentation](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    /// See documentation for `KVM_TRANSLATE`.
    ///
    /// # Arguments
    ///
    /// * `gva` - The virtual address to translate.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # use kvm_ioctls::Kvm;
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    /// #[cfg(target_arch = "x86_64")]
    /// let tr = vcpu.translate_gva(0x10000).unwrap();
    /// ```
    #[cfg(target_arch = "x86_64")]
    pub fn translate_gva(&self, gva: u64) -> Result<kvm_translation> {
        let mut tr = kvm_translation {
            linear_address: gva,
            ..Default::default()
        };

        // SAFETY: Safe because we know that our file is a vCPU fd, we know the kernel will only
        // write the correct amount of memory to our pointer, and we verify the return result.
        let ret = unsafe { ioctl_with_mut_ref(self, KVM_TRANSLATE(), &mut tr) };
        if ret != 0 {
            return Err(errno::Error::last());
        }
        Ok(tr)
    }

    /// Enable the given [`SyncReg`] to be copied to userspace on the next exit
    ///
    /// # Arguments
    ///
    /// * `reg` - The [`SyncReg`] to copy out of the guest
    ///
    /// # Example
    ///
    ///  ```rust
    /// # extern crate kvm_ioctls;
    /// # use kvm_ioctls::{Kvm, SyncReg, Cap};
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let mut vcpu = vm.create_vcpu(0).unwrap();
    /// vcpu.set_sync_valid_reg(SyncReg::Register);
    /// vcpu.set_sync_valid_reg(SyncReg::SystemRegister);
    /// vcpu.set_sync_valid_reg(SyncReg::VcpuEvents);
    /// ```
    #[cfg(target_arch = "x86_64")]
    pub fn set_sync_valid_reg(&mut self, reg: SyncReg) {
        let kvm_run: &mut kvm_run = self.kvm_run_ptr.as_mut_ref();
        kvm_run.kvm_valid_regs |= reg as u64;
    }

    /// Tell KVM to copy the given [`SyncReg`] into the guest on the next entry
    ///
    /// # Arguments
    ///
    /// * `reg` - The [`SyncReg`] to copy into the guest
    ///
    /// # Example
    ///
    ///  ```rust
    /// # extern crate kvm_ioctls;
    /// # use kvm_ioctls::{Kvm, SyncReg, Cap};
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let mut vcpu = vm.create_vcpu(0).unwrap();
    /// vcpu.set_sync_dirty_reg(SyncReg::Register);
    /// ```
    #[cfg(target_arch = "x86_64")]
    pub fn set_sync_dirty_reg(&mut self, reg: SyncReg) {
        let kvm_run: &mut kvm_run = self.kvm_run_ptr.as_mut_ref();
        kvm_run.kvm_dirty_regs |= reg as u64;
    }

    /// Disable the given [`SyncReg`] to be copied to userspace on the next exit
    ///
    /// # Arguments
    ///
    /// * `reg` - The [`SyncReg`] to not copy out of the guest
    ///
    /// # Example
    ///
    ///  ```rust
    /// # extern crate kvm_ioctls;
    /// # use kvm_ioctls::{Kvm, SyncReg, Cap};
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let mut vcpu = vm.create_vcpu(0).unwrap();
    /// vcpu.clear_sync_valid_reg(SyncReg::Register);
    /// ```
    #[cfg(target_arch = "x86_64")]
    pub fn clear_sync_valid_reg(&mut self, reg: SyncReg) {
        let kvm_run: &mut kvm_run = self.kvm_run_ptr.as_mut_ref();
        kvm_run.kvm_valid_regs &= !(reg as u64);
    }

    /// Tell KVM to not copy the given [`SyncReg`] into the guest on the next entry
    ///
    /// # Arguments
    ///
    /// * `reg` - The [`SyncReg`] to not copy out into the guest
    ///
    /// # Example
    ///
    ///  ```rust
    /// # extern crate kvm_ioctls;
    /// # use kvm_ioctls::{Kvm, SyncReg, Cap};
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let mut vcpu = vm.create_vcpu(0).unwrap();
    /// vcpu.clear_sync_dirty_reg(SyncReg::Register);
    /// ```
    #[cfg(target_arch = "x86_64")]
    pub fn clear_sync_dirty_reg(&mut self, reg: SyncReg) {
        let kvm_run: &mut kvm_run = self.kvm_run_ptr.as_mut_ref();
        kvm_run.kvm_dirty_regs &= !(reg as u64);
    }

    /// Get the [`kvm_sync_regs`] from the VM
    ///
    /// # Example
    ///
    ///  ```rust
    /// # extern crate kvm_ioctls;
    /// # use kvm_ioctls::{Kvm, SyncReg, Cap};
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let mut vcpu = vm.create_vcpu(0).unwrap();
    /// if kvm.check_extension(Cap::SyncRegs) {
    ///     vcpu.set_sync_valid_reg(SyncReg::Register);
    ///     vcpu.run();
    ///     let guest_rax = vcpu.sync_regs().regs.rax;
    /// }
    /// ```
    #[cfg(target_arch = "x86_64")]
    pub fn sync_regs(&self) -> kvm_sync_regs {
        let kvm_run = self.kvm_run_ptr.as_ref();

        // SAFETY: Accessing this union field could be out of bounds if the `kvm_run`
        // allocation isn't large enough. The `kvm_run` region is set using
        // `get_vcpu_map_size`, so this region is in bounds
        unsafe { kvm_run.s.regs }
    }

    /// Get a mutable reference to the [`kvm_sync_regs`] from the VM
    ///
    /// # Example
    ///
    ///  ```rust
    /// # extern crate kvm_ioctls;
    /// # use kvm_ioctls::{Kvm, SyncReg, Cap};
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let mut vcpu = vm.create_vcpu(0).unwrap();
    /// if kvm.check_extension(Cap::SyncRegs) {
    ///     vcpu.set_sync_valid_reg(SyncReg::Register);
    ///     vcpu.run();
    ///     // Set the guest RAX to 0xdeadbeef
    ///     vcpu.sync_regs_mut().regs.rax = 0xdeadbeef;
    ///     vcpu.set_sync_dirty_reg(SyncReg::Register);
    ///     vcpu.run();
    /// }
    /// ```
    #[cfg(target_arch = "x86_64")]
    pub fn sync_regs_mut(&mut self) -> &mut kvm_sync_regs {
        let kvm_run: &mut kvm_run = self.kvm_run_ptr.as_mut_ref();

        // SAFETY: Accessing this union field could be out of bounds if the `kvm_run`
        // allocation isn't large enough. The `kvm_run` region is set using
        // `get_vcpu_map_size`, so this region is in bounds
        unsafe { &mut kvm_run.s.regs }
    }

    /// Triggers an SMI on the virtual CPU.
    ///
    /// See documentation for `KVM_SMI`.
    ///
    /// ```rust
    /// # use kvm_ioctls::{Kvm, Cap};
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    /// if kvm.check_extension(Cap::X86Smm) {
    ///     vcpu.smi().unwrap();
    /// }
    /// ```
    #[cfg(target_arch = "x86_64")]
    pub fn smi(&self) -> Result<()> {
        // SAFETY: Safe because we call this with a Vcpu fd and we trust the kernel.
        let ret = unsafe { ioctl(self, KVM_SMI()) };
        match ret {
            0 => Ok(()),
            _ => Err(errno::Error::last()),
        }
    }

    /// Queues an NMI on the thread's vcpu. Only usable if `KVM_CAP_USER_NMI`
    /// is available.
    ///
    /// See the documentation for `KVM_NMI`.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use kvm_ioctls::{Kvm, Cap};
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    /// if kvm.check_extension(Cap::UserNmi) {
    ///     vcpu.nmi().unwrap();
    /// }
    /// ```
    #[cfg(target_arch = "x86_64")]
    pub fn nmi(&self) -> Result<()> {
        // SAFETY: Safe because we call this with a Vcpu fd and we trust the kernel.
        let ret = unsafe { ioctl(self, KVM_NMI()) };
        match ret {
            0 => Ok(()),
            _ => Err(errno::Error::last()),
        }
    }

    /// Maps the coalesced MMIO ring page. This allows reading entries from
    /// the ring via [`coalesced_mmio_read()`](VcpuFd::coalesced_mmio_read).
    ///
    /// # Returns
    ///
    /// Returns an error if the buffer could not be mapped, usually because
    /// `KVM_CAP_COALESCED_MMIO` ([`Cap::CoalescedMmio`](crate::Cap::CoalescedMmio))
    /// is not available.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use kvm_ioctls::{Kvm, Cap};
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    /// let mut vcpu = vm.create_vcpu(0).unwrap();
    /// if kvm.check_extension(Cap::CoalescedMmio) {
    ///     vcpu.map_coalesced_mmio_ring().unwrap();
    /// }
    /// ```
    pub fn map_coalesced_mmio_ring(&mut self) -> Result<()> {
        if self.coalesced_mmio_ring.is_none() {
            let ring = KvmCoalescedIoRing::mmap_from_fd(&self.vcpu)?;
            self.coalesced_mmio_ring = Some(ring);
        }
        Ok(())
    }

    /// Read a single entry from the coalesced MMIO ring.
    /// For entries to be appended to the ring by the kernel, addresses must be registered
    /// via [`VmFd::register_coalesced_mmio()`](crate::VmFd::register_coalesced_mmio()).
    ///
    /// [`map_coalesced_mmio_ring()`](VcpuFd::map_coalesced_mmio_ring) must have been called beforehand.
    ///
    /// See the documentation for `KVM_(UN)REGISTER_COALESCED_MMIO`.
    ///
    /// # Returns
    ///
    /// * An error if [`map_coalesced_mmio_ring()`](VcpuFd::map_coalesced_mmio_ring)
    ///   was not called beforehand.
    /// * [`Ok<None>`] if the ring is empty.
    /// * [`Ok<Some<kvm_coalesced_mmio>>`] if an entry was successfully read.
    pub fn coalesced_mmio_read(&mut self) -> Result<Option<kvm_coalesced_mmio>> {
        self.coalesced_mmio_ring
            .as_mut()
            .ok_or(errno::Error::new(libc::EIO))
            .map(|ring| ring.read_entry())
    }
}

/// Helper function to create a new `VcpuFd`.
///
/// This should not be exported as a public function because the preferred way is to use
/// `create_vcpu` from `VmFd`. The function cannot be part of the `VcpuFd` implementation because
/// then it would be exported with the public `VcpuFd` interface.
pub fn new_vcpu(vcpu: File, kvm_run_ptr: KvmRunWrapper) -> VcpuFd {
    VcpuFd {
        vcpu,
        kvm_run_ptr,
        coalesced_mmio_ring: None,
    }
}

impl AsRawFd for VcpuFd {
    fn as_raw_fd(&self) -> RawFd {
        self.vcpu.as_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks)]
    extern crate byteorder;

    use super::*;
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    use crate::cap::Cap;
    use crate::ioctls::system::Kvm;
    use std::ptr::NonNull;

    // Helper function for memory mapping `size` bytes of anonymous memory.
    // Panics if the mmap fails.
    fn mmap_anonymous(size: usize) -> NonNull<u8> {
        use std::ptr::null_mut;

        let addr = unsafe {
            libc::mmap(
                null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANONYMOUS | libc::MAP_SHARED | libc::MAP_NORESERVE,
                -1,
                0,
            )
        };
        if addr == libc::MAP_FAILED {
            panic!("mmap failed.");
        }

        NonNull::new(addr).unwrap().cast()
    }

    #[test]
    fn test_create_vcpu() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();

        vm.create_vcpu(0).unwrap();
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_get_cpuid() {
        let kvm = Kvm::new().unwrap();
        if kvm.check_extension(Cap::ExtCpuid) {
            let vm = kvm.create_vm().unwrap();
            let cpuid = kvm.get_supported_cpuid(KVM_MAX_CPUID_ENTRIES).unwrap();
            let ncpuids = cpuid.as_slice().len();
            assert!(ncpuids <= KVM_MAX_CPUID_ENTRIES);
            let nr_vcpus = kvm.get_nr_vcpus();
            for cpu_idx in 0..nr_vcpus {
                let vcpu = vm.create_vcpu(cpu_idx as u64).unwrap();
                vcpu.set_cpuid2(&cpuid).unwrap();
                let retrieved_cpuid = vcpu.get_cpuid2(ncpuids).unwrap();
                // Only check the first few leafs as some (e.g. 13) are reserved.
                assert_eq!(cpuid.as_slice()[..3], retrieved_cpuid.as_slice()[..3]);
            }
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_get_cpuid_fail_num_entries_too_high() {
        let kvm = Kvm::new().unwrap();
        if kvm.check_extension(Cap::ExtCpuid) {
            let vm = kvm.create_vm().unwrap();
            let vcpu = vm.create_vcpu(0).unwrap();
            let err_cpuid = vcpu.get_cpuid2(KVM_MAX_CPUID_ENTRIES + 1_usize).err();
            assert_eq!(err_cpuid.unwrap().errno(), libc::ENOMEM);
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_get_cpuid_fail_num_entries_too_small() {
        let kvm = Kvm::new().unwrap();
        if kvm.check_extension(Cap::ExtCpuid) {
            let vm = kvm.create_vm().unwrap();
            let cpuid = kvm.get_supported_cpuid(KVM_MAX_CPUID_ENTRIES).unwrap();
            let ncpuids = cpuid.as_slice().len();
            assert!(ncpuids <= KVM_MAX_CPUID_ENTRIES);
            let nr_vcpus = kvm.get_nr_vcpus();
            for cpu_idx in 0..nr_vcpus {
                let vcpu = vm.create_vcpu(cpu_idx as u64).unwrap();
                vcpu.set_cpuid2(&cpuid).unwrap();
                let err = vcpu.get_cpuid2(ncpuids - 1_usize).err();
                assert_eq!(err.unwrap().errno(), libc::E2BIG);
            }
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_set_cpuid() {
        let kvm = Kvm::new().unwrap();
        if kvm.check_extension(Cap::ExtCpuid) {
            let vm = kvm.create_vm().unwrap();
            let mut cpuid = kvm.get_supported_cpuid(KVM_MAX_CPUID_ENTRIES).unwrap();
            let ncpuids = cpuid.as_slice().len();
            assert!(ncpuids <= KVM_MAX_CPUID_ENTRIES);
            let vcpu = vm.create_vcpu(0).unwrap();

            // Setting Manufacturer ID
            {
                let entries = cpuid.as_mut_slice();
                for entry in entries.iter_mut() {
                    if entry.function == 0 {
                        // " KVMKVMKVM "
                        entry.ebx = 0x4b4d564b;
                        entry.ecx = 0x564b4d56;
                        entry.edx = 0x4d;
                    }
                }
            }
            vcpu.set_cpuid2(&cpuid).unwrap();
            let cpuid_0 = vcpu.get_cpuid2(ncpuids).unwrap();
            for entry in cpuid_0.as_slice() {
                if entry.function == 0 {
                    assert_eq!(entry.ebx, 0x4b4d564b);
                    assert_eq!(entry.ecx, 0x564b4d56);
                    assert_eq!(entry.edx, 0x4d);
                }
            }

            // Disabling Intel SHA extensions.
            const EBX_SHA_SHIFT: u32 = 29;
            let mut ebx_sha_off = 0u32;
            {
                let entries = cpuid.as_mut_slice();
                for entry in entries.iter_mut() {
                    if entry.function == 7 && entry.ecx == 0 {
                        entry.ebx &= !(1 << EBX_SHA_SHIFT);
                        ebx_sha_off = entry.ebx;
                    }
                }
            }
            vcpu.set_cpuid2(&cpuid).unwrap();
            let cpuid_1 = vcpu.get_cpuid2(ncpuids).unwrap();
            for entry in cpuid_1.as_slice() {
                if entry.function == 7 && entry.ecx == 0 {
                    assert_eq!(entry.ebx, ebx_sha_off);
                }
            }
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[allow(non_snake_case)]
    #[test]
    fn test_fpu() {
        // as per https://github.com/torvalds/linux/blob/master/arch/x86/include/asm/fpu/internal.h
        let KVM_FPU_CWD: usize = 0x37f;
        let KVM_FPU_MXCSR: usize = 0x1f80;
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        let mut fpu: kvm_fpu = kvm_fpu {
            fcw: KVM_FPU_CWD as u16,
            mxcsr: KVM_FPU_MXCSR as u32,
            ..Default::default()
        };

        fpu.fcw = KVM_FPU_CWD as u16;
        fpu.mxcsr = KVM_FPU_MXCSR as u32;

        vcpu.set_fpu(&fpu).unwrap();
        assert_eq!(vcpu.get_fpu().unwrap().fcw, KVM_FPU_CWD as u16);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn lapic_test() {
        use std::io::Cursor;
        // We might get read of byteorder if we replace mem::transmute with something safer.
        use self::byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
        // As per https://github.com/torvalds/linux/arch/x86/kvm/lapic.c
        // Try to write and read the APIC_ICR (0x300) register which is non-read only and
        // one can simply write to it.
        let kvm = Kvm::new().unwrap();
        assert!(kvm.check_extension(Cap::Irqchip));
        let vm = kvm.create_vm().unwrap();
        // The get_lapic ioctl will fail if there is no irqchip created beforehand.
        vm.create_irq_chip().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        let mut klapic: kvm_lapic_state = vcpu.get_lapic().unwrap();

        let reg_offset = 0x300;
        let value = 2_u32;
        //try to write and read the APIC_ICR	0x300
        let write_slice =
            unsafe { &mut *(&mut klapic.regs[reg_offset..] as *mut [i8] as *mut [u8]) };
        let mut writer = Cursor::new(write_slice);
        writer.write_u32::<LittleEndian>(value).unwrap();
        vcpu.set_lapic(&klapic).unwrap();
        klapic = vcpu.get_lapic().unwrap();
        let read_slice = unsafe { &*(&klapic.regs[reg_offset..] as *const [i8] as *const [u8]) };
        let mut reader = Cursor::new(read_slice);
        assert_eq!(reader.read_u32::<LittleEndian>().unwrap(), value);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn msrs_test() {
        use vmm_sys_util::fam::FamStruct;
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();

        // Set the following MSRs.
        let msrs_to_set = [
            kvm_msr_entry {
                index: 0x0000_0174,
                data: 0x0,
                ..Default::default()
            },
            kvm_msr_entry {
                index: 0x0000_0175,
                data: 0x1,
                ..Default::default()
            },
        ];
        let msrs_wrapper = Msrs::from_entries(&msrs_to_set).unwrap();
        vcpu.set_msrs(&msrs_wrapper).unwrap();

        // Now test that GET_MSRS returns the same.
        // Configure the struct to say which entries we want.
        let mut returned_kvm_msrs = Msrs::from_entries(&[
            kvm_msr_entry {
                index: 0x0000_0174,
                ..Default::default()
            },
            kvm_msr_entry {
                index: 0x0000_0175,
                ..Default::default()
            },
        ])
        .unwrap();
        let nmsrs = vcpu.get_msrs(&mut returned_kvm_msrs).unwrap();

        // Verify the lengths match.
        assert_eq!(nmsrs, msrs_to_set.len());
        assert_eq!(nmsrs, returned_kvm_msrs.as_fam_struct_ref().len());

        // Verify the contents match.
        let returned_kvm_msr_entries = returned_kvm_msrs.as_slice();
        for (i, entry) in returned_kvm_msr_entries.iter().enumerate() {
            assert_eq!(entry, &msrs_to_set[i]);
        }
    }

    #[cfg(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64",
        target_arch = "s390x"
    ))]
    #[test]
    fn mpstate_test() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        let mp_state = vcpu.get_mp_state().unwrap();
        vcpu.set_mp_state(mp_state).unwrap();
        let other_mp_state = vcpu.get_mp_state().unwrap();
        assert_eq!(mp_state, other_mp_state);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn xsave_test() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        let xsave = vcpu.get_xsave().unwrap();
        vcpu.set_xsave(&xsave).unwrap();
        let other_xsave = vcpu.get_xsave().unwrap();
        assert_eq!(&xsave.region[..], &other_xsave.region[..]);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn xcrs_test() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        let xcrs = vcpu.get_xcrs().unwrap();
        vcpu.set_xcrs(&xcrs).unwrap();
        let other_xcrs = vcpu.get_xcrs().unwrap();
        assert_eq!(xcrs, other_xcrs);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn debugregs_test() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        let debugregs = vcpu.get_debug_regs().unwrap();
        vcpu.set_debug_regs(&debugregs).unwrap();
        let other_debugregs = vcpu.get_debug_regs().unwrap();
        assert_eq!(debugregs, other_debugregs);
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn vcpu_events_test() {
        let kvm = Kvm::new().unwrap();
        if kvm.check_extension(Cap::VcpuEvents) {
            let vm = kvm.create_vm().unwrap();
            let vcpu = vm.create_vcpu(0).unwrap();
            let vcpu_events = vcpu.get_vcpu_events().unwrap();
            vcpu.set_vcpu_events(&vcpu_events).unwrap();
            let other_vcpu_events = vcpu.get_vcpu_events().unwrap();
            assert_eq!(vcpu_events, other_vcpu_events);
        }
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn test_run_code() {
        use std::io::Write;

        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        #[rustfmt::skip]
        let code = [
            0x40, 0x20, 0x80, 0x52, /* mov w0, #0x102 */
            0x00, 0x01, 0x00, 0xb9, /* str w0, [x8]; test physical memory write */
            0x81, 0x60, 0x80, 0x52, /* mov w1, #0x304 */
            0x02, 0x00, 0x80, 0x52, /* mov w2, #0x0 */
            0x20, 0x01, 0x40, 0xb9, /* ldr w0, [x9]; test MMIO read */
            0x1f, 0x18, 0x14, 0x71, /* cmp w0, #0x506 */
            0x20, 0x00, 0x82, 0x1a, /* csel w0, w1, w2, eq */
            0x20, 0x01, 0x00, 0xb9, /* str w0, [x9]; test MMIO write */
            0x00, 0x80, 0xb0, 0x52, /* mov w0, #0x84000000 */
            0x00, 0x00, 0x1d, 0x32, /* orr w0, w0, #0x08 */
            0x02, 0x00, 0x00, 0xd4, /* hvc #0x0 */
            0x00, 0x00, 0x00, 0x14, /* b <this address>; shouldn't get here, but if so loop forever */
        ];

        let mem_size = 0x20000;
        let load_addr = mmap_anonymous(mem_size).as_ptr();
        let guest_addr: u64 = 0x10000;
        let slot: u32 = 0;
        let mem_region = kvm_userspace_memory_region {
            slot,
            guest_phys_addr: guest_addr,
            memory_size: mem_size as u64,
            userspace_addr: load_addr as u64,
            flags: KVM_MEM_LOG_DIRTY_PAGES,
        };
        unsafe {
            vm.set_user_memory_region(mem_region).unwrap();
        }

        unsafe {
            // Get a mutable slice of `mem_size` from `load_addr`.
            // This is safe because we mapped it before.
            let mut slice = std::slice::from_raw_parts_mut(load_addr, mem_size);
            slice.write_all(&code).unwrap();
        }

        let mut vcpu_fd = vm.create_vcpu(0).unwrap();
        let mut kvi = kvm_vcpu_init::default();
        vm.get_preferred_target(&mut kvi).unwrap();
        kvi.features[0] |= 1 << KVM_ARM_VCPU_PSCI_0_2;
        vcpu_fd.vcpu_init(&kvi).unwrap();

        let core_reg_base: u64 = 0x6030_0000_0010_0000;
        let mmio_addr: u64 = guest_addr + mem_size as u64;

        // Set the PC to the guest address where we loaded the code.
        vcpu_fd
            .set_one_reg(core_reg_base + 2 * 32, &(guest_addr as u128).to_le_bytes())
            .unwrap();

        // Set x8 and x9 to the addresses the guest test code needs
        vcpu_fd
            .set_one_reg(
                core_reg_base + 2 * 8,
                &(guest_addr as u128 + 0x10000).to_le_bytes(),
            )
            .unwrap();
        vcpu_fd
            .set_one_reg(core_reg_base + 2 * 9, &(mmio_addr as u128).to_le_bytes())
            .unwrap();

        loop {
            match vcpu_fd.run().expect("run failed") {
                VcpuExit::MmioRead(addr, data) => {
                    assert_eq!(addr, mmio_addr);
                    assert_eq!(data.len(), 4);
                    data[3] = 0x0;
                    data[2] = 0x0;
                    data[1] = 0x5;
                    data[0] = 0x6;
                }
                VcpuExit::MmioWrite(addr, data) => {
                    assert_eq!(addr, mmio_addr);
                    assert_eq!(data.len(), 4);
                    assert_eq!(data[3], 0x0);
                    assert_eq!(data[2], 0x0);
                    assert_eq!(data[1], 0x3);
                    assert_eq!(data[0], 0x4);
                    // The code snippet dirties one page at guest_addr + 0x10000.
                    // The code page should not be dirty, as it's not written by the guest.
                    let dirty_pages_bitmap = vm.get_dirty_log(slot, mem_size).unwrap();
                    let dirty_pages: u32 = dirty_pages_bitmap
                        .into_iter()
                        .map(|page| page.count_ones())
                        .sum();
                    assert_eq!(dirty_pages, 1);
                }
                VcpuExit::SystemEvent(type_, data) => {
                    assert_eq!(type_, KVM_SYSTEM_EVENT_SHUTDOWN);
                    assert_eq!(data[0], 0);
                    break;
                }
                r => panic!("unexpected exit reason: {:?}", r),
            }
        }
    }

    #[cfg(target_arch = "riscv64")]
    #[test]
    fn test_run_code() {
        use std::io::Write;

        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        #[rustfmt::skip]
        let code = [
            0x13, 0x05, 0x50, 0x40, // li   a0, 0x0405;
            0x23, 0x20, 0xac, 0x00, // sw   a0, 0(s8);  test physical memory write
            0x03, 0xa5, 0x0c, 0x00, // lw   a0, 0(s9);  test MMIO read
            0x93, 0x05, 0x70, 0x60, // li   a1, 0x0607;
            0x23, 0xa0, 0xbc, 0x00, // sw   a1, 0(s9);  test MMIO write
            0x6f, 0x00, 0x00, 0x00, // j .; shouldn't get here, but if so loop forever
        ];

        let mem_size = 0x20000;
        let load_addr = mmap_anonymous(mem_size).as_ptr();
        let guest_addr: u64 = 0x10000;
        let slot: u32 = 0;
        let mem_region = kvm_userspace_memory_region {
            slot,
            guest_phys_addr: guest_addr,
            memory_size: mem_size as u64,
            userspace_addr: load_addr as u64,
            flags: KVM_MEM_LOG_DIRTY_PAGES,
        };
        unsafe {
            vm.set_user_memory_region(mem_region).unwrap();
        }

        unsafe {
            // Get a mutable slice of `mem_size` from `load_addr`.
            // This is safe because we mapped it before.
            let mut slice = std::slice::from_raw_parts_mut(load_addr, mem_size);
            slice.write_all(&code).unwrap();
        }

        let mut vcpu_fd = vm.create_vcpu(0).unwrap();

        let core_reg_base: u64 = 0x8030_0000_0200_0000;
        let mmio_addr: u64 = guest_addr + mem_size as u64;

        // Set the PC to the guest address where we loaded the code.
        vcpu_fd
            .set_one_reg(core_reg_base, &(guest_addr as u128).to_le_bytes())
            .unwrap();

        // Set s8 and s9 to the addresses the guest test code needs
        vcpu_fd
            .set_one_reg(
                core_reg_base + 24,
                &(guest_addr as u128 + 0x10000).to_le_bytes(),
            )
            .unwrap();
        vcpu_fd
            .set_one_reg(core_reg_base + 25, &(mmio_addr as u128).to_le_bytes())
            .unwrap();

        loop {
            match vcpu_fd.run().expect("run failed") {
                VcpuExit::MmioRead(addr, data) => {
                    assert_eq!(addr, mmio_addr);
                    assert_eq!(data.len(), 4);
                    data[3] = 0x0;
                    data[2] = 0x0;
                    data[1] = 0x5;
                    data[0] = 0x6;
                }
                VcpuExit::MmioWrite(addr, data) => {
                    assert_eq!(addr, mmio_addr);
                    assert_eq!(data.len(), 4);
                    assert_eq!(data[3], 0x0);
                    assert_eq!(data[2], 0x0);
                    assert_eq!(data[1], 0x6);
                    assert_eq!(data[0], 0x7);
                    // The code snippet dirties one page at guest_addr + 0x10000.
                    // The code page should not be dirty, as it's not written by the guest.
                    let dirty_pages_bitmap = vm.get_dirty_log(slot, mem_size).unwrap();
                    let dirty_pages: u32 = dirty_pages_bitmap
                        .into_iter()
                        .map(|page| page.count_ones())
                        .sum();
                    assert_eq!(dirty_pages, 1);
                    break;
                }
                r => panic!("unexpected exit reason: {:?}", r),
            }
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_run_code() {
        use std::io::Write;

        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        // This example is based on https://lwn.net/Articles/658511/
        #[rustfmt::skip]
        let code = [
            0xba, 0xf8, 0x03, /* mov $0x3f8, %dx */
            0x00, 0xd8, /* add %bl, %al */
            0x04, b'0', /* add $'0', %al */
            0xee, /* out %al, %dx */
            0xec, /* in %dx, %al */
            0xc6, 0x06, 0x00, 0x80, 0x00, /* movl $0, (0x8000); This generates a MMIO Write.*/
            0x8a, 0x16, 0x00, 0x80, /* movl (0x8000), %dl; This generates a MMIO Read.*/
            0xc6, 0x06, 0x00, 0x20, 0x00, /* movl $0, (0x2000); Dirty one page in guest mem. */
            0xf4, /* hlt */
        ];
        let expected_rips: [u64; 3] = [0x1003, 0x1005, 0x1007];

        let mem_size = 0x4000;
        let load_addr = mmap_anonymous(mem_size).as_ptr();
        let guest_addr: u64 = 0x1000;
        let slot: u32 = 0;
        let mem_region = kvm_userspace_memory_region {
            slot,
            guest_phys_addr: guest_addr,
            memory_size: mem_size as u64,
            userspace_addr: load_addr as u64,
            flags: KVM_MEM_LOG_DIRTY_PAGES,
        };
        unsafe {
            vm.set_user_memory_region(mem_region).unwrap();
        }

        unsafe {
            // Get a mutable slice of `mem_size` from `load_addr`.
            // This is safe because we mapped it before.
            let mut slice = std::slice::from_raw_parts_mut(load_addr, mem_size);
            slice.write_all(&code).unwrap();
        }

        let mut vcpu_fd = vm.create_vcpu(0).unwrap();

        let mut vcpu_sregs = vcpu_fd.get_sregs().unwrap();
        assert_ne!(vcpu_sregs.cs.base, 0);
        assert_ne!(vcpu_sregs.cs.selector, 0);
        vcpu_sregs.cs.base = 0;
        vcpu_sregs.cs.selector = 0;
        vcpu_fd.set_sregs(&vcpu_sregs).unwrap();

        let mut vcpu_regs = vcpu_fd.get_regs().unwrap();
        // Set the Instruction Pointer to the guest address where we loaded the code.
        vcpu_regs.rip = guest_addr;
        vcpu_regs.rax = 2;
        vcpu_regs.rbx = 3;
        vcpu_regs.rflags = 2;
        vcpu_fd.set_regs(&vcpu_regs).unwrap();

        let mut debug_struct = kvm_guest_debug {
            control: KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_SINGLESTEP,
            pad: 0,
            arch: kvm_guest_debug_arch {
                debugreg: [0, 0, 0, 0, 0, 0, 0, 0],
            },
        };
        vcpu_fd.set_guest_debug(&debug_struct).unwrap();

        let mut instr_idx = 0;
        loop {
            match vcpu_fd.run().expect("run failed") {
                VcpuExit::IoIn(addr, data) => {
                    assert_eq!(addr, 0x3f8);
                    assert_eq!(data.len(), 1);
                }
                VcpuExit::IoOut(addr, data) => {
                    assert_eq!(addr, 0x3f8);
                    assert_eq!(data.len(), 1);
                    assert_eq!(data[0], b'5');
                }
                VcpuExit::MmioRead(addr, data) => {
                    assert_eq!(addr, 0x8000);
                    assert_eq!(data.len(), 1);
                }
                VcpuExit::MmioWrite(addr, data) => {
                    assert_eq!(addr, 0x8000);
                    assert_eq!(data.len(), 1);
                    assert_eq!(data[0], 0);
                }
                VcpuExit::Debug(debug) => {
                    if instr_idx == expected_rips.len() - 1 {
                        // Disabling debugging/single-stepping
                        debug_struct.control = 0;
                        vcpu_fd.set_guest_debug(&debug_struct).unwrap();
                    } else if instr_idx >= expected_rips.len() {
                        unreachable!();
                    }
                    let vcpu_regs = vcpu_fd.get_regs().unwrap();
                    assert_eq!(vcpu_regs.rip, expected_rips[instr_idx]);
                    assert_eq!(debug.exception, 1);
                    assert_eq!(debug.pc, expected_rips[instr_idx]);
                    // Check first 15 bits of DR6
                    let mask = (1 << 16) - 1;
                    assert_eq!(debug.dr6 & mask, 0b100111111110000);
                    // Bit 10 in DR7 is always 1
                    assert_eq!(debug.dr7, 1 << 10);
                    instr_idx += 1;
                }
                VcpuExit::Hlt => {
                    // The code snippet dirties 2 pages:
                    // * one when the code itself is loaded in memory;
                    // * and one more from the `movl` that writes to address 0x8000
                    let dirty_pages_bitmap = vm.get_dirty_log(slot, mem_size).unwrap();
                    let dirty_pages: u32 = dirty_pages_bitmap
                        .into_iter()
                        .map(|page| page.count_ones())
                        .sum();
                    assert_eq!(dirty_pages, 2);
                    break;
                }
                r => panic!("unexpected exit reason: {:?}", r),
            }
        }
    }

    #[test]
    #[cfg(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64"
    ))]
    fn test_faulty_vcpu_fd() {
        use std::os::unix::io::{FromRawFd, IntoRawFd};

        let badf_errno = libc::EBADF;

        let mut faulty_vcpu_fd = VcpuFd {
            vcpu: unsafe { File::from_raw_fd(-2) },
            kvm_run_ptr: KvmRunWrapper {
                kvm_run_ptr: mmap_anonymous(10).cast(),
                mmap_size: 10,
            },
            coalesced_mmio_ring: None,
        };

        assert_eq!(
            faulty_vcpu_fd.get_mp_state().unwrap_err().errno(),
            badf_errno
        );
        assert_eq!(
            faulty_vcpu_fd
                .set_mp_state(kvm_mp_state::default())
                .unwrap_err()
                .errno(),
            badf_errno
        );
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        assert_eq!(
            faulty_vcpu_fd.get_vcpu_events().unwrap_err().errno(),
            badf_errno
        );
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        assert_eq!(
            faulty_vcpu_fd
                .set_vcpu_events(&kvm_vcpu_events::default())
                .unwrap_err()
                .errno(),
            badf_errno
        );
        assert_eq!(faulty_vcpu_fd.run().unwrap_err().errno(), badf_errno);

        // Don't drop the File object, or it'll notice the file it's trying to close is
        // invalid and abort the process.
        let _ = faulty_vcpu_fd.vcpu.into_raw_fd();
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_faulty_vcpu_fd_x86_64() {
        use std::os::unix::io::{FromRawFd, IntoRawFd};

        let badf_errno = libc::EBADF;

        let faulty_vcpu_fd = VcpuFd {
            vcpu: unsafe { File::from_raw_fd(-2) },
            kvm_run_ptr: KvmRunWrapper {
                kvm_run_ptr: mmap_anonymous(10).cast(),
                mmap_size: 10,
            },
            coalesced_mmio_ring: None,
        };

        assert_eq!(faulty_vcpu_fd.get_regs().unwrap_err().errno(), badf_errno);
        assert_eq!(
            faulty_vcpu_fd
                .set_regs(&unsafe { std::mem::zeroed() })
                .unwrap_err()
                .errno(),
            badf_errno
        );
        assert_eq!(faulty_vcpu_fd.get_sregs().unwrap_err().errno(), badf_errno);
        assert_eq!(
            faulty_vcpu_fd
                .set_sregs(&unsafe { std::mem::zeroed() })
                .unwrap_err()
                .errno(),
            badf_errno
        );
        assert_eq!(faulty_vcpu_fd.get_fpu().unwrap_err().errno(), badf_errno);
        assert_eq!(
            faulty_vcpu_fd
                .set_fpu(&unsafe { std::mem::zeroed() })
                .unwrap_err()
                .errno(),
            badf_errno
        );
        assert_eq!(
            faulty_vcpu_fd
                .set_cpuid2(
                    &Kvm::new()
                        .unwrap()
                        .get_supported_cpuid(KVM_MAX_CPUID_ENTRIES)
                        .unwrap()
                )
                .unwrap_err()
                .errno(),
            badf_errno
        );
        assert_eq!(
            faulty_vcpu_fd.get_cpuid2(1).err().unwrap().errno(),
            badf_errno
        );
        // `kvm_lapic_state` does not implement debug by default so we cannot
        // use unwrap_err here.
        faulty_vcpu_fd.get_lapic().unwrap_err();
        assert_eq!(
            faulty_vcpu_fd
                .set_lapic(&unsafe { std::mem::zeroed() })
                .unwrap_err()
                .errno(),
            badf_errno
        );
        assert_eq!(
            faulty_vcpu_fd
                .get_msrs(&mut Msrs::new(1).unwrap())
                .unwrap_err()
                .errno(),
            badf_errno
        );
        assert_eq!(
            faulty_vcpu_fd
                .set_msrs(&Msrs::new(1).unwrap())
                .unwrap_err()
                .errno(),
            badf_errno
        );
        assert_eq!(
            faulty_vcpu_fd.get_xsave().err().unwrap().errno(),
            badf_errno
        );
        assert_eq!(
            faulty_vcpu_fd
                .set_xsave(&kvm_xsave::default())
                .unwrap_err()
                .errno(),
            badf_errno
        );
        assert_eq!(faulty_vcpu_fd.get_xcrs().unwrap_err().errno(), badf_errno);
        assert_eq!(
            faulty_vcpu_fd
                .set_xcrs(&kvm_xcrs::default())
                .err()
                .unwrap()
                .errno(),
            badf_errno
        );
        assert_eq!(
            faulty_vcpu_fd.get_debug_regs().unwrap_err().errno(),
            badf_errno
        );
        assert_eq!(
            faulty_vcpu_fd
                .set_debug_regs(&kvm_debugregs::default())
                .unwrap_err()
                .errno(),
            badf_errno
        );
        assert_eq!(
            faulty_vcpu_fd.kvmclock_ctrl().unwrap_err().errno(),
            badf_errno
        );
        faulty_vcpu_fd.get_tsc_khz().unwrap_err();
        faulty_vcpu_fd.set_tsc_khz(1000000).unwrap_err();
        faulty_vcpu_fd.translate_gva(u64::MAX).unwrap_err();

        // Don't drop the File object, or it'll notice the file it's trying to close is
        // invalid and abort the process.
        let _ = faulty_vcpu_fd.vcpu.into_raw_fd();
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn test_faulty_vcpu_target_aarch64() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();

        // KVM defines valid targets as 0 to KVM_ARM_NUM_TARGETS-1, so pick a big raw number
        // greater than that as target to be invalid
        let kvi = kvm_vcpu_init {
            target: 300,
            ..Default::default()
        };

        vcpu.vcpu_init(&kvi).unwrap_err();
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn test_faulty_vcpu_fd_aarch64() {
        use std::os::unix::io::{FromRawFd, IntoRawFd};

        let badf_errno = libc::EBADF;

        let faulty_vcpu_fd = VcpuFd {
            vcpu: unsafe { File::from_raw_fd(-2) },
            kvm_run_ptr: KvmRunWrapper {
                kvm_run_ptr: mmap_anonymous(10).cast(),
                mmap_size: 10,
            },
            coalesced_mmio_ring: None,
        };

        let device_attr = kvm_device_attr {
            group: KVM_ARM_VCPU_PMU_V3_CTRL,
            attr: u64::from(KVM_ARM_VCPU_PMU_V3_INIT),
            addr: 0x0,
            flags: 0,
        };

        let reg_id = 0x6030_0000_0010_0042;
        let mut reg_data = 0u128.to_le_bytes();

        assert_eq!(
            faulty_vcpu_fd
                .set_device_attr(&device_attr)
                .unwrap_err()
                .errno(),
            badf_errno
        );
        assert_eq!(
            faulty_vcpu_fd
                .has_device_attr(&device_attr)
                .unwrap_err()
                .errno(),
            badf_errno
        );
        assert_eq!(
            faulty_vcpu_fd
                .vcpu_init(&kvm_vcpu_init::default())
                .unwrap_err()
                .errno(),
            badf_errno
        );
        assert_eq!(
            faulty_vcpu_fd
                .vcpu_finalize(&(KVM_ARM_VCPU_SVE as i32))
                .unwrap_err()
                .errno(),
            badf_errno
        );
        assert_eq!(
            faulty_vcpu_fd
                .get_reg_list(&mut RegList::new(500).unwrap())
                .unwrap_err()
                .errno(),
            badf_errno
        );
        assert_eq!(
            faulty_vcpu_fd
                .set_one_reg(reg_id, &reg_data)
                .unwrap_err()
                .errno(),
            badf_errno
        );
        assert_eq!(
            faulty_vcpu_fd
                .get_one_reg(reg_id, &mut reg_data)
                .unwrap_err()
                .errno(),
            badf_errno
        );

        // Don't drop the File object, or it'll notice the file it's trying to close is
        // invalid and abort the process.
        faulty_vcpu_fd.vcpu.into_raw_fd();
    }

    #[test]
    #[cfg(target_arch = "riscv64")]
    fn test_faulty_vcpu_fd_riscv64() {
        use std::os::unix::io::{FromRawFd, IntoRawFd};

        let badf_errno = libc::EBADF;

        let faulty_vcpu_fd = VcpuFd {
            vcpu: unsafe { File::from_raw_fd(-2) },
            kvm_run_ptr: KvmRunWrapper {
                kvm_run_ptr: mmap_anonymous(10).cast(),
                mmap_size: 10,
            },
            coalesced_mmio_ring: None,
        };

        let reg_id = 0x8030_0000_0200_000a;
        let mut reg_data = 0u128.to_le_bytes();

        assert_eq!(
            faulty_vcpu_fd
                .get_reg_list(&mut RegList::new(200).unwrap())
                .unwrap_err()
                .errno(),
            badf_errno
        );
        assert_eq!(
            faulty_vcpu_fd
                .set_one_reg(reg_id, &reg_data)
                .unwrap_err()
                .errno(),
            badf_errno
        );
        assert_eq!(
            faulty_vcpu_fd
                .get_one_reg(reg_id, &mut reg_data)
                .unwrap_err()
                .errno(),
            badf_errno
        );

        // Don't drop the File object, or it'll notice the file it's trying to close is
        // invalid and abort the process.
        faulty_vcpu_fd.vcpu.into_raw_fd();
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn test_get_preferred_target() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();

        let mut kvi = kvm_vcpu_init::default();

        vm.get_preferred_target(&mut kvi)
            .expect("Cannot get preferred target");
        vcpu.vcpu_init(&kvi).unwrap();
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn test_set_one_reg() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();

        let mut kvi = kvm_vcpu_init::default();
        vm.get_preferred_target(&mut kvi)
            .expect("Cannot get preferred target");
        vcpu.vcpu_init(&kvi).expect("Cannot initialize vcpu");
        let data: u128 = 0;
        let reg_id: u64 = 0;

        vcpu.set_one_reg(reg_id, &data.to_le_bytes()).unwrap_err();
        // Exercising KVM_SET_ONE_REG by trying to alter the data inside the PSTATE register (which is a
        // specific aarch64 register).
        // This regiseter is 64 bit wide (8 bytes).
        const PSTATE_REG_ID: u64 = 0x6030_0000_0010_0042;
        vcpu.set_one_reg(PSTATE_REG_ID, &data.to_le_bytes())
            .expect("Failed to set pstate register");

        // Trying to set 8 byte register with 7 bytes must fail.
        vcpu.set_one_reg(PSTATE_REG_ID, &[0_u8; 7]).unwrap_err();
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn test_get_one_reg() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();

        let mut kvi = kvm_vcpu_init::default();
        vm.get_preferred_target(&mut kvi)
            .expect("Cannot get preferred target");
        vcpu.vcpu_init(&kvi).expect("Cannot initialize vcpu");

        // PSR (Processor State Register) bits.
        // Taken from arch/arm64/include/uapi/asm/ptrace.h.
        const PSR_MODE_EL1H: u64 = 0x0000_0005;
        const PSR_F_BIT: u64 = 0x0000_0040;
        const PSR_I_BIT: u64 = 0x0000_0080;
        const PSR_A_BIT: u64 = 0x0000_0100;
        const PSR_D_BIT: u64 = 0x0000_0200;
        const PSTATE_FAULT_BITS_64: u64 =
            PSR_MODE_EL1H | PSR_A_BIT | PSR_F_BIT | PSR_I_BIT | PSR_D_BIT;
        let data: u128 = PSTATE_FAULT_BITS_64 as u128;
        const PSTATE_REG_ID: u64 = 0x6030_0000_0010_0042;
        vcpu.set_one_reg(PSTATE_REG_ID, &data.to_le_bytes())
            .expect("Failed to set pstate register");

        let mut bytes = [0_u8; 16];
        vcpu.get_one_reg(PSTATE_REG_ID, &mut bytes)
            .expect("Failed to get pstate register");
        let data = u128::from_le_bytes(bytes);
        assert_eq!(data, PSTATE_FAULT_BITS_64 as u128);

        // Trying to get 8 byte register with 7 bytes must fail.
        vcpu.get_one_reg(PSTATE_REG_ID, &mut [0_u8; 7]).unwrap_err();
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn test_get_reg_list() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();

        let mut reg_list = RegList::new(1).unwrap();
        // KVM_GET_REG_LIST demands that the vcpus be initalized, so we expect this to fail.
        let err = vcpu.get_reg_list(&mut reg_list).unwrap_err();
        assert!(err.errno() == libc::ENOEXEC);

        let mut kvi = kvm_vcpu_init::default();
        vm.get_preferred_target(&mut kvi)
            .expect("Cannot get preferred target");
        vcpu.vcpu_init(&kvi).expect("Cannot initialize vcpu");

        // KVM_GET_REG_LIST offers us a number of registers for which we have
        // not allocated memory, so the first time it fails.
        let err = vcpu.get_reg_list(&mut reg_list).unwrap_err();
        assert!(err.errno() == libc::E2BIG);
        // SAFETY: This structure is a result from a specific vCPU ioctl
        assert!(unsafe { reg_list.as_mut_fam_struct() }.n > 0);

        // We make use of the number of registers returned to allocate memory and
        // try one more time.
        // SAFETY: This structure is a result from a specific vCPU ioctl
        let mut reg_list =
            RegList::new(unsafe { reg_list.as_mut_fam_struct() }.n as usize).unwrap();
        vcpu.get_reg_list(&mut reg_list).unwrap()
    }

    #[test]
    #[cfg(target_arch = "riscv64")]
    fn test_set_one_reg() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();

        let data: u128 = 0;
        let reg_id: u64 = 0;

        vcpu.set_one_reg(reg_id, &data.to_le_bytes()).unwrap_err();
        // Exercising KVM_SET_ONE_REG by trying to alter the data inside the A0
        // register.
        // This regiseter is 64 bit wide (8 bytes).
        const A0_REG_ID: u64 = 0x8030_0000_0200_000a;
        vcpu.set_one_reg(A0_REG_ID, &data.to_le_bytes())
            .expect("Failed to set a0 register");

        // Trying to set 8 byte register with 7 bytes must fail.
        vcpu.set_one_reg(A0_REG_ID, &[0_u8; 7]).unwrap_err();
    }

    #[test]
    #[cfg(target_arch = "riscv64")]
    fn test_get_one_reg() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();

        const PRESET: u64 = 0x7;
        let data: u128 = PRESET as u128;
        const A0_REG_ID: u64 = 0x8030_0000_0200_000a;
        vcpu.set_one_reg(A0_REG_ID, &data.to_le_bytes())
            .expect("Failed to set a0 register");

        let mut bytes = [0_u8; 16];
        vcpu.get_one_reg(A0_REG_ID, &mut bytes)
            .expect("Failed to get a0 register");
        let data = u128::from_le_bytes(bytes);
        assert_eq!(data, PRESET as u128);

        // Trying to get 8 byte register with 7 bytes must fail.
        vcpu.get_one_reg(A0_REG_ID, &mut [0_u8; 7]).unwrap_err();
    }

    #[test]
    #[cfg(target_arch = "riscv64")]
    fn test_get_reg_list() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();

        let mut reg_list = RegList::new(1).unwrap();

        // KVM_GET_REG_LIST offers us a number of registers for which we have
        // not allocated memory, so the first time it fails.
        let err = vcpu.get_reg_list(&mut reg_list).unwrap_err();
        assert!(err.errno() == libc::E2BIG);
        // SAFETY: This structure is a result from a specific vCPU ioctl
        assert!(unsafe { reg_list.as_mut_fam_struct() }.n > 0);

        // We make use of the number of registers returned to allocate memory and
        // try one more time.
        // SAFETY: This structure is a result from a specific vCPU ioctl
        let mut reg_list =
            RegList::new(unsafe { reg_list.as_mut_fam_struct() }.n as usize).unwrap();
        vcpu.get_reg_list(&mut reg_list).unwrap();

        // Test get a register list contains 200 registers explicitly
        let mut reg_list = RegList::new(200).unwrap();
        vcpu.get_reg_list(&mut reg_list).unwrap();
    }

    #[test]
    fn test_get_kvm_run() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let mut vcpu = vm.create_vcpu(0).unwrap();
        vcpu.kvm_run_ptr.as_mut_ref().immediate_exit = 1;
        assert_eq!(vcpu.get_kvm_run().immediate_exit, 1);
    }

    #[test]
    fn test_set_kvm_immediate_exit() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let mut vcpu = vm.create_vcpu(0).unwrap();
        assert_eq!(vcpu.kvm_run_ptr.as_ref().immediate_exit, 0);
        vcpu.set_kvm_immediate_exit(1);
        assert_eq!(vcpu.kvm_run_ptr.as_ref().immediate_exit, 1);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_enable_cap() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let mut cap = kvm_enable_cap {
            // KVM_CAP_HYPERV_SYNIC needs KVM_CAP_SPLIT_IRQCHIP enabled
            cap: KVM_CAP_SPLIT_IRQCHIP,
            ..Default::default()
        };
        cap.args[0] = 24;
        vm.enable_cap(&cap).unwrap();

        let vcpu = vm.create_vcpu(0).unwrap();
        if kvm.check_extension(Cap::HypervSynic) {
            let cap = kvm_enable_cap {
                cap: KVM_CAP_HYPERV_SYNIC,
                ..Default::default()
            };
            vcpu.enable_cap(&cap).unwrap();
        }
    }
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_get_tsc_khz() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();

        if !kvm.check_extension(Cap::GetTscKhz) {
            vcpu.get_tsc_khz().unwrap_err();
        } else {
            assert!(vcpu.get_tsc_khz().unwrap() > 0);
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_set_tsc_khz() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        let freq = vcpu.get_tsc_khz().unwrap();

        if !(kvm.check_extension(Cap::GetTscKhz) && kvm.check_extension(Cap::TscControl)) {
            vcpu.set_tsc_khz(0).unwrap_err();
        } else {
            vcpu.set_tsc_khz(freq - 500000).unwrap();
            assert_eq!(vcpu.get_tsc_khz().unwrap(), freq - 500000);
            vcpu.set_tsc_khz(freq + 500000).unwrap();
            assert_eq!(vcpu.get_tsc_khz().unwrap(), freq + 500000);
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_sync_regs() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let mut vcpu = vm.create_vcpu(0).unwrap();

        // Test setting each valid register
        let sync_regs = [
            SyncReg::Register,
            SyncReg::SystemRegister,
            SyncReg::VcpuEvents,
        ];
        for reg in &sync_regs {
            vcpu.set_sync_valid_reg(*reg);
            assert_eq!(vcpu.kvm_run_ptr.as_ref().kvm_valid_regs, *reg as u64);
            vcpu.clear_sync_valid_reg(*reg);
            assert_eq!(vcpu.kvm_run_ptr.as_ref().kvm_valid_regs, 0);
        }

        // Test that multiple valid SyncRegs can be set at the same time
        vcpu.set_sync_valid_reg(SyncReg::Register);
        vcpu.set_sync_valid_reg(SyncReg::SystemRegister);
        vcpu.set_sync_valid_reg(SyncReg::VcpuEvents);
        assert_eq!(
            vcpu.kvm_run_ptr.as_ref().kvm_valid_regs,
            SyncReg::Register as u64 | SyncReg::SystemRegister as u64 | SyncReg::VcpuEvents as u64
        );

        // Test setting each dirty register
        let sync_regs = [
            SyncReg::Register,
            SyncReg::SystemRegister,
            SyncReg::VcpuEvents,
        ];

        for reg in &sync_regs {
            vcpu.set_sync_dirty_reg(*reg);
            assert_eq!(vcpu.kvm_run_ptr.as_ref().kvm_dirty_regs, *reg as u64);
            vcpu.clear_sync_dirty_reg(*reg);
            assert_eq!(vcpu.kvm_run_ptr.as_ref().kvm_dirty_regs, 0);
        }

        // Test that multiple dirty SyncRegs can be set at the same time
        vcpu.set_sync_dirty_reg(SyncReg::Register);
        vcpu.set_sync_dirty_reg(SyncReg::SystemRegister);
        vcpu.set_sync_dirty_reg(SyncReg::VcpuEvents);
        assert_eq!(
            vcpu.kvm_run_ptr.as_ref().kvm_dirty_regs,
            SyncReg::Register as u64 | SyncReg::SystemRegister as u64 | SyncReg::VcpuEvents as u64
        );
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_sync_regs_with_run() {
        use std::io::Write;

        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        if kvm.check_extension(Cap::SyncRegs) {
            // This example is based on https://lwn.net/Articles/658511/
            #[rustfmt::skip]
            let code = [
                0xff, 0xc0, /* inc eax */
                0xf4, /* hlt */
            ];

            let mem_size = 0x4000;
            let load_addr = mmap_anonymous(mem_size).as_ptr();
            let guest_addr: u64 = 0x1000;
            let slot: u32 = 0;
            let mem_region = kvm_userspace_memory_region {
                slot,
                guest_phys_addr: guest_addr,
                memory_size: mem_size as u64,
                userspace_addr: load_addr as u64,
                flags: KVM_MEM_LOG_DIRTY_PAGES,
            };
            unsafe {
                vm.set_user_memory_region(mem_region).unwrap();
            }

            unsafe {
                // Get a mutable slice of `mem_size` from `load_addr`.
                // This is safe because we mapped it before.
                let mut slice = std::slice::from_raw_parts_mut(load_addr, mem_size);
                slice.write_all(&code).unwrap();
            }

            let mut vcpu = vm.create_vcpu(0).unwrap();

            let orig_sregs = vcpu.get_sregs().unwrap();

            let sync_regs = vcpu.sync_regs_mut();

            // Initialize the sregs in sync_regs to be the original sregs
            sync_regs.sregs = orig_sregs;
            sync_regs.sregs.cs.base = 0;
            sync_regs.sregs.cs.selector = 0;

            // Set up the guest to attempt to `inc rax`
            sync_regs.regs.rip = guest_addr;
            sync_regs.regs.rax = 0x8000;
            sync_regs.regs.rflags = 2;

            // Initialize the sync_reg flags
            vcpu.set_sync_valid_reg(SyncReg::Register);
            vcpu.set_sync_valid_reg(SyncReg::SystemRegister);
            vcpu.set_sync_valid_reg(SyncReg::VcpuEvents);
            vcpu.set_sync_dirty_reg(SyncReg::Register);
            vcpu.set_sync_dirty_reg(SyncReg::SystemRegister);
            vcpu.set_sync_dirty_reg(SyncReg::VcpuEvents);

            // hlt is the only expected return from guest execution
            assert!(matches!(vcpu.run().expect("run failed"), VcpuExit::Hlt));

            let regs = vcpu.get_regs().unwrap();

            let sync_regs = vcpu.sync_regs();
            assert_eq!(regs, sync_regs.regs);
            assert_eq!(sync_regs.regs.rax, 0x8001);
        }
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_translate_gva() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        vcpu.translate_gva(0x10000).unwrap();
        assert_eq!(vcpu.translate_gva(0x10000).unwrap().valid, 1);
        assert_eq!(
            vcpu.translate_gva(0x10000).unwrap().physical_address,
            0x10000
        );
        vcpu.translate_gva(u64::MAX).unwrap();
        assert_eq!(vcpu.translate_gva(u64::MAX).unwrap().valid, 0);
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn test_vcpu_attr() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();

        let dist_attr = kvm_device_attr {
            group: KVM_ARM_VCPU_PMU_V3_CTRL,
            attr: u64::from(KVM_ARM_VCPU_PMU_V3_INIT),
            addr: 0x0,
            flags: 0,
        };

        vcpu.has_device_attr(&dist_attr).unwrap_err();
        vcpu.set_device_attr(&dist_attr).unwrap_err();
        let mut kvi: kvm_vcpu_init = kvm_vcpu_init::default();
        vm.get_preferred_target(&mut kvi)
            .expect("Cannot get preferred target");
        kvi.features[0] |= 1 << KVM_ARM_VCPU_PSCI_0_2 | 1 << KVM_ARM_VCPU_PMU_V3;
        vcpu.vcpu_init(&kvi).unwrap();
        vcpu.has_device_attr(&dist_attr).unwrap();
        vcpu.set_device_attr(&dist_attr).unwrap();
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn test_pointer_authentication() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();

        let mut kvi = kvm_vcpu_init::default();
        vm.get_preferred_target(&mut kvi)
            .expect("Cannot get preferred target");
        if kvm.check_extension(Cap::ArmPtrAuthAddress) {
            kvi.features[0] |= 1 << KVM_ARM_VCPU_PTRAUTH_ADDRESS;
        }
        if kvm.check_extension(Cap::ArmPtrAuthGeneric) {
            kvi.features[0] |= 1 << KVM_ARM_VCPU_PTRAUTH_GENERIC;
        }
        vcpu.vcpu_init(&kvi).unwrap();
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_userspace_rdmsr_exit() {
        use std::io::Write;

        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        #[rustfmt::skip]
        let code = [
            0x0F, 0x32, /* rdmsr */
            0xF4        /* hlt */
        ];

        if !vm.check_extension(Cap::X86UserSpaceMsr) {
            return;
        }
        let cap = kvm_enable_cap {
            cap: Cap::X86UserSpaceMsr as u32,
            args: [MsrExitReason::Unknown.bits() as u64, 0, 0, 0],
            ..Default::default()
        };
        vm.enable_cap(&cap).unwrap();

        let mem_size = 0x4000;
        let load_addr = mmap_anonymous(mem_size).as_ptr();
        let guest_addr: u64 = 0x1000;
        let slot: u32 = 0;
        let mem_region = kvm_userspace_memory_region {
            slot,
            guest_phys_addr: guest_addr,
            memory_size: mem_size as u64,
            userspace_addr: load_addr as u64,
            flags: 0,
        };
        unsafe {
            vm.set_user_memory_region(mem_region).unwrap();

            // Get a mutable slice of `mem_size` from `load_addr`.
            // This is safe because we mapped it before.
            let mut slice = std::slice::from_raw_parts_mut(load_addr, mem_size);
            slice.write_all(&code).unwrap();
        }

        let mut vcpu = vm.create_vcpu(0).unwrap();

        // Set up special registers
        let mut vcpu_sregs = vcpu.get_sregs().unwrap();
        assert_ne!(vcpu_sregs.cs.base, 0);
        assert_ne!(vcpu_sregs.cs.selector, 0);
        vcpu_sregs.cs.base = 0;
        vcpu_sregs.cs.selector = 0;
        vcpu.set_sregs(&vcpu_sregs).unwrap();

        // Set the Instruction Pointer to the guest address where we loaded
        // the code, and RCX to the MSR to be read.
        let mut vcpu_regs = vcpu.get_regs().unwrap();
        vcpu_regs.rip = guest_addr;
        vcpu_regs.rcx = 0x474f4f00;
        vcpu.set_regs(&vcpu_regs).unwrap();

        match vcpu.run().unwrap() {
            VcpuExit::X86Rdmsr(exit) => {
                assert_eq!(exit.reason, MsrExitReason::Unknown);
                assert_eq!(exit.index, 0x474f4f00);
            }
            e => panic!("Unexpected exit: {:?}", e),
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_userspace_hypercall_exit() {
        use std::io::Write;

        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();

        // Use `vmcall` or `vmmcall` depending on what's supported.
        let cpuid = kvm.get_supported_cpuid(KVM_MAX_CPUID_ENTRIES).unwrap();
        let supports_vmcall = cpuid
            .as_slice()
            .iter()
            .find(|entry| entry.function == 1)
            .map_or(false, |entry| entry.ecx & (1 << 5) != 0);
        let supports_vmmcall = cpuid
            .as_slice()
            .iter()
            .find(|entry| entry.function == 0x8000_0001)
            .map_or(false, |entry| entry.ecx & (1 << 2) != 0);
        #[rustfmt::skip]
        let code = if supports_vmcall {
            [
                0x0F, 0x01, 0xC1, /* vmcall */
                0xF4              /* hlt */
            ]
        } else if supports_vmmcall {
            [
                0x0F, 0x01, 0xD9, /* vmmcall */
                0xF4              /* hlt */
            ]
        } else {
            return;
        };

        if !vm.check_extension(Cap::ExitHypercall) {
            return;
        }
        const KVM_HC_MAP_GPA_RANGE: u64 = 12;
        let cap = kvm_enable_cap {
            cap: Cap::ExitHypercall as u32,
            args: [1 << KVM_HC_MAP_GPA_RANGE, 0, 0, 0],
            ..Default::default()
        };
        vm.enable_cap(&cap).unwrap();

        let mem_size = 0x4000;
        let load_addr = mmap_anonymous(mem_size).as_ptr();
        let guest_addr: u64 = 0x1000;
        let slot: u32 = 0;
        let mem_region = kvm_userspace_memory_region {
            slot,
            guest_phys_addr: guest_addr,
            memory_size: mem_size as u64,
            userspace_addr: load_addr as u64,
            flags: 0,
        };
        unsafe {
            vm.set_user_memory_region(mem_region).unwrap();

            // Get a mutable slice of `mem_size` from `load_addr`.
            // This is safe because we mapped it before.
            let mut slice = std::slice::from_raw_parts_mut(load_addr, mem_size);
            slice.write_all(&code).unwrap();
        }

        let mut vcpu = vm.create_vcpu(0).unwrap();

        // Set up special registers
        let mut vcpu_sregs = vcpu.get_sregs().unwrap();
        assert_ne!(vcpu_sregs.cs.base, 0);
        assert_ne!(vcpu_sregs.cs.selector, 0);
        vcpu_sregs.cs.base = 0;
        vcpu_sregs.cs.selector = 0;
        vcpu.set_sregs(&vcpu_sregs).unwrap();

        // Set the Instruction Pointer to the guest address where we loaded
        // the code, and RCX to the MSR to be read.
        let mut vcpu_regs = vcpu.get_regs().unwrap();
        vcpu_regs.rip = guest_addr;
        vcpu_regs.rax = KVM_HC_MAP_GPA_RANGE;
        vcpu_regs.rbx = 0x1234000;
        vcpu_regs.rcx = 1;
        vcpu_regs.rdx = 0;
        vcpu.set_regs(&vcpu_regs).unwrap();

        match vcpu.run().unwrap() {
            VcpuExit::Hypercall(exit) => {
                assert_eq!(exit.nr, KVM_HC_MAP_GPA_RANGE);
                assert_eq!(exit.args[0], 0x1234000);
                assert_eq!(exit.args[1], 1);
                assert_eq!(exit.args[2], 0);
            }
            e => panic!("Unexpected exit: {:?}", e),
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_userspace_wrmsr_exit() {
        use std::io::Write;

        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        #[rustfmt::skip]
        let code = [
            0x0F, 0x30, /* wrmsr */
            0xF4        /* hlt */
        ];

        if !vm.check_extension(Cap::X86UserSpaceMsr) {
            return;
        }
        let cap = kvm_enable_cap {
            cap: Cap::X86UserSpaceMsr as u32,
            args: [MsrExitReason::Unknown.bits() as u64, 0, 0, 0],
            ..Default::default()
        };
        vm.enable_cap(&cap).unwrap();

        let mem_size = 0x4000;
        let load_addr = mmap_anonymous(mem_size).as_ptr();
        let guest_addr: u64 = 0x1000;
        let slot: u32 = 0;
        let mem_region = kvm_userspace_memory_region {
            slot,
            guest_phys_addr: guest_addr,
            memory_size: mem_size as u64,
            userspace_addr: load_addr as u64,
            flags: 0,
        };
        unsafe {
            vm.set_user_memory_region(mem_region).unwrap();

            // Get a mutable slice of `mem_size` from `load_addr`.
            // This is safe because we mapped it before.
            let mut slice = std::slice::from_raw_parts_mut(load_addr, mem_size);
            slice.write_all(&code).unwrap();
        }

        let mut vcpu = vm.create_vcpu(0).unwrap();

        // Set up special registers
        let mut vcpu_sregs = vcpu.get_sregs().unwrap();
        assert_ne!(vcpu_sregs.cs.base, 0);
        assert_ne!(vcpu_sregs.cs.selector, 0);
        vcpu_sregs.cs.base = 0;
        vcpu_sregs.cs.selector = 0;
        vcpu.set_sregs(&vcpu_sregs).unwrap();

        // Set the Instruction Pointer to the guest address where we loaded
        // the code, RCX to the MSR to be written, and EDX:EAX to the data to
        // be written.
        let mut vcpu_regs = vcpu.get_regs().unwrap();
        vcpu_regs.rip = guest_addr;
        vcpu_regs.rcx = 0x474f4f00;
        vcpu_regs.rax = 0xdeadbeef;
        vcpu_regs.rdx = 0xd0c0ffee;
        vcpu.set_regs(&vcpu_regs).unwrap();

        match vcpu.run().unwrap() {
            VcpuExit::X86Wrmsr(exit) => {
                assert_eq!(exit.reason, MsrExitReason::Unknown);
                assert_eq!(exit.index, 0x474f4f00);
                assert_eq!(exit.data & 0xffffffff, 0xdeadbeef);
                assert_eq!((exit.data >> 32) & 0xffffffff, 0xd0c0ffee);
            }
            e => panic!("Unexpected exit: {:?}", e),
        }
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_coalesced_pio() {
        use crate::IoEventAddress;
        use std::io::Write;

        const PORT: u64 = 0x2c;
        const DATA: u64 = 0x39;
        const SIZE: u32 = 1;

        #[rustfmt::skip]
        let code = [
            0xe6, 0x2c,   // out 0x2c, al
            0xf4,         // hlt
            0xe6, 0x2c,   // out 0x2c, al
            0xf4,         // hlt
        ];

        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        assert!(vm.check_extension(Cap::CoalescedPio));

        // Prepare guest memory
        let mem_size = 0x4000;
        let load_addr = mmap_anonymous(mem_size).as_ptr();
        let guest_addr: u64 = 0x1000;
        let slot = 0;
        let mem_region = kvm_userspace_memory_region {
            slot,
            guest_phys_addr: guest_addr,
            memory_size: mem_size as u64,
            userspace_addr: load_addr as u64,
            flags: 0,
        };

        unsafe {
            vm.set_user_memory_region(mem_region).unwrap();

            // Get a mutable slice of `mem_size` from `load_addr`.
            // This is safe because we mapped it before.
            let mut slice = std::slice::from_raw_parts_mut(load_addr, mem_size);
            slice.write_all(&code).unwrap();
        }

        let addr = IoEventAddress::Pio(PORT);
        vm.register_coalesced_mmio(addr, SIZE).unwrap();

        let mut vcpu = vm.create_vcpu(0).unwrap();

        // Map the MMIO ring
        vcpu.map_coalesced_mmio_ring().unwrap();

        // Set regs
        let mut regs = vcpu.get_regs().unwrap();
        regs.rip = guest_addr;
        regs.rax = DATA;
        regs.rflags = 2;
        vcpu.set_regs(&regs).unwrap();

        // Set sregs
        let mut sregs = vcpu.get_sregs().unwrap();
        sregs.cs.base = 0;
        sregs.cs.selector = 0;
        vcpu.set_sregs(&sregs).unwrap();

        // Run and check that the exit was caused by the hlt and not the port
        // I/O
        let exit = vcpu.run().unwrap();
        assert!(matches!(exit, VcpuExit::Hlt));

        // Check that the ring buffer entry is what we expect
        let entry = vcpu.coalesced_mmio_read().unwrap().unwrap();
        assert_eq!(entry.phys_addr, PORT);
        assert_eq!(entry.len, 1);
        assert_eq!(entry.data[0] as u64, DATA);
        // SAFETY: this field is a u32 in all variants of the union,
        // so access is always safe.
        let pio = unsafe { entry.__bindgen_anon_1.pio };
        assert_eq!(pio, 1);

        // The ring buffer should be empty now
        assert!(vcpu.coalesced_mmio_read().unwrap().is_none());

        // Unregister and check that the next PIO write triggers an exit
        vm.unregister_coalesced_mmio(addr, SIZE).unwrap();
        let exit = vcpu.run().unwrap();
        let VcpuExit::IoOut(port, data) = exit else {
            panic!("Unexpected VM exit: {:?}", exit);
        };
        assert_eq!(port, PORT as u16);
        assert_eq!(data, (DATA as u8).to_le_bytes());
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_coalesced_mmio() {
        use crate::IoEventAddress;
        use std::io::Write;

        const ADDR: u64 = 0x124;
        const DATA: u64 = 0x39;
        const SIZE: u32 = 2;

        #[rustfmt::skip]
        let code = [
            0x66, 0x31, 0xFF,        // xor di,di
            0x66, 0xBF, 0x24, 0x01,  // mov di, 0x124
            0x67, 0x66, 0x89, 0x05,  // mov WORD PTR [di], ax
            0xF4,                    // hlt
            0x66, 0x31, 0xFF,        // xor di,di
            0x66, 0xBF, 0x24, 0x01,  // mov di, 0x124
            0x67, 0x66, 0x89, 0x05,  // mov WORD PTR [di], ax
            0xF4,                    // hlt
        ];

        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        assert!(vm.check_extension(Cap::CoalescedMmio));

        // Prepare guest memory
        let mem_size = 0x4000;
        let load_addr = mmap_anonymous(mem_size).as_ptr();
        let guest_addr: u64 = 0x1000;
        let slot: u32 = 0;
        let mem_region = kvm_userspace_memory_region {
            slot,
            guest_phys_addr: guest_addr,
            memory_size: mem_size as u64,
            userspace_addr: load_addr as u64,
            flags: 0,
        };

        unsafe {
            vm.set_user_memory_region(mem_region).unwrap();

            // Get a mutable slice of `mem_size` from `load_addr`.
            // This is safe because we mapped it before.
            let mut slice = std::slice::from_raw_parts_mut(load_addr, mem_size);
            slice.write_all(&code).unwrap();
        }

        let addr = IoEventAddress::Mmio(ADDR);
        vm.register_coalesced_mmio(addr, SIZE).unwrap();

        let mut vcpu = vm.create_vcpu(0).unwrap();

        // Map the MMIO ring
        vcpu.map_coalesced_mmio_ring().unwrap();

        // Set regs
        let mut regs = vcpu.get_regs().unwrap();
        regs.rip = guest_addr;
        regs.rax = DATA;
        regs.rdx = ADDR;
        regs.rflags = 2;
        vcpu.set_regs(&regs).unwrap();

        // Set sregs
        let mut sregs = vcpu.get_sregs().unwrap();
        sregs.cs.base = 0;
        sregs.cs.selector = 0;
        vcpu.set_sregs(&sregs).unwrap();

        // Run and check that the exit was caused by the hlt and not the MMIO
        // access
        let exit = vcpu.run().unwrap();
        assert!(matches!(exit, VcpuExit::Hlt));

        // Check that the ring buffer entry is what we expect
        let entry = vcpu.coalesced_mmio_read().unwrap().unwrap();
        assert_eq!(entry.phys_addr, ADDR);
        assert_eq!(entry.len, SIZE);
        assert_eq!(entry.data[0] as u64, DATA);
        // SAFETY: this field is a u32 in all variants of the union,
        // so access is always safe.
        let pio = unsafe { entry.__bindgen_anon_1.pio };
        assert_eq!(pio, 0);

        // The ring buffer should be empty now
        assert!(vcpu.coalesced_mmio_read().unwrap().is_none());

        // Unregister and check that the next MMIO write triggers an exit
        vm.unregister_coalesced_mmio(addr, SIZE).unwrap();
        let exit = vcpu.run().unwrap();
        let VcpuExit::MmioWrite(addr, data) = exit else {
            panic!("Unexpected VM exit: {:?}", exit);
        };
        assert_eq!(addr, ADDR);
        assert_eq!(data, (DATA as u16).to_le_bytes());
    }
}
