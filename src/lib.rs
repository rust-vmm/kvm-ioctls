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
mod ioctls;

pub use cap::Cap;
pub use ioctls::system::Kvm;
pub use ioctls::vcpu::{VcpuExit, VcpuFd};
pub use ioctls::vm::VmFd;
pub use ioctls::{CpuId, KvmRunWrapper, Result};

/// Maximum number of CPUID entries that can be returned by a call to KVM ioctls.
///
/// This value is taken from Linux Kernel v4.14.13 (arch/x86/include/asm/kvm_host.h).
/// It can be used for calls to [get_supported_cpuid](struct.Kvm.html#method.get_supported_cpuid) and
/// [get_emulated_cpuid](struct.Kvm.html#method.get_emulated_cpuid).
pub const MAX_KVM_CPUID_ENTRIES: usize = 80;
