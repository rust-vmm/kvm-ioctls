// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Rust FFI bindings to KVM, generated using [bindgen](https://crates.io/crates/bindgen).

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

#[cfg(all(feature = "fam-wrappers", not(target_arch = "riscv64")))]
#[macro_use]
extern crate vmm_sys_util;

#[cfg(all(feature = "serde", not(target_arch = "riscv64")))]
extern crate serde;

#[cfg(all(feature = "serde", not(target_arch = "riscv64")))]
extern crate zerocopy;

#[cfg(all(feature = "serde", not(target_arch = "riscv64")))]
#[macro_use]
mod serialize;

#[cfg(target_arch = "x86_64")]
mod x86_64;
#[cfg(target_arch = "x86_64")]
pub use self::x86_64::*;

#[cfg(any(target_arch = "aarch", target_arch = "aarch64"))]
mod arm64;
#[cfg(any(target_arch = "aarch", target_arch = "aarch64"))]
pub use self::arm64::*;

#[cfg(target_arch = "riscv64")]
mod riscv64;
#[cfg(target_arch = "riscv64")]
pub use self::riscv64::*;
