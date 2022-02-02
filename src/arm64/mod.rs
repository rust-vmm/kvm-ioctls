// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#[allow(clippy::all)]
// Keep this until https://github.com/rust-lang/rust-bindgen/issues/1651 is fixed.
#[cfg_attr(test, allow(deref_nullptr))]
pub mod bindings;
#[cfg(feature = "fam-wrappers")]
pub mod fam_wrappers;

pub use self::bindings::*;
#[cfg(feature = "fam-wrappers")]
pub use self::fam_wrappers::*;
