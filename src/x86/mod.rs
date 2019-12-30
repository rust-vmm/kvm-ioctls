// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "fam-wrappers")]
mod fam_wrappers;

// Export 4.14 bindings when the feature kvm-v4_20_0 is not specified.
#[cfg(all(feature = "kvm-v4_14_0", not(feature = "kvm-v4_20_0")))]
#[allow(clippy::all)]
mod bindings_v4_14_0;

// Export 4.20 bindings when kvm-v4_20_0 is specified or no kernel version
// related features are specified.
#[cfg(any(
    feature = "kvm-v4_20_0",
    all(not(feature = "kvm-v4_14_0"), not(feature = "kvm-v4_20_0"))
))]
#[allow(clippy::all)]
mod bindings_v4_20_0;

pub mod bindings {
    #[cfg(all(feature = "kvm-v4_14_0", not(feature = "kvm-v4_20_0")))]
    pub use super::bindings_v4_14_0::*;

    #[cfg(any(
        feature = "kvm-v4_20_0",
        all(not(feature = "kvm-v4_14_0"), not(feature = "kvm-v4_20_0"))
    ))]
    pub use super::bindings_v4_20_0::*;

    #[cfg(feature = "fam-wrappers")]
    pub use super::fam_wrappers::*;
}
