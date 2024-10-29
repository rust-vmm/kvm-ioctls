// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use bindings::{
    kvm_clock_data, kvm_cpuid2, kvm_cpuid_entry2, kvm_debugregs, kvm_dtable, kvm_irqchip,
    kvm_irqchip__bindgen_ty_1, kvm_lapic_state, kvm_mp_state, kvm_msr_entry, kvm_msrs,
    kvm_pit_channel_state, kvm_pit_state2, kvm_regs, kvm_segment, kvm_sregs, kvm_vcpu_events,
    kvm_xcr, kvm_xcrs, kvm_xsave,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zerocopy::{transmute, AsBytes, FromBytes, FromZeroes};

serde_impls!(
    kvm_regs,
    kvm_segment,
    kvm_dtable,
    kvm_sregs,
    kvm_msr_entry,
    kvm_cpuid_entry2,
    kvm_pit_channel_state,
    kvm_pit_state2,
    kvm_vcpu_events,
    kvm_debugregs,
    kvm_xcr,
    kvm_xcrs,
    kvm_mp_state,
    kvm_clock_data,
    kvm_lapic_state,
    kvm_msrs,
    kvm_cpuid2,
    kvm_xsave,
    kvm_irqchip
);

// SAFETY: zerocopy's derives explicitly disallow deriving for unions where
// the fields have different sizes, due to the smaller fields having padding.
// Miri however does not complain about these implementations (e.g. about
// reading the "padding" for one union field as valid data for a bigger one)
unsafe impl FromZeroes for kvm_irqchip__bindgen_ty_1 {
    fn only_derive_is_allowed_to_implement_this_trait()
    where
        Self: Sized,
    {
    }
}

// SAFETY: zerocopy's derives explicitly disallow deriving for unions where
// the fields have different sizes, due to the smaller fields having padding.
// Miri however does not complain about these implementations (e.g. about
// reading the "padding" for one union field as valid data for a bigger one)
unsafe impl FromBytes for kvm_irqchip__bindgen_ty_1 {
    fn only_derive_is_allowed_to_implement_this_trait()
    where
        Self: Sized,
    {
    }
}

// SAFETY: zerocopy's derives explicitly disallow deriving for unions where
// the fields have different sizes, due to the smaller fields having padding.
// Miri however does not complain about these implementations (e.g. about
// reading the "padding" for one union field as valid data for a bigger one)
unsafe impl AsBytes for kvm_irqchip__bindgen_ty_1 {
    fn only_derive_is_allowed_to_implement_this_trait()
    where
        Self: Sized,
    {
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bindings::*;

    fn is_serde<T: Serialize + for<'de> Deserialize<'de> + Default>() {
        let serialized = bincode::serialize(&T::default()).unwrap();
        let deserialized = bincode::deserialize::<T>(serialized.as_ref()).unwrap();
        let serialized_again = bincode::serialize(&deserialized).unwrap();
        // Compare the serialized state after a roundtrip, to work around issues with
        // bindings not implementing `PartialEq`.
        assert_eq!(serialized, serialized_again);
    }

    #[test]
    fn static_assert_serde_implementations() {
        // This test statically (= at compile-time) asserts that various bindgen generated
        // structures implement serde's `Serialize` and `Deserialize` traits.
        // This is to make sure that we do not accidentally remove those implementations
        // when regenerating bindings. If this test fails to compile, please add
        //
        // #[cfg_attr(
        //     feature = "serde",
        //     derive(zerocopy::AsBytes, zerocopy::FromBytes, zerocopy::FromZeroes)
        // )]
        //
        // to all structures causing compilation errors (we need the zerocopy traits, as the
        // `Serialize` and `Deserialize` implementations are provided by the `serde_impls!` macro
        // above, which implements serialization based on zerocopy's `FromBytes` and `AsBytes`
        // traits that it expects to be derived).
        //
        // NOTE: This only include "top-level" items, and does not list out bindgen-anonymous types
        // (e.g. types like `kvm_vcpu_events__bindgen_ty_5`). These types can change name across
        // bindgen versions. If after re-adding the derives to all the below items you can compile
        // errors about anonymous types not implementing `Serialize`/`Deserialize`, please also add
        // the derives to all anonymous types references in the definitions of the below items.

        is_serde::<kvm_clock_data>();
        is_serde::<kvm_regs>();
        is_serde::<kvm_segment>();
        is_serde::<kvm_dtable>();
        is_serde::<kvm_sregs>();
        is_serde::<kvm_msr_entry>();
        is_serde::<kvm_msrs>();
        is_serde::<kvm_cpuid_entry2>();
        is_serde::<kvm_cpuid2>();
        is_serde::<kvm_pit_channel_state>();
        is_serde::<kvm_pit_state2>();
        is_serde::<kvm_vcpu_events>();
        is_serde::<kvm_debugregs>();
        is_serde::<kvm_xcr>();
        is_serde::<kvm_xcrs>();
        is_serde::<kvm_irqchip>();
        is_serde::<kvm_mp_state>();
    }

    fn is_serde_json<T: Serialize + for<'de> Deserialize<'de> + Default>() {
        let serialized = serde_json::to_string(&T::default()).unwrap();
        let deserialized = serde_json::from_str::<T>(serialized.as_ref()).unwrap();
        let serialized_again = serde_json::to_string(&deserialized).unwrap();
        // Compare the serialized state after a roundtrip, to work around issues with
        // bindings not implementing `PartialEq`.
        assert_eq!(serialized, serialized_again);
    }

    #[test]
    fn test_json_serde() {
        is_serde_json::<kvm_clock_data>();
        is_serde_json::<kvm_regs>();
        is_serde_json::<kvm_segment>();
        is_serde_json::<kvm_dtable>();
        is_serde_json::<kvm_sregs>();
        is_serde_json::<kvm_msr_entry>();
        is_serde_json::<kvm_msrs>();
        is_serde_json::<kvm_cpuid_entry2>();
        is_serde_json::<kvm_cpuid2>();
        is_serde_json::<kvm_pit_channel_state>();
        is_serde_json::<kvm_pit_state2>();
        is_serde_json::<kvm_vcpu_events>();
        is_serde_json::<kvm_debugregs>();
        is_serde_json::<kvm_xcr>();
        is_serde_json::<kvm_xcrs>();
        is_serde_json::<kvm_irqchip>();
        is_serde_json::<kvm_mp_state>();
    }
}
