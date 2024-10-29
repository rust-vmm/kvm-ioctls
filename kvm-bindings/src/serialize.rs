// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//! Module containing serialization utilities

/// Macro that generates serde::Serialize and serde::Deserialize implementations for the given types.
/// This macro assumes that the types implement zerocopy::FromBytes and zerocopy::AsBytes, and uses
/// these implementations to serialize as opaque byte arrays. During deserialization, it will
/// try to deserialize as a `Vec`. If this deserialized `Vec` has a length that equals `size_of::<T>`,
/// it will transmute to `T` (using zerocopy), otherwise the `Vec` will either be zero-padded, or truncated.
/// This will hopefully allow live update of bindings across kernel versions even if the kernel adds
/// new fields to the end of some struct (we heavily rely on the kernel not making ABI breaking changes here).
macro_rules! serde_impls {
    ($($typ: ty),*) => {
        $(
            impl Serialize for $typ {
                fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
                where
                    S: Serializer
                {
                    let bytes = self.as_bytes();
                    serializer.serialize_bytes(bytes)
                }
            }

            impl<'de> Deserialize<'de> for $typ {
                fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
                where
                    D: Deserializer<'de>
                {
                    struct BytesVisitor;

                    impl<'a> serde::de::Visitor<'a> for BytesVisitor {
                        type Value = [u8; std::mem::size_of::<$typ>()];

                        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                            formatter.write_str("a byte array")
                        }

                        fn visit_bytes<E>(self, bytes: &[u8]) -> Result<Self::Value, E> {
                            let mut backing = [0u8; std::mem::size_of::<$typ>()];
                            let limit = bytes.len().min(backing.len());
                            backing[..limit].copy_from_slice(&bytes[..limit]);
                            Ok(backing)
                        }

                        fn visit_seq<A: serde::de::SeqAccess<'a>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                            let mut backing = [0u8; std::mem::size_of::<$typ>()];

                            for backing_byte in &mut backing {
                                let Some(byte) = seq.next_element()? else { break };

                                *backing_byte = byte;
                            }

                            Ok(backing)
                        }
                    }

                    let backing = deserializer.deserialize_bytes(BytesVisitor)?;

                    Ok(transmute!(backing))
                }
            }
        )*
    }
}
