// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use kvm_bindings::__IncompleteArrayField;
use std::mem;
use std::mem::size_of;

/// Errors associated with the KvmVec struct.
#[derive(Debug, Clone)]
pub enum Error {
    /// The max size has been exceeded
    SizeLimitExceeded,
}

/// Trait for accessing some properties of certain KVM structures that resemble an array.
///
/// The kvm API has many structs that resemble the following `MockKvmArray` structure:
///
/// # Example
///
/// ```
/// extern crate kvm_bindings;
/// use kvm_bindings::*;
///
/// use kvm_ioctls::{KvmArray, KvmVec};
///
/// const MAX_LEN: usize = 100;
///
/// #[repr(C)]
/// #[derive(Default)]
/// struct MockKvmArray {
///     pub len: __u32,
///     pub padding: __u32,
///     pub entries: __IncompleteArrayField<__u32>,
/// }
///
/// impl KvmArray for MockKvmArray {
///     type Entry = u32;
///
///     fn len(&self) -> usize {
///         self.len as usize
///     }
///
///     fn set_len(&mut self, len: usize) {
///         self.len = len as u32
///     }
///
///     fn max_len() -> usize {
///         MAX_LEN
///     }
///
///     fn entries(&self) -> &__IncompleteArrayField<u32> {
///         &self.entries
///     }
///
///     fn entries_mut(&mut self) -> &mut __IncompleteArrayField<u32> {
///         &mut self.entries
///     }
/// }
/// ```
#[allow(clippy::len_without_is_empty)]
pub trait KvmArray {
    /// The type of the __IncompleteArrayField entries
    type Entry: PartialEq + Copy;

    /// Get the array length
    ///
    fn len(&self) -> usize;

    /// Get the array length as mut
    ///
    fn set_len(&mut self, len: usize);

    /// Get max array length
    ///
    fn max_len() -> usize;

    /// Get the array entries
    ///
    fn entries(&self) -> &__IncompleteArrayField<Self::Entry>;

    /// Get the array entries as mut
    ///
    fn entries_mut(&mut self) -> &mut __IncompleteArrayField<Self::Entry>;
}

/// An adapter that helps in treating a KvmArray similarly to an actual `Vec`.
///
pub struct KvmVec<T: Default + KvmArray> {
    // this variable holds the KvmArray structure. We use a `Vec<T>` To make the allocation
    // large enough while still being aligned for `T`. Only the first element of `Vec<T>` will
    // actually be used as a `T`. The remaining memory in the `Vec<T>` is for `entries`, which
    // must be contiguous. Since the entries are of type `KvmArray::Entry`
    // we must be careful to convert the desired capacity of the `KvmVec`
    // from `KvmArray::Entry` to `T` when reserving or releasing memory.
    mem_allocator: Vec<T>,
    // the number of elements of type `KvmArray::Entry` currently in the vec
    len: usize,
    // the capacity of the `KvmVec` measured in elements of type `KvmArray::Entry`
    capacity: usize,
}

impl<T: Default + KvmArray> KvmVec<T> {
    /// Get the capacity required by mem_allocator in order to hold
    /// the provided number of  `KvmArray::Entry`
    ///
    fn kvm_vec_len_to_mem_allocator_len(kvm_vec_len: usize) -> usize {
        let kvm_vec_size_in_bytes = size_of::<T>() + kvm_vec_len * size_of::<T::Entry>();
        (kvm_vec_size_in_bytes + size_of::<T>() - 1) / size_of::<T>()
    }

    /// Get the number of elements of type `KvmArray::Entry` that fit
    /// in a mem_allocator of provided len
    ///
    fn mem_allocator_len_to_kvm_vec_len(mem_allocator_len: usize) -> usize {
        if mem_allocator_len == 0 {
            return 0;
        }

        let array_size_in_bytes = (mem_allocator_len - 1) * size_of::<T>();
        array_size_in_bytes / size_of::<T::Entry>()
    }

    /// Constructs a new KvmVec<T> that contains `num_elements` empty elements
    /// of type `KvmArray::Entry`
    ///
    /// # Arguments
    ///
    /// * `num_elements` - The number of empty elements of type `KvmArray::Entry` in the initial `KvmVec`
    ///
    /// # Example
    ///
    /// ```
    /// extern crate kvm_bindings;
    /// use kvm_bindings::*;
    ///
    /// #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    /// use kvm_ioctls::{KvmArray, KvmVec, CpuId};
    ///
    /// #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    /// fn example() {
    ///     let cpuid = CpuId::new(3);
    ///     assert_eq!(cpuid.as_entries_slice().len(), 3);
    ///     for entry in cpuid.as_entries_slice().iter() {
    ///         assert_eq!(*entry, kvm_cpuid_entry2::default())
    ///     }
    /// }
    /// ```
    ///
    pub fn new(num_elements: usize) -> KvmVec<T> {
        let required_mem_allocator_capacity =
            KvmVec::<T>::kvm_vec_len_to_mem_allocator_len(num_elements);

        let mut mem_allocator = Vec::with_capacity(required_mem_allocator_capacity);
        for _ in 0..required_mem_allocator_capacity {
            mem_allocator.push(T::default())
        }
        mem_allocator[0].set_len(num_elements);

        KvmVec {
            mem_allocator,
            len: num_elements,
            capacity: num_elements,
        }
    }

    /// Creates a new `KvmVec` structure based on a supplied vector of `KvmArray::Entry`.
    ///
    /// # Arguments
    ///
    /// * `entries` - The vector of `KvmArray::Entry` entries.
    ///
    /// # Example
    ///
    /// ```
    /// extern crate kvm_bindings;
    /// use kvm_bindings::*;
    ///
    /// #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    /// use kvm_ioctls::{KvmArray, KvmVec, CpuId};
    ///
    /// #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    /// fn example() {
    /// // Create a vec to hold one cpuid entry.
    ///     let mut cpuid_entries = Vec::new();
    ///     let new_entry = kvm_cpuid_entry2 {
    ///         function: 0x4,
    ///         index: 0,
    ///         flags: 1,
    ///          eax: 0b1100000,
    ///         ebx: 0,
    ///         ecx: 0,
    ///         edx: 0,
    ///         padding: [0, 0, 0],
    ///     };
    ///     cpuid_entries.push(new_entry);
    ///     let cpuid = CpuId::from_entries(&cpuid_entries);
    /// }
    /// ```
    ///
    pub fn from_entries(entries: &[T::Entry]) -> KvmVec<T> {
        let mut kvm_vec = KvmVec::<T>::new(entries.len());

        {
            let kvm_vec_entries = kvm_vec.as_mut_kvm_struct().entries_mut();
            // this is safe because the provided length is correct
            let kvm_vec_entries_slice = unsafe { kvm_vec_entries.as_mut_slice(entries.len()) };
            kvm_vec_entries_slice.copy_from_slice(entries);
        }

        kvm_vec
    }

    /// Get a reference to the actual KVM structure instance.
    ///
    pub fn as_kvm_struct(&self) -> &T {
        &self.mem_allocator[0]
    }

    /// Get a mut reference to the actual KVM structure instance.
    ///
    pub fn as_mut_kvm_struct(&mut self) -> &mut T {
        &mut self.mem_allocator[0]
    }

    /// Get a pointer to the KVM struct so it can be passed to the kernel.
    ///
    pub fn as_ptr(&self) -> *const T {
        self.as_kvm_struct()
    }

    /// Get a mutable pointer to the KVM struct so it can be passed to the kernel.
    ///
    pub fn as_mut_ptr(&mut self) -> *mut T {
        self.as_mut_kvm_struct()
    }

    /// Get a mut `Vec<KvmArray::Entry>` that contains all the elements.
    /// It is important to call `mem::forget` after using this vector.
    /// Otherwise rust will destroy it.
    ///
    fn as_vec(&mut self) -> Vec<T::Entry> {
        unsafe {
            let entries_ptr = self.as_mut_kvm_struct().entries_mut().as_mut_ptr();
            // This is safe since self.len and self.capacity should be correct
            Vec::from_raw_parts(entries_ptr, self.len, self.capacity as usize)
        }
    }

    /// Get the mutable elements slice so they can be modified before passing to the VCPU.
    ///
    /// # Example
    /// ```
    /// #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    /// use kvm_ioctls::{CpuId, Kvm, MAX_KVM_CPUID_ENTRIES};
    ///
    /// #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    /// fn example() {
    ///     let kvm = Kvm::new().unwrap();
    ///     let mut cpuid = kvm.get_supported_cpuid(MAX_KVM_CPUID_ENTRIES).unwrap();
    ///     let cpuid_entries = cpuid.as_entries_slice();
    /// }
    /// ```
    pub fn as_entries_slice(&self) -> &[T::Entry] {
        let len = self.as_kvm_struct().len();
        unsafe { self.as_kvm_struct().entries().as_slice(len as usize) }
    }

    /// Get the mutable elements slice so they can be modified before passing to the VCPU.
    ///
    /// # Example
    /// ```
    /// #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    /// use kvm_ioctls::{CpuId, Kvm, MAX_KVM_CPUID_ENTRIES};
    ///
    /// #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    /// fn example() {
    ///     let kvm = Kvm::new().unwrap();
    ///     let mut cpuid = kvm.get_supported_cpuid(MAX_KVM_CPUID_ENTRIES).unwrap();
    ///     let cpuid_entries = cpuid.as_mut_entries_slice();
    /// }
    /// ```
    ///
    pub fn as_mut_entries_slice(&mut self) -> &mut [T::Entry] {
        let len = self.as_kvm_struct().len();
        unsafe {
            self.as_mut_kvm_struct()
                .entries_mut()
                .as_mut_slice(len as usize)
        }
    }

    /// Reserves capacity for at least `additional` more `KvmArray::Entry` elements.
    /// If the capacity is already reserved, this method doesn't do anything
    ///
    fn reserve(&mut self, additional: usize) {
        let desired_capacity = self.len + additional;
        if desired_capacity <= self.capacity {
            return;
        }

        let current_mem_allocator_len = self.mem_allocator.len();
        let required_mem_allocator_len =
            KvmVec::<T>::kvm_vec_len_to_mem_allocator_len(desired_capacity);
        let additional_mem_allocator_len = required_mem_allocator_len - current_mem_allocator_len;

        self.mem_allocator.reserve(additional_mem_allocator_len);
        self.capacity =
            KvmVec::<T>::mem_allocator_len_to_kvm_vec_len(self.mem_allocator.capacity());
    }

    /// Updates the length of `self` to the specified value.
    /// Also updates the length of the `T::Entry` structure and of `self.mem_allocator` accordingly.
    ///
    fn update_len(&mut self, len: usize) {
        self.len = len;
        self.as_mut_kvm_struct().set_len(len);

        /// We need to set the len of the mem_allocator to be the number of T elements needed
        /// to fit an array of `len` elements of type `T::Entry`. This way, when we call
        /// `self.mem_allocator.shrink_to_fit()` only the unnecessary memory will be released.
        let required_mem_allocator_len = KvmVec::<T>::kvm_vec_len_to_mem_allocator_len(len);
        unsafe {
            self.mem_allocator.set_len(required_mem_allocator_len);
        }
    }

    /// Appends an element to the end of the collection and updates `len`.
    ///
    /// # Arguments
    ///
    /// * `entry` - The element that will be appended to the end of the collection.
    ///
    /// # Error: When len is already equal to max possible len it returns Error::SizeLimitExceeded
    ///
    /// # Example
    /// ```
    /// extern crate kvm_bindings;
    /// use kvm_bindings::*;
    ///
    /// #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    /// use kvm_ioctls::{KvmArray, KvmVec, CpuId};
    ///
    /// #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    /// fn example() {
    ///     let mut cpuid = CpuId::new(3);
    ///     cpuid.push(kvm_cpuid_entry2 {
    ///         function: 1,
    ///         index: 0,
    ///         flags: 0,
    ///         eax: 0,
    ///         ebx: 0,
    ///         ecx: 0,
    ///         edx: 0,
    ///         padding: [0, 0, 0]
    ///     });
    ///     assert_eq!(cpuid.as_entries_slice()[3].function, 1)
    /// }
    /// ```
    ///
    pub fn push(&mut self, entry: T::Entry) -> Result<(), Error> {
        let desired_len = self.len + 1;
        if desired_len > T::max_len() {
            return Err(Error::SizeLimitExceeded);
        }

        self.reserve(1);

        let mut entries = self.as_vec();
        entries.push(entry);
        self.update_len(desired_len);

        mem::forget(entries);

        Ok(())
    }

    /// Retains only the elements specified by the predicate.
    ///
    /// # Arguments
    ///
    /// * `f` - The function used to evaluate whether an entry will be kept or not.
    ///         When `f` returns `true` the entry is kept.
    ///
    /// # Example
    /// ```
    /// extern crate kvm_bindings;
    /// use kvm_bindings::*;
    ///
    /// #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    /// use kvm_ioctls::{KvmArray, KvmVec, CpuId};
    ///
    /// #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    /// fn example() {
    ///     let mut cpuid = CpuId::new(3);
    ///     cpuid.retain(|entry| {
    ///         entry.function != 0
    ///     });
    ///     assert_eq!(cpuid.as_entries_slice().len(), 0);
    /// }
    /// ```
    ///
    pub fn retain<P>(&mut self, f: P)
    where
        P: FnMut(&T::Entry) -> bool,
    {
        let mut entries = self.as_vec();
        entries.retain(f);

        self.update_len(entries.len());
        self.mem_allocator.shrink_to_fit();
        self.capacity =
            KvmVec::<T>::mem_allocator_len_to_kvm_vec_len(self.mem_allocator.capacity());

        mem::forget(entries);
    }
}

impl<T: Default + KvmArray> PartialEq for KvmVec<T> {
    fn eq(&self, other: &KvmVec<T>) -> bool {
        self.len == other.len && self.as_entries_slice() == other.as_entries_slice()
    }
}

impl<T: Default + KvmArray> Clone for KvmVec<T> {
    fn clone(&self) -> Self {
        let mut clone = KvmVec::<T>::new(self.len);

        let num_bytes = self.mem_allocator.len() * size_of::<T>();
        let src_byte_slice =
            unsafe { std::slice::from_raw_parts(self.as_ptr() as *const u8, num_bytes) };
        let dst_byte_slice =
            unsafe { std::slice::from_raw_parts_mut(clone.as_mut_ptr() as *mut u8, num_bytes) };
        dst_byte_slice.copy_from_slice(src_byte_slice);

        clone
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kvm_bindings::*;

    const MAX_LEN: usize = 100;

    #[repr(C)]
    #[derive(Default)]
    struct MockKvmArray {
        pub len: __u32,
        pub padding: __u32,
        pub entries: __IncompleteArrayField<__u32>,
    }

    impl KvmArray for MockKvmArray {
        type Entry = u32;

        fn len(&self) -> usize {
            self.len as usize
        }

        fn set_len(&mut self, len: usize) {
            self.len = len as u32
        }

        fn max_len() -> usize {
            MAX_LEN
        }

        fn entries(&self) -> &__IncompleteArrayField<u32> {
            &self.entries
        }

        fn entries_mut(&mut self) -> &mut __IncompleteArrayField<u32> {
            &mut self.entries
        }
    }

    type MockKvmVec = KvmVec<MockKvmArray>;

    const ENTRIES_OFFSET: usize = 2;

    const KVM_VEC_LEN_TO_MEM_ALLOCATOR_LEN: &'static [(usize, usize)] = &[
        (0, 1),
        (1, 2),
        (2, 2),
        (3, 3),
        (4, 3),
        (5, 4),
        (10, 6),
        (50, 26),
        (100, 51),
    ];

    const MEM_ALLOCATOR_LEN_TO_KVM_VEC_LEN: &'static [(usize, usize)] = &[
        (0, 0),
        (1, 0),
        (2, 2),
        (3, 4),
        (4, 6),
        (5, 8),
        (10, 18),
        (50, 98),
        (100, 198),
    ];

    #[test]
    fn test_kvm_vec_len_to_mem_allocator_len() {
        for pair in KVM_VEC_LEN_TO_MEM_ALLOCATOR_LEN {
            let kvm_vec_len = pair.0;
            let mem_allocator_len = pair.1;
            assert_eq!(
                mem_allocator_len,
                MockKvmVec::kvm_vec_len_to_mem_allocator_len(kvm_vec_len)
            );
        }
    }

    #[test]
    fn test_mem_allocator_len_to_kvm_vec_len() {
        for pair in MEM_ALLOCATOR_LEN_TO_KVM_VEC_LEN {
            let mem_allocator_len = pair.0;
            let kvm_vec_len = pair.1;
            assert_eq!(
                kvm_vec_len,
                MockKvmVec::mem_allocator_len_to_kvm_vec_len(mem_allocator_len)
            );
        }
    }

    #[test]
    fn test_new() {
        let num_entries = 10;

        let kvm_vec = MockKvmVec::new(num_entries);
        assert_eq!(num_entries, kvm_vec.capacity);

        let u32_slice = unsafe {
            std::slice::from_raw_parts(kvm_vec.as_ptr() as *const u32, num_entries + ENTRIES_OFFSET)
        };
        assert_eq!(num_entries, u32_slice[0] as usize);
        for entry in u32_slice[1..].iter() {
            assert_eq!(*entry, 0);
        }
    }

    #[test]
    fn test_from_entries() {
        let num_entries: usize = 10;

        let mut entries = Vec::new();
        for i in 0..num_entries {
            entries.push(i as u32);
        }

        let kvm_vec = MockKvmVec::from_entries(entries.as_slice());
        let u32_slice = unsafe {
            std::slice::from_raw_parts(kvm_vec.as_ptr() as *const u32, num_entries + ENTRIES_OFFSET)
        };
        assert_eq!(num_entries, u32_slice[0] as usize);
        for i in 0..num_entries {
            assert_eq!(kvm_vec.as_entries_slice()[i], entries[i]);
        }
    }

    #[test]
    fn test_entries_slice() {
        let num_entries = 10;
        let mut kvm_vec = MockKvmVec::new(num_entries);

        let expected_slice = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

        {
            let mut mut_entries_slice = kvm_vec.as_mut_entries_slice();
            mut_entries_slice.copy_from_slice(expected_slice);
        }

        let u32_slice = unsafe {
            std::slice::from_raw_parts(kvm_vec.as_ptr() as *const u32, num_entries + ENTRIES_OFFSET)
        };
        assert_eq!(expected_slice, &u32_slice[ENTRIES_OFFSET..]);
        assert_eq!(expected_slice, kvm_vec.as_entries_slice());
    }

    #[test]
    fn test_reserve() {
        let mut kvm_vec = MockKvmVec::new(0);

        // test that the right capacity is reserved
        for pair in KVM_VEC_LEN_TO_MEM_ALLOCATOR_LEN {
            let num_elements = pair.0;
            let required_mem_allocator_len = pair.1;

            let kvm_vec_capacity = kvm_vec.capacity;
            kvm_vec.reserve(num_elements);

            assert!(kvm_vec.mem_allocator.capacity() >= required_mem_allocator_len);
            assert_eq!(0, kvm_vec.len);
            assert!(kvm_vec.capacity >= num_elements);
        }

        // test that when the capacity is already reserved, the method doesn't do anything
        let current_capacity = kvm_vec.capacity;
        kvm_vec.reserve(current_capacity - 1);
        assert_eq!(current_capacity, kvm_vec.capacity);
    }

    #[test]
    fn test_push() {
        let mut kvm_vec = MockKvmVec::new(0);

        for i in 0..MAX_LEN {
            assert!(kvm_vec.push(i as u32).is_ok());
            assert_eq!(kvm_vec.as_entries_slice()[i], i as u32);
        }

        assert!(kvm_vec.push(0).is_err());
    }

    #[test]
    fn test_retain() {
        let mut kvm_vec = MockKvmVec::new(0);

        for i in 0..MAX_LEN {
            assert!(kvm_vec.push(i as u32).is_ok());
        }

        kvm_vec.retain(|entry| entry % 2 == 0);

        for entry in kvm_vec.as_entries_slice().iter() {
            assert_eq!(0, entry % 2);
        }
    }

    #[test]
    fn test_partial_eq() {
        let mut kvm_vec_1 = MockKvmVec::new(0);
        let mut kvm_vec_2 = MockKvmVec::new(0);
        let mut kvm_vec_3 = MockKvmVec::new(0);

        for i in 0..MAX_LEN {
            assert!(kvm_vec_1.push(i as u32).is_ok());
            assert!(kvm_vec_2.push(i as u32).is_ok());
            assert!(kvm_vec_3.push(0).is_ok());
        }

        assert!(kvm_vec_1 == kvm_vec_2);
        assert!(kvm_vec_1 != kvm_vec_3);
    }

    #[test]
    fn test_clone() {
        let mut kvm_vec = MockKvmVec::new(0);

        for i in 0..MAX_LEN {
            assert!(kvm_vec.push(i as u32).is_ok());
        }

        assert!(kvm_vec == kvm_vec.clone());
    }
}
