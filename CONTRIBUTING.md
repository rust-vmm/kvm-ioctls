# Contributing to kvm-bindings

## Dependencies

### Bindgen
The bindings are currently generated using
[bindgen](https://crates.io/crates/bindgen) version 0.64.0:
```bash
cargo install bindgen-cli --vers 0.64.0
```

### Linux Kernel
Generating bindings depends on the Linux kernel, so you need to have the
repository on your machine:

```bash
git clone https://github.com/torvalds/linux.git
```

## Updating bindings / adding a new architecture

When adding a new architecture, the bindings must be generated for all existing
versions for consistency reasons.

### Example for arm64 and kernel version 6.9

For this example we assume that you have both linux and kvm-bindings
repositories in your root.

```bash
# Step 1 (if adding a new architecture): Create a new module using the name of the architecture in src/
pushd kvm-bindings
mkdir src/arm64
popd

# linux is the repository that you cloned at the previous step.
pushd linux
# Step 2: Checkout the version you want to generate the bindings for.
git checkout v6.9

# Step 3: Generate the bindings.
# This will generate the headers for the targeted architecture and place them
# in the user specified directory

export ARCH=arm64
make headers_install ARCH=$ARCH INSTALL_HDR_PATH="$ARCH"_headers
pushd "$ARCH"_headers
bindgen include/linux/kvm.h -o bindings.rs  \
     --impl-debug --with-derive-default  \
     --with-derive-partialeq  --impl-partialeq \
     -- -Iinclude
popd

# Step 4: Copy the generated file to the arm64 module.
popd
cp linux/"$ARCH"_headers/bindings.rs kvm-bindings/src/arm64

```

Steps 2, 3 and 4 must be repeated for all existing architectures.

Now that we have the bindings generated, for a new architecture we can copy the
module file from one of the existing modules.

```bash
cp arm/mod.rs arm64/
```

Also, you will need to add the new architecture to `kvm-bindings/lib.rs`.

When regenerating bindings, care must be taken to re-add various `zerocopy`
derives under the `serde` feature. All items that require derives are
listed in the `x86_64/serialize.rs` and `arm64/serialize.rs` inside the
`serde_impls!` macro invocation, and missing derives will cause these
modules to fail compilation. For all items listed here, the following
derive should be present:

```rs
#[cfg_attr(
    feature = "serde",
    derive(zerocopy::AsBytes, zerocopy::FromBytes, zerocopy::FromZeroes)
)]
```

Any types whose name contains a suffix akin to `__bindgen_ty_<number>` and
which is contained in any struct listed in `serialize.rs` will also need
to have this derive added (otherwise compilation will fail). Note that
these types are not explicitly listed in `serialize.rs`, as their names
can change across `bindgen.rs` versions.

Lastly, in `x86_64/bindings.rs`, the derives also need to be added to
`struct __BindgenBitfieldUnit<Storage>` and `struct __IncompleteArrayField<T>`.
Additionally, these structs need to have their layout changed from `#[repr(C)]`
to `#[repr(transparent)]`. This is needed because `zerocopy` traits can only be
derived on generic structures that are `repr(transparent)` or `repr(packed)`.

### Future Improvements
All the above steps are scriptable, so in the next iteration I will add a
script to generate the bindings.

# Testing

This crate is tested using
[rust-vmm-ci](https://github.com/rust-vmm/rust-vmm-ci) and
[Buildkite](https://buildkite.com/) pipelines. Each new feature added to this crate must be
accompanied by Buildkite steps for testing the following:
- Release builds (using musl/gnu) with the new feature on arm and x86
- Coverage test as specified in the
[rust-vmm-ci readme](https://github.com/rust-vmm/rust-vmm-ci#getting-started-with-rust-vmm-ci).
