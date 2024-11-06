[![Build Status](https://badge.buildkite.com/9e0e6c88972a3248a0908506d6946624da84e4e18c0870c4d0.svg)](https://buildkite.com/rust-vmm/kvm-ioctls-ci)

# kvm

The `kvm` workspace hosts libraries related to Rust bindings to the Kernel Virtual Machine (KVM). It currently consists of the following crates:

- `kvm-bindings` -> Rust FFI bindings to KVM
- `kvm-ioctls` -> Safe wrappers over the KVM API

## Running the tests

Our Continuous Integration (CI) pipeline is implemented on top of
[Buildkite](https://buildkite.com/).
For the complete list of tests, check our
[CI pipeline](https://buildkite.com/rust-vmm/kvm-ci).

Each individual test runs in a container. To reproduce a test locally, you can
use the dev-container on x86_64, arm64 and riscv64.

```bash
# For running riscv64 tests, replace v47 with v47-riscv. This provides an
# emulated riscv64 environment on a x86_64 host.
docker run --device=/dev/kvm \
           -it \
           --security-opt seccomp=unconfined \
           --volume $(pwd)/kvm:/kvm \
           rustvmm/dev:v47
cd kvm-ioctls/
cargo test
```

For more details about the integration tests that are run for `kvm`,
check the [rust-vmm-ci](https://github.com/rust-vmm/rust-vmm-ci) readme. 
