[![crates.io](https://img.shields.io/crates/v/kvm-ioctls.svg)](https://crates.io/crates/kvm-ioctls)

# kvm-ioctls

The kvm-ioctls crate provides safe wrappers over the
[KVM API](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt), a set
of ioctls used for creating and configuring Virtual Machines (VMs) on Linux.
The ioctls are accessible through four structures:
- `Kvm` - wrappers over system ioctls
- `VmFd` - wrappers over VM ioctls
- `VcpuFd` - wrappers over vCPU ioctls
- `DeviceFd` - wrappers over device ioctls

For further details check the
[KVM API](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt) as well
as the code documentation.

## Supported Platforms

The kvm-ioctls can be used on x86_64, aarch64 and riscv64 (experimental).


