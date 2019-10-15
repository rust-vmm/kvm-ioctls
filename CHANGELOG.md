# Unreleased

## Added
- Support for setting vcpu `kvm_immediate_exit` flag
- Support for vcpu `KVM_GET_CPUID2`
- Support for vcpu `KVM_GET_MP_STATE`
- Support for vcpu `KVM_SET_MP_STATE`
- Support for vcpu `KVM_GET_VCPU_EVENTS`
- Support for vcpu `KVM_SET_VCPU_EVENTS`
- Support for vcpu `KVM_GET_DEBUGREGS`
- Support for vcpu `KVM_SET_DEBUGREGS`
- Support for vcpu `KVM_GET_XSAVE`
- Support for vcpu `KVM_SET_XSAVE`
- Support for vcpu `KVM_GET_XCRS`
- Support for vcpu `KVM_SET_XCRS`
- Support for vm `KVM_GET_IRQCHIP`
- Support for vm `KVM_SET_IRQCHIP`
- Support for vm `KVM_GET_CLOCK`
- Support for vm `KVM_SET_CLOCK`
- Support for vm `KVM_GET_PIT2`
- Support for vm `KVM_SET_PIT2`

## Changed
- Function offering support for `KVM_SET_MSRS` also returns the number
  of MSR entries successfully written.

# v0.2.0

## Added
- Add support for `KVM_ENABLE_CAP`.
- Add support for `KVM_SIGNAL_MSI`.

## Fixed
- Fix bug in KvmRunWrapper. The memory for kvm_run struct was not unmapped
  after the KvmRunWrapper object got out of scope.
- Return proper value when receiving the EOI KVM exit.
- Mark set_user_memory_region as unsafe.

# v0.1.0

First release of the kvm-ioctls crate.

The kvm-ioctls crate provides safe wrappers over the KVM API, a set of ioctls
used for creating and configuring Virtual Machines (VMs) on Linux.
The ioctls are accessible through four structures:
- Kvm - wrappers over system ioctls
- VmFd - wrappers over VM ioctls
- VcpuFd - wrappers over vCPU ioctls
- DeviceFd - wrappers over device ioctls

The kvm-ioctls can be used on x86_64 and aarch64. Right now the aarch64
support is considered experimental.
