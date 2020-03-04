// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::fs::File;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};

use ioctls::Result;
use kvm_bindings::kvm_device_attr;
use kvm_ioctls::{KVM_HAS_DEVICE_ATTR, KVM_SET_DEVICE_ATTR};
use vmm_sys_util::errno;
use vmm_sys_util::ioctl::ioctl_with_ref;

/// Wrapper over the file descriptor obtained when creating an emulated device in the kernel.
pub struct DeviceFd {
    fd: File,
}

impl DeviceFd {
    /// Tests whether a device supports a particular attribute.
    ///
    /// See the documentation for `KVM_HAS_DEVICE_ATTR`.
    /// # Arguments
    ///
    /// * `device_attr` - The device attribute to be tested. `addr` field is ignored.
    ///
    pub fn has_device_attr(&self, device_attr: &kvm_device_attr) -> Result<()> {
        let ret = unsafe { ioctl_with_ref(self, KVM_HAS_DEVICE_ATTR(), device_attr) };
        if ret != 0 {
            return Err(errno::Error::last());
        }
        Ok(())
    }

    /// Sets a specified piece of device configuration and/or state.
    ///
    /// See the documentation for `KVM_SET_DEVICE_ATTR`.
    /// # Arguments
    ///
    /// * `device_attr` - The device attribute to be set.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # extern crate kvm_bindings;
    /// # use kvm_ioctls::Kvm;
    /// # use kvm_bindings::{
    ///    kvm_device_type_KVM_DEV_TYPE_VFIO,
    ///    KVM_DEV_VFIO_GROUP, KVM_DEV_VFIO_GROUP_ADD, KVM_CREATE_DEVICE_TEST
    /// };
    /// let kvm = Kvm::new().unwrap();
    /// let vm = kvm.create_vm().unwrap();
    ///
    /// let mut device = kvm_bindings::kvm_create_device {
    ///     type_: kvm_device_type_KVM_DEV_TYPE_VFIO,
    ///     fd: 0,
    ///     flags: KVM_CREATE_DEVICE_TEST,
    /// };
    ///
    /// let device_fd = vm
    ///     .create_device(&mut device)
    ///     .expect("Cannot create KVM device");
    ///
    /// let dist_attr = kvm_bindings::kvm_device_attr {
    ///     group: KVM_DEV_VFIO_GROUP,
    ///     attr: u64::from(KVM_DEV_VFIO_GROUP_ADD),
    ///     addr: 0x0,
    ///     flags: 0,
    /// };
    ///
    /// if (device_fd.has_device_attr(&dist_attr).is_ok()) {
    ///     device_fd.set_device_attr(&dist_attr).unwrap();
    /// }
    /// ```
    ///
    pub fn set_device_attr(&self, device_attr: &kvm_device_attr) -> Result<()> {
        let ret = unsafe { ioctl_with_ref(self, KVM_SET_DEVICE_ATTR(), device_attr) };
        if ret != 0 {
            return Err(errno::Error::last());
        }
        Ok(())
    }
}

/// Helper function for creating a new device.
pub fn new_device(dev_fd: File) -> DeviceFd {
    DeviceFd { fd: dev_fd }
}

impl AsRawFd for DeviceFd {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl FromRawFd for DeviceFd {
    /// This function is also unsafe as the primitives currently returned have the contract that
    /// they are the sole owner of the file descriptor they are wrapping. Usage of this function
    /// could accidentally allow violating this contract which can cause memory unsafety in code
    /// that relies on it being true.
    unsafe fn from_raw_fd(fd: RawFd) -> Self {
        DeviceFd {
            fd: File::from_raw_fd(fd),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ioctls::system::Kvm;
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    use kvm_bindings::{
        kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V3, kvm_device_type_KVM_DEV_TYPE_VFIO,
        KVM_DEV_VFIO_GROUP, KVM_DEV_VFIO_GROUP_ADD,
    };
    #[cfg(target_arch = "aarch64")]
    use kvm_bindings::{
        KVM_DEV_ARM_VGIC_CTRL_INIT, KVM_DEV_ARM_VGIC_GRP_CTRL, KVM_DEV_VFIO_GROUP,
        KVM_DEV_VFIO_GROUP_ADD,
    };

    use kvm_bindings::KVM_CREATE_DEVICE_TEST;

    #[test]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn test_create_device() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();

        let mut gic_device = kvm_bindings::kvm_create_device {
            type_: kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V3,
            fd: 0,
            flags: KVM_CREATE_DEVICE_TEST,
        };
        // This fails on x86_64 because there is no VGIC there.
        assert!(vm.create_device(&mut gic_device).is_err());

        gic_device.type_ = kvm_device_type_KVM_DEV_TYPE_VFIO;

        let device_fd = vm
            .create_device(&mut gic_device)
            .expect("Cannot create KVM device");

        // Following lines to re-construct device_fd are used to test
        // DeviceFd::from_raw_fd() and DeviceFd::as_raw_fd().
        let raw_fd = unsafe { libc::dup(device_fd.as_raw_fd()) };
        assert!(raw_fd >= 0);
        let device_fd = unsafe { DeviceFd::from_raw_fd(raw_fd) };

        let dist_attr = kvm_bindings::kvm_device_attr {
            group: KVM_DEV_VFIO_GROUP,
            attr: u64::from(KVM_DEV_VFIO_GROUP_ADD),
            addr: 0x0,
            flags: 0,
        };

        // We are just creating a test device. Creating a real device would make the CI dependent
        // on host configuration (like having /dev/vfio). We expect this to fail.
        assert!(device_fd.has_device_attr(&dist_attr).is_err());
        assert!(device_fd.set_device_attr(&dist_attr).is_err());
        assert_eq!(errno::Error::last().errno(), 25);
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn test_create_device() {
        use ioctls::vm::create_gic_device;
        use kvm_bindings::kvm_device_type_KVM_DEV_TYPE_FSL_MPIC_20;

        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();

        let mut gic_device = kvm_bindings::kvm_create_device {
            type_: kvm_device_type_KVM_DEV_TYPE_FSL_MPIC_20,
            fd: 0,
            flags: KVM_CREATE_DEVICE_TEST,
        };
        // This fails on aarch64 as it does not use MPIC (MultiProcessor Interrupt Controller),
        // it uses the VGIC.
        assert!(vm.create_device(&mut gic_device).is_err());

        let device_fd = create_gic_device(&vm, 0);

        // Following lines to re-construct device_fd are used to test
        // DeviceFd::from_raw_fd() and DeviceFd::as_raw_fd().
        let raw_fd = unsafe { libc::dup(device_fd.as_raw_fd()) };
        assert!(raw_fd >= 0);
        let device_fd = unsafe { DeviceFd::from_raw_fd(raw_fd) };

        // Set some attribute that does not apply to VGIC, expect the test to fail.
        let dist_attr = kvm_bindings::kvm_device_attr {
            group: KVM_DEV_VFIO_GROUP,
            attr: u64::from(KVM_DEV_VFIO_GROUP_ADD),
            addr: 0x0,
            flags: 0,
        };
        assert!(device_fd.has_device_attr(&dist_attr).is_err());

        // Following attribute works with VGIC, they should be accepted.
        let dist_attr = kvm_bindings::kvm_device_attr {
            group: KVM_DEV_ARM_VGIC_GRP_CTRL,
            attr: u64::from(KVM_DEV_ARM_VGIC_CTRL_INIT),
            addr: 0x0,
            flags: 0,
        };

        assert!(device_fd.has_device_attr(&dist_attr).is_ok());
        assert!(device_fd.set_device_attr(&dist_attr).is_ok());
    }
}
