use kvm_bindings::*;

use libc::{open, O_CLOEXEC, O_RDWR};
use std::fs::File;
use std::io;
use std::os::raw::{c_char, c_ulong};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};

use cap::Cap;
use ioctls::vec_with_array_field;
use ioctls::vm::{new_vmfd, VmFd};
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use ioctls::CpuId;
use ioctls::Result;
use kvm_ioctls::*;
use sys_ioctl::*;

/// A wrapper over the `/dev/kvm` file.
///
/// The handle is used to issue KVM system ioctls.
pub struct Kvm {
    kvm: File,
}

impl Kvm {
    /// Opens `/dev/kvm/` and returns a `Kvm` object on success.
    ///
    #[allow(clippy::new_ret_no_self)]
    pub fn new() -> Result<Self> {
        // Open `/dev/kvm` using `O_CLOEXEC` flag.
        let fd = Self::open_with_cloexec(true)?;
        // Safe because we verify that ret is valid and we own the fd.
        Ok(unsafe { Self::new_with_fd_number(fd) })
    }

    /// Creates a new Kvm object assuming `fd` represents an existing open file descriptor
    /// associated with `/dev/kvm`.
    ///
    /// # Arguments
    ///
    /// * `fd` - File descriptor for `/dev/kvm`.
    ///
    pub unsafe fn new_with_fd_number(fd: RawFd) -> Self {
        Kvm {
            kvm: File::from_raw_fd(fd),
        }
    }

    /// Opens `/dev/kvm` and returns the fd number on success.
    ///
    /// # Arguments
    ///
    /// * `close_on_exec`: If true opens `/dev/kvm` using the `O_CLOEXEC` flag.
    ///
    pub fn open_with_cloexec(close_on_exec: bool) -> Result<RawFd> {
        let open_flags = O_RDWR | if close_on_exec { O_CLOEXEC } else { 0 };
        // Safe because we give a constant nul-terminated string and verify the result.
        let ret = unsafe { open("/dev/kvm\0".as_ptr() as *const c_char, open_flags) };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(ret)
        }
    }

    /// Returns the KVM API version.
    ///
    /// See the documentation for `KVM_GET_API_VERSION`.
    pub fn get_api_version(&self) -> i32 {
        // Safe because we know that our file is a KVM fd and that the request is one of the ones
        // defined by kernel.
        unsafe { ioctl(self, KVM_GET_API_VERSION()) }
    }

    /// Wrapper over `KVM_CHECK_EXTENSION`.
    /// Returns 0 if the capability is not available and a positive integer otherwise.
    ///
    fn check_extension_int(&self, c: Cap) -> i32 {
        // Safe because we know that our file is a KVM fd and that the extension is one of the ones
        // defined by kernel.
        unsafe { ioctl_with_val(self, KVM_CHECK_EXTENSION(), c as c_ulong) }
    }

    /// Checks if a particular `Cap` is available.
    ///
    /// See the documentation for `KVM_CHECK_EXTENSION`.
    /// Returns "0 if the capability is unsupported or a positive integer otherwise.
    ///
    /// # Arguments
    ///
    /// * `c` - KVM capability.
    ///
    pub fn check_extension(&self, c: Cap) -> bool {
        self.check_extension_int(c) > 0
    }

    ///  Returns the size of the memory mapping required to use the vcpu's `kvm_run` structure.
    ///
    /// See the documentation for `KVM_GET_VCPU_MMAP_SIZE`.
    ///
    pub fn get_vcpu_mmap_size(&self) -> Result<usize> {
        // Safe because we know that our file is a KVM fd and we verify the return result.
        let res = unsafe { ioctl(self, KVM_GET_VCPU_MMAP_SIZE()) };
        if res > 0 {
            Ok(res as usize)
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// Gets the recommended number of VCPUs per VM.
    ///
    /// See the documentation for `KVM_CAP_NR_VCPUS`.
    /// Default to 4 when `KVM_CAP_NR_VCPUS` is not implemented.
    pub fn get_nr_vcpus(&self) -> usize {
        let x = self.check_extension_int(Cap::NrVcpus);
        if x > 0 {
            x as usize
        } else {
            4
        }
    }

    /// Gets the maximum allowed memory slots per VM.
    ///
    /// KVM reports the number of available memory slots (`KVM_CAP_NR_MEMSLOTS`)
    /// using the extension interface.  Both x86 and s390 implement this, ARM
    /// and powerpc do not yet enable it.
    /// Default to 32 when `KVM_CAP_NR_MEMSLOTS` is not implemented.
    ///
    pub fn get_nr_memslots(&self) -> usize {
        let x = self.check_extension_int(Cap::NrMemslots);
        if x > 0 {
            x as usize
        } else {
            32
        }
    }

    /// Gets the recommended maximum number of VCPUs per VM.
    ///
    /// See the documentation for `KVM_CAP_MAX_VCPUS`.
    /// Default to `KVM_CAP_NR_VCPUS` when `KVM_CAP_MAX_VCPUS` is not implemented.
    ///
    pub fn get_max_vcpus(&self) -> usize {
        match self.check_extension_int(Cap::MaxVcpus) {
            0 => self.get_nr_vcpus(),
            x => x as usize,
        }
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn get_cpuid(&self, kind: u64, max_entries_count: usize) -> Result<CpuId> {
        let mut cpuid = CpuId::new(max_entries_count);

        let ret = unsafe {
            // ioctl is unsafe. The kernel is trusted not to write beyond the bounds of the memory
            // allocated for the struct. The limit is read from nent, which is set to the allocated
            // size(max_entries_count) above.
            ioctl_with_mut_ptr(self, kind, cpuid.as_mut_ptr())
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(cpuid)
    }

    /// X86 specific call to get the system emulated CPUID values.
    ///
    /// See the documentation for KVM_GET_EMULATED_CPUID.
    ///
    /// # Arguments
    ///
    /// * `max_entries_count` - Maximum number of CPUID entries. This function can return less than
    ///                         this when the hardware does not support so many CPUID entries.
    ///
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn get_emulated_cpuid(&self, max_entries_count: usize) -> Result<CpuId> {
        self.get_cpuid(KVM_GET_EMULATED_CPUID(), max_entries_count)
    }

    /// X86 specific call to get the system supported CPUID values.
    ///
    /// See the documentation for KVM_GET_SUPPORTED_CPUID.
    ///
    /// # Arguments
    ///
    /// * `max_entries_count` - Maximum number of CPUID entries. This function can return less than
    ///                         this when the hardware does not support so many CPUID entries.
    ///
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn get_supported_cpuid(&self, max_entries_count: usize) -> Result<CpuId> {
        self.get_cpuid(KVM_GET_SUPPORTED_CPUID(), max_entries_count)
    }

    /// X86 specific call to get list of supported MSRS
    ///
    /// See the documentation for KVM_GET_MSR_INDEX_LIST.
    ///
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn get_msr_index_list(&self) -> Result<Vec<u32>> {
        const MAX_KVM_MSR_ENTRIES: usize = 256;

        let mut msr_list = vec_with_array_field::<kvm_msr_list, u32>(MAX_KVM_MSR_ENTRIES);
        msr_list[0].nmsrs = MAX_KVM_MSR_ENTRIES as u32;

        let ret = unsafe {
            // ioctl is unsafe. The kernel is trusted not to write beyond the bounds of the memory
            // allocated for the struct. The limit is read from nmsrs, which is set to the allocated
            // size (MAX_KVM_MSR_ENTRIES) above.
            ioctl_with_mut_ref(self, KVM_GET_MSR_INDEX_LIST(), &mut msr_list[0])
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut nmsrs = msr_list[0].nmsrs;

        // Mapping the unsized array to a slice is unsafe because the length isn't known.  Using
        // the length we originally allocated with eliminates the possibility of overflow.
        let indices: &[u32] = unsafe {
            if nmsrs > MAX_KVM_MSR_ENTRIES as u32 {
                nmsrs = MAX_KVM_MSR_ENTRIES as u32;
            }
            msr_list[0].indices.as_slice(nmsrs as usize)
        };

        Ok(indices.to_vec())
    }

    /// Creates a VM fd using the KVM fd.
    ///
    /// See the documentation for `KVM_CREATE_VM`.
    /// A call to this function will also initialize the size of the vcpu mmap area using the
    /// `KVM_GET_VCPU_MMAP_SIZE` ioctl.
    ///
    pub fn create_vm(&self) -> Result<VmFd> {
        // Safe because we know `self.kvm` is a real KVM fd as this module is the only one that
        // create Kvm objects.
        let ret = unsafe { ioctl(&self.kvm, KVM_CREATE_VM()) };
        if ret >= 0 {
            // Safe because we verify the value of ret and we are the owners of the fd.
            let vm_file = unsafe { File::from_raw_fd(ret) };
            let run_mmap_size = self.get_vcpu_mmap_size()?;
            Ok(new_vmfd(vm_file, run_mmap_size))
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

impl AsRawFd for Kvm {
    fn as_raw_fd(&self) -> RawFd {
        self.kvm.as_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use MAX_KVM_CPUID_ENTRIES;

    #[test]
    fn test_kvm_new() {
        Kvm::new().unwrap();
    }

    #[test]
    fn test_kvm_api_version() {
        let kvm = Kvm::new().unwrap();
        assert_eq!(kvm.get_api_version(), 12);
        assert!(kvm.check_extension(Cap::UserMemory));
    }

    #[test]
    fn test_kvm_getters() {
        let kvm = Kvm::new().unwrap();

        // vCPU related getters
        let nr_vcpus = kvm.get_nr_vcpus();
        assert!(nr_vcpus >= 4);

        assert!(kvm.get_max_vcpus() >= nr_vcpus);

        // Memory related getters
        assert!(kvm.get_vcpu_mmap_size().unwrap() > 0);
        assert!(kvm.get_nr_memslots() >= 32);
    }

    #[test]
    fn test_create_vm() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();

        assert_eq!(vm.get_run_size(), kvm.get_vcpu_mmap_size().unwrap());
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[test]
    fn test_get_supported_cpuid() {
        let kvm = Kvm::new().unwrap();
        let mut cpuid = kvm.get_supported_cpuid(MAX_KVM_CPUID_ENTRIES).unwrap();
        let cpuid_entries = cpuid.mut_entries_slice();
        assert!(cpuid_entries.len() > 0);
        assert!(cpuid_entries.len() <= MAX_KVM_CPUID_ENTRIES);
    }

    #[test]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn test_get_emulated_cpuid() {
        let kvm = Kvm::new().unwrap();
        let mut cpuid = kvm.get_emulated_cpuid(MAX_KVM_CPUID_ENTRIES).unwrap();
        let cpuid_entries = cpuid.mut_entries_slice();
        assert!(cpuid_entries.len() > 0);
        assert!(cpuid_entries.len() <= MAX_KVM_CPUID_ENTRIES);
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[test]
    fn test_cpuid_clone() {
        let kvm = Kvm::new().unwrap();
        let cpuid_1 = kvm.get_supported_cpuid(MAX_KVM_CPUID_ENTRIES).unwrap();
        let mut cpuid_2 = cpuid_1.clone();
        assert!(cpuid_1 == cpuid_2);
        cpuid_2 = unsafe { std::mem::zeroed() };
        assert!(cpuid_1 != cpuid_2);
    }

    #[test]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn get_msr_index_list() {
        let kvm = Kvm::new().unwrap();
        let msr_list = kvm.get_msr_index_list().unwrap();
        assert!(msr_list.len() >= 2);
    }

    fn get_raw_errno<T>(result: super::Result<T>) -> i32 {
        result.err().unwrap().raw_os_error().unwrap()
    }

    #[test]
    fn test_bad_kvm_fd() {
        let badf_errno = libc::EBADF;

        let faulty_kvm = Kvm {
            kvm: unsafe { File::from_raw_fd(-1) },
        };

        assert_eq!(get_raw_errno(faulty_kvm.get_vcpu_mmap_size()), badf_errno);
        assert_eq!(faulty_kvm.get_nr_vcpus(), 4);
        assert_eq!(faulty_kvm.get_nr_memslots(), 32);
        assert_eq!(get_raw_errno(faulty_kvm.get_emulated_cpuid(4)), badf_errno);
        assert_eq!(get_raw_errno(faulty_kvm.get_supported_cpuid(4)), badf_errno);
        assert_eq!(get_raw_errno(faulty_kvm.get_msr_index_list()), badf_errno);
        assert_eq!(get_raw_errno(faulty_kvm.create_vm()), badf_errno);
    }
}
