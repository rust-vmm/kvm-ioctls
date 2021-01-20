#![cfg(feature = "amd-sev")]

use kvm_bindings::*;
use std::fs::{File, OpenOptions};
use std::mem::size_of_val;
use std::os::unix::io::{AsRawFd, RawFd};

use ioctls::{vm::VmFd, Result};
use kvm_ioctls::*;
use sev::launch::*;
use vmm_sys_util::errno;
use vmm_sys_util::ioctl::ioctl_with_mut_ref;

#[repr(u32)]
#[allow(dead_code)]
#[derive(Copy, Clone, Debug)]
pub enum SevCmd {
    Init = 0,
    EsInit,

    LaunchStart,
    LaunchUpdateData,
    LaunchUpdateVmsa,
    LaunchSecret,
    LaunchMeasure,
    LaunchFinish,

    SendStart,
    SendUpdateData,
    SendUpdateVmsa,
    SendFinish,

    ReceiveStart,
    ReceiveUpdateData,
    ReceiveUpdateVmsa,
    ReceiveFinish,

    GuestStatus,
    DebugDecrypt,
    DebugEncrypt,
    CertExport,
}

#[derive(Copy, Clone)]
pub struct Handle(u32);
/// Learn from ``SevState`` introduced in QEMU, adding few changes.
/// An enumeration of SEV state information used during @query-sev.
///
/// @Uninit: The guest is uninitialized.
///
/// @Init: The guest is initialized.
///
/// @LaunchUpdate: The guest is currently being launched; plaintext data and
///                register state is being imported.
///
/// @LaunchSecret: The guest is currently being launched; ciphertext data
///                is being imported.
///
/// @Running: The guest is fully launched or migrated in.
///
/// @SendUpdate: The guest is currently being migrated out to another machine.
///
/// @ReceiveUpdate: The guest is currently being migrated from another machine.
#[derive(PartialEq, Debug)]
pub struct Uninit;
#[derive(PartialEq, Debug)]
pub struct Init;
pub struct LaunchUpdate(Handle);
pub struct LaunchSecret(Handle, Measurement);
pub struct Running(Handle, Measurement);
#[allow(dead_code)]
pub struct SendUpdate(Handle, Measurement);
#[allow(dead_code)]
pub struct ReceiveUpdate(Handle, Measurement);

/// Wrapper over `/dev/sev` Fd
pub struct SevFd {
    sev: File,
}

impl AsRawFd for SevFd {
    fn as_raw_fd(&self) -> RawFd {
        self.sev.as_raw_fd()
    }
}

/// Helper function to create a new `SevFd`.
///
/// This should not be exported as a public function because the preferred way is to use
/// `new_with_vm` from `SevLaunch`.
fn new_sevfd(sev: File) -> SevFd {
    SevFd { sev }
}

/// KVM SEV launch contex, using a `state machine` pattern.
pub struct SevLaunch<S> {
    pub sev: SevFd,
    pub vm: VmFd,
    pub state: S,
}

impl<T> SevLaunch<T> {
    /// Wrapper over `KVM_MEMORY_ENCRYPT_OP`.
    ///
    /// See documentation for `KVM_MEMORY_ENCRYPT_OP`.
    ///
    /// # Arguments
    /// * `cmd` - command argument to `KVM_MEM_ENCRYPT_OP` (in). For details check the `kvm_sev_cmd`
    ///           structure in the
    ///           [KVM SEV API doc](https://www.kernel.org/doc/html/latest/virt/kvm/amd-memory-encryption.html).
    /// * `data` - struct containing arguments specific to command (out).
    ///
    /// Returns data or an error otherwise.
    fn sev_ioctl<U>(&self, cmd: SevCmd, mut data: U) -> Result<U> {
        let mut input = kvm_sev_cmd {
            id: cmd as u32,
            data: &mut data as *mut _ as u64,
            error: 0,
            sev_fd: self.sev.as_raw_fd() as u32,
        };

        // The ioctl is safe because we allocated the struct and we know the
        // kernel will write exactly the size of the struct.
        let ret = unsafe { ioctl_with_mut_ref(&self.vm, KVM_MEMORY_ENCRYPT_OP(), &mut input) };
        if ret == 0 {
            Ok(data)
        } else {
            Err(errno::Error::last())
        }
    }
}

impl SevLaunch<Uninit> {
    /// Instantiate a new SEV launch context with VmFd.
    pub fn new_with_vm(vm: VmFd) -> Result<Self> {
        let sev = OpenOptions::new().read(true).write(true).open("/dev/sev")?;

        // Safe because we are the owners of the fd.
        Ok(SevLaunch {
            sev: new_sevfd(sev),
            vm: vm,
            state: Uninit,
        })
    }

    /// Initialize the SEV platform context.
    /// In a typical workflow, this command should be the first command issued.
    pub fn init(self) -> Result<SevLaunch<Init>> {
        self.sev_ioctl(SevCmd::Init, ())?;

        Ok(SevLaunch {
            sev: self.sev,
            vm: self.vm,
            state: Init,
        })
    }
}

impl From<SevLaunch<Uninit>> for SevLaunch<Init> {
    fn from(launch: SevLaunch<Uninit>) -> SevLaunch<Init> {
        launch
            .init()
            .expect("Launch state transition failed from Uninit to Init")
    }
}

impl SevLaunch<Init> {
    /// Create the memory encryption context according to user-provided `Start` information,
    /// incl. a guest policy the owner's public Diffie-Hellman (PDH) key and session information.
    pub fn start(self, start: Start) -> Result<SevLaunch<LaunchUpdate>> {
        let start = kvm_sev_launch_start {
            handle: 0,
            policy: start.policy.into(),
            dh_uaddr: &start.cert as *const _ as u64,
            dh_len: size_of_val(&start.cert) as u32,
            session_uaddr: &start.session as *const _ as u64,
            session_len: size_of_val(&start.session) as u32,
        };

        let res = self.sev_ioctl(SevCmd::LaunchStart, start)?;

        Ok(SevLaunch {
            sev: self.sev,
            vm: self.vm,
            state: LaunchUpdate(Handle(res.handle)),
        })
    }
}

impl SevLaunch<LaunchUpdate> {
    /// Encrypts a memory region specified by user in place.
    /// It also calculates a measurement of the memory contents which is a signature
    /// of the memory contents that can be sent to the guest owner as an attestation
    /// that the memory was encrypted correctly by the firmware.
    pub fn update_data(&self, data: &[u8]) -> Result<()> {
        let update = kvm_sev_launch_update_data {
            uaddr: data.as_ptr() as u64,
            len: data.len() as u32,
        };

        self.sev_ioctl(SevCmd::LaunchUpdateData, update)?;

        Ok(())
    }

    /// Retrieve the measurement of the data encrypted.
    /// The guest owner may wait to provide the guest with confidential information until
    /// it can verify the measurement thru comparison.
    pub fn measure(self) -> Result<SevLaunch<LaunchSecret>> {
        let mut mr = Measurement::default();
        let measurement = kvm_sev_launch_measure {
            uaddr: &mut mr as *mut _ as u64,
            len: size_of_val(&mr) as u32,
        };

        self.sev_ioctl(SevCmd::LaunchMeasure, measurement)?;

        Ok(SevLaunch {
            sev: self.sev,
            vm: self.vm,
            state: LaunchSecret(self.state.0, mr),
        })
    }
}

impl From<SevLaunch<LaunchUpdate>> for SevLaunch<LaunchSecret> {
    fn from(launch: SevLaunch<LaunchUpdate>) -> SevLaunch<LaunchSecret> {
        launch
            .measure()
            .expect("Launch state transition failed from LaunchUpdate to LaunchSecret")
    }
}

impl SevLaunch<LaunchSecret> {
    /// Get the measurement kept by the SEV launch context (in a `LaunchSecret` state)
    pub fn get_measure(&self) -> Measurement {
        self.state.1
    }

    /// Inject secret data after the measurement has been validated by the guest owner.
    pub fn secret(&self, mut secret: Secret, gaddr: u64, size: u32) -> Result<()> {
        let secret = kvm_sev_launch_secret {
            hdr_uaddr: &mut secret.header as *mut _ as u64,
            hdr_len: size_of_val(&secret.header) as u32,
            guest_uaddr: gaddr,
            guest_len: size,
            trans_uaddr: secret.ciphertext.as_mut_ptr() as u64,
            trans_len: secret.ciphertext.len() as u32,
        };

        self.sev_ioctl(SevCmd::LaunchSecret, secret)?;
        Ok(())
    }

    /// Issued to make the guest ready for the execution, should be after completion
    /// of the launch flow.
    pub fn finish(self) -> Result<SevLaunch<Running>> {
        self.sev_ioctl(SevCmd::LaunchFinish, ())?;

        Ok(SevLaunch {
            sev: self.sev,
            vm: self.vm,
            state: Running(self.state.0, self.state.1),
        })
    }
}

impl From<SevLaunch<LaunchSecret>> for SevLaunch<Running> {
    fn from(launch: SevLaunch<LaunchSecret>) -> SevLaunch<Running> {
        launch
            .finish()
            .expect("Launch state transition failed from LaunchSecret to Running")
    }
}

#[cfg(test)]
mod tests {
    extern crate codicon;
    extern crate lazy_static;
    extern crate raw_cpuid;
    extern crate regex;

    use super::*;
    use ioctls::{system::Kvm, vcpu::VcpuExit};

    use self::codicon::*;
    use self::lazy_static::lazy_static;
    use self::regex::Regex;
    use sev::session::{Initialized, Session};
    use sev::Build;
    use std::convert::TryFrom;
    use std::io::Write;

    #[derive(Debug)]
    enum AmdCodeName {
        NAPLES = 1,
        ROME = 2,
    }

    impl AmdCodeName {
        #[allow(dead_code)]
        fn from_char(c: char) -> Option<AmdCodeName> {
            match c {
                '1' => Some(AmdCodeName::NAPLES),
                '2' => Some(AmdCodeName::ROME),
                _ => None,
            }
        }
    }

    #[allow(dead_code)]
    fn extract_cpu_series(input: &str) -> Option<&str> {
        lazy_static! {
            // We support ASK/ARK certificates for EPYC 7xx1 (Naples) and
            // ASK/ARK certificates for EPYC 7xx2 (Rome) currently
            static ref RE: Regex = Regex::new(r"[7][0-9]{2}[1-2]").unwrap();
        }
        RE.captures(input)
            .and_then(|cap| cap.get(0).map(|series| series.as_str()))
    }

    #[allow(dead_code)]
    fn get_cpu_code_name() -> Option<AmdCodeName> {
        let cpuid = raw_cpuid::CpuId::new();
        match cpuid
            .get_extended_function_info()
            .as_ref()
            .map_or_else(
                || "n/a",
                |extfuninfo| {
                    extract_cpu_series(extfuninfo.processor_brand_string().unwrap_or("unreadable"))
                        .unwrap()
                },
            )
            .chars()
            .last()
        {
            Some(c) => AmdCodeName::from_char(c),
            None => None,
        }
    }

    // Helper function for memory mapping `size` bytes of anonymous memory.
    // Panics if the mmap fails.
    fn mmap_anonymous(size: usize) -> *mut u8 {
        use std::ptr::null_mut;

        let addr = unsafe {
            libc::mmap(
                null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANONYMOUS | libc::MAP_SHARED | libc::MAP_NORESERVE,
                -1,
                0,
            )
        };
        if addr == libc::MAP_FAILED {
            panic!("mmap failed.");
        }

        addr as *mut u8
    }

    // construct SEV certificate chain from local
    fn build_local_chain(
        fw: &sev::firmware::Firmware,
        cek_path: &str,
        ask_ark_path: &str,
    ) -> sev::certs::Chain {
        let mut cek = File::open(cek_path).unwrap();
        let mut chain = fw
            .pdh_cert_export()
            .expect("unable to export SEV certificates");
        chain.cek = sev::certs::sev::Certificate::decode(&mut cek, ()).expect("Invalid CEK!");

        let mut rome = File::open(ask_ark_path).unwrap();
        sev::certs::Chain {
            ca: sev::certs::ca::Chain::decode(&mut rome, ()).expect("Invalid CA chain!"),
            sev: chain,
        }
    }

    // construct SEV certificate chain from remote
    fn fetch_chain(fw: &sev::firmware::Firmware, codename: AmdCodeName) -> sev::certs::Chain {
        const CEK_SVC: &str = "https://kdsintf.amd.com/cek/id";
        let link = match codename {
            AmdCodeName::NAPLES => {
                "https://developer.amd.com/wp-content/resources/ask_ark_naples.cert"
            }
            AmdCodeName::ROME => "https://developer.amd.com/wp-content/resources/ask_ark_rome.cert",
        };

        let mut chain = fw
            .pdh_cert_export()
            .expect("unable to export SEV certificates");

        let id = fw.get_identifer().expect("error fetching identifier");
        let url = format!("{}/{}", CEK_SVC, id);

        let mut rsp = reqwest::get(&url).expect(&format!("unable to contact server"));
        assert!(rsp.status().is_success());

        chain.cek = sev::certs::sev::Certificate::decode(&mut rsp, ()).expect("Invalid CEK!");

        let mut rsp = reqwest::get(link).expect(&format!("unable to contact server"));
        assert!(rsp.status().is_success());

        sev::certs::Chain {
            ca: sev::certs::ca::Chain::decode(&mut rsp, ()).expect("Invalid CA chain!"),
            sev: chain,
        }
    }

    fn build_chain(fw: &sev::firmware::Firmware, local: bool) -> sev::certs::Chain {
        if local {
            build_local_chain(&fw, "/tmp/cek.cert", "/tmp/ask_ark_rome.cert")
        } else {
            let codename = get_cpu_code_name().expect("Invalid CPU!");
            fetch_chain(&fw, codename)
        }
    }

    fn prepare_launch() -> (Build, Session<Initialized>, Start) {
        let fw = sev::firmware::Firmware::open().unwrap();
        let build = fw.platform_status().unwrap().build;

        let chain = if let Ok(mut file) = File::open("/tmp/test_run_sev.chain") {
            sev::certs::Chain::decode(&mut file, ()).unwrap()
        } else {
            let chain = build_chain(&fw, true);

            let mut file = File::create("/tmp/test_run_sev.chain").unwrap();
            chain.encode(&mut file, ()).unwrap();
            chain
        };

        let policy = sev::launch::Policy::default();
        let session = sev::session::Session::try_from(policy).unwrap();
        let start = session.start(chain).unwrap();
        (build, session, start)
    }

    #[test]
    fn test_new_sev_launch() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();

        let launch = SevLaunch::new_with_vm(vm);
        assert!(launch.is_ok());

        let launch = launch.unwrap();
        assert!(launch.sev.as_raw_fd() >= 0);
        assert_eq!(launch.state, Uninit);
    }

    #[test]
    fn test_sev_launch_init() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();

        let launch = SevLaunch::new_with_vm(vm).unwrap();
        let launch = launch.init();
        assert!(launch.is_ok());
        assert_eq!(launch.unwrap().state, Init);
    }

    #[test]
    fn test_sev_launch_start() {
        let (_, _, start) = prepare_launch();

        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();

        let launch = vm.create_sev_launch().unwrap();
        assert!(launch.start(start).is_ok());
    }

    #[test]
    fn test_sev_launch_measure() {
        let (build, session, start) = prepare_launch();

        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();

        let launch = vm.create_sev_launch().unwrap();
        let launch = launch.start(start).unwrap();
        let launch = launch.measure();
        assert!(launch.is_ok());
        let launch = launch.unwrap();
        let measurement = launch.get_measure();

        let session = session.measure().unwrap();
        let session = session.verify(build, measurement);
        assert!(session.is_ok());
    }

    #[test]
    fn test_sev_launch_update_data() {
        let (build, session, start) = prepare_launch();

        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();

        let mem_size = 0x4000;
        let load_addr = mmap_anonymous(mem_size);
        let guest_addr: u64 = 0x1000;
        let slot: u32 = 0;
        let mem_region = kvm_userspace_memory_region {
            slot,
            guest_phys_addr: guest_addr,
            memory_size: mem_size as u64,
            userspace_addr: load_addr as u64,
            flags: KVM_MEM_LOG_DIRTY_PAGES,
        };
        unsafe {
            vm.set_user_memory_region(mem_region).unwrap();
        }

        let launch = vm.create_sev_launch().unwrap();
        let launch = launch.start(start).unwrap();

        let slice = unsafe { std::slice::from_raw_parts_mut(load_addr, mem_size) };
        // Make sure that we do session.update_data before launch.update_data.
        // SEV LAUNCH_UPDATE_DATA will encrypt the plaintext context pointed to
        // (with the guest’s VEK) *in place*, which will thus alter the content.
        let mut session = session.measure().unwrap();
        session.update_data(slice).unwrap();

        assert!(launch.update_data(slice).is_ok());
        let launch = launch.measure();
        assert!(launch.is_ok());
        let launch = launch.unwrap();
        let measurement = launch.get_measure();

        let session = session.verify(build, measurement);
        assert!(session.is_ok());
    }

    #[test]
    fn test_sev_launch_finish() {
        let (_, _, start) = prepare_launch();

        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();

        let launch = vm.create_sev_launch().unwrap();
        let launch = launch.start(start).unwrap();
        let launch = launch.measure().unwrap();
        assert!(launch.finish().is_ok());
    }

    #[test]
    fn test_sev_launch_state_machine() {
        let (_, _, start) = prepare_launch();

        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();

        let launch_uninit = SevLaunch::new_with_vm(vm).unwrap();
        let launch_init = SevLaunch::<Init>::from(launch_uninit);
        let launch_update = launch_init.start(start).unwrap();
        let launch_secret = SevLaunch::<LaunchSecret>::from(launch_update);
        SevLaunch::<Running>::from(launch_secret);
    }

    #[test]
    fn test_run_sev_code() {
        let (build, session, start) = prepare_launch();

        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();

        // This example is based on https://lwn.net/Articles/658511/
        #[rustfmt::skip]
        let code = [
            0xba, 0xf8, 0x03, /* mov $0x3f8, %dx */
            0x00, 0xd8, /* add %bl, %al */
            0x04, b'0', /* add $'0', %al */
            0xee, /* out %al, %dx */
            0xec, /* in %dx, %al */
            0xc6, 0x06, 0x00, 0x80, 0x00, /* movl $0, (0x8000); This generates a MMIO Write.*/
            0x8a, 0x16, 0x00, 0x80, /* movl (0x8000), %dl; This generates a MMIO Read.*/
            0xc6, 0x06, 0x00, 0x20, 0x00, /* movl $0, (0x2000); Dirty one page in guest mem. */
            0xf4, /* hlt */
        ];

        let mem_size = 0x4000;
        let load_addr = mmap_anonymous(mem_size);
        let guest_addr: u64 = 0x1000;
        let slot: u32 = 0;
        let mem_region = kvm_userspace_memory_region {
            slot,
            guest_phys_addr: guest_addr,
            memory_size: mem_size as u64,
            userspace_addr: load_addr as u64,
            flags: KVM_MEM_LOG_DIRTY_PAGES,
        };
        unsafe {
            vm.set_user_memory_region(mem_region).unwrap();
        }

        unsafe {
            // Get a mutable slice of `mem_size` from `load_addr`.
            // This is safe because we mapped it before.
            let mut slice = std::slice::from_raw_parts_mut(load_addr, mem_size);
            slice.write_all(&[0]).unwrap();
        }

        let launch = vm.create_sev_launch().unwrap();
        let launch = launch.start(start).unwrap();
        let launch = launch.measure().unwrap();
        let measurement = launch.get_measure();

        let session = session.measure().unwrap();
        let session = session.verify(build, measurement).unwrap();
        let secret = session
            .secret(sev::launch::HeaderFlags::default(), &code)
            .unwrap();

        // Injects the encrypted code into the VM.
        let len = secret.ciphertext.len() as u32;
        launch.secret(secret, load_addr as u64, len).unwrap();
        let launch = launch.finish().unwrap();

        let vm = launch.vm;
        let vcpu_fd = vm.create_vcpu(0).unwrap();

        let mut vcpu_sregs = vcpu_fd.get_sregs().unwrap();
        assert_ne!(vcpu_sregs.cs.base, 0);
        assert_ne!(vcpu_sregs.cs.selector, 0);
        vcpu_sregs.cs.base = 0;
        vcpu_sregs.cs.selector = 0;
        vcpu_fd.set_sregs(&vcpu_sregs).unwrap();

        let mut vcpu_regs = vcpu_fd.get_regs().unwrap();
        // Set the Instruction Pointer to the guest address where we loaded the code.
        vcpu_regs.rip = guest_addr;
        vcpu_regs.rax = 2;
        vcpu_regs.rbx = 3;
        vcpu_regs.rflags = 2;
        vcpu_fd.set_regs(&vcpu_regs).unwrap();

        loop {
            match vcpu_fd.run().expect("run failed") {
                VcpuExit::IoIn(addr, data) => {
                    assert_eq!(addr, 0x3f8);
                    assert_eq!(data.len(), 1);
                }
                VcpuExit::IoOut(addr, data) => {
                    assert_eq!(addr, 0x3f8);
                    assert_eq!(data.len(), 1);
                    assert_eq!(data[0], b'5');
                }
                VcpuExit::MmioRead(addr, data) => {
                    assert_eq!(addr, 0x8000);
                    assert_eq!(data.len(), 1);
                }
                VcpuExit::MmioWrite(addr, data) => {
                    assert_eq!(addr, 0x8000);
                    assert_eq!(data.len(), 1);
                    assert_eq!(data[0], 0);
                }
                VcpuExit::Hlt => {
                    // The code snippet dirties 2 pages:
                    // * one when the code itself is loaded in memory;
                    // * and one more from the `movl` that writes to address 0x8000
                    let dirty_pages_bitmap = vm.get_dirty_log(slot, mem_size).unwrap();
                    let dirty_pages: u32 = dirty_pages_bitmap
                        .into_iter()
                        .map(|page| page.count_ones())
                        .sum();
                    assert_eq!(dirty_pages, 2);
                    break;
                }
                r => panic!("unexpected exit reason: {:?}", r),
            }
        }
    }
}
