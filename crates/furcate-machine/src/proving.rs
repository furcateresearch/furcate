//! The proving ground: boot a guest with a virtual TPM and read its registers.
//!
//! This is what makes the rest of the system testable. Booting a machine
//! hundreds of times and deliberately corrupting its boot chain is impossible
//! on a production server and routine here.
//!
//! The harness composes a QEMU invocation with OVMF firmware and a swtpm
//! socket. Nothing here talks to the guest OS — the register values come from
//! the vTPM, which is the point: they are what the *firmware* measured, not
//! what the guest claims.

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

/// Where a guest's virtual TPM state and sockets live.
pub struct Sandbox {
    pub root: PathBuf,
}

impl Sandbox {
    pub fn new(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        std::fs::create_dir_all(&root)
            .with_context(|| format!("creating sandbox at {}", root.display()))?;
        Ok(Self { root })
    }

    pub fn state_dir(&self) -> PathBuf {
        self.root.join("tpm")
    }

    pub fn socket(&self) -> PathBuf {
        self.root.join("swtpm-sock")
    }

    /// Remove all state, so the next boot starts from a clean chip.
    ///
    /// Deliberately explicit rather than automatic: a proving run that
    /// silently reset the vTPM between boots could not detect a register
    /// failing to change when it should have.
    pub fn reset(&self) -> Result<()> {
        if self.state_dir().exists() {
            std::fs::remove_dir_all(self.state_dir()).context("clearing vTPM state")?;
        }
        Ok(())
    }
}

/// A running software TPM.
pub struct Swtpm {
    child: Child,
    socket: PathBuf,
}

impl Swtpm {
    /// Start a vTPM for a guest.
    pub fn start(sandbox: &Sandbox) -> Result<Self> {
        let state = sandbox.state_dir();
        std::fs::create_dir_all(&state).context("creating vTPM state directory")?;
        let socket = sandbox.socket();
        let _ = std::fs::remove_file(&socket);

        let child = Command::new("swtpm")
            .args([
                "socket",
                "--tpm2",
                "--tpmstate",
                &format!("dir={}", state.display()),
                "--ctrl",
                &format!("type=unixio,path={}", socket.display()),
                "--flags",
                "startup-clear",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .context("starting swtpm — is swtpm installed?")?;

        Ok(Self { child, socket })
    }

    /// Start a vTPM listening on TCP, for exercising a TPM client directly
    /// rather than through a guest.
    ///
    /// This is how code that touches the chip gets tested without touching the
    /// chip. libtpms is a real TPM 2.0 implementation, so resource exhaustion,
    /// object slots and failure modes behave as they do in silicon — but a
    /// faulted software TPM is discarded rather than requiring a power cycle.
    pub fn start_tcp(sandbox: &Sandbox, port: u16) -> Result<Self> {
        let state = sandbox.state_dir();
        std::fs::create_dir_all(&state).context("creating vTPM state directory")?;

        let child = Command::new("swtpm")
            .args([
                "socket",
                "--tpm2",
                "--tpmstate",
                &format!("dir={}", state.display()),
                "--server",
                &format!("type=tcp,port={port}"),
                "--ctrl",
                &format!("type=tcp,port={}", port + 1),
                "--flags",
                "not-need-init,startup-clear",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .context("starting swtpm on TCP — is swtpm installed?")?;

        Ok(Self {
            child,
            socket: PathBuf::from(format!("tcp:{port}")),
        })
    }

    /// Wait for a TCP-mode vTPM to accept connections.
    pub fn wait_tcp(port: u16, attempts: u32) -> Result<()> {
        for _ in 0..attempts {
            if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
                return Ok(());
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        bail!("swtpm did not accept connections on port {port}")
    }

    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// Wait for the control socket to appear.
    pub fn wait_ready(&self, attempts: u32) -> Result<()> {
        for _ in 0..attempts {
            if self.socket.exists() {
                return Ok(());
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        bail!("swtpm control socket did not appear at {}", self.socket.display())
    }
}

impl Drop for Swtpm {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.socket);
    }
}

/// Firmware to boot the guest with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Firmware {
    pub code: PathBuf,
    pub vars_template: PathBuf,
}

impl Firmware {
    /// Locate OVMF on this host.
    ///
    /// Both a 4MB and a legacy layout are searched, and the secure-boot
    /// variant is preferred when present: a firmware that does not enforce
    /// secure boot measures less, which would understate what a real machine
    /// records.
    pub fn discover() -> Result<Self> {
        let candidates: [(&str, &str); 3] = [
            ("/usr/share/OVMF/OVMF_CODE_4M.ms.fd", "/usr/share/OVMF/OVMF_VARS_4M.ms.fd"),
            ("/usr/share/OVMF/OVMF_CODE_4M.fd", "/usr/share/OVMF/OVMF_VARS_4M.fd"),
            ("/usr/share/OVMF/OVMF_CODE.fd", "/usr/share/OVMF/OVMF_VARS.fd"),
        ];
        for (code, vars) in candidates {
            if Path::new(code).exists() && Path::new(vars).exists() {
                return Ok(Firmware {
                    code: PathBuf::from(code),
                    vars_template: PathBuf::from(vars),
                });
            }
        }
        bail!("no OVMF firmware found; install the `ovmf` package")
    }
}

/// A guest boot request.
pub struct BootRequest {
    pub memory_mb: u32,
    /// Optional disk image. Without one the guest boots the firmware only,
    /// which is enough to exercise firmware measurement.
    pub disk: Option<PathBuf>,
    /// Seconds before the guest is killed.
    pub timeout_s: u64,
}

impl Default for BootRequest {
    fn default() -> Self {
        Self {
            memory_mb: 512,
            disk: None,
            timeout_s: 20,
        }
    }
}

/// Build the QEMU command line for a guest with a virtual TPM.
///
/// Separated from execution so the composition can be asserted in tests
/// without needing a hypervisor.
pub fn qemu_args(
    firmware: &Firmware,
    vars: &Path,
    tpm_socket: &Path,
    request: &BootRequest,
) -> Vec<String> {
    let mut args: Vec<String> = vec![
        "-machine".into(),
        // q35 with KVM: the firmware only measures into a TPM on a modern
        // chipset, and the older i440fx model does not carry the required
        // ACPI tables.
        "q35,accel=kvm".into(),
        "-m".into(),
        request.memory_mb.to_string(),
        "-nographic".into(),
        "-no-reboot".into(),
        // Firmware code is read-only; variables are per-guest so secure boot
        // state cannot leak between runs.
        "-drive".into(),
        format!("if=pflash,format=raw,readonly=on,file={}", firmware.code.display()),
        "-drive".into(),
        format!("if=pflash,format=raw,file={}", vars.display()),
        // The vTPM: a character device on the swtpm socket, a TPM backend
        // over it, and a CRB device the firmware knows how to measure into.
        "-chardev".into(),
        format!("socket,id=chrtpm,path={}", tpm_socket.display()),
        "-tpmdev".into(),
        "emulator,id=tpm0,chardev=chrtpm".into(),
        "-device".into(),
        "tpm-crb,tpmdev=tpm0".into(),
    ];
    if let Some(disk) = &request.disk {
        args.push("-drive".into());
        args.push(format!("format=raw,file={}", disk.display()));
    }
    args
}

/// Boot a guest and wait for it to exit or time out.
pub fn boot(sandbox: &Sandbox, request: &BootRequest) -> Result<()> {
    let firmware = Firmware::discover()?;
    let vars = sandbox.root.join("OVMF_VARS.fd");
    if !vars.exists() {
        std::fs::copy(&firmware.vars_template, &vars)
            .context("copying firmware variables into the sandbox")?;
    }

    let swtpm = Swtpm::start(sandbox)?;
    swtpm.wait_ready(50)?;

    let args = qemu_args(&firmware, &vars, swtpm.socket(), request);
    let mut child = Command::new("qemu-system-x86_64")
        .args(&args)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .context("starting qemu-system-x86_64")?;

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(request.timeout_s);
    loop {
        if let Some(_status) = child.try_wait().context("waiting for the guest")? {
            break;
        }
        if std::time::Instant::now() > deadline {
            // A firmware-only boot never exits on its own; reaching the
            // deadline is the expected path, not a failure.
            let _ = child.kill();
            let _ = child.wait();
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    Ok(())
}

/// Whether the vTPM persisted state, which is the evidence a guest actually
/// booted far enough to touch the chip.
pub fn state_written(sandbox: &Sandbox) -> bool {
    let dir = sandbox.state_dir();
    std::fs::read_dir(&dir)
        .map(|entries| entries.flatten().any(|e| e.path().is_file()))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn firmware() -> Firmware {
        Firmware {
            code: PathBuf::from("/usr/share/OVMF/OVMF_CODE_4M.fd"),
            vars_template: PathBuf::from("/usr/share/OVMF/OVMF_VARS_4M.fd"),
        }
    }

    #[test]
    fn the_command_line_wires_a_tpm_device() {
        let args = qemu_args(
            &firmware(),
            Path::new("/tmp/vars.fd"),
            Path::new("/tmp/sock"),
            &BootRequest::default(),
        );
        let joined = args.join(" ");
        assert!(joined.contains("-tpmdev"));
        assert!(joined.contains("emulator,id=tpm0,chardev=chrtpm"));
        assert!(joined.contains("tpm-crb,tpmdev=tpm0"));
    }

    #[test]
    fn firmware_code_is_mounted_read_only() {
        // Writable firmware would let a guest alter what the next boot
        // measures, which defeats the whole exercise.
        let args = qemu_args(
            &firmware(),
            Path::new("/tmp/vars.fd"),
            Path::new("/tmp/sock"),
            &BootRequest::default(),
        );
        let code_arg = args
            .iter()
            .find(|a| a.contains("OVMF_CODE"))
            .expect("firmware code drive");
        assert!(code_arg.contains("readonly=on"));
    }

    #[test]
    fn variables_are_per_guest_not_shared() {
        let args = qemu_args(
            &firmware(),
            Path::new("/tmp/guest-1/vars.fd"),
            Path::new("/tmp/sock"),
            &BootRequest::default(),
        );
        let vars_arg = args
            .iter()
            .find(|a| a.contains("guest-1"))
            .expect("per-guest variables");
        assert!(!vars_arg.contains("readonly"));
    }

    #[test]
    fn a_modern_chipset_is_used() {
        let args = qemu_args(
            &firmware(),
            Path::new("/tmp/vars.fd"),
            Path::new("/tmp/sock"),
            &BootRequest::default(),
        );
        assert!(args.iter().any(|a| a.starts_with("q35")));
    }

    #[test]
    fn a_disk_is_attached_only_when_requested() {
        let without = qemu_args(
            &firmware(),
            Path::new("/tmp/v"),
            Path::new("/tmp/s"),
            &BootRequest::default(),
        );
        assert!(!without.iter().any(|a| a.contains("format=raw,file=/tmp/disk")));

        let with = qemu_args(
            &firmware(),
            Path::new("/tmp/v"),
            Path::new("/tmp/s"),
            &BootRequest {
                disk: Some(PathBuf::from("/tmp/disk")),
                ..Default::default()
            },
        );
        assert!(with.iter().any(|a| a.contains("format=raw,file=/tmp/disk")));
    }

    #[test]
    fn a_sandbox_reset_clears_chip_state() {
        let dir = std::env::temp_dir().join("furcate-proving-test");
        let s = Sandbox::new(&dir).unwrap();
        std::fs::create_dir_all(s.state_dir()).unwrap();
        std::fs::write(s.state_dir().join("tpm2-00.permall"), b"state").unwrap();
        assert!(state_written(&s));
        s.reset().unwrap();
        assert!(!state_written(&s));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
