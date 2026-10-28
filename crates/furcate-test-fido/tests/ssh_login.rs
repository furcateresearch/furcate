//! sshd accepts a certificate for a software FIDO key, end to end.
//!
//! A test CA signs a certificate for an `sk-ecdsa` key made by this crate's
//! authenticator, carrying one principal, `<user>@test-node`, and a
//! force-command, as a passkey login certificate does. An sshd on loopback
//! trusting that CA lets it in, and refuses the same key certified for another
//! machine. The force-command prints `$SSH_USER_AUTH`, and furcate-authn reads
//! and verifies the certificate in it, which is what the session recorder
//! relies on.

use std::path::{Path, PathBuf};
use std::process::Command;

fn provider() -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    let deps = exe.parent().unwrap();
    for dir in [deps, deps.parent().unwrap()] {
        for e in std::fs::read_dir(dir).unwrap().flatten() {
            let n = e.file_name().to_string_lossy().into_owned();
            if n.starts_with("libfurcate_test_fido") && n.ends_with(".so") {
                return e.path();
            }
        }
    }
    panic!("libfurcate_test_fido.so was not built next to {}", exe.display());
}

fn run(cmd: &mut Command) -> std::process::Output {
    let o = cmd.output().unwrap();
    assert!(o.status.success(), "{cmd:?}: {}", String::from_utf8_lossy(&o.stderr));
    o
}

fn me() -> String {
    String::from_utf8(run(Command::new("id").arg("-un")).stdout).unwrap().trim().to_string()
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

struct Sshd(std::process::Child, PathBuf);

impl Drop for Sshd {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
        let _ = std::fs::remove_dir_all(&self.1);
    }
}

fn keygen(dir: &Path, args: &[&str]) {
    run(Command::new("ssh-keygen").current_dir(dir).args(args).env_remove("SSH_AUTH_SOCK"));
}

fn login(dir: &Path, port: u16, so: &Path, cert: &str) -> std::process::Output {
    Command::new("ssh")
        .current_dir(dir)
        .env_remove("SSH_AUTH_SOCK")
        .args(["-F", "/dev/null", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes"])
        .args(["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null"])
        .arg("-o")
        .arg(format!("SecurityKeyProvider={}", so.display()))
        .args(["-o", "IdentityFile=user", "-o"])
        .arg(format!("CertificateFile={cert}"))
        .args(["-p", &port.to_string(), &format!("{}@127.0.0.1", me()), "ignored"])
        .output()
        .unwrap()
}

#[test]
fn a_software_fido_key_logs_in_with_a_certificate_for_this_machine_only() {
    let sshd_bin = Path::new("/usr/sbin/sshd");
    assert!(sshd_bin.exists(), "this test needs OpenSSH's sshd at /usr/sbin/sshd");
    let so = provider();
    let dir = std::env::temp_dir().join(format!("furcate-test-fido-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let user = me();

    keygen(&dir, &["-q", "-t", "ed25519", "-N", "", "-C", "test-ca", "-f", "ca"]);
    keygen(&dir, &["-q", "-t", "ed25519", "-N", "", "-f", "hostkey"]);
    keygen(&dir, &["-q", "-t", "ecdsa-sk", "-N", "", "-w", so.to_str().unwrap(), "-f", "user"]);
    let principal = format!("{user}@test-node");
    let force = "cat \"$SSH_USER_AUTH\"";
    for (name, p) in [("good", principal.as_str()), ("other", &format!("{user}@other-node") as &str)] {
        std::fs::copy(dir.join("user.pub"), dir.join(format!("{name}.pub"))).unwrap();
        keygen(
            &dir,
            &["-q", "-s", "ca", "-I", "furcate:passkey:test:1", "-n", p, "-V", "+5m", "-z", "1",
              "-O", "clear", "-O", "permit-pty", "-O", &format!("force-command={force}"), &format!("{name}.pub")],
        );
    }
    std::fs::write(dir.join("principals"), format!("{user}\n{principal}\n")).unwrap();
    let port = free_port();
    let conf = format!(
        "Port {port}\nListenAddress 127.0.0.1\nHostKey {d}/hostkey\nPidFile {d}/sshd.pid\n\
         AuthorizedKeysFile none\nTrustedUserCAKeys {d}/ca.pub\nAuthorizedPrincipalsFile {d}/principals\n\
         ExposeAuthInfo yes\nUsePAM no\nStrictModes no\nPasswordAuthentication no\n\
         KbdInteractiveAuthentication no\nPubkeyAuthentication yes\nLogLevel VERBOSE\n",
        d = dir.display()
    );
    std::fs::write(dir.join("sshd_config"), conf).unwrap();
    let child = Command::new(sshd_bin)
        .args(["-D", "-e", "-f"])
        .arg(dir.join("sshd_config"))
        .stderr(std::fs::File::create(dir.join("sshd.log")).unwrap())
        .spawn()
        .unwrap();
    let sshd = Sshd(child, dir.clone());
    for _ in 0..50 {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    let ok = login(&dir, port, &so, "good-cert.pub");
    let log = || std::fs::read_to_string(dir.join("sshd.log")).unwrap_or_default();
    assert!(ok.status.success(), "login refused: {}\nsshd: {}", String::from_utf8_lossy(&ok.stderr), log());
    let auth = String::from_utf8(ok.stdout).unwrap();

    // What the recorder does with $SSH_USER_AUTH.
    let line = furcate_authn::sshcert::from_user_auth(&auth).unwrap();
    let ca = std::fs::read_to_string(dir.join("ca.pub")).unwrap();
    let cert = furcate_authn::sshcert::verify(&line, ca.trim()).unwrap();
    assert_eq!(cert.principals, vec![principal.clone()]);
    assert_eq!(cert.force_command.as_deref(), Some(force));
    assert_eq!(cert.serial, 1);
    let key = std::fs::read_to_string(dir.join("user.pub")).unwrap();
    let (_, digest) = furcate_authn::order::ssh_key_sha256(key.trim()).unwrap();
    assert_eq!(cert.key_sha256, digest, "the certificate names the key a login order would");

    let other = login(&dir, port, &so, "other-cert.pub");
    assert!(!other.status.success(), "a certificate for another machine got in");
    drop(sshd);
}
