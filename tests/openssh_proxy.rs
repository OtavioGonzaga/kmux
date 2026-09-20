use base64::Engine;
use kmux::agent::UnixSocketAgent;
use kmux::proxy::{FilteredAgent, ProxyServer};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("kmux-openssh-{}-{unique}", std::process::id()));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn available(command: &str) -> bool {
    Command::new(command).arg("-h").output().is_ok()
}

fn wait_for_socket(path: &Path) {
    for _ in 0..100 {
        if path.exists() {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("OpenSSH agent did not create {}", path.display());
}

fn stop_agent(agent: &mut Child) {
    let _ = agent.kill();
    let _ = agent.wait();
}

#[test]
fn openssh_agent_identities_are_filtered_by_the_proxy() {
    if !available("ssh-agent") || !available("ssh-add") || !available("ssh-keygen") {
        eprintln!("skipping OpenSSH integration test: required commands are unavailable");
        return;
    }

    let dir = TempDir::new();
    let upstream_socket = dir.0.join("upstream.sock");
    let mut agent = Command::new("ssh-agent")
        .args(["-D", "-a"])
        .arg(&upstream_socket)
        .spawn()
        .unwrap();
    wait_for_socket(&upstream_socket);

    let allowed_keys = [dir.0.join("allowed-first"), dir.0.join("allowed-second")];
    let excluded_key = dir.0.join("excluded");
    for key in allowed_keys.iter().chain(std::iter::once(&excluded_key)) {
        assert!(
            Command::new("ssh-keygen")
                .args(["-q", "-t", "ed25519", "-N", "", "-f"])
                .arg(key)
                .status()
                .unwrap()
                .success()
        );
        assert!(
            Command::new("ssh-add")
                .arg(key)
                .env("SSH_AUTH_SOCK", &upstream_socket)
                .status()
                .unwrap()
                .success()
        );
    }

    let allowed = allowed_keys.map(|key| {
        let public_key = std::fs::read_to_string(key.with_extension("pub")).unwrap();
        let key_blob = base64::engine::general_purpose::STANDARD
            .decode(public_key.split_whitespace().nth(1).unwrap())
            .unwrap();
        (key, public_key, key_blob)
    });
    let excluded_public = std::fs::read_to_string(excluded_key.with_extension("pub")).unwrap();
    let proxy_socket = dir.0.join("proxy.sock");
    let proxy = ProxyServer::bind(
        &proxy_socket,
        FilteredAgent::new(
            UnixSocketAgent::new(&upstream_socket),
            allowed.iter().map(|(_, _, blob)| blob.clone()),
        ),
    )
    .unwrap();

    let output = Command::new("ssh-add")
        .arg("-L")
        .env("SSH_AUTH_SOCK", proxy.path())
        .output()
        .unwrap();
    let signature_checks = allowed
        .iter()
        .map(|(key, _, _)| {
            Command::new("ssh-add")
                .arg("-T")
                .arg(key.with_extension("pub"))
                .env("SSH_AUTH_SOCK", proxy.path())
                .output()
                .unwrap()
        })
        .collect::<Vec<_>>();
    let excluded_signature_check = Command::new("ssh-add")
        .arg("-T")
        .arg(excluded_key.with_extension("pub"))
        .env("SSH_AUTH_SOCK", proxy.path())
        .output()
        .unwrap();
    drop(proxy);
    stop_agent(&mut agent);

    assert!(output.status.success(), "ssh-add failed: {:?}", output);
    for signature_check in signature_checks {
        assert!(
            signature_check.status.success(),
            "ssh-add signature check failed: {:?}",
            signature_check
        );
    }
    assert!(!excluded_signature_check.status.success());
    let identities = String::from_utf8(output.stdout).unwrap();
    for (_, public_key, _) in &allowed {
        assert!(identities.contains(public_key));
    }
    assert!(!identities.contains(&excluded_public));
    assert!(!proxy_socket.exists());
}
