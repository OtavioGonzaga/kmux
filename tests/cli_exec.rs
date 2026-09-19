use kmux::catalog::Fingerprint;
use rustix::process::{Pid, Signal, kill_process};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Arc, Barrier, mpsc};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn unique_path(name: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("kmux-{name}-{}-{unique}", std::process::id()))
}

#[test]
fn exec_forwards_sigint_and_sigterm_to_the_direct_child() {
    for signal in [Signal::INT, Signal::TERM] {
        let dir = unique_path("signal-test");
        std::fs::create_dir(&dir).unwrap();
        let upstream_socket = dir.join("upstream.sock");
        let listener = UnixListener::bind(&upstream_socket).unwrap();
        let key_blob = b"signal-public-key".to_vec();
        let worker_blob = key_blob.clone();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            assert_eq!(read_frame(&mut stream), [11]);
            let mut response = vec![12];
            response.extend_from_slice(&1_u32.to_be_bytes());
            put_string(&mut response, &worker_blob);
            put_string(&mut response, b"signal key");
            write_frame(&mut stream, &response);
        });
        let fingerprint = Fingerprint::from_public_key_blob(&key_blob);
        let config = dir.join("config.yaml");
        std::fs::write(&config, format!("version: 1\nagents:\n  test:\n    type: unix\n    socket: {}\nkeys:\n  test-key:\n    fingerprint: \"{fingerprint}\"\n    agent: test\n    scopes: [test]\n", upstream_socket.display())).unwrap();
        let trap = match signal {
            Signal::INT => "INT",
            Signal::TERM => "TERM",
            _ => unreachable!(),
        };
        let mut kmux = Command::new(env!("CARGO_BIN_EXE_kmux"))
            .args([
                "--config",
                config.to_str().unwrap(),
                "exec",
                "test",
                "--",
                "sh",
                "-c",
            ])
            .arg(format!(
                "echo ready; trap 'exit 0' {trap}; while :; do sleep 1; done"
            ))
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let (ready_sent, ready_received) = mpsc::channel();
        let stdout = kmux.stdout.take().unwrap();
        thread::spawn(move || {
            let mut ready = String::new();
            let result = BufReader::new(stdout)
                .read_line(&mut ready)
                .map(|_| ready)
                .map_err(|error| error.to_string());
            let _ = ready_sent.send(result);
        });
        assert_eq!(
            ready_received
                .recv_timeout(Duration::from_secs(3))
                .unwrap()
                .unwrap(),
            "ready\n"
        );
        kill_process(Pid::from_child(&kmux), signal).unwrap();
        assert!(wait_with_timeout(&mut kmux).success());
        worker.join().unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }
}

#[test]
fn version_uses_the_binary_name_and_package_version() {
    let output = Command::new(env!("CARGO_BIN_EXE_kmux"))
        .arg("--version")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!("kmux {}\n", env!("CARGO_PKG_VERSION"))
    );
}

fn write_frame(stream: &mut impl Write, payload: &[u8]) {
    stream
        .write_all(&(payload.len() as u32).to_be_bytes())
        .unwrap();
    stream.write_all(payload).unwrap();
    stream.flush().unwrap();
}

fn read_frame(stream: &mut impl Read) -> Vec<u8> {
    let mut length = [0; 4];
    stream.read_exact(&mut length).unwrap();
    let mut payload = vec![0; u32::from_be_bytes(length) as usize];
    stream.read_exact(&mut payload).unwrap();
    payload
}

fn put_string(payload: &mut Vec<u8>, value: &[u8]) {
    payload.extend_from_slice(&(value.len() as u32).to_be_bytes());
    payload.extend_from_slice(value);
}

#[test]
fn exec_passes_an_ephemeral_proxy_to_the_child_and_preserves_its_exit_code() {
    let dir = unique_path("cli-test");
    std::fs::create_dir(&dir).unwrap();
    let upstream_socket = dir.join("upstream.sock");
    let listener = UnixListener::bind(&upstream_socket).unwrap();
    let key_blob = b"test-public-key".to_vec();
    let worker_blob = key_blob.clone();
    let worker = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        assert_eq!(read_frame(&mut stream), [11]);
        let mut response = vec![12];
        response.extend_from_slice(&1_u32.to_be_bytes());
        put_string(&mut response, &worker_blob);
        put_string(&mut response, b"test key");
        write_frame(&mut stream, &response);
    });

    let fingerprint = Fingerprint::from_public_key_blob(&key_blob);
    let config = dir.join("config.yaml");
    std::fs::write(
        &config,
        format!(
            "version: 1\nagents:\n  test:\n    type: unix\n    socket: {}\nkeys:\n  test-key:\n    fingerprint: \"{fingerprint}\"\n    agent: test\n    scopes: [test]\n",
            upstream_socket.display()
        ),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_kmux"))
        .args([
            "--config",
            config.to_str().unwrap(),
            "exec",
            "test",
            "--",
            "sh",
            "-c",
        ])
        .arg("printf '%s' \"$SSH_AUTH_SOCK\"; exit 23")
        .output()
        .unwrap();
    worker.join().unwrap();

    let proxy_socket = PathBuf::from(String::from_utf8(output.stdout).unwrap());
    assert_eq!(output.status.code(), Some(23));
    assert!(
        proxy_socket
            .parent()
            .unwrap()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("kmux-")
    );
    assert!(!proxy_socket.exists());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn concurrent_exec_uses_unique_runtime_directories() {
    let dir = unique_path("concurrent-runtime");
    let runtime = dir.join("runtime");
    std::fs::create_dir_all(&runtime).unwrap();
    let upstream_socket = dir.join("upstream.sock");
    let listener = UnixListener::bind(&upstream_socket).unwrap();
    let key_blob = b"concurrent-public-key".to_vec();
    let worker_blob = key_blob.clone();
    let worker = thread::spawn(move || {
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().unwrap();
            assert_eq!(read_frame(&mut stream), [11]);
            let mut response = vec![12];
            response.extend_from_slice(&1_u32.to_be_bytes());
            put_string(&mut response, &worker_blob);
            put_string(&mut response, b"concurrent key");
            write_frame(&mut stream, &response);
        }
    });
    let fingerprint = Fingerprint::from_public_key_blob(&key_blob);
    let config = dir.join("config.yaml");
    std::fs::write(&config, format!("version: 1\nagents:\n  test:\n    type: unix\n    socket: {}\nkeys:\n  test-key:\n    fingerprint: \"{fingerprint}\"\n    agent: test\n    scopes: [test]\n", upstream_socket.display())).unwrap();

    let barrier = Arc::new(Barrier::new(3));
    let (outputs_sent, outputs_received) = mpsc::channel();
    thread::scope(|scope| {
        for _ in 0..2 {
            let barrier = barrier.clone();
            let outputs_sent = outputs_sent.clone();
            let config = config.clone();
            let runtime = runtime.clone();
            scope.spawn(move || {
                barrier.wait();
                let output = Command::new(env!("CARGO_BIN_EXE_kmux"))
                    .env("XDG_RUNTIME_DIR", runtime)
                    .args([
                        "--config",
                        config.to_str().unwrap(),
                        "exec",
                        "test",
                        "--",
                        "sh",
                        "-c",
                    ])
                    .arg("printf '%s' \"$SSH_AUTH_SOCK\"")
                    .output()
                    .unwrap();
                outputs_sent.send(output).unwrap();
            });
        }
        barrier.wait();
        let first = outputs_received
            .recv_timeout(Duration::from_secs(5))
            .unwrap();
        let second = outputs_received
            .recv_timeout(Duration::from_secs(5))
            .unwrap();
        assert!(first.status.success());
        assert!(second.status.success());
        let first_path = PathBuf::from(String::from_utf8(first.stdout).unwrap());
        let second_path = PathBuf::from(String::from_utf8(second.stdout).unwrap());
        assert_ne!(first_path.parent(), second_path.parent());
        assert!(!first_path.exists());
        assert!(!second_path.exists());
    });
    worker.join().unwrap();
    let _ = std::fs::remove_dir_all(dir);
}

fn wait_with_timeout(child: &mut std::process::Child) -> std::process::ExitStatus {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("kmux did not exit after forwarding the signal");
        }
        thread::sleep(Duration::from_millis(10));
    }
}
