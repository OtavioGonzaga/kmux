use kmux::catalog::Fingerprint;
use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn unique_path(name: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("kmux-{name}-{}-{unique}", std::process::id()))
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
    assert!(proxy_socket.parent().unwrap().ends_with("kmux"));
    assert!(!proxy_socket.exists());

    let _ = std::fs::remove_dir_all(&dir);
    thread::sleep(Duration::from_millis(1));
}
