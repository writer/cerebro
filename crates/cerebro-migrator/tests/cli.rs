use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn discover_command_reads_go_list_stream_from_stdin() {
    let package = serde_json::json!({
        "Dir": "/repo/internal/a",
        "ImportPath": "github.com/writer/cerebro/internal/a",
        "Module": {"Path": "github.com/writer/cerebro"},
        "GoFiles": ["a.go"]
    })
    .to_string();
    let mut child = Command::new(env!("CARGO_BIN_EXE_cerebro-migrator"))
        .args(["discover", "--module", "github.com/writer/cerebro"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(package.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let discovered: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        discovered["graph"]["packages"].as_object().unwrap().len(),
        1
    );
    assert_eq!(
        discovered["condensation"]["components"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}
