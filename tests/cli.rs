use std::{fs, process::Command};

use tempfile::tempdir;

/// A claimed digest cannot inject terminal controls or report lines into CLI output.
#[test]
fn mismatch_output_does_not_echo_claimed_digest() {
    let package = tempdir().unwrap();
    let malicious_digest = "injected\n\u{1b}[2J";
    let manifest = serde_json::json!({
        "schema_version": 1,
        "file": {"id": "550e8400-e29b-41d4-a716-446655440000"},
        "composition": [],
        "selected_record_ids": [],
        "excluded_record_ids": [],
        "records": [{
            "id": "6ba7b811-9dad-4f11-80b4-00c04fd430c8",
            "type": "contact",
            "content": {},
            "content_hashes": {"sha256": malicious_digest, "blake3": "changed"},
        }],
    });
    fs::write(package.path().join("manifest.json"), manifest.to_string()).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_darkroom-verify"))
        .arg(package.path())
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(stdout.contains("Sha256 mismatch"));
    assert!(!stdout.contains("injected"));
    assert!(!stdout.contains('\u{1b}'));
    assert!(output.stderr.is_empty());
}
