use std::{fs, io::Cursor};

use sha2::{Digest, Sha256};
use tempfile::{TempDir, tempdir};

use super::{
    CheckOutcome, CheckSubject, HashAlgorithm, VerifyError, canonical_json, dual_hash, hash_bytes,
    record_seal_hashes, record_seal_preimage, verify_package,
};

fn write_package(original_bytes: &[u8]) -> (TempDir, String) {
    let package = tempdir().unwrap();
    let file_id = "550e8400-e29b-41d4-a716-446655440000";
    let record_id = "6ba7b811-9dad-4f11-80b4-00c04fd430c8";
    let blob_id = "6ba7b810-9dad-4f11-80b4-00c04fd430c8";
    let content = r#"{"a":1,"b":"two"}"#;
    let (content_sha256, content_blake3) = hash_bytes(content.as_bytes());
    let (source_sha256, source_blake3) = hash_bytes(original_bytes);

    let manifest = format!(
        r#"{{
            "schema_version": 1,
            "file": {{"id": "{file_id}"}},
            "composition": [{{"type": "record_reference", "record_id": "{record_id}"}}],
            "selected_record_ids": ["{record_id}"],
            "excluded_record_ids": [],
            "records": [{{
                "id": "{record_id}",
                "type": "contact",
                "content": {content},
                "content_hashes": {{"sha256": "{content_sha256}", "blake3": "{content_blake3}"}},
                "source": {{
                    "blob_id": "{blob_id}",
                    "hashes": {{"sha256": "{source_sha256}", "blake3": "{source_blake3}"}}
                }}
            }}]
        }}"#
    );
    fs::write(package.path().join("manifest.json"), manifest).unwrap();

    let originals = package.path().join("originals");
    fs::create_dir(&originals).unwrap();
    fs::write(
        originals.join(format!("{blob_id}-source.txt")),
        b"original bytes",
    )
    .unwrap();

    (package, blob_id.to_string())
}

fn set_record_content(package: &TempDir, record_type: &str, content: serde_json::Value) {
    let manifest_path = package.path().join("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();
    manifest["records"][0]["type"] = record_type.into();
    manifest["records"][0]["content"] = content;
    fs::write(&manifest_path, manifest.to_string()).unwrap();
}

/// Add a valid Seal commitment to the first manifest record.
fn seal_record(package: &TempDir) {
    let manifest_path = package.path().join("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();
    let record = &manifest["records"][0];
    let record_id = record["id"].as_str().unwrap();
    let record_type = record["type"].as_str().unwrap();
    let hashes = record_seal_hashes(record_id, record_type, &record["content"]).unwrap();
    manifest["records"][0]["sealed"] = serde_json::json!({
        "at": 1,
        "sha256": hashes.sha256,
        "blake3": hashes.blake3,
    });
    fs::write(&manifest_path, manifest.to_string()).unwrap();
}

/// Pins the accepted record Seal preimage and both digest values.
#[test]
fn record_seal_contract_matches_accepted_vector() {
    let content = serde_json::json!({"name": "Ada"});
    let preimage = record_seal_preimage("record-1", "contact", &content).unwrap();

    assert_eq!(
        String::from_utf8(preimage).unwrap(),
        r#"{"evidentiary_content":{"name":"Ada"},"record_id":"record-1","record_type":"contact"}"#,
    );

    let hashes = record_seal_hashes("record-1", "contact", &content).unwrap();
    assert_eq!(
        hashes.sha256,
        "5d6bbd516ec4516046f35b0cb12983273d42e6a5490b74733b6b59291586be70"
    );
    assert_eq!(
        hashes.blake3,
        "3ed81787faa075856572e46058b3da6da311561224046810dc7a7b574c0e405f"
    );
}

/// Proves streaming hashing reads beyond its internal buffer.
#[test]
fn dual_hash_reads_past_internal_buffer() {
    let bytes = vec![0x5a; 9_000];
    let expected_sha256 = format!("{:x}", Sha256::digest(&bytes));
    let expected_blake3 = blake3::hash(&bytes).to_hex().to_string();

    let actual = dual_hash(&mut Cursor::new(bytes)).unwrap();

    assert_eq!(actual, (expected_sha256, expected_blake3));
}

#[test]
fn intact_package_verifies() {
    let (package, _) = write_package(b"original bytes");

    let report = verify_package(package.path()).unwrap();

    assert!(report.passed());
    assert_eq!(report.checks.len(), 2);
}

/// Proves a valid record Seal passes standalone verification.
#[test]
fn intact_record_seal_verifies() {
    let (package, _) = write_package(b"original bytes");
    seal_record(&package);

    let report = verify_package(package.path()).unwrap();

    assert!(report.passed());
    assert!(report.checks.iter().any(|check| {
        matches!(
            (&check.subject, &check.outcome),
            (CheckSubject::RecordSeal { .. }, CheckOutcome::Verified)
        )
    }));
}

/// Proves each stored Seal digest is verified independently.
#[test]
fn each_changed_record_seal_digest_fails_independently() {
    for (field, algorithm) in [
        ("sha256", HashAlgorithm::Sha256),
        ("blake3", HashAlgorithm::Blake3),
    ] {
        let (package, _) = write_package(b"original bytes");
        seal_record(&package);
        let manifest_path = package.path().join("manifest.json");
        let mut manifest: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();
        manifest["records"][0]["sealed"][field] = "changed".into();
        fs::write(&manifest_path, manifest.to_string()).unwrap();

        let report = verify_package(package.path()).unwrap();
        let seal = report
            .checks
            .iter()
            .find(|check| matches!(check.subject, CheckSubject::RecordSeal { .. }))
            .unwrap();
        assert!(matches!(
            seal.outcome,
            CheckOutcome::Mismatch {
                algorithm: actual,
                ..
            } if actual == algorithm
        ));
    }
}

#[test]
fn tampered_original_fails() {
    let (package, blob_id) = write_package(b"different bytes");

    let report = verify_package(package.path()).unwrap();

    assert!(!report.passed());
    let original = report
        .checks
        .iter()
        .find(|check| matches!(&check.subject, CheckSubject::Original { blob_id: id } if *id == blob_id))
        .unwrap();
    assert!(matches!(original.outcome, CheckOutcome::Mismatch { .. }));
}

#[test]
fn missing_original_is_reported() {
    let (package, _) = write_package(b"original bytes");
    fs::remove_dir_all(package.path().join("originals")).unwrap();

    let report = verify_package(package.path()).unwrap();

    assert!(!report.passed());
    assert!(
        report
            .checks
            .iter()
            .any(|check| matches!(check.outcome, CheckOutcome::Missing))
    );
}

#[test]
fn unordered_content_keys_still_verify() {
    let (package, _) = write_package(b"original bytes");
    let manifest_path = package.path().join("manifest.json");
    let reordered = fs::read_to_string(&manifest_path)
        .unwrap()
        .replace(r#"{"a":1,"b":"two"}"#, r#"{"b":"two","a":1}"#);
    fs::write(&manifest_path, reordered).unwrap();

    let report = verify_package(package.path()).unwrap();

    assert!(report.passed());
}

#[test]
fn missing_manifest_is_an_error() {
    let package = tempdir().unwrap();

    assert!(verify_package(package.path()).is_err());
}

#[test]
fn invalid_uuid_forms_are_rejected() {
    for invalid in [
        "not-a-uuid",
        "550e8400-e29b-11d4-a716-446655440000",
        "550e8400-e29b-41d4-c716-446655440000",
    ] {
        let (package, _) = write_package(b"original bytes");
        let manifest_path = package.path().join("manifest.json");
        let manifest = fs::read_to_string(&manifest_path)
            .unwrap()
            .replace("550e8400-e29b-41d4-a716-446655440000", invalid);
        fs::write(&manifest_path, manifest).unwrap();

        assert!(matches!(
            verify_package(package.path()),
            Err(VerifyError::IdentifierInvalid)
        ));
    }
}

/// Unsupported composition nodes make the manifest structurally invalid.
#[test]
fn unsupported_composition_nodes_are_rejected() {
    let (package, _) = write_package(b"original bytes");
    let manifest_path = package.path().join("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();
    manifest["composition"][0] = serde_json::json!({"type": "unsupported"});
    fs::write(&manifest_path, manifest.to_string()).unwrap();

    assert!(verify_package(package.path()).is_err());
}

/// Record identifiers are unique within one manifest.
#[test]
fn duplicate_manifest_record_ids_are_rejected() {
    let (package, _) = write_package(b"original bytes");
    let manifest_path = package.path().join("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();
    let duplicate = manifest["records"][0].clone();
    manifest["records"].as_array_mut().unwrap().push(duplicate);
    fs::write(&manifest_path, manifest.to_string()).unwrap();

    assert!(verify_package(package.path()).is_err());
}

/// Every selected identifier resolves to a record in the manifest.
#[test]
fn selected_record_ids_must_resolve() {
    let (package, _) = write_package(b"original bytes");
    let manifest_path = package.path().join("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();
    manifest["selected_record_ids"][0] = "f47ac10b-58cc-4372-a567-0e02b2c3d479".into();
    fs::write(&manifest_path, manifest.to_string()).unwrap();

    assert!(verify_package(package.path()).is_err());
}

/// Imported-table source metadata resolves to an attachment manifest record.
#[test]
fn table_source_attachment_ids_must_resolve() {
    let (package, _) = write_package(b"original bytes");
    let mut content = table_content(&["k3nq7pv2"]);
    content["source"] = serde_json::json!({
        "attachment_record_id": "0c1d98ad-ef18-4f86-a2f4-74f220f546bf",
        "delimiter": ",",
        "first_row_as_header": true,
        "parser_version": 1,
    });
    set_record_content(&package, "table", content);

    assert!(verify_package(package.path()).is_err());
}

#[test]
fn invalid_conversation_message_id_is_rejected() {
    let (package, _) = write_package(b"original bytes");
    set_record_content(
        &package,
        "conversation",
        serde_json::json!({"messages": [{"id": "message-1"}]}),
    );

    assert!(matches!(
        verify_package(package.path()),
        Err(VerifyError::IdentifierInvalid)
    ));
}

#[test]
fn invalid_image_annotation_id_is_rejected() {
    let (package, _) = write_package(b"original bytes");
    set_record_content(
        &package,
        "image",
        serde_json::json!({
            "blob_id": "6ba7b810-9dad-4f11-80b4-00c04fd430c8",
            "annotations": [{"id": "not-a-uuid"}],
        }),
    );

    assert!(matches!(
        verify_package(package.path()),
        Err(VerifyError::IdentifierInvalid)
    ));
}

#[test]
fn invalid_attachment_and_image_content_blob_ids_are_rejected() {
    for (record_type, content) in [
        (
            "attachment",
            serde_json::json!({"blob_id": "6BA7B810-9DAD-4F11-80B4-00C04FD430C8"}),
        ),
        (
            "image",
            serde_json::json!({"blob_id": "blob-1", "annotations": []}),
        ),
    ] {
        let (package, _) = write_package(b"original bytes");
        set_record_content(&package, record_type, content);
        assert!(matches!(
            verify_package(package.path()),
            Err(VerifyError::IdentifierInvalid)
        ));
    }
}

#[test]
fn attachment_and_image_sources_must_match_content_blob_ids() {
    let other_blob_id = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
    for (record_type, content) in [
        ("attachment", serde_json::json!({"blob_id": other_blob_id})),
        (
            "image",
            serde_json::json!({"blob_id": other_blob_id, "annotations": []}),
        ),
    ] {
        let (package, _) = write_package(b"original bytes");
        set_record_content(&package, record_type, content);

        assert!(matches!(
            verify_package(package.path()),
            Err(VerifyError::SourceBindingInvalid)
        ));
    }
}

#[test]
fn attachment_and_image_sources_are_required() {
    for (record_type, content) in [
        (
            "attachment",
            serde_json::json!({"blob_id": "6ba7b810-9dad-4f11-80b4-00c04fd430c8"}),
        ),
        (
            "image",
            serde_json::json!({
                "blob_id": "6ba7b810-9dad-4f11-80b4-00c04fd430c8",
                "annotations": [],
            }),
        ),
    ] {
        let (package, _) = write_package(b"original bytes");
        set_record_content(&package, record_type, content);
        let manifest_path = package.path().join("manifest.json");
        let mut manifest: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();
        manifest["records"][0]["source"] = serde_json::Value::Null;
        fs::write(&manifest_path, manifest.to_string()).unwrap();

        assert!(matches!(
            verify_package(package.path()),
            Err(VerifyError::SourceBindingInvalid)
        ));
    }
}

#[test]
fn conflicting_hashes_for_one_source_are_rejected() {
    let (package, _) = write_package(b"original bytes");
    let manifest_path = package.path().join("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();
    let mut conflicting_record = manifest["records"][0].clone();
    conflicting_record["id"] = "f47ac10b-58cc-4372-a567-0e02b2c3d479".into();
    conflicting_record["source"]["hashes"]["sha256"] = "different".into();
    manifest["records"]
        .as_array_mut()
        .unwrap()
        .push(conflicting_record);
    fs::write(&manifest_path, manifest.to_string()).unwrap();

    assert!(matches!(
        verify_package(package.path()),
        Err(VerifyError::SourceDeclarationConflict)
    ));
}

/// Canonical table content with the given column IDs and one matching row.
fn table_content(column_ids: &[&str]) -> serde_json::Value {
    serde_json::json!({
        "title": "Findings",
        "header_row": true,
        "columns": column_ids
            .iter()
            .map(|id| serde_json::json!({"id": id, "name": "Claim"}))
            .collect::<Vec<_>>(),
        "rows": [column_ids.iter().map(|_| "cell").collect::<Vec<_>>()],
    })
}

#[test]
fn sealed_table_package_verifies() {
    let (package, _) = write_package(b"original bytes");
    set_record_content(&package, "table", table_content(&["k3nq7pv2", "b8xr2mtq"]));
    let manifest_path = package.path().join("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();
    let canonical = canonical_json(&manifest["records"][0]["content"]).unwrap();
    let (sha256, blake3) = hash_bytes(&canonical);
    manifest["records"][0]["content_hashes"] =
        serde_json::json!({"sha256": sha256, "blake3": blake3});
    fs::write(&manifest_path, manifest.to_string()).unwrap();
    seal_record(&package);

    let report = verify_package(package.path()).expect("a sealed table package verifies");

    assert!(report.passed(), "{report:?}");
}

#[test]
fn tampered_table_content_fails_verification() {
    let (package, _) = write_package(b"original bytes");
    set_record_content(&package, "table", table_content(&["k3nq7pv2"]));
    seal_record(&package);

    // Rewrite one cell without touching the declared hashes.
    let manifest_path = package.path().join("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();
    manifest["records"][0]["content"]["rows"][0][0] = "altered".into();
    fs::write(&manifest_path, manifest.to_string()).unwrap();

    let report = verify_package(package.path()).expect("verification runs");

    assert!(!report.passed());
}

#[test]
fn malformed_or_repeated_table_column_ids_are_rejected() {
    for column_ids in [
        vec!["short"],
        vec!["k3nq7pv-"],
        vec!["k3nq7pv2", "k3nq7pv2"],
    ] {
        let (package, _) = write_package(b"original bytes");
        set_record_content(&package, "table", table_content(&column_ids));

        assert!(
            matches!(
                verify_package(package.path()),
                Err(VerifyError::TableColumnIdentifierInvalid)
            ),
            "{column_ids:?}"
        );
    }
}

/// An imported table names its source attachment. A malformed identifier is
/// rejected before any hash is reported as verified.
#[test]
fn malformed_table_source_attachment_id_is_rejected() {
    let (package, _) = write_package(b"original bytes");
    let mut content = table_content(&["k3nq7pv2"]);
    content["source"] = serde_json::json!({
        "attachment_record_id": "not-a-uuid",
        "delimiter": ",",
        "first_row_as_header": true,
        "parser_version": 1,
    });
    set_record_content(&package, "table", content);

    assert!(matches!(
        verify_package(package.path()),
        Err(VerifyError::IdentifierInvalid)
    ));
}

/// The verifier accepts the closed source shape and rejects missing, unknown,
/// unsupported, or inconsistent parser metadata.
#[test]
fn table_source_metadata_is_closed_and_validated() {
    let valid_source = serde_json::json!({
        "attachment_record_id": "0c1d98ad-ef18-4f86-a2f4-74f220f546bf",
        "delimiter": ",",
        "first_row_as_header": true,
        "parser_version": 1,
    });
    let (valid_package, _) = write_package(b"original bytes");
    let mut valid_content = table_content(&["k3nq7pv2"]);
    valid_content["source"] = valid_source.clone();
    set_record_content(&valid_package, "table", valid_content);
    let manifest_path = valid_package.path().join("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();
    let source = manifest["records"][0]["source"].clone();
    let blob_id = source["blob_id"].as_str().unwrap();
    let content = serde_json::json!({"blob_id": blob_id});
    let canonical = canonical_json(&content).unwrap();
    let (sha256, blake3) = hash_bytes(&canonical);
    manifest["records"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({
            "id": "0c1d98ad-ef18-4f86-a2f4-74f220f546bf",
            "type": "attachment",
            "content": content,
            "content_hashes": {"sha256": sha256, "blake3": blake3},
            "source": source,
        }));
    fs::write(&manifest_path, manifest.to_string()).unwrap();
    assert!(verify_package(valid_package.path()).is_ok());

    let mut missing_delimiter = valid_source.clone();
    missing_delimiter
        .as_object_mut()
        .unwrap()
        .remove("delimiter");
    let mut unknown_field = valid_source.clone();
    unknown_field["locale"] = "en".into();
    let mut unsupported_delimiter = valid_source.clone();
    unsupported_delimiter["delimiter"] = "|".into();
    let mut unsupported_version = valid_source.clone();
    unsupported_version["parser_version"] = 2.into();
    let invalid_sources = [
        missing_delimiter,
        unknown_field,
        unsupported_delimiter,
        unsupported_version,
    ];

    for source in invalid_sources {
        let (package, _) = write_package(b"original bytes");
        let mut content = table_content(&["k3nq7pv2"]);
        content["source"] = source.clone();
        set_record_content(&package, "table", content);
        assert!(verify_package(package.path()).is_err(), "{source}");
    }
}

/// A source claim that omits BLAKE3 is incomplete. The verifier must reject the
/// manifest rather than report success after checking only SHA-256.
#[test]
fn source_claim_without_blake3_is_rejected() {
    let (package, _) = write_package(b"original bytes");
    let manifest_path = package.path().join("manifest.json");
    let manifest = fs::read_to_string(&manifest_path).unwrap();

    let mut document: serde_json::Value = serde_json::from_str(&manifest).unwrap();
    document["records"][0]["source"]["hashes"]
        .as_object_mut()
        .unwrap()
        .remove("blake3");
    fs::write(&manifest_path, document.to_string()).unwrap();

    assert!(matches!(
        verify_package(package.path()),
        Err(VerifyError::ManifestInvalid(_))
    ));
}

/// Two files sharing one blob id prefix are ambiguous. Taking the first match
/// would silently pick one, so the package fails instead.
#[test]
fn duplicate_originals_for_one_source_are_rejected() {
    let (package, blob_id) = write_package(b"original bytes");
    fs::write(
        package
            .path()
            .join("originals")
            .join(format!("{blob_id}-second.txt")),
        b"original bytes",
    )
    .unwrap();

    assert!(matches!(
        verify_package(package.path()),
        Err(VerifyError::OriginalsEntryDuplicate)
    ));
}

/// A symlink is not an included original. It must fail without being followed,
/// so a package cannot point verification outside itself.
#[cfg(unix)]
#[test]
fn symlinked_original_is_rejected() {
    let (package, blob_id) = write_package(b"original bytes");
    let originals = package.path().join("originals");
    let target = package.path().join("outside.txt");
    fs::write(&target, b"original bytes").unwrap();
    fs::remove_file(originals.join(format!("{blob_id}-source.txt"))).unwrap();
    std::os::unix::fs::symlink(&target, originals.join(format!("{blob_id}-source.txt"))).unwrap();

    assert!(matches!(
        verify_package(package.path()),
        Err(VerifyError::OriginalsEntryInvalid)
    ));
}

/// The originals directory itself cannot redirect verification outside the package.
#[cfg(unix)]
#[test]
fn symlinked_originals_directory_is_rejected() {
    let (package, blob_id) = write_package(b"original bytes");
    let originals = package.path().join("originals");
    let outside = tempdir().unwrap();
    fs::write(
        outside.path().join(format!("{blob_id}-source.txt")),
        b"original bytes",
    )
    .unwrap();
    fs::remove_dir_all(&originals).unwrap();
    std::os::unix::fs::symlink(outside.path(), &originals).unwrap();

    assert!(matches!(
        verify_package(package.path()),
        Err(VerifyError::OriginalsEntryInvalid)
    ));
}

/// An existing originals path must be a directory.
#[test]
fn originals_path_must_be_a_directory() {
    let (package, _) = write_package(b"original bytes");
    let originals = package.path().join("originals");
    fs::remove_dir_all(&originals).unwrap();
    fs::write(&originals, b"not a directory").unwrap();

    assert!(matches!(
        verify_package(package.path()),
        Err(VerifyError::OriginalsEntryInvalid)
    ));
}

/// `originals/` holds included originals and nothing else. An entry that is
/// not named for a blob id cannot be bound to a source claim.
#[test]
fn unrecognized_originals_entry_is_rejected() {
    let (package, _) = write_package(b"original bytes");
    fs::write(package.path().join("originals").join("notes.txt"), b"x").unwrap();

    assert!(matches!(
        verify_package(package.path()),
        Err(VerifyError::OriginalsEntryInvalid)
    ));
}

/// Rejects validly named originals that have no source declaration.
#[test]
fn undeclared_original_is_rejected() {
    for without_sources in [false, true] {
        let (package, _) = write_package(b"original bytes");
        if without_sources {
            let manifest_path = package.path().join("manifest.json");
            let mut manifest: serde_json::Value =
                serde_json::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();
            manifest["records"][0]["source"] = serde_json::Value::Null;
            fs::write(&manifest_path, manifest.to_string()).unwrap();
        }
        fs::write(
            package
                .path()
                .join("originals")
                .join("f47ac10b-58cc-4372-a567-0e02b2c3d479-extra.txt"),
            b"undeclared bytes",
        )
        .unwrap();

        assert!(matches!(
            verify_package(package.path()),
            Err(VerifyError::OriginalsEntryInvalid)
        ));
    }
}
