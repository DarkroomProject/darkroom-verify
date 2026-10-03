use std::io::{Cursor, Read};

use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{CheckOutcome, HashAlgorithm, HashPairReport};

#[derive(Serialize)]
struct RecordSealPreimage<'a> {
    record_id: &'a str,
    record_type: &'a str,
    evidentiary_content: &'a Value,
}

pub(super) fn compare(
    expected_sha256: &str,
    actual_sha256: &str,
    expected_blake3: &str,
    actual_blake3: &str,
) -> CheckOutcome {
    if expected_sha256 != actual_sha256 {
        return CheckOutcome::Mismatch {
            algorithm: HashAlgorithm::Sha256,
        };
    }

    if expected_blake3 != actual_blake3 {
        return CheckOutcome::Mismatch {
            algorithm: HashAlgorithm::Blake3,
        };
    }

    CheckOutcome::Verified
}

/// Streams a reader through SHA-256 and BLAKE3 in one pass.
pub(super) fn dual_hash(reader: &mut impl Read) -> Result<(String, String), std::io::Error> {
    let mut sha256 = Sha256::new();
    let mut blake3 = blake3::Hasher::new();
    let mut buffer = [0_u8; 8_192];

    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        sha256.update(&buffer[..count]);
        blake3.update(&buffer[..count]);
    }

    Ok((
        format!("{:x}", sha256.finalize()),
        blake3.finalize().to_hex().to_string(),
    ))
}

/// Serializes a value with RFC 8785 JSON canonicalization.
pub(super) fn canonical_json(value: &impl Serialize) -> serde_json::Result<Vec<u8>> {
    serde_json_canonicalizer::to_vec(value)
}

/// Builds the canonical record Seal preimage.
pub(super) fn record_seal_preimage(
    record_id: &str,
    record_type: &str,
    evidentiary_content: &Value,
) -> serde_json::Result<Vec<u8>> {
    canonical_json(&RecordSealPreimage {
        record_id,
        record_type,
        evidentiary_content,
    })
}

/// Computes both record Seal digests from the canonical preimage.
pub(super) fn record_seal_hashes(
    record_id: &str,
    record_type: &str,
    evidentiary_content: &Value,
) -> serde_json::Result<HashPairReport> {
    let preimage = record_seal_preimage(record_id, record_type, evidentiary_content)?;
    let (sha256, blake3) = dual_hash(&mut Cursor::new(preimage)).expect("Cursor reads cannot fail");

    Ok(HashPairReport { sha256, blake3 })
}

pub(super) fn hash_bytes(bytes: &[u8]) -> (String, String) {
    dual_hash(&mut Cursor::new(bytes)).expect("Cursor reads cannot fail")
}
