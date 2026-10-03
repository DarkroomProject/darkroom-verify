use std::{collections::HashSet, fs, path::Path};

use integrity::{canonical_json, compare, hash_bytes, record_seal_hashes};
use manifest::{Manifest, ManifestRecord, validate_manifest_ids, validate_source_declarations};
use originals::{OriginalsInventory, verify_original};

#[cfg(test)]
use integrity::{dual_hash, record_seal_preimage};

mod integrity;
mod manifest;
mod originals;

const MANIFEST_FILENAME: &str = "manifest.json";

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("manifest.json not found in package")]
    ManifestMissing,

    #[error("manifest.json could not be read")]
    ManifestUnreadable(#[source] std::io::Error),

    #[error("manifest.json is not a valid export manifest")]
    ManifestInvalid(#[source] serde_json::Error),

    #[error("manifest.json contains an invalid UUIDv4 identifier")]
    IdentifierInvalid,

    #[error("manifest.json contains invalid record relationships")]
    ManifestStructureInvalid,

    #[error("manifest.json contains an invalid or repeated table column identifier")]
    TableColumnIdentifierInvalid,

    #[error("manifest.json contains invalid table content")]
    TableContentInvalid,

    #[error("manifest.json contains invalid table source metadata")]
    TableSourceInvalid,

    #[error("manifest.json source does not match its record content")]
    SourceBindingInvalid,

    #[error("manifest.json contains conflicting hashes for one source")]
    SourceDeclarationConflict,

    #[error("manifest.json uses an unsupported schema version")]
    ManifestVersionUnsupported,

    #[error("originals/ contains an entry that is not an included original")]
    OriginalsEntryInvalid,

    #[error("originals/ contains more than one file for one source")]
    OriginalsEntryDuplicate,

    #[error("originals/ could not be read")]
    OriginalsDirectoryUnreadable(#[source] std::io::Error),
}

#[derive(Debug, Clone)]
pub struct HashPairReport {
    pub sha256: String,
    pub blake3: String,
}

#[derive(Debug, Clone)]
pub struct VerifyReport {
    /// Hashes computed over the manifest.json bytes, for comparison
    /// against the integrity document or package directory name.
    pub manifest_hashes: HashPairReport,
    pub checks: Vec<Check>,
}

impl VerifyReport {
    /// Returns true when every check verified successfully.
    pub fn passed(&self) -> bool {
        self.checks
            .iter()
            .all(|check| matches!(check.outcome, CheckOutcome::Verified))
    }
}

#[derive(Debug, Clone)]
pub struct Check {
    pub subject: CheckSubject,
    pub outcome: CheckOutcome,
}

#[derive(Debug, Clone)]
pub enum CheckSubject {
    RecordContent { record_id: String },
    RecordSeal { record_id: String },
    Original { blob_id: String },
}

#[derive(Debug, Clone)]
pub enum CheckOutcome {
    Verified,
    Mismatch { algorithm: HashAlgorithm },
    Missing,
    Unreadable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    Sha256,
    Blake3,
}

/// Verifies record content hashes and exported original hashes for one
/// export package directory.
pub fn verify_package(package_path: &Path) -> Result<VerifyReport, VerifyError> {
    let manifest_path = package_path.join(MANIFEST_FILENAME);
    if !manifest_path.is_file() {
        return Err(VerifyError::ManifestMissing);
    }

    let manifest_bytes = fs::read(&manifest_path).map_err(VerifyError::ManifestUnreadable)?;
    let manifest: Manifest =
        serde_json::from_slice(&manifest_bytes).map_err(VerifyError::ManifestInvalid)?;
    if manifest.schema_version != 1 {
        return Err(VerifyError::ManifestVersionUnsupported);
    }

    validate_manifest_ids(&manifest)?;
    validate_source_declarations(&manifest)?;

    let (sha256, blake3) = hash_bytes(&manifest_bytes);
    let manifest_hashes = HashPairReport { sha256, blake3 };

    let mut checks = Vec::new();

    for record in &manifest.records {
        checks.push(Check {
            subject: CheckSubject::RecordContent {
                record_id: record.id.clone(),
            },
            outcome: verify_record_content(record),
        });

        if record.sealed.is_some() {
            checks.push(Check {
                subject: CheckSubject::RecordSeal {
                    record_id: record.id.clone(),
                },
                outcome: verify_record_seal(record),
            });
        }
    }

    let mut source_blob_ids: HashSet<_> = manifest
        .records
        .iter()
        .filter_map(|record| record.source.as_ref())
        .map(|source| source.blob_id.as_str())
        .collect();
    let originals = OriginalsInventory::read(package_path, &source_blob_ids)?;
    for source in manifest.records.iter().filter_map(|r| r.source.as_ref()) {
        if !source_blob_ids.remove(source.blob_id.as_str()) {
            continue;
        }

        checks.push(Check {
            subject: CheckSubject::Original {
                blob_id: source.blob_id.clone(),
            },
            outcome: verify_original(&originals, source),
        });
    }

    Ok(VerifyReport {
        manifest_hashes,
        checks,
    })
}

/// Recomputes hashes over the record's canonical content JSON.
fn verify_record_content(record: &ManifestRecord) -> CheckOutcome {
    let canonical = canonical_json(&record.content).expect("manifest content must canonicalize");
    let (sha256, blake3) = hash_bytes(&canonical);

    compare(
        &record.content_hashes.sha256,
        &sha256,
        &record.content_hashes.blake3,
        &blake3,
    )
}

/// Recompute and compare both stored record Seal digests.
fn verify_record_seal(record: &ManifestRecord) -> CheckOutcome {
    let sealed = record.sealed.as_ref().expect("caller checks Sealed state");
    let hashes = record_seal_hashes(&record.id, record.record_type.as_str(), &record.content)
        .expect("manifest content must canonicalize");

    compare(
        &sealed.sha256,
        &hashes.sha256,
        &sealed.blake3,
        &hashes.blake3,
    )
}

#[cfg(test)]
mod tests;
