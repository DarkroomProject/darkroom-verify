use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
};

use crate::{
    CheckOutcome, VerifyError,
    integrity::{compare, dual_hash},
    manifest::{ManifestSource, validate_uuid_v4},
};

const ORIGINALS_DIRECTORY: &str = "originals";
/// Length of a hyphenated UUID in text form.
const UUID_TEXT_LEN: usize = 36;

/// One validated entry per blob id, built from `originals/` exactly once.
///
/// Building it up front turns filesystem ambiguity into an explicit failure:
/// a per-source scan that takes the first prefix match cannot tell one
/// candidate from two.
pub(super) struct OriginalsInventory {
    entries: HashMap<String, PathBuf>,
}

impl OriginalsInventory {
    /// Reads `originals/` once. An absent directory is empty, not an error;
    /// each declared source then reports `Missing` on its own.
    pub(super) fn read(
        package_path: &Path,
        declared_blob_ids: &HashSet<&str>,
    ) -> Result<Self, VerifyError> {
        let directory = package_path.join(ORIGINALS_DIRECTORY);
        let mut entries: HashMap<String, PathBuf> = HashMap::new();

        let metadata = match fs::symlink_metadata(&directory) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self { entries });
            }
            Err(error) => return Err(VerifyError::OriginalsDirectoryUnreadable(error)),
        };
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(VerifyError::OriginalsEntryInvalid);
        }

        let listing =
            fs::read_dir(&directory).map_err(VerifyError::OriginalsDirectoryUnreadable)?;

        for entry in listing {
            let entry = entry.map_err(|_| VerifyError::OriginalsEntryInvalid)?;
            let path = entry.path();

            // `symlink_metadata` does not follow links, so a symlink fails here
            // instead of silently resolving outside the package.
            let metadata =
                fs::symlink_metadata(&path).map_err(|_| VerifyError::OriginalsEntryInvalid)?;
            if !metadata.is_file() {
                return Err(VerifyError::OriginalsEntryInvalid);
            }

            let blob_id = parse_original_blob_id(&path)?;
            if !declared_blob_ids.contains(blob_id.as_str()) {
                return Err(VerifyError::OriginalsEntryInvalid);
            }
            if entries.insert(blob_id, path).is_some() {
                return Err(VerifyError::OriginalsEntryDuplicate);
            }
        }

        Ok(Self { entries })
    }

    /// Returns the one file declared for `blob_id`, if the package includes it.
    fn get(&self, blob_id: &str) -> Option<&Path> {
        self.entries.get(blob_id).map(PathBuf::as_path)
    }
}

/// Hashes the included original bound to this source blob id.
pub(super) fn verify_original(
    originals: &OriginalsInventory,
    source: &ManifestSource,
) -> CheckOutcome {
    let Some(path) = originals.get(&source.blob_id) else {
        return CheckOutcome::Missing;
    };

    let Ok(mut reader) = fs::File::open(path) else {
        return CheckOutcome::Unreadable;
    };
    let Ok((sha256, blake3)) = dual_hash(&mut reader) else {
        return CheckOutcome::Unreadable;
    };

    compare(
        &source.hashes.sha256,
        &sha256,
        &source.hashes.blake3,
        &blake3,
    )
}

/// Reads the blob id from an `originals/` filename, which the exporter writes
/// as `{blob_id}-{sanitized name}`. Any other shape is rejected.
fn parse_original_blob_id(path: &Path) -> Result<String, VerifyError> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(VerifyError::OriginalsEntryInvalid)?;

    let blob_id = name
        .get(..UUID_TEXT_LEN)
        .ok_or(VerifyError::OriginalsEntryInvalid)?;

    if name.as_bytes().get(UUID_TEXT_LEN) != Some(&b'-') {
        return Err(VerifyError::OriginalsEntryInvalid);
    }

    validate_uuid_v4(blob_id)?;

    Ok(blob_id.to_string())
}
