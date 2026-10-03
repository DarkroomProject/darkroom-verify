use std::collections::{HashMap, HashSet};

use serde::Deserialize;
use uuid::{Uuid, Variant, Version};

use crate::{VerifyError, integrity::canonical_json};

const TABLE_MAX_CELL_BYTES: usize = 256 * 1024;
const TABLE_MAX_CELLS: usize = 50_000;
const TABLE_MAX_COLUMNS: usize = 256;
const TABLE_MAX_CONTENT_BYTES: usize = 5 * 1024 * 1024;
const TABLE_COLUMN_ID_LEN: usize = 8;
const TABLE_PARSER_VERSION: u32 = 1;

#[derive(Deserialize)]
pub(super) struct Manifest {
    pub(super) schema_version: u8,
    file: ManifestFile,
    composition: Vec<ManifestCompositionNode>,
    selected_record_ids: Vec<String>,
    excluded_record_ids: Vec<String>,
    pub(super) records: Vec<ManifestRecord>,
}

#[derive(Deserialize)]
struct ManifestFile {
    id: String,
}

#[derive(Deserialize)]
pub(super) struct ManifestRecord {
    pub(super) id: String,
    #[serde(rename = "type")]
    pub(super) record_type: ManifestRecordType,
    pub(super) content: serde_json::Value,
    pub(super) content_hashes: ManifestHashPair,
    pub(super) sealed: Option<ManifestSealed>,
    pub(super) source: Option<ManifestSource>,
}

#[derive(Deserialize)]
pub(super) struct ManifestSealed {
    #[serde(rename = "at")]
    _at: i64,
    pub(super) sha256: String,
    pub(super) blake3: String,
}

#[derive(Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(super) enum ManifestRecordType {
    Attachment,
    Contact,
    Conversation,
    Image,
    Place,
    Table,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum ManifestCompositionNode {
    Paragraph {
        children: Vec<ManifestCompositionNode>,
    },
    Text {
        #[serde(rename = "text")]
        _text: String,
        #[serde(rename = "styles")]
        _styles: Vec<ManifestTextStyle>,
    },
    Link {
        #[serde(rename = "url")]
        _url: String,
        children: Vec<ManifestCompositionNode>,
    },
    LineBreak,
    Heading {
        #[serde(rename = "level")]
        _level: u8,
        children: Vec<ManifestCompositionNode>,
    },
    List {
        #[serde(rename = "kind")]
        _kind: ManifestListKind,
        #[serde(rename = "start")]
        _start: Option<u64>,
        children: Vec<ManifestCompositionNode>,
    },
    ListItem {
        #[serde(rename = "value")]
        _value: Option<u64>,
        #[serde(rename = "checked")]
        _checked: Option<bool>,
        children: Vec<ManifestCompositionNode>,
    },
    Divider {
        #[serde(rename = "title")]
        _title: String,
        #[serde(rename = "alignment")]
        _alignment: ManifestDividerAlignment,
        #[serde(rename = "thickness")]
        _thickness: ManifestDividerThickness,
        #[serde(rename = "text_color")]
        _text_color: Option<ManifestBlockColor>,
        #[serde(rename = "line_color")]
        _line_color: Option<ManifestBlockColor>,
    },
    RecordReference {
        record_id: String,
    },
}

impl ManifestCompositionNode {
    /// Adds every nested record reference to the supplied set.
    fn collect_record_ids<'a>(&'a self, record_ids: &mut HashSet<&'a str>) {
        match self {
            Self::Paragraph { children }
            | Self::Link { children, .. }
            | Self::Heading { children, .. }
            | Self::List { children, .. }
            | Self::ListItem { children, .. } => {
                for child in children {
                    child.collect_record_ids(record_ids);
                }
            }
            Self::RecordReference { record_id } => {
                record_ids.insert(record_id);
            }
            Self::Text { .. } | Self::LineBreak | Self::Divider { .. } => {}
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum ManifestTextStyle {
    Bold,
    Italic,
    Strikethrough,
    Underline,
    Code,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum ManifestListKind {
    Bullet,
    Number,
    Check,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum ManifestDividerAlignment {
    None,
    Left,
    Center,
    Right,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum ManifestDividerThickness {
    Sm,
    Md,
    Lg,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum ManifestBlockColor {
    Rust,
    Gold,
    Moss,
    Sky,
    Violet,
    Pink,
    Gray,
}

impl ManifestRecordType {
    /// Return the manifest string used by the shared Seal preimage.
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Attachment => "attachment",
            Self::Contact => "contact",
            Self::Conversation => "conversation",
            Self::Image => "image",
            Self::Place => "place",
            Self::Table => "table",
        }
    }
}

#[derive(Deserialize)]
struct AttachmentContentIds {
    blob_id: String,
}

#[derive(Deserialize)]
struct ImageContentIds {
    blob_id: String,
    annotations: Vec<NestedId>,
}

#[derive(Deserialize)]
struct ConversationContentIds {
    messages: Vec<NestedId>,
}

#[derive(Deserialize)]
struct NestedId {
    id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TableContent {
    #[serde(rename = "title")]
    _title: Option<String>,

    #[serde(rename = "header_row")]
    _header_row: bool,

    columns: Vec<TableColumn>,
    rows: Vec<Vec<String>>,
    source: Option<TableSourceIds>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TableColumn {
    id: String,

    #[serde(rename = "name")]
    _name: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TableSourceIds {
    attachment_record_id: String,

    #[serde(rename = "delimiter")]
    _delimiter: TableDelimiter,

    #[serde(rename = "first_row_as_header")]
    _first_row_as_header: bool,

    parser_version: u32,
}

#[derive(Clone, Copy, Deserialize)]
enum TableDelimiter {
    #[serde(rename = ",")]
    Comma,

    #[serde(rename = ";")]
    Semicolon,

    #[serde(rename = "\t")]
    Tab,
}

#[derive(Deserialize)]
pub(super) struct ManifestHashPair {
    pub(super) sha256: String,
    pub(super) blake3: String,
}

#[derive(Deserialize)]
pub(super) struct ManifestSource {
    pub(super) blob_id: String,
    pub(super) hashes: ManifestSourceHashes,
}

#[derive(Deserialize, PartialEq, Eq)]
pub(super) struct ManifestSourceHashes {
    pub(super) sha256: String,
    /// Required. A claim without both hashes is an incomplete claim, and the
    /// verifier must not report success after checking only half of it.
    pub(super) blake3: String,
}

pub(super) fn validate_manifest_ids(manifest: &Manifest) -> Result<(), VerifyError> {
    validate_uuid_v4(&manifest.file.id)?;
    for id in manifest
        .selected_record_ids
        .iter()
        .chain(&manifest.excluded_record_ids)
        .chain(manifest.records.iter().map(|record| &record.id))
        .chain(
            manifest
                .records
                .iter()
                .filter_map(|record| record.source.as_ref().map(|source| &source.blob_id)),
        )
    {
        validate_uuid_v4(id)?;
    }

    for record in &manifest.records {
        validate_record_content_ids(record)?;
    }

    validate_manifest_relationships(manifest)
}

/// Validates manifest identifier uniqueness and cross-references.
fn validate_manifest_relationships(manifest: &Manifest) -> Result<(), VerifyError> {
    let mut record_types = HashMap::new();
    for record in &manifest.records {
        if record_types
            .insert(record.id.as_str(), record.record_type)
            .is_some()
        {
            return Err(VerifyError::ManifestStructureInvalid);
        }
    }

    let selected = unique_ids(&manifest.selected_record_ids)?;
    let excluded = unique_ids(&manifest.excluded_record_ids)?;
    if !selected.is_disjoint(&excluded) || selected.iter().any(|id| !record_types.contains_key(id))
    {
        return Err(VerifyError::ManifestStructureInvalid);
    }

    let mut composition = HashSet::new();
    for node in &manifest.composition {
        node.collect_record_ids(&mut composition);
    }

    for record_id in &composition {
        validate_uuid_v4(record_id)?;
    }

    if composition != selected {
        return Err(VerifyError::ManifestStructureInvalid);
    }

    for record in &manifest.records {
        if record.record_type != ManifestRecordType::Table {
            continue;
        }

        let content: TableContent = serde_json::from_value(record.content.clone())
            .map_err(|_| VerifyError::TableContentInvalid)?;
        if let Some(source) = content.source
            && record_types.get(source.attachment_record_id.as_str())
                != Some(&ManifestRecordType::Attachment)
        {
            return Err(VerifyError::ManifestStructureInvalid);
        }
    }

    Ok(())
}

/// Builds a set and rejects repeated identifiers.
fn unique_ids(ids: &[String]) -> Result<HashSet<&str>, VerifyError> {
    let unique = ids.iter().map(String::as_str).collect::<HashSet<_>>();
    if unique.len() != ids.len() {
        return Err(VerifyError::ManifestStructureInvalid);
    }

    Ok(unique)
}

fn validate_record_content_ids(record: &ManifestRecord) -> Result<(), VerifyError> {
    match record.record_type {
        ManifestRecordType::Attachment => {
            let content: AttachmentContentIds = serde_json::from_value(record.content.clone())
                .map_err(VerifyError::ManifestInvalid)?;
            validate_uuid_v4(&content.blob_id)?;
            validate_source_binding(record, &content.blob_id)
        }
        ManifestRecordType::Image => {
            let content: ImageContentIds = serde_json::from_value(record.content.clone())
                .map_err(VerifyError::ManifestInvalid)?;

            validate_uuid_v4(&content.blob_id)?;

            for annotation in content.annotations {
                validate_uuid_v4(&annotation.id)?;
            }

            validate_source_binding(record, &content.blob_id)
        }
        ManifestRecordType::Conversation => {
            let content: ConversationContentIds = serde_json::from_value(record.content.clone())
                .map_err(VerifyError::ManifestInvalid)?;

            for message in content.messages {
                validate_uuid_v4(&message.id)?;
            }

            Ok(())
        }
        ManifestRecordType::Table => {
            let canonical =
                canonical_json(&record.content).map_err(|_| VerifyError::TableContentInvalid)?;
            if canonical.len() > TABLE_MAX_CONTENT_BYTES {
                return Err(VerifyError::TableContentInvalid);
            }

            let content: TableContent = serde_json::from_value(record.content.clone())
                .map_err(|_| VerifyError::TableContentInvalid)?;
            if content.columns.is_empty() || content.columns.len() > TABLE_MAX_COLUMNS {
                return Err(VerifyError::TableContentInvalid);
            }

            let mut seen = HashSet::new();
            for column in &content.columns {
                if !valid_table_column_id(&column.id) || !seen.insert(column.id.as_str()) {
                    return Err(VerifyError::TableColumnIdentifierInvalid);
                }
            }

            if !valid_table_rows(&content.rows, content.columns.len()) {
                return Err(VerifyError::TableContentInvalid);
            }

            match &content.source {
                Some(source) => validate_table_source(source),
                None => Ok(()),
            }
        }

        ManifestRecordType::Contact | ManifestRecordType::Place => Ok(()),
    }
}

/// Validates imported-table source identity and parser version.
fn validate_table_source(source: &TableSourceIds) -> Result<(), VerifyError> {
    validate_uuid_v4(&source.attachment_record_id)?;
    if source.parser_version != TABLE_PARSER_VERSION {
        return Err(VerifyError::TableSourceInvalid);
    }

    Ok(())
}

/// Checks table rows against the rectangular shape and stored content limits.
fn valid_table_rows(rows: &[Vec<String>], column_count: usize) -> bool {
    let within_cell_limit = rows
        .len()
        .checked_mul(column_count)
        .is_some_and(|cells| cells <= TABLE_MAX_CELLS);

    within_cell_limit
        && rows.iter().all(|row| {
            row.len() == column_count && row.iter().all(|cell| cell.len() <= TABLE_MAX_CELL_BYTES)
        })
}

/// Checks the fixed-width lowercase identifier used by table columns.
fn valid_table_column_id(id: &str) -> bool {
    id.len() == TABLE_COLUMN_ID_LEN
        && id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
}

fn validate_source_binding(
    record: &ManifestRecord,
    content_blob_id: &str,
) -> Result<(), VerifyError> {
    match &record.source {
        Some(source) if source.blob_id == content_blob_id => Ok(()),
        _ => Err(VerifyError::SourceBindingInvalid),
    }
}

pub(super) fn validate_source_declarations(manifest: &Manifest) -> Result<(), VerifyError> {
    let mut declared_hashes = HashMap::new();
    for source in manifest
        .records
        .iter()
        .filter_map(|record| record.source.as_ref())
    {
        if let Some(hashes) = declared_hashes.insert(&source.blob_id, &source.hashes)
            && hashes != &source.hashes
        {
            return Err(VerifyError::SourceDeclarationConflict);
        }
    }

    Ok(())
}

pub(super) fn validate_uuid_v4(value: &str) -> Result<(), VerifyError> {
    let uuid = Uuid::parse_str(value).map_err(|_| VerifyError::IdentifierInvalid)?;
    if uuid.get_version() != Some(Version::Random)
        || uuid.get_variant() != Variant::RFC4122
        || uuid.to_string() != value
    {
        return Err(VerifyError::IdentifierInvalid);
    }

    Ok(())
}
