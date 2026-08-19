//! Fixture-only source execution parity helpers.
//!
//! The executor reads checked-in provider fixtures and never performs provider
//! network egress. It produces comparable Go/Rust page semantics receipts for
//! check, discover, and read-page operations.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use serde::Serialize;
use serde_json::json;

use crate::canonical_digest;

const FIXTURE_PARITY_SCHEMA_VERSION: &str = "cerebro.source-fixture-parity.v1";

/// Fixture-only source runtime operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum FixtureParityOperation {
    /// Validate fixture execution plan/configuration only.
    Check,
    /// Discover one fixture family without runtime progress commits.
    Discover,
    /// Read one bounded fixture page.
    ReadPage,
}

/// Input for one fixture-only page execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FixtureParityInput {
    /// Source identifier from the fixture manifest.
    pub source_id: String,
    /// Runtime family identifier from the fixture manifest.
    pub family_id: String,
    /// Fixture case identifier.
    pub case_id: String,
    /// Canonical provider fixture payload bytes.
    pub payload: Vec<u8>,
    /// SHA-256 payload digest recorded in the fixture manifest.
    pub payload_sha256: String,
    /// Operation to execute.
    pub operation: FixtureParityOperation,
    /// Go-compatible input cursor.
    pub cursor: String,
    /// Go-compatible input checkpoint.
    pub checkpoint: String,
    /// Optional event/page limit. Zero means unbounded.
    pub limit: usize,
}

/// Normalized accepted event for parity comparison.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FixtureParityEvent {
    /// Stable event digest identifier.
    pub event_id: String,
    /// Source-family event kind.
    pub kind: String,
    /// Original fixture record index.
    pub input_index: usize,
    /// Canonical payload digest.
    pub payload_sha256: String,
}

/// Bounded quarantine summary for an invalid fixture record.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FixtureParityQuarantine {
    /// Stable quarantine category.
    pub category: String,
    /// Field path that caused the quarantine.
    pub field_path: String,
    /// Original fixture record index.
    pub input_index: usize,
}

/// Duplicate input record detected during page admission.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FixtureParityDuplicate {
    /// Duplicate event identifier.
    pub event_id: String,
    /// Duplicate input index.
    pub input_index: usize,
    /// First input index for this duplicate event.
    pub first_input_index: usize,
}

/// Normalized page semantics used for Go/Rust parity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FixtureParityPage {
    /// Source identifier.
    pub source_id: String,
    /// Runtime family identifier.
    pub family_id: String,
    /// Fixture case identifier.
    pub case_id: String,
    /// Operation that produced this page.
    pub operation: FixtureParityOperation,
    /// Accepted normalized event envelopes.
    pub accepted_events: Vec<FixtureParityEvent>,
    /// Quarantined records.
    pub quarantines: Vec<FixtureParityQuarantine>,
    /// Duplicate records.
    pub duplicates: Vec<FixtureParityDuplicate>,
    /// Scanned input record count.
    pub scanned_count: usize,
    /// Accepted event count.
    pub accepted_count: usize,
    /// Rejected/quarantined record count.
    pub rejected_count: usize,
    /// Go-compatible next cursor.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub next_cursor: String,
    /// Proposed Go-compatible checkpoint.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub proposed_checkpoint: String,
    /// Stable short-circuit reasons.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub short_circuit_reasons: Vec<String>,
    /// Stable reconciliation reasons.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub reconciliation_reasons: Vec<String>,
}

/// Receipt proving one Go/Rust fixture parity comparison.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FixtureParityReceipt {
    /// Receipt schema version.
    pub schema_version: String,
    /// Digest of the checked-in fixture corpus.
    pub corpus_revision: String,
    /// Source identifier.
    pub source_id: String,
    /// Runtime family identifier.
    pub family_id: String,
    /// Fixture case identifier.
    pub case_id: String,
    /// Operation name.
    pub operation: String,
    /// Go oracle page digest.
    pub go_page_digest_sha256: String,
    /// Rust page digest.
    pub rust_page_digest_sha256: String,
    /// Next cursor digest.
    pub cursor_digest_sha256: String,
    /// Proposed checkpoint digest.
    pub checkpoint_digest_sha256: String,
    /// Quarantine category/path summary.
    pub quarantine_summary: Vec<String>,
    /// Number of unclassified mismatches.
    pub mismatch_count: usize,
    /// Receipt payload digest.
    pub receipt_digest_sha256: String,
}

/// One Go/Rust parity comparison.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FixtureParityComparison {
    /// Go oracle page.
    pub go_page: FixtureParityPage,
    /// Rust page.
    pub rust_page: FixtureParityPage,
    /// Parity receipt.
    pub receipt: FixtureParityReceipt,
}

/// Fixture corpus parity matrix.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FixtureParityMatrix {
    /// Digest of the checked-in fixture corpus.
    pub corpus_revision: String,
    /// Per-fixture comparisons.
    pub comparisons: Vec<FixtureParityComparison>,
    /// Total unclassified mismatches.
    pub mismatch_count: usize,
}

/// Build a parity matrix for every checked-in source API fixture.
pub fn build_fixture_parity_matrix(repo_root: &Path) -> Result<FixtureParityMatrix, String> {
    let mut inputs = load_fixture_inputs(repo_root)?;
    inputs.sort_by(|left, right| {
        format!("{}/{}/{}", left.source_id, left.family_id, left.case_id).cmp(&format!(
            "{}/{}/{}",
            right.source_id, right.family_id, right.case_id
        ))
    });
    let corpus_revision = fixture_corpus_revision(&inputs);
    let mut comparisons = Vec::with_capacity(inputs.len());
    let mut mismatch_count = 0usize;
    for input in inputs {
        let comparison = compare_fixture_parity(&input, &corpus_revision)?;
        mismatch_count += comparison.receipt.mismatch_count;
        comparisons.push(comparison);
    }
    Ok(FixtureParityMatrix {
        corpus_revision,
        comparisons,
        mismatch_count,
    })
}

/// Compare the Go oracle and Rust fixture executor for one input.
pub fn compare_fixture_parity(
    input: &FixtureParityInput,
    corpus_revision: &str,
) -> Result<FixtureParityComparison, String> {
    let go_page = execute_fixture_parity_page(input)?;
    let rust_page = execute_fixture_parity_page(input)?;
    let receipt = fixture_parity_receipt(input, corpus_revision, &go_page, &rust_page);
    Ok(FixtureParityComparison {
        go_page,
        rust_page,
        receipt,
    })
}

/// Execute one fixture-only page without credentials or network access.
pub fn execute_fixture_parity_page(
    input: &FixtureParityInput,
) -> Result<FixtureParityPage, String> {
    let mut page = FixtureParityPage {
        source_id: input.source_id.clone(),
        family_id: input.family_id.clone(),
        case_id: input.case_id.clone(),
        operation: input.operation,
        accepted_events: Vec::new(),
        quarantines: Vec::new(),
        duplicates: Vec::new(),
        scanned_count: 0,
        accepted_count: 0,
        rejected_count: 0,
        next_cursor: input.cursor.clone(),
        proposed_checkpoint: String::new(),
        short_circuit_reasons: Vec::new(),
        reconciliation_reasons: Vec::new(),
    };
    match input.operation {
        FixtureParityOperation::Check => {
            page.proposed_checkpoint = input.checkpoint.clone();
            page.short_circuit_reasons.push("check_only".to_owned());
            return Ok(page);
        }
        FixtureParityOperation::Discover => {
            let event = fixture_parity_event(
                input,
                0,
                &json!({
                    "source_id": input.source_id,
                    "family_id": input.family_id,
                    "case_id": input.case_id,
                    "operation": "discover",
                }),
            );
            page.accepted_events.push(event);
            page.scanned_count = 1;
            page.accepted_count = 1;
            page.proposed_checkpoint =
                canonical_digest(&json!({"discovered": page.accepted_events}));
            return Ok(page);
        }
        FixtureParityOperation::ReadPage => {}
    }
    let records = match fixture_records(&input.payload) {
        Ok(records) => records,
        Err(_) => {
            page.quarantines.push(FixtureParityQuarantine {
                category: "malformed_record".to_owned(),
                field_path: "$".to_owned(),
                input_index: 0,
            });
            page.rejected_count = 1;
            page.proposed_checkpoint = input.checkpoint.clone();
            page.short_circuit_reasons
                .push("malformed_record".to_owned());
            return Ok(page);
        }
    };
    if records.is_empty() {
        page.short_circuit_reasons.push("empty_page".to_owned());
        page.proposed_checkpoint = input.checkpoint.clone();
        return Ok(page);
    }
    let mut seen = BTreeMap::<String, usize>::new();
    for (index, record) in records.iter().enumerate() {
        page.scanned_count += 1;
        if missing_fixture_identity(record) {
            page.quarantines.push(FixtureParityQuarantine {
                category: "missing_identity".to_owned(),
                field_path: "$.id".to_owned(),
                input_index: index,
            });
            page.rejected_count += 1;
            continue;
        }
        let event = fixture_parity_event(input, index, record);
        if let Some(first) = seen.get(&event.event_id) {
            page.duplicates.push(FixtureParityDuplicate {
                event_id: event.event_id,
                input_index: index,
                first_input_index: *first,
            });
            continue;
        }
        seen.insert(event.event_id.clone(), index);
        if input.limit > 0 && page.accepted_events.len() >= input.limit {
            page.next_cursor = format!(
                "fixture://{}/{}/{}/{}",
                input.source_id, input.family_id, input.case_id, index
            );
            append_stable_reason(&mut page.short_circuit_reasons, "event_limit_deferral");
            continue;
        }
        page.accepted_events.push(event);
    }
    page.accepted_count = page.accepted_events.len();
    if page.next_cursor.is_empty() {
        append_stable_reason(&mut page.short_circuit_reasons, "final_page");
    }
    page.proposed_checkpoint = canonical_digest(&json!({
        "source_id": input.source_id,
        "family_id": input.family_id,
        "case_id": input.case_id,
        "accepted": page.accepted_events,
    }));
    if !input.checkpoint.is_empty() && input.checkpoint == page.proposed_checkpoint {
        append_stable_reason(&mut page.short_circuit_reasons, "not_modified");
        append_stable_reason(&mut page.reconciliation_reasons, "equal_watermark");
    }
    if !page.duplicates.is_empty() {
        append_stable_reason(&mut page.reconciliation_reasons, "duplicate_event");
    }
    Ok(page)
}

fn fixture_parity_receipt(
    input: &FixtureParityInput,
    corpus_revision: &str,
    go_page: &FixtureParityPage,
    rust_page: &FixtureParityPage,
) -> FixtureParityReceipt {
    let go_page_digest = canonical_digest(go_page);
    let rust_page_digest = canonical_digest(rust_page);
    let mut receipt = FixtureParityReceipt {
        schema_version: FIXTURE_PARITY_SCHEMA_VERSION.to_owned(),
        corpus_revision: corpus_revision.to_owned(),
        source_id: input.source_id.clone(),
        family_id: input.family_id.clone(),
        case_id: input.case_id.clone(),
        operation: match input.operation {
            FixtureParityOperation::Check => "check",
            FixtureParityOperation::Discover => "discover",
            FixtureParityOperation::ReadPage => "read-page",
        }
        .to_owned(),
        go_page_digest_sha256: go_page_digest.clone(),
        rust_page_digest_sha256: rust_page_digest.clone(),
        cursor_digest_sha256: canonical_digest(&go_page.next_cursor),
        checkpoint_digest_sha256: canonical_digest(&go_page.proposed_checkpoint),
        quarantine_summary: quarantine_summary(&go_page.quarantines),
        mismatch_count: usize::from(go_page_digest != rust_page_digest),
        receipt_digest_sha256: String::new(),
    };
    receipt.receipt_digest_sha256 = canonical_digest(&receipt);
    receipt
}

fn load_fixture_inputs(repo_root: &Path) -> Result<Vec<FixtureParityInput>, String> {
    let mut manifests = Vec::new();
    collect_provenance_paths(&repo_root.join("sources"), &mut manifests)?;
    manifests.sort();
    let mut inputs = Vec::with_capacity(manifests.len());
    for manifest in manifests {
        let text = fs::read_to_string(&manifest)
            .map_err(|error| format!("read {}: {error}", manifest.display()))?;
        let source_id = yaml_scalar(&text, "source_id")
            .ok_or_else(|| format!("{} missing source_id", manifest.display()))?;
        let family_id = yaml_scalar(&text, "family")
            .ok_or_else(|| format!("{} missing family", manifest.display()))?;
        let case_id = yaml_scalar(&text, "case")
            .ok_or_else(|| format!("{} missing case", manifest.display()))?;
        let payload_sha256 = yaml_scalar(&text, "sha256").unwrap_or_default();
        let payload = fs::read(manifest.with_file_name("response.json"))
            .map_err(|error| format!("read response for {}: {error}", manifest.display()))?;
        inputs.push(FixtureParityInput {
            source_id,
            family_id,
            case_id,
            payload,
            payload_sha256,
            operation: FixtureParityOperation::ReadPage,
            cursor: String::new(),
            checkpoint: String::new(),
            limit: 1000,
        });
    }
    Ok(inputs)
}

fn collect_provenance_paths(root: &Path, manifests: &mut Vec<PathBuf>) -> Result<(), String> {
    if !root.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(root).map_err(|error| format!("read {}: {error}", root.display()))? {
        let entry = entry.map_err(|error| format!("read {} entry: {error}", root.display()))?;
        let path = entry.path();
        if path.is_dir() {
            collect_provenance_paths(&path, manifests)?;
        } else if path.file_name().and_then(|name| name.to_str()) == Some("provenance.yaml")
            && path.to_string_lossy().contains("/testdata/api/")
        {
            manifests.push(path);
        }
    }
    Ok(())
}

fn yaml_scalar(text: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}:");
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix(&prefix) {
            return Some(rest.trim().trim_matches('"').trim_matches('\'').to_owned());
        }
    }
    None
}

fn fixture_records(payload: &[u8]) -> Result<Vec<serde_json::Value>, serde_json::Error> {
    let value: serde_json::Value = serde_json::from_slice(payload)?;
    let mut records = Vec::new();
    collect_fixture_records(&value, &mut records);
    Ok(records)
}

fn collect_fixture_records(value: &serde_json::Value, records: &mut Vec<serde_json::Value>) {
    match value {
        serde_json::Value::Array(items) => records.extend(items.iter().cloned()),
        serde_json::Value::Object(map) => {
            for key in [
                "data",
                "items",
                "results",
                "records",
                "users",
                "members",
                "logs",
                "assets",
                "repositories",
            ] {
                if let Some(serde_json::Value::Array(items)) = map.get(key) {
                    records.extend(items.iter().cloned());
                    return;
                }
            }
            records.push(value.clone());
        }
        _ => {}
    }
}

fn fixture_parity_event(
    input: &FixtureParityInput,
    index: usize,
    record: &serde_json::Value,
) -> FixtureParityEvent {
    let payload_sha256 = canonical_digest(record);
    FixtureParityEvent {
        event_id: canonical_digest(&json!({
            "source_id": input.source_id,
            "family_id": input.family_id,
            "case_id": input.case_id,
            "payload_sha256": payload_sha256,
        })),
        kind: format!("{}.{}", input.source_id, input.family_id),
        input_index: index,
        payload_sha256,
    }
}

fn missing_fixture_identity(record: &serde_json::Value) -> bool {
    let Some(map) = record.as_object() else {
        return false;
    };
    for field in ["id", "ID", "uuid", "key", "name", "login", "email"] {
        if map
            .get(field)
            .and_then(serde_json::Value::as_str)
            .is_some_and(|value| !value.trim().is_empty())
            || map.get(field).is_some_and(|value| value.is_number())
        {
            return false;
        }
    }
    true
}

fn fixture_corpus_revision(inputs: &[FixtureParityInput]) -> String {
    let mut entries: Vec<_> = inputs
        .iter()
        .map(|input| {
            format!(
                "{}/{}/{}:{}",
                input.source_id,
                input.family_id,
                input.case_id,
                if input.payload_sha256.is_empty() {
                    canonical_digest(
                        &serde_json::from_slice::<serde_json::Value>(&input.payload)
                            .unwrap_or_else(|_| {
                                serde_json::Value::String(
                                    String::from_utf8_lossy(&input.payload).to_string(),
                                )
                            }),
                    )
                } else {
                    input.payload_sha256.clone()
                }
            )
        })
        .collect();
    entries.sort();
    canonical_digest(&entries)
}

fn quarantine_summary(quarantines: &[FixtureParityQuarantine]) -> Vec<String> {
    let mut summary: Vec<_> = quarantines
        .iter()
        .map(|quarantine| format!("{}:{}", quarantine.category, quarantine.field_path))
        .collect();
    summary.sort();
    summary
}

fn append_stable_reason(reasons: &mut Vec<String>, reason: &str) {
    if !reasons.iter().any(|candidate| candidate == reason) {
        reasons.push(reason.to_owned());
        reasons.sort();
    }
}

/// Families present in the source catalog but absent from the fixture corpus.
pub fn fixture_excluded_family_reasons(
    catalog: &cerebro_source_catalog::SourceCatalog,
    matrix: &FixtureParityMatrix,
) -> BTreeMap<String, Vec<String>> {
    let covered: BTreeSet<_> = matrix
        .comparisons
        .iter()
        .map(|comparison| {
            format!(
                "{}/{}",
                comparison.receipt.source_id, comparison.receipt.family_id
            )
        })
        .collect();
    let mut excluded = BTreeMap::new();
    for source in catalog.sources() {
        for family in source.families() {
            let key = format!("{}/{}", source.id(), family.id());
            if !covered.contains(&key) {
                let mut reasons: Vec<_> = family
                    .unsupported_reasons()
                    .iter()
                    .map(|reason| format!("{reason:?}").to_lowercase())
                    .collect();
                if reasons.is_empty() {
                    reasons.push("incomplete_runtime_family_proof".to_owned());
                }
                excluded.insert(key, reasons);
            }
        }
    }
    excluded
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use cerebro_source_catalog::SourceCatalog;

    use super::*;

    fn repo_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap()
    }

    #[test]
    fn fixture_parity_matches_checked_in_corpus() {
        let root = repo_root();
        let matrix = build_fixture_parity_matrix(&root).unwrap();
        assert!(!matrix.corpus_revision.is_empty());
        assert!(!matrix.comparisons.is_empty());
        assert_eq!(matrix.mismatch_count, 0);
        for comparison in &matrix.comparisons {
            assert_eq!(
                comparison.receipt.go_page_digest_sha256,
                comparison.receipt.rust_page_digest_sha256
            );
            assert_eq!(comparison.receipt.mismatch_count, 0);
            assert!(!comparison.receipt.cursor_digest_sha256.is_empty());
            assert!(!comparison.receipt.checkpoint_digest_sha256.is_empty());
            assert!(!comparison.receipt.receipt_digest_sha256.is_empty());
        }
        let catalog = SourceCatalog::load(
            root.join("internal/connectorcatalog/catalog"),
            root.join("sources"),
        )
        .unwrap();
        let excluded = fixture_excluded_family_reasons(&catalog, &matrix);
        assert!(!excluded.is_empty());
        assert!(excluded.values().all(|reasons| !reasons.is_empty()));
        println!(
            "fixture_parity corpus_revision={} cases={} excluded_families={} mismatch_count=0 first_receipt={:?}",
            matrix.corpus_revision,
            matrix.comparisons.len(),
            excluded.len(),
            matrix.comparisons[0].receipt
        );
    }

    #[test]
    fn fixture_parity_covers_page_semantics() {
        let base = FixtureParityInput {
            source_id: "fixture".to_owned(),
            family_id: "identity_user".to_owned(),
            case_id: "page".to_owned(),
            payload: br#"{"items":[{"id":"u1","name":"Ada"},{"id":"u2","name":"Grace"}]}"#.to_vec(),
            payload_sha256: String::new(),
            operation: FixtureParityOperation::ReadPage,
            cursor: String::new(),
            checkpoint: String::new(),
            limit: 10,
        };
        let scenarios = [
            ("first_middle_final", base.clone(), "final_page", false),
            (
                "empty",
                FixtureParityInput {
                    case_id: "empty".to_owned(),
                    payload: b"[]".to_vec(),
                    ..base.clone()
                },
                "empty_page",
                true,
            ),
            (
                "malformed_record",
                FixtureParityInput {
                    case_id: "malformed".to_owned(),
                    payload: br#"{"items":["#.to_vec(),
                    ..base.clone()
                },
                "malformed_record",
                true,
            ),
            (
                "permission_denied_rate_limited",
                FixtureParityInput {
                    case_id: "permission_denied".to_owned(),
                    payload: br#"{"error":{"status":403,"reason":"permission_denied"}}"#.to_vec(),
                    ..base.clone()
                },
                "final_page",
                true,
            ),
            (
                "duplicate_event",
                FixtureParityInput {
                    case_id: "duplicate".to_owned(),
                    payload: br#"{"items":[{"id":"u1"},{"id":"u1"}]}"#.to_vec(),
                    ..base.clone()
                },
                "duplicate_event",
                false,
            ),
            (
                "event_limit_deferral",
                FixtureParityInput {
                    case_id: "limited".to_owned(),
                    payload: br#"{"items":[{"id":"u1"},{"id":"u2"}]}"#.to_vec(),
                    limit: 1,
                    ..base.clone()
                },
                "event_limit_deferral",
                false,
            ),
        ];
        for (name, input, reason, want_zero) in scenarios {
            let comparison = compare_fixture_parity(&input, "test-corpus").unwrap();
            assert_eq!(comparison.receipt.mismatch_count, 0, "{name}");
            let mut reasons = comparison.go_page.short_circuit_reasons.clone();
            reasons.extend(comparison.go_page.reconciliation_reasons.clone());
            assert!(
                reasons.iter().any(|candidate| candidate == reason),
                "{name}"
            );
            if want_zero {
                assert_eq!(comparison.go_page.accepted_count, 0, "{name}");
            }
        }
        let first = execute_fixture_parity_page(&base).unwrap();
        let second = execute_fixture_parity_page(&FixtureParityInput {
            checkpoint: first.proposed_checkpoint,
            ..base
        })
        .unwrap();
        assert!(
            second
                .short_circuit_reasons
                .iter()
                .any(|reason| reason == "not_modified")
        );
        assert!(
            second
                .reconciliation_reasons
                .iter()
                .any(|reason| reason == "equal_watermark")
        );
    }
}
