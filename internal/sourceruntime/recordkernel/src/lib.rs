#![deny(unsafe_code)]

//! A deterministic, capability-free source record kernel.
//!
//! The kernel makes three boundaries executable:
//!
//! - only a validated plan exposes record mapping;
//! - one execution permit can be consumed only once inside the kernel;
//! - JSON object key order does not change the ordered records or receipt.
//!
//! A draft plan cannot execute. This is a compile-time failure, not a branch:
//!
//! ```compile_fail
//! use cerebro_sourceruntime_recordkernel::{
//!     DraftContract, ExecutionPermit, SourcePage, SourcePlan,
//! };
//!
//! let draft = SourcePlan::new(DraftContract::new("directory", "identity", "id"));
//! let permit = ExecutionPermit::issue("attempt-1").unwrap();
//! draft.map_page(SourcePage::empty(), permit);
//! ```
//!
//! An execution permit is move-only. It cannot authorize a second call:
//!
//! ```compile_fail
//! use cerebro_sourceruntime_recordkernel::{
//!     DraftContract, ExecutionPermit, SourcePage, SourcePlan,
//! };
//!
//! let plan = SourcePlan::new(DraftContract::new("directory", "identity", "id"))
//!     .validate()
//!     .unwrap();
//! let permit = ExecutionPermit::issue("attempt-1").unwrap();
//! let _ = plan.map_page(SourcePage::empty(), permit);
//! let _ = plan.map_page(SourcePage::empty(), permit);
//! ```

use std::{
    collections::{BTreeMap, HashSet},
    error::Error,
    fmt,
    marker::PhantomData,
};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

#[cfg(target_arch = "wasm32")]
mod wasm_abi;

pub const ABI_VERSION: u32 = 1;
pub const MAX_INPUT_BYTES: usize = 1 << 20;
pub const MAX_OUTPUT_BYTES: usize = 2 << 20;

const HARD_MAX_RECORDS: usize = 1_000;
const HARD_MAX_RECORD_BYTES: usize = 256 << 10;
const MAX_IDENTIFIER_BYTES: usize = 256;
const MAX_CURSOR_BYTES: usize = 4 << 10;

/// Marks a source plan whose contract has not been validated.
#[derive(Debug)]
pub struct Draft;

/// Marks a source plan whose contract satisfies all kernel bounds.
#[derive(Debug)]
pub struct Validated;

/// The source-owned fields required to map provider records.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DraftContract {
    source_id: String,
    family: String,
    id_field: String,
    max_records: usize,
    max_record_bytes: usize,
}

impl DraftContract {
    pub fn new(
        source_id: impl Into<String>,
        family: impl Into<String>,
        id_field: impl Into<String>,
    ) -> Self {
        Self {
            source_id: source_id.into(),
            family: family.into(),
            id_field: id_field.into(),
            max_records: HARD_MAX_RECORDS,
            max_record_bytes: HARD_MAX_RECORD_BYTES,
        }
    }

    pub fn with_limits(mut self, max_records: usize, max_record_bytes: usize) -> Self {
        self.max_records = max_records;
        self.max_record_bytes = max_record_bytes;
        self
    }
}

/// A source plan indexed by its validation state.
#[derive(Debug)]
pub struct SourcePlan<State> {
    contract: DraftContract,
    state: PhantomData<State>,
}

impl SourcePlan<Draft> {
    pub fn new(contract: DraftContract) -> Self {
        Self {
            contract,
            state: PhantomData,
        }
    }

    pub fn validate(self) -> Result<SourcePlan<Validated>, KernelRejection> {
        validate_identifier("source_id_invalid", "source id", &self.contract.source_id)?;
        validate_identifier("family_invalid", "family", &self.contract.family)?;
        validate_identifier("id_field_invalid", "id field", &self.contract.id_field)?;
        if self.contract.max_records == 0 || self.contract.max_records > HARD_MAX_RECORDS {
            return Err(max_records_invalid());
        }
        if self.contract.max_record_bytes == 0
            || self.contract.max_record_bytes > HARD_MAX_RECORD_BYTES
        {
            return Err(max_record_bytes_invalid());
        }
        Ok(SourcePlan {
            contract: self.contract,
            state: PhantomData,
        })
    }
}

/// A host-issued, move-only permit for one mapping attempt.
#[derive(Debug)]
pub struct ExecutionPermit {
    attempt_id: String,
}

impl ExecutionPermit {
    pub fn issue(attempt_id: impl Into<String>) -> Result<Self, KernelRejection> {
        let attempt_id = attempt_id.into();
        validate_identifier("attempt_id_invalid", "attempt id", &attempt_id)?;
        Ok(Self { attempt_id })
    }
}

/// One provider page. The cursor is carried into the checkpoint only after mapping completes.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct SourcePage {
    #[serde(default)]
    records: Vec<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    next_cursor: Option<String>,
}

impl SourcePage {
    pub fn new(records: Vec<Value>, next_cursor: Option<String>) -> Self {
        Self {
            records,
            next_cursor,
        }
    }

    pub fn empty() -> Self {
        Self::default()
    }

    fn canonicalize(&mut self) {
        for record in &mut self.records {
            *record = canonicalize_json(std::mem::take(record));
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct WireContract {
    source_id: String,
    family: String,
    id_field: String,
    max_records: i64,
    max_record_bytes: i64,
}

impl WireContract {
    fn into_draft(self) -> Result<DraftContract, KernelRejection> {
        let max_records = usize::try_from(self.max_records)
            .ok()
            .filter(|value| *value > 0 && *value <= HARD_MAX_RECORDS)
            .ok_or_else(max_records_invalid)?;
        let max_record_bytes = usize::try_from(self.max_record_bytes)
            .ok()
            .filter(|value| *value > 0 && *value <= HARD_MAX_RECORD_BYTES)
            .ok_or_else(max_record_bytes_invalid)?;
        Ok(DraftContract {
            source_id: self.source_id,
            family: self.family,
            id_field: self.id_field,
            max_records,
            max_record_bytes,
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct MappingRequest {
    contract: WireContract,
    page: SourcePage,
    attempt_id: String,
}

/// The stable result returned across the Wasm boundary.
#[derive(Debug, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum MappingOutcome {
    Mapped { response: MappingResponse },
    Rejected { code: String, message: String },
}

impl MappingOutcome {
    fn rejected(rejection: KernelRejection) -> Self {
        Self::Rejected {
            code: rejection.code.to_owned(),
            message: rejection.message,
        }
    }
}

/// Records and a receipt produced from one fully accepted page attempt.
#[derive(Debug, Serialize)]
pub struct MappingResponse {
    source_id: String,
    family: String,
    attempt_id: String,
    accepted: Vec<AcceptedRecord>,
    quarantined: Vec<QuarantinedRecord>,
    checkpoint: PageCheckpoint,
    receipt: PageReceipt,
}

#[derive(Debug, Serialize)]
struct AcceptedRecord {
    external_id: String,
    fingerprint_sha256: String,
    payload: Value,
}

#[derive(Debug, Serialize)]
struct QuarantinedRecord {
    input_index: usize,
    code: &'static str,
    fingerprint_sha256: String,
}

#[derive(Debug, Serialize)]
struct PageCheckpoint {
    #[serde(skip_serializing_if = "Option::is_none")]
    next_cursor: Option<String>,
    input_sha256: String,
}

#[derive(Debug, Serialize)]
struct PageReceipt {
    accepted: usize,
    quarantined: usize,
    records_sha256: String,
}

/// A bounded rejection safe to expose without returning source payload bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KernelRejection {
    code: &'static str,
    message: String,
}

impl KernelRejection {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for KernelRejection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for KernelRejection {}

/// Evaluates a bounded JSON request and returns stable JSON bytes.
pub fn evaluate_json(input: &[u8]) -> Result<Vec<u8>, serde_json::Error> {
    if input.len() > MAX_INPUT_BYTES {
        return serde_json::to_vec(&MappingOutcome::rejected(KernelRejection::new(
            "input_too_large",
            format!("input exceeds {MAX_INPUT_BYTES} bytes"),
        )));
    }
    let mut request: MappingRequest = serde_json::from_slice(input)?;
    request.page.canonicalize();
    let canonical_input = serde_json::to_vec(&request)?;
    let contract = match request.contract.into_draft() {
        Ok(contract) => contract,
        Err(rejection) => return serde_json::to_vec(&MappingOutcome::rejected(rejection)),
    };
    let plan = match SourcePlan::new(contract).validate() {
        Ok(plan) => plan,
        Err(rejection) => return serde_json::to_vec(&MappingOutcome::rejected(rejection)),
    };
    let permit = match ExecutionPermit::issue(request.attempt_id) {
        Ok(permit) => permit,
        Err(rejection) => return serde_json::to_vec(&MappingOutcome::rejected(rejection)),
    };
    let outcome = match plan.map_page_with_canonical_input(request.page, permit, &canonical_input) {
        Ok(response) => MappingOutcome::Mapped { response },
        Err(rejection) => MappingOutcome::rejected(rejection),
    };
    serde_json::to_vec(&outcome)
}

impl SourcePlan<Validated> {
    /// Maps one page under a permit that is consumed by this call.
    pub fn map_page(
        &self,
        mut page: SourcePage,
        permit: ExecutionPermit,
    ) -> Result<MappingResponse, KernelRejection> {
        page.canonicalize();
        let canonical_input = serde_json::to_vec(&(&self.contract, &page, &permit.attempt_id))
            .map_err(|_| {
                KernelRejection::new("input_receipt_failed", "input receipt cannot be serialized")
            })?;
        self.map_page_with_canonical_input(page, permit, &canonical_input)
    }

    fn map_page_with_canonical_input(
        &self,
        page: SourcePage,
        permit: ExecutionPermit,
        canonical_input: &[u8],
    ) -> Result<MappingResponse, KernelRejection> {
        if page.records.len() > self.contract.max_records {
            return Err(KernelRejection::new(
                "page_record_limit_exceeded",
                format!(
                    "page contains {} records; contract maximum is {}",
                    page.records.len(),
                    self.contract.max_records
                ),
            ));
        }
        if page
            .next_cursor
            .as_ref()
            .is_some_and(|cursor| cursor.len() > MAX_CURSOR_BYTES)
        {
            return Err(KernelRejection::new(
                "cursor_too_large",
                format!("cursor exceeds {MAX_CURSOR_BYTES} bytes"),
            ));
        }

        let mut accepted = Vec::with_capacity(page.records.len());
        let mut quarantined = Vec::new();
        let mut seen_ids = HashSet::new();
        for (input_index, payload) in page.records.into_iter().enumerate() {
            let canonical = serde_json::to_vec(&payload).map_err(|_| {
                KernelRejection::new("record_serialization_failed", "record cannot be serialized")
            })?;
            let fingerprint_sha256 = sha256_hex(&canonical);
            if canonical.len() > self.contract.max_record_bytes {
                quarantined.push(QuarantinedRecord {
                    input_index,
                    code: "record_too_large",
                    fingerprint_sha256,
                });
                continue;
            }
            let Some(object) = payload.as_object() else {
                quarantined.push(QuarantinedRecord {
                    input_index,
                    code: "record_not_object",
                    fingerprint_sha256,
                });
                continue;
            };
            let Some(external_id) = object
                .get(&self.contract.id_field)
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty() && value.len() <= MAX_IDENTIFIER_BYTES)
            else {
                quarantined.push(QuarantinedRecord {
                    input_index,
                    code: "external_id_invalid",
                    fingerprint_sha256,
                });
                continue;
            };
            if !seen_ids.insert(external_id.to_owned()) {
                quarantined.push(QuarantinedRecord {
                    input_index,
                    code: "duplicate_external_id",
                    fingerprint_sha256,
                });
                continue;
            }
            accepted.push(AcceptedRecord {
                external_id: external_id.to_owned(),
                fingerprint_sha256,
                payload,
            });
        }
        accepted.sort_by(|left, right| left.external_id.cmp(&right.external_id));
        quarantined.sort_by_key(|record| record.input_index);

        let records_sha256 = sha256_hex(&serde_json::to_vec(&(&accepted, &quarantined)).map_err(
            |_| KernelRejection::new("receipt_failed", "record receipt cannot be serialized"),
        )?);
        Ok(MappingResponse {
            source_id: self.contract.source_id.clone(),
            family: self.contract.family.clone(),
            attempt_id: permit.attempt_id,
            receipt: PageReceipt {
                accepted: accepted.len(),
                quarantined: quarantined.len(),
                records_sha256,
            },
            accepted,
            quarantined,
            checkpoint: PageCheckpoint {
                next_cursor: page.next_cursor,
                input_sha256: sha256_hex(canonical_input),
            },
        })
    }
}

fn validate_identifier(
    code: &'static str,
    label: &'static str,
    value: &str,
) -> Result<(), KernelRejection> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(KernelRejection::new(
            code,
            format!(
                "{label} must be 1 to {MAX_IDENTIFIER_BYTES} bytes without surrounding whitespace or control characters"
            ),
        ));
    }
    Ok(())
}

fn max_records_invalid() -> KernelRejection {
    KernelRejection::new(
        "max_records_invalid",
        format!("max records must be between 1 and {HARD_MAX_RECORDS}"),
    )
}

fn max_record_bytes_invalid() -> KernelRejection {
    KernelRejection::new(
        "max_record_bytes_invalid",
        format!("max record bytes must be between 1 and {HARD_MAX_RECORD_BYTES}"),
    )
}

fn sha256_hex(input: &[u8]) -> String {
    let digest = Sha256::digest(input);
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}

fn canonicalize_json(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(canonicalize_json).collect()),
        Value::Object(object) => {
            let sorted = object
                .into_iter()
                .map(|(key, value)| (key, canonicalize_json(value)))
                .collect::<BTreeMap<_, _>>();
            Value::Object(sorted.into_iter().collect())
        }
        scalar => scalar,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn maps_records_in_stable_identity_order_and_quarantines_invalid_rows() {
        let contract = DraftContract::new("directory", "identity", "id").with_limits(10, 1_024);
        let plan = SourcePlan::new(contract).validate().expect("valid plan");
        let page = SourcePage::new(
            vec![
                json!({"id":"user-b","name":"B"}),
                json!({"name":"missing"}),
                json!({"id":"user-a","name":"A"}),
                json!({"id":"user-a","name":"duplicate"}),
            ],
            Some("cursor-2".to_owned()),
        );
        let response = plan
            .map_page(
                page,
                ExecutionPermit::issue("attempt-1").expect("valid permit"),
            )
            .expect("mapping succeeds");

        assert_eq!(
            response
                .accepted
                .iter()
                .map(|record| record.external_id.as_str())
                .collect::<Vec<_>>(),
            ["user-a", "user-b"]
        );
        assert_eq!(
            response
                .quarantined
                .iter()
                .map(|record| record.code)
                .collect::<Vec<_>>(),
            ["external_id_invalid", "duplicate_external_id"]
        );
        assert_eq!(response.receipt.accepted, 2);
        assert_eq!(response.receipt.quarantined, 2);
    }

    #[test]
    fn json_object_key_order_does_not_change_the_receipt() {
        let left = br#"{"contract":{"source_id":"directory","family":"identity","id_field":"id","max_records":10,"max_record_bytes":1024},"page":{"records":[{"id":"u-1","name":"A"}]},"attempt_id":"attempt-1"}"#;
        let right = br#"{"attempt_id":"attempt-1","page":{"records":[{"name":"A","id":"u-1"}]},"contract":{"max_record_bytes":1024,"id_field":"id","family":"identity","source_id":"directory","max_records":10}}"#;

        assert_eq!(
            evaluate_json(left).expect("left evaluates"),
            evaluate_json(right).expect("right evaluates")
        );
    }

    #[test]
    fn invalid_contract_is_a_bounded_rejection() {
        let input = br#"{"contract":{"source_id":" directory","family":"identity","id_field":"id","max_records":10,"max_record_bytes":1024},"page":{},"attempt_id":"attempt-1"}"#;
        let output: Value =
            serde_json::from_slice(&evaluate_json(input).expect("evaluation serializes"))
                .expect("valid outcome JSON");

        assert_eq!(output["outcome"], "rejected");
        assert_eq!(output["code"], "source_id_invalid");
        assert!(output.get("contract").is_none());
    }

    #[test]
    fn hard_bounds_reject_before_record_mapping() {
        let plan =
            SourcePlan::new(DraftContract::new("directory", "identity", "id").with_limits(1, 32))
                .validate()
                .expect("valid plan");
        let rejection = plan
            .map_page(
                SourcePage::new(vec![json!({"id":"1"}), json!({"id":"2"})], None),
                ExecutionPermit::issue("attempt-1").expect("valid permit"),
            )
            .expect_err("record limit must fail closed");

        assert_eq!(rejection.code, "page_record_limit_exceeded");
    }
}
