#![deny(unsafe_code)]

//! Authoritative admission for source events before durable append.
//!
//! The kernel validates the normalized envelope and catalog contract, quarantines
//! bounded missing-field failures, rejects conflicting duplicate identities, and
//! returns a deterministic receipt. It has no host imports and cannot append,
//! project, read credentials, or call a provider.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

#[cfg(not(target_arch = "wasm32"))]
use std::io;

use cerebro_wasm_guest::BoundedOutput;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

#[cfg(target_arch = "wasm32")]
mod wasm_abi;

pub const ABI_VERSION: u32 = 2;
pub const MAX_INPUT_BYTES: usize = 32 << 20;
pub const MAX_OUTPUT_BYTES: usize = 8 << 20;

const SCHEMA_VERSION: &str = "source-event-admission.v2";
const MAX_EVENTS: usize = 5_000;
const MAX_CONTRACTS: usize = 4_096;
const MAX_ATTRIBUTES: usize = 512;
const MAX_TEXT_BYTES: usize = 512;
const MIN_TIMESTAMP_SECONDS: i64 = -62_135_596_800;
const MAX_TIMESTAMP_SECONDS: i64 = 253_402_300_799;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionRequest {
    pub schema_version: String,
    #[serde(default)]
    pub contracts: Vec<EventContract>,
    #[serde(default)]
    pub events: Vec<EventEnvelope>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EventContract {
    pub kind: String,
    #[serde(default)]
    pub schema_ref: String,
    #[serde(default)]
    pub required_attributes: Vec<String>,
    #[serde(default)]
    pub required_payload_fields: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EventEnvelope {
    pub id: String,
    pub tenant_id: String,
    pub source_id: String,
    pub kind: String,
    pub occurred_at: Option<Timestamp>,
    pub schema_ref: String,
    pub payload_json: String,
    #[serde(default)]
    pub attributes: BTreeMap<String, String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Timestamp {
    pub seconds: i64,
    pub nanos: i32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum AdmissionOutcome {
    Admitted { response: AdmissionResponse },
    Rejected { rejection: EventRejection },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AdmissionResponse {
    pub schema_version: String,
    pub accepted: Vec<AcceptedEvent>,
    pub quarantined: Vec<QuarantinedEvent>,
    pub duplicates: Vec<DuplicateEvent>,
    pub receipt: AdmissionReceipt,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AcceptedEvent {
    pub input_index: usize,
    pub event_id: String,
    pub event_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EventRejection {
    pub input_index: Option<usize>,
    pub code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    pub message: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct QuarantinedEvent {
    pub input_index: usize,
    pub event_id: String,
    pub event_sha256: String,
    pub code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DuplicateEvent {
    pub input_index: usize,
    pub first_input_index: usize,
    pub event_id: String,
    pub event_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AdmissionReceipt {
    pub scanned: usize,
    pub accepted: usize,
    pub quarantined: usize,
    pub duplicates: usize,
    pub contracts_sha256: String,
    pub scanned_sha256: String,
    pub accepted_sha256: String,
    pub result_sha256: String,
}

#[derive(Serialize)]
struct AdmissionReceiptBody<'a> {
    schema_version: &'a str,
    contracts_sha256: &'a str,
    scanned_sha256: &'a str,
    accepted: &'a [AcceptedEvent],
    quarantined: &'a [QuarantinedEvent],
    duplicates: &'a [DuplicateEvent],
}

impl EventRejection {
    fn fatal(code: &str, message: impl Into<String>) -> Self {
        Self {
            input_index: None,
            code: code.to_owned(),
            field: None,
            message: message.into(),
        }
    }

    fn event(index: usize, code: &str, field: Option<&str>, message: impl Into<String>) -> Self {
        Self {
            input_index: Some(index),
            code: code.to_owned(),
            field: field.map(str::to_owned),
            message: message.into(),
        }
    }
}

/// Evaluates a bounded JSON request and returns a bounded JSON outcome.
pub fn evaluate_json(input: &[u8]) -> Result<Vec<u8>, serde_json::Error> {
    let outcome = match serde_json::from_slice::<AdmissionRequest>(input) {
        Ok(request) => admit(request),
        Err(error) => return Err(error),
    };
    let mut output = BoundedOutput::new(MAX_OUTPUT_BYTES);
    serde_json::to_writer(&mut output, &outcome)?;
    Ok(output.into_inner())
}

/// Evaluates a bounded CBOR request for the native worker transport.
#[cfg(not(target_arch = "wasm32"))]
pub fn evaluate_cbor(input: &[u8]) -> io::Result<Vec<u8>> {
    let request = ciborium::from_reader::<AdmissionRequest, _>(input)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let outcome = admit(request);
    let mut output = BoundedOutput::new(MAX_OUTPUT_BYTES);
    ciborium::into_writer(&outcome, &mut output)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    Ok(output.into_inner())
}

pub fn admit(request: AdmissionRequest) -> AdmissionOutcome {
    if request.schema_version != SCHEMA_VERSION {
        return rejected(EventRejection::fatal(
            "unsupported_schema",
            format!("schema_version must be {SCHEMA_VERSION}"),
        ));
    }
    if request.events.len() > MAX_EVENTS {
        return rejected(EventRejection::fatal(
            "event_limit_exceeded",
            format!("event count exceeds {MAX_EVENTS}"),
        ));
    }
    let contracts = match normalize_contracts(request.contracts) {
        Ok(contracts) => contracts,
        Err(rejection) => return rejected(rejection),
    };
    let normalized_contracts = contracts.values().collect::<Vec<_>>();
    let contracts_sha256 = match canonical_digest(&normalized_contracts) {
        Ok(digest) => digest,
        Err(rejection) => return rejected(rejection),
    };

    let mut accepted = Vec::with_capacity(request.events.len());
    let mut quarantined = Vec::new();
    let mut duplicates = Vec::new();
    let mut seen = BTreeMap::<String, (usize, String)>::new();
    let mut scanned_digests = Vec::with_capacity(request.events.len());

    for (input_index, event) in request.events.iter().enumerate() {
        let payload = match parse_payload(input_index, &event.payload_json) {
            Ok(payload) => payload,
            Err(rejection) => return rejected(rejection),
        };
        let event_sha256 = match canonical_digest(&EventReceiptInput::new(event, &payload)) {
            Ok(digest) => digest,
            Err(rejection) => return rejected(with_index(rejection, input_index)),
        };
        scanned_digests.push(event_sha256.clone());
        match validate_event(input_index, event, &payload, &contracts) {
            EventDecision::Accept => {}
            EventDecision::Quarantine(rejection) => {
                quarantined.push(QuarantinedEvent {
                    input_index,
                    event_id: event.id.clone(),
                    event_sha256,
                    code: rejection.code,
                    field: rejection.field,
                });
                continue;
            }
            EventDecision::Reject(rejection) => return rejected(rejection),
        }
        if let Some((first_input_index, first_digest)) = seen.get(&event.id) {
            if first_digest != &event_sha256 {
                return rejected(EventRejection::event(
                    input_index,
                    "duplicate_event_conflict",
                    Some("id"),
                    format!(
                        "event id {:?} conflicts with input index {first_input_index}",
                        event.id
                    ),
                ));
            }
            duplicates.push(DuplicateEvent {
                input_index,
                first_input_index: *first_input_index,
                event_id: event.id.clone(),
                event_sha256,
            });
            continue;
        }
        seen.insert(event.id.clone(), (input_index, event_sha256.clone()));
        accepted.push(AcceptedEvent {
            input_index,
            event_id: event.id.clone(),
            event_sha256,
        });
    }

    let scanned_sha256 = digest_serializable(&scanned_digests).unwrap_or_default();
    let accepted_sha256 = digest_serializable(&accepted).unwrap_or_default();
    let result_sha256 = digest_serializable(&AdmissionReceiptBody {
        schema_version: SCHEMA_VERSION,
        contracts_sha256: &contracts_sha256,
        scanned_sha256: &scanned_sha256,
        accepted: &accepted,
        quarantined: &quarantined,
        duplicates: &duplicates,
    })
    .unwrap_or_default();
    AdmissionOutcome::Admitted {
        response: AdmissionResponse {
            schema_version: SCHEMA_VERSION.to_owned(),
            receipt: AdmissionReceipt {
                scanned: request.events.len(),
                accepted: accepted.len(),
                quarantined: quarantined.len(),
                duplicates: duplicates.len(),
                contracts_sha256,
                scanned_sha256,
                accepted_sha256,
                result_sha256,
            },
            accepted,
            quarantined,
            duplicates,
        },
    }
}

fn rejected(rejection: EventRejection) -> AdmissionOutcome {
    AdmissionOutcome::Rejected { rejection }
}

fn with_index(mut rejection: EventRejection, index: usize) -> EventRejection {
    rejection.input_index = Some(index);
    rejection
}

fn normalize_contracts(
    contracts: Vec<EventContract>,
) -> Result<BTreeMap<String, EventContract>, EventRejection> {
    if contracts.len() > MAX_CONTRACTS {
        return Err(EventRejection::fatal(
            "contract_limit_exceeded",
            format!("event contract count exceeds {MAX_CONTRACTS}"),
        ));
    }
    let mut normalized = BTreeMap::new();
    for mut contract in contracts {
        contract.kind = contract.kind.trim().to_owned();
        contract.schema_ref = contract.schema_ref.trim().to_owned();
        contract.required_attributes = normalized_strings(contract.required_attributes);
        contract.required_payload_fields = normalized_strings(contract.required_payload_fields);
        if !valid_required_text(&contract.kind) || !valid_event_kind(&contract.kind) {
            return Err(EventRejection::fatal(
                "invalid_contract",
                format!("event contract kind {:?} is invalid", contract.kind),
            ));
        }
        if !contract.schema_ref.is_empty()
            && (!valid_required_text(&contract.schema_ref)
                || !valid_schema_ref(&contract.schema_ref))
        {
            return Err(EventRejection::fatal(
                "invalid_contract",
                format!(
                    "event contract schema_ref {:?} is invalid",
                    contract.schema_ref
                ),
            ));
        }
        if contract.required_attributes.is_empty() && contract.required_payload_fields.is_empty() {
            return Err(EventRejection::fatal(
                "invalid_contract",
                format!("event contract {:?} has no requirements", contract.kind),
            ));
        }
        if contract
            .required_attributes
            .iter()
            .chain(&contract.required_payload_fields)
            .any(|value| !valid_required_text(value))
        {
            return Err(EventRejection::fatal(
                "invalid_contract",
                format!(
                    "event contract {:?} contains an invalid required field",
                    contract.kind
                ),
            ));
        }
        if normalized.insert(contract.kind.clone(), contract).is_some() {
            return Err(EventRejection::fatal(
                "duplicate_contract",
                "event contract kind is duplicated",
            ));
        }
    }
    Ok(normalized)
}

fn normalized_strings(values: Vec<String>) -> Vec<String> {
    values
        .into_iter()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

enum EventDecision {
    Accept,
    Quarantine(EventRejection),
    Reject(EventRejection),
}

fn validate_event(
    input_index: usize,
    event: &EventEnvelope,
    payload: &Value,
    contracts: &BTreeMap<String, EventContract>,
) -> EventDecision {
    for (field, value) in [
        ("id", &event.id),
        ("tenant_id", &event.tenant_id),
        ("source_id", &event.source_id),
        ("kind", &event.kind),
        ("schema_ref", &event.schema_ref),
    ] {
        if !valid_required_text(value) {
            return EventDecision::Reject(EventRejection::event(
                input_index,
                "invalid_event_envelope",
                Some(field),
                format!("{field} is required without surrounding whitespace"),
            ));
        }
    }
    if !valid_event_kind(&event.kind) {
        return EventDecision::Reject(EventRejection::event(
            input_index,
            "invalid_event_kind",
            Some("kind"),
            "kind must use dot-separated lowercase identifiers",
        ));
    }
    if !valid_schema_ref(&event.schema_ref) {
        return EventDecision::Reject(EventRejection::event(
            input_index,
            "invalid_schema_ref",
            Some("schema_ref"),
            "schema_ref must use source/family/vN format",
        ));
    }
    let Some(occurred_at) = event.occurred_at else {
        return EventDecision::Reject(EventRejection::event(
            input_index,
            "invalid_timestamp",
            Some("occurred_at"),
            "occurred_at is required",
        ));
    };
    if occurred_at.seconds < MIN_TIMESTAMP_SECONDS
        || occurred_at.seconds > MAX_TIMESTAMP_SECONDS
        || !(0..1_000_000_000).contains(&occurred_at.nanos)
    {
        return EventDecision::Reject(EventRejection::event(
            input_index,
            "invalid_timestamp",
            Some("occurred_at"),
            "occurred_at is outside the protobuf timestamp range",
        ));
    }
    if event.attributes.len() > MAX_ATTRIBUTES {
        return EventDecision::Reject(EventRejection::event(
            input_index,
            "attribute_limit_exceeded",
            Some("attributes"),
            format!("attribute count exceeds {MAX_ATTRIBUTES}"),
        ));
    }
    for key in event.attributes.keys() {
        if !valid_required_text(key) {
            return EventDecision::Reject(EventRejection::event(
                input_index,
                "invalid_attribute_key",
                Some("attributes"),
                "attribute keys must not be empty or contain surrounding whitespace",
            ));
        }
    }

    if contracts.is_empty() {
        return EventDecision::Accept;
    }
    let Some(contract) = contracts.get(&event.kind) else {
        return EventDecision::Reject(EventRejection::event(
            input_index,
            "event_contract_missing",
            Some("kind"),
            format!("kind {:?} has no matching event contract", event.kind),
        ));
    };
    if !contract.schema_ref.is_empty() && contract.schema_ref != event.schema_ref {
        return EventDecision::Reject(EventRejection::event(
            input_index,
            "event_contract_schema_mismatch",
            Some("schema_ref"),
            format!(
                "schema_ref {:?} does not match contract {:?}",
                event.schema_ref, contract.schema_ref
            ),
        ));
    }
    for key in &contract.required_attributes {
        if event
            .attributes
            .get(key)
            .is_none_or(|value| value.trim().is_empty())
        {
            return EventDecision::Quarantine(EventRejection::event(
                input_index,
                "missing_required_attribute",
                Some(key),
                format!(
                    "kind {:?} is missing required attribute {key:?}",
                    event.kind
                ),
            ));
        }
    }
    for field in &contract.required_payload_fields {
        if !payload_has_field(payload, field) {
            return EventDecision::Quarantine(EventRejection::event(
                input_index,
                "missing_required_payload_field",
                Some(field),
                format!(
                    "kind {:?} is missing required payload field {field:?}",
                    event.kind
                ),
            ));
        }
    }
    EventDecision::Accept
}

fn parse_payload(input_index: usize, payload_json: &str) -> Result<Value, EventRejection> {
    if payload_json.is_empty() {
        return Err(EventRejection::event(
            input_index,
            "invalid_event_payload",
            Some("payload"),
            "payload is required",
        ));
    }
    serde_json::from_str(payload_json)
        .map(canonicalize_json)
        .map_err(|_| {
            EventRejection::event(
                input_index,
                "invalid_event_payload",
                Some("payload"),
                "payload must be valid JSON",
            )
        })
}

#[derive(Serialize)]
struct EventReceiptInput<'a> {
    id: &'a str,
    tenant_id: &'a str,
    source_id: &'a str,
    kind: &'a str,
    occurred_at: Option<Timestamp>,
    schema_ref: &'a str,
    payload: &'a Value,
    attributes: &'a BTreeMap<String, String>,
}

impl<'a> EventReceiptInput<'a> {
    fn new(event: &'a EventEnvelope, payload: &'a Value) -> Self {
        Self {
            id: &event.id,
            tenant_id: &event.tenant_id,
            source_id: &event.source_id,
            kind: &event.kind,
            occurred_at: event.occurred_at,
            schema_ref: &event.schema_ref,
            payload,
            attributes: &event.attributes,
        }
    }
}

fn valid_required_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_TEXT_BYTES
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn valid_event_kind(value: &str) -> bool {
    let parts = value.split('.').collect::<Vec<_>>();
    parts.len() >= 2 && parts.into_iter().all(valid_identifier_part)
}

fn valid_schema_ref(value: &str) -> bool {
    let parts = value.split('/').collect::<Vec<_>>();
    if parts.len() < 3 {
        return false;
    }
    parts[..parts.len() - 1]
        .iter()
        .copied()
        .all(valid_identifier_part)
        && parts.last().is_some_and(|version| {
            version.strip_prefix('v').is_some_and(|digits| {
                !digits.is_empty() && digits.chars().all(|ch| ch.is_ascii_digit())
            })
        })
}

fn valid_identifier_part(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_' || ch == '-')
}

fn payload_has_field(payload: &Value, path: &str) -> bool {
    path.split('|')
        .map(str::trim)
        .any(|candidate| payload_has_field_path(payload, candidate))
}

fn payload_has_field_path(payload: &Value, path: &str) -> bool {
    if path.is_empty() {
        return false;
    }
    let mut current = payload;
    for part in path.split('.') {
        if part.trim().is_empty() {
            return false;
        }
        let Some(value) = current.as_object().and_then(|object| object.get(part)) else {
            return false;
        };
        if value.is_null() || value.as_str().is_some_and(|text| text.trim().is_empty()) {
            return false;
        }
        current = value;
    }
    true
}

fn canonical_digest<T: Serialize>(value: &T) -> Result<String, EventRejection> {
    digest_serializable(value).ok_or_else(|| {
        EventRejection::fatal("receipt_failed", "event receipt cannot be serialized")
    })
}

fn digest_serializable<T: Serialize>(value: &T) -> Option<String> {
    serde_json::to_vec(value).ok().map(|body| sha256(&body))
}

fn sha256(input: &[u8]) -> String {
    let digest = Sha256::digest(input);
    let mut output = String::with_capacity(7 + digest.len() * 2);
    output.push_str("sha256:");
    for byte in digest {
        use fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}

fn canonicalize_json(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(canonicalize_json).collect()),
        Value::Object(object) => Value::Object(
            object
                .into_iter()
                .map(|(key, value)| (key, canonicalize_json(value)))
                .collect::<BTreeMap<_, _>>()
                .into_iter()
                .collect(),
        ),
        scalar => scalar,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn timestamp() -> Timestamp {
        Timestamp {
            seconds: 1_700_000_000,
            nanos: 0,
        }
    }

    fn event(id: &str, payload: Value) -> EventEnvelope {
        EventEnvelope {
            id: id.to_owned(),
            tenant_id: "tenant-1".to_owned(),
            source_id: "directory".to_owned(),
            kind: "directory.identity".to_owned(),
            occurred_at: Some(timestamp()),
            schema_ref: "directory/identity/v1".to_owned(),
            payload_json: serde_json::to_string(&payload).expect("test payload serializes"),
            attributes: BTreeMap::from([("resource_id".to_owned(), "user-1".to_owned())]),
        }
    }

    fn contract() -> EventContract {
        EventContract {
            kind: "directory.identity".to_owned(),
            schema_ref: "directory/identity/v1".to_owned(),
            required_attributes: vec!["resource_id".to_owned()],
            required_payload_fields: vec!["identity.id|user.id".to_owned()],
        }
    }

    fn request(events: Vec<EventEnvelope>) -> AdmissionRequest {
        AdmissionRequest {
            schema_version: SCHEMA_VERSION.to_owned(),
            contracts: vec![contract()],
            events,
        }
    }

    fn rejection_code(outcome: AdmissionOutcome) -> String {
        match outcome {
            AdmissionOutcome::Rejected { rejection } => rejection.code,
            AdmissionOutcome::Admitted { .. } => panic!("expected a rejected admission"),
        }
    }

    #[test]
    fn admits_valid_events_and_returns_a_stable_receipt() {
        let left = admit(request(vec![event(
            "event-1",
            json!({"identity":{"id":"user-1"},"name":"A"}),
        )]));
        let right = admit(request(vec![event(
            "event-1",
            json!({"name":"A","identity":{"id":"user-1"}}),
        )]));
        assert_eq!(left, right);
        let AdmissionOutcome::Admitted { response } = left else {
            panic!("valid event must be admitted");
        };
        assert_eq!(response.receipt.accepted, 1);
        assert_eq!(response.receipt.quarantined, 0);
    }

    #[test]
    fn quarantines_missing_contract_fields_without_admitting_them() {
        let quarantined_event = event("event-1", json!({"name":"A"}));
        let expected_digest = canonical_digest(&EventReceiptInput::new(
            &quarantined_event,
            &json!({"name":"A"}),
        ))
        .expect("event receipt serializes");
        let outcome = admit(request(vec![quarantined_event]));
        let AdmissionOutcome::Admitted { response } = outcome else {
            panic!("missing field is a bounded quarantine");
        };
        assert!(response.accepted.is_empty());
        assert_eq!(response.quarantined[0].event_id, "event-1");
        assert_eq!(response.quarantined[0].event_sha256, expected_digest);
        assert_eq!(
            response.quarantined[0].code,
            "missing_required_payload_field"
        );
        assert_eq!(
            response.quarantined[0].field.as_deref(),
            Some("identity.id|user.id")
        );
    }

    #[test]
    fn receipt_binds_quarantined_input_content() {
        let first = admit(request(vec![event("event-1", json!({"identity": {}}))]));
        let second = admit(request(vec![event("event-2", json!({"identity": {}}))]));
        let (
            AdmissionOutcome::Admitted { response: first },
            AdmissionOutcome::Admitted { response: second },
        ) = (first, second)
        else {
            panic!("missing fields should produce bounded quarantines");
        };
        assert_ne!(first.receipt.scanned_sha256, second.receipt.scanned_sha256);
        assert_ne!(first.receipt.result_sha256, second.receipt.result_sha256);
    }

    #[test]
    fn receipt_binds_normalized_contract_semantics() {
        let source_event = event("event-1", json!({"identity":{"id":"user-1"}}));
        let mut reordered = contract();
        reordered.required_attributes = vec!["resource_id".to_owned(), "resource_id".to_owned()];
        reordered.required_payload_fields = vec![
            "user.id".to_owned(),
            "identity.id|user.id".to_owned(),
            "user.id".to_owned(),
        ];
        let mut equivalent = reordered.clone();
        equivalent.required_payload_fields.reverse();
        let left = admit(AdmissionRequest {
            schema_version: SCHEMA_VERSION.to_owned(),
            contracts: vec![reordered],
            events: vec![source_event.clone()],
        });
        let right = admit(AdmissionRequest {
            schema_version: SCHEMA_VERSION.to_owned(),
            contracts: vec![equivalent],
            events: vec![source_event.clone()],
        });
        let mut changed = contract();
        changed
            .required_payload_fields
            .push("identity.name".to_owned());
        let changed = admit(AdmissionRequest {
            schema_version: SCHEMA_VERSION.to_owned(),
            contracts: vec![changed],
            events: vec![source_event],
        });
        let (
            AdmissionOutcome::Admitted { response: left },
            AdmissionOutcome::Admitted { response: right },
            AdmissionOutcome::Admitted { response: changed },
        ) = (left, right, changed)
        else {
            panic!("bounded contract decisions must be admitted outcomes");
        };
        assert_eq!(
            left.receipt.contracts_sha256,
            right.receipt.contracts_sha256
        );
        assert_eq!(left.receipt.result_sha256, right.receipt.result_sha256);
        assert_ne!(
            left.receipt.contracts_sha256,
            changed.receipt.contracts_sha256
        );
        assert_ne!(left.receipt.result_sha256, changed.receipt.result_sha256);
    }

    #[test]
    fn identical_duplicates_collapse_but_conflicting_duplicates_fail_closed() {
        let first = event("event-1", json!({"identity":{"id":"user-1"}}));
        let duplicate = first.clone();
        let admitted = admit(request(vec![first.clone(), duplicate]));
        let AdmissionOutcome::Admitted { response } = admitted else {
            panic!("identical duplicate should collapse");
        };
        assert_eq!(response.accepted.len(), 1);
        assert_eq!(response.duplicates.len(), 1);

        let conflict = event("event-1", json!({"identity":{"id":"user-2"}}));
        let rejected = admit(request(vec![first, conflict]));
        let AdmissionOutcome::Rejected { rejection } = rejected else {
            panic!("conflicting duplicate should fail closed");
        };
        assert_eq!(rejection.code, "duplicate_event_conflict");
        assert_eq!(rejection.input_index, Some(1));
    }

    #[test]
    fn malformed_envelopes_and_contracts_fail_the_batch() {
        let mut invalid = event("event-1", json!({"identity":{"id":"user-1"}}));
        invalid.tenant_id = " tenant-1".to_owned();
        let AdmissionOutcome::Rejected { rejection } = admit(request(vec![invalid])) else {
            panic!("invalid envelope should reject");
        };
        assert_eq!(rejection.code, "invalid_event_envelope");

        let mut invalid_contract = contract();
        invalid_contract.required_attributes.clear();
        invalid_contract.required_payload_fields.clear();
        let AdmissionOutcome::Rejected { rejection } = admit(AdmissionRequest {
            schema_version: SCHEMA_VERSION.to_owned(),
            contracts: vec![invalid_contract],
            events: vec![],
        }) else {
            panic!("invalid contract should reject");
        };
        assert_eq!(rejection.code, "invalid_contract");

        let mut oversized_contract = contract();
        oversized_contract.required_attributes = vec!["x".repeat(MAX_TEXT_BYTES + 1)];
        let AdmissionOutcome::Rejected { rejection } = admit(AdmissionRequest {
            schema_version: SCHEMA_VERSION.to_owned(),
            contracts: vec![oversized_contract],
            events: vec![],
        }) else {
            panic!("oversized contract fields should reject");
        };
        assert_eq!(rejection.code, "invalid_contract");

        let mut oversized_event = event("event-1", json!({"identity":{"id":"user-1"}}));
        oversized_event.id = "x".repeat(MAX_TEXT_BYTES + 1);
        let AdmissionOutcome::Rejected { rejection } = admit(request(vec![oversized_event])) else {
            panic!("oversized event identity should reject");
        };
        assert_eq!(rejection.code, "invalid_event_envelope");

        let AdmissionOutcome::Rejected { rejection } = admit(AdmissionRequest {
            schema_version: SCHEMA_VERSION.to_owned(),
            contracts: vec![],
            events: vec![event("event-1", Value::Null); MAX_EVENTS + 1],
        }) else {
            panic!("oversized event page should reject");
        };
        assert_eq!(rejection.code, "event_limit_exceeded");
    }

    #[test]
    fn largest_quarantine_page_fits_the_declared_output_budget() {
        let kind = format!("a.{}", "b".repeat(MAX_TEXT_BYTES - 2));
        let field = "x".repeat(MAX_TEXT_BYTES);
        let contract = EventContract {
            kind: kind.clone(),
            schema_ref: String::new(),
            required_attributes: vec![field],
            required_payload_fields: vec![],
        };
        let events = (0..MAX_EVENTS)
            .map(|index| {
                let mut source_event = event(
                    &format!("{index:04}-{}", "e".repeat(MAX_TEXT_BYTES - 5)),
                    json!({}),
                );
                source_event.kind = kind.clone();
                source_event.attributes.clear();
                source_event
            })
            .collect();
        let request = AdmissionRequest {
            schema_version: SCHEMA_VERSION.to_owned(),
            contracts: vec![contract],
            events,
        };
        let input = serde_json::to_vec(&request).expect("largest bounded request serializes");
        assert!(input.len() <= MAX_INPUT_BYTES);
        let output = evaluate_json(&input).expect("largest bounded quarantine output fits");
        assert!(output.len() <= MAX_OUTPUT_BYTES);
    }

    #[test]
    fn json_boundary_rejects_unknown_fields() {
        assert!(evaluate_json(br#"{"schema_version":"source-event-admission.v2","events":[],"contracts":[],"unknown":true}"#).is_err());
    }

    #[test]
    fn rejects_missing_timestamp_and_invalid_payload_without_host_validation() {
        let mut missing_timestamp = event("event-1", json!({"identity": {"id": "user-1"}}));
        missing_timestamp.occurred_at = None;
        let AdmissionOutcome::Rejected { rejection } = admit(AdmissionRequest {
            schema_version: SCHEMA_VERSION.to_owned(),
            contracts: vec![],
            events: vec![missing_timestamp],
        }) else {
            panic!("missing timestamp must reject the batch");
        };
        assert_eq!(rejection.code, "invalid_timestamp");

        let mut invalid_payload = event("event-1", Value::Null);
        invalid_payload.payload_json = "{".to_owned();
        let AdmissionOutcome::Rejected { rejection } = admit(AdmissionRequest {
            schema_version: SCHEMA_VERSION.to_owned(),
            contracts: vec![],
            events: vec![invalid_payload.clone()],
        }) else {
            panic!("invalid payload must reject the batch");
        };
        assert_eq!(rejection.code, "invalid_event_payload");

        let request = AdmissionRequest {
            schema_version: SCHEMA_VERSION.to_owned(),
            contracts: vec![],
            events: vec![invalid_payload],
        };
        let request_json = serde_json::to_vec(&request).expect("request serializes");
        let output =
            evaluate_json(&request_json).expect("rejection serializes at the JSON boundary");
        assert!(
            String::from_utf8(output)
                .expect("JSON is UTF-8")
                .contains("invalid_event_payload")
        );
    }

    #[test]
    fn exercises_bounded_rejection_surface() {
        let unsupported = AdmissionRequest {
            schema_version: "source-event-admission.v0".to_owned(),
            contracts: vec![],
            events: vec![],
        };
        assert_eq!(rejection_code(admit(unsupported)), "unsupported_schema");

        let too_many_contracts = AdmissionRequest {
            schema_version: SCHEMA_VERSION.to_owned(),
            contracts: vec![contract(); MAX_CONTRACTS + 1],
            events: vec![],
        };
        assert_eq!(
            rejection_code(admit(too_many_contracts)),
            "contract_limit_exceeded"
        );

        for (name, edit) in [
            (
                "kind",
                (|contract: &mut EventContract| contract.kind = "Directory".to_owned())
                    as fn(&mut EventContract),
            ),
            (
                "schema",
                (|contract: &mut EventContract| contract.schema_ref = "bad".to_owned())
                    as fn(&mut EventContract),
            ),
        ] {
            let mut invalid = contract();
            edit(&mut invalid);
            assert_eq!(
                rejection_code(admit(AdmissionRequest {
                    schema_version: SCHEMA_VERSION.to_owned(),
                    contracts: vec![invalid],
                    events: vec![],
                })),
                "invalid_contract",
                "{name}"
            );
        }

        assert_eq!(
            rejection_code(admit(AdmissionRequest {
                schema_version: SCHEMA_VERSION.to_owned(),
                contracts: vec![contract(), contract()],
                events: vec![],
            })),
            "duplicate_contract"
        );

        let mut invalid_kind = event("event-1", Value::Null);
        invalid_kind.kind = "Directory".to_owned();
        assert_eq!(
            rejection_code(admit(AdmissionRequest {
                schema_version: SCHEMA_VERSION.to_owned(),
                contracts: vec![],
                events: vec![invalid_kind],
            })),
            "invalid_event_kind"
        );

        let mut invalid_schema = event("event-1", Value::Null);
        invalid_schema.schema_ref = "bad".to_owned();
        assert_eq!(
            rejection_code(admit(AdmissionRequest {
                schema_version: SCHEMA_VERSION.to_owned(),
                contracts: vec![],
                events: vec![invalid_schema],
            })),
            "invalid_schema_ref"
        );

        let mut invalid_timestamp = event("event-1", Value::Null);
        invalid_timestamp.occurred_at = Some(Timestamp {
            seconds: MAX_TIMESTAMP_SECONDS + 1,
            nanos: 0,
        });
        assert_eq!(
            rejection_code(admit(AdmissionRequest {
                schema_version: SCHEMA_VERSION.to_owned(),
                contracts: vec![],
                events: vec![invalid_timestamp],
            })),
            "invalid_timestamp"
        );

        let mut too_many_attributes = event("event-1", Value::Null);
        too_many_attributes.attributes = (0..=MAX_ATTRIBUTES)
            .map(|index| (format!("key-{index}"), "value".to_owned()))
            .collect();
        assert_eq!(
            rejection_code(admit(AdmissionRequest {
                schema_version: SCHEMA_VERSION.to_owned(),
                contracts: vec![],
                events: vec![too_many_attributes],
            })),
            "attribute_limit_exceeded"
        );

        let mut invalid_attribute = event("event-1", Value::Null);
        invalid_attribute
            .attributes
            .insert(" bad".to_owned(), "value".to_owned());
        assert_eq!(
            rejection_code(admit(AdmissionRequest {
                schema_version: SCHEMA_VERSION.to_owned(),
                contracts: vec![],
                events: vec![invalid_attribute],
            })),
            "invalid_attribute_key"
        );

        let mut missing_contract = event("event-1", Value::Null);
        missing_contract.kind = "directory.group".to_owned();
        missing_contract.schema_ref = "directory/group/v1".to_owned();
        assert_eq!(
            rejection_code(admit(request(vec![missing_contract]))),
            "event_contract_missing"
        );

        let mut mismatched_schema = event("event-1", Value::Null);
        mismatched_schema.schema_ref = "directory/identity/v2".to_owned();
        assert_eq!(
            rejection_code(admit(request(vec![mismatched_schema]))),
            "event_contract_schema_mismatch"
        );

        let mut missing_attribute = event("event-1", json!({"identity":{"id":"user-1"}}));
        missing_attribute.attributes.clear();
        let AdmissionOutcome::Admitted { response } = admit(request(vec![missing_attribute]))
        else {
            panic!("missing attribute should be quarantined");
        };
        assert_eq!(response.quarantined[0].code, "missing_required_attribute");

        let mut empty_payload = event("event-1", Value::Null);
        empty_payload.payload_json.clear();
        assert_eq!(
            rejection_code(admit(AdmissionRequest {
                schema_version: SCHEMA_VERSION.to_owned(),
                contracts: vec![],
                events: vec![empty_payload],
            })),
            "invalid_event_payload"
        );

        let generic = event("event-1", json!([{"z": 1, "a": 2}]));
        assert!(matches!(
            admit(AdmissionRequest {
                schema_version: SCHEMA_VERSION.to_owned(),
                contracts: vec![],
                events: vec![generic],
            }),
            AdmissionOutcome::Admitted { .. }
        ));

        let payload = json!({"identity":{"id":null,"name":"  "}});
        assert!(!payload_has_field(&payload, ""));
        assert!(!payload_has_field(&payload, "identity..id"));
        assert!(!payload_has_field(&payload, "identity.id"));
        assert!(!payload_has_field(&payload, "identity.name"));
        assert!(payload_has_field(&payload, "identity.missing|identity"));
    }
}
