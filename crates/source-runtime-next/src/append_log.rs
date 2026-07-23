use std::{
    collections::{BTreeMap, HashMap},
    error::Error,
    fmt,
};

use cerebro_organizational_model::{
    CollectionId, CollectionReceipt, ObservationId, SourceRuntimeId, TenantId,
};
use prost::Message;
use prost_types::Timestamp;

use crate::{CollectedBatch, CollectedScope, SourceRecord};

const SOURCE_RUNTIME_ID_ATTRIBUTE: &str = "source_runtime_id";

#[derive(Clone, PartialEq, Message)]
struct CommittedSourceWire {
    #[prost(string, tag = "1")]
    id: String,
    #[prost(string, tag = "2")]
    tenant_id: String,
    #[prost(string, tag = "3")]
    source_id: String,
    #[prost(string, tag = "4")]
    kind: String,
    #[prost(message, optional, tag = "5")]
    occurred_at: Option<Timestamp>,
    #[prost(string, tag = "6")]
    schema_ref: String,
    #[prost(bytes = "vec", tag = "7")]
    payload: Vec<u8>,
    #[prost(map = "string, string", tag = "8")]
    attributes: HashMap<String, String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AppendLogDecodeError {
    Protobuf(String),
    Missing(&'static str),
    InvalidTimestamp,
    InvalidPayload(String),
    InvalidModel(String),
}

impl fmt::Display for AppendLogDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protobuf(message) => write!(formatter, "decode append-log protobuf: {message}"),
            Self::Missing(field) => write!(formatter, "source event is missing {field}"),
            Self::InvalidTimestamp => {
                formatter.write_str("source event occurrence time is invalid")
            }
            Self::InvalidPayload(message) => {
                write!(
                    formatter,
                    "source event payload is not valid JSON: {message}"
                )
            }
            Self::InvalidModel(message) => {
                write!(
                    formatter,
                    "source event violates the graph model: {message}"
                )
            }
        }
    }
}

impl Error for AppendLogDecodeError {}

/// A source event that came from the canonical append-log protobuf envelope.
///
/// Callers cannot construct this value directly. Tenant, runtime, observation,
/// family, timestamp, and JSON payload validation happen before it crosses the
/// Rust graph boundary.
#[derive(Clone, Debug, PartialEq)]
pub struct CommittedSourceEvent {
    tenant_id: TenantId,
    source_runtime_id: SourceRuntimeId,
    observation_id: ObservationId,
    source_id: String,
    family_id: String,
    observed_at_unix_ms: i64,
    attributes: BTreeMap<String, String>,
    payload: serde_json::Value,
}

impl CommittedSourceEvent {
    /// Decode a canonical append-log envelope.
    ///
    /// `Ok(None)` means the envelope is not a connector source event. Once an
    /// envelope identifies a source, malformed source data is an error rather
    /// than something the consumer may silently skip.
    pub fn decode(payload: &[u8]) -> Result<Option<Self>, AppendLogDecodeError> {
        let wire = CommittedSourceWire::decode(payload)
            .map_err(|error| AppendLogDecodeError::Protobuf(error.to_string()))?;
        let source_id = wire.source_id.trim().to_owned();
        if source_id.is_empty() {
            return Ok(None);
        }
        let kind = wire.kind.trim();
        let source_prefix = format!("{source_id}.");
        if !kind.starts_with(&source_prefix) || kind.len() == source_prefix.len() {
            return Err(AppendLogDecodeError::Missing(
                "a source-owned kind in source.family form",
            ));
        }
        let tenant = required(&wire.tenant_id, "tenant_id")?;
        let runtime = wire
            .attributes
            .get(SOURCE_RUNTIME_ID_ATTRIBUTE)
            .map(String::as_str)
            .ok_or(AppendLogDecodeError::Missing("source_runtime_id"))?;
        let event_id = required(&wire.id, "event_id")?;
        let occurred_at = wire
            .occurred_at
            .ok_or(AppendLogDecodeError::Missing("occurred_at"))?;
        let observed_at_unix_ms = timestamp_millis(occurred_at)?;
        let payload = if wire.payload.is_empty() {
            serde_json::Value::Object(serde_json::Map::new())
        } else {
            serde_json::from_slice(&wire.payload)
                .map_err(|error| AppendLogDecodeError::InvalidPayload(error.to_string()))?
        };
        let tenant_id = TenantId::parse(tenant).map_err(model_error)?;
        let source_runtime_id =
            SourceRuntimeId::parse(required(runtime, "source_runtime_id")?).map_err(model_error)?;
        let observation_id = ObservationId::parse(event_id).map_err(model_error)?;
        Ok(Some(Self {
            tenant_id,
            source_runtime_id,
            observation_id,
            source_id,
            family_id: kind[source_prefix.len()..].to_owned(),
            observed_at_unix_ms,
            attributes: wire.attributes.into_iter().collect(),
            payload,
        }))
    }

    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    pub fn source_runtime_id(&self) -> &SourceRuntimeId {
        &self.source_runtime_id
    }

    pub fn observation_id(&self) -> &ObservationId {
        &self.observation_id
    }

    pub fn source_id(&self) -> &str {
        &self.source_id
    }

    pub fn family_id(&self) -> &str {
        &self.family_id
    }

    pub fn observed_at_unix_ms(&self) -> i64 {
        self.observed_at_unix_ms
    }

    pub fn attributes(&self) -> &BTreeMap<String, String> {
        &self.attributes
    }

    pub fn payload(&self) -> &serde_json::Value {
        &self.payload
    }

    pub fn collection_id(&self) -> Result<CollectionId, AppendLogDecodeError> {
        CollectionId::parse(format!("event:{}", self.observation_id)).map_err(model_error)
    }

    pub fn into_batch(
        self,
        provider_kind: String,
        provider_id: String,
    ) -> Result<CollectedBatch, AppendLogDecodeError> {
        let collection_id = self.collection_id()?;
        let scope = CollectionReceipt::incremental(
            self.tenant_id,
            self.source_runtime_id,
            collection_id,
            format!("{}.{}", self.source_id, self.family_id),
            self.observed_at_unix_ms,
        )
        .map_err(model_error)?;
        Ok(CollectedBatch {
            scope: CollectedScope::NonAuthoritative(scope),
            records: vec![SourceRecord {
                observation_id: self.observation_id,
                family: self.family_id,
                provider_kind,
                provider_id,
                fields: self.attributes,
                payload: self.payload,
            }],
            next_cursor: None,
        })
    }
}

fn required<'a>(value: &'a str, field: &'static str) -> Result<&'a str, AppendLogDecodeError> {
    let value = value.trim();
    if value.is_empty() {
        Err(AppendLogDecodeError::Missing(field))
    } else {
        Ok(value)
    }
}

fn timestamp_millis(value: Timestamp) -> Result<i64, AppendLogDecodeError> {
    if value.seconds < 0 || !(0..1_000_000_000).contains(&value.nanos) {
        return Err(AppendLogDecodeError::InvalidTimestamp);
    }
    value
        .seconds
        .checked_mul(1_000)
        .and_then(|seconds| seconds.checked_add(i64::from(value.nanos) / 1_000_000))
        .filter(|value| *value > 0)
        .ok_or(AppendLogDecodeError::InvalidTimestamp)
}

fn model_error(error: impl fmt::Display) -> AppendLogDecodeError {
    AppendLogDecodeError::InvalidModel(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode(wire: CommittedSourceWire) -> Vec<u8> {
        wire.encode_to_vec()
    }

    fn source_wire() -> CommittedSourceWire {
        CommittedSourceWire {
            id: "event-1".to_owned(),
            tenant_id: "tenant-a".to_owned(),
            source_id: "box".to_owned(),
            kind: "box.content_assets".to_owned(),
            occurred_at: Some(Timestamp {
                seconds: 1_720_000_000,
                nanos: 123_000_000,
            }),
            schema_ref: "box/content_assets/v1".to_owned(),
            payload: br#"{"id":"file-1","name":"board.pdf"}"#.to_vec(),
            attributes: HashMap::from([
                ("source_runtime_id".to_owned(), "box-prod".to_owned()),
                ("provider_id".to_owned(), "file-1".to_owned()),
            ]),
        }
    }

    #[test]
    fn canonical_source_event_becomes_a_sealed_committed_event() {
        let event = CommittedSourceEvent::decode(&encode(source_wire()))
            .unwrap()
            .unwrap();
        assert_eq!(event.tenant_id().as_str(), "tenant-a");
        assert_eq!(event.source_runtime_id().as_str(), "box-prod");
        assert_eq!(event.observation_id().as_str(), "event-1");
        assert_eq!(event.source_id(), "box");
        assert_eq!(event.family_id(), "content_assets");
        assert_eq!(event.collection_id().unwrap().as_str(), "event:event-1");
        assert_eq!(event.observed_at_unix_ms(), 1_720_000_000_123);
        assert_eq!(event.attributes()["provider_id"], "file-1");
        assert_eq!(event.payload()["name"], "board.pdf");
    }

    #[test]
    fn non_source_event_is_not_claimed_by_the_consumer() {
        let mut wire = source_wire();
        wire.source_id.clear();
        wire.kind = "sec.findings.v1.recorded".to_owned();
        assert_eq!(CommittedSourceEvent::decode(&encode(wire)).unwrap(), None);
    }

    #[test]
    fn source_owned_envelope_cannot_bypass_required_fields() {
        for mutate in [
            |wire: &mut CommittedSourceWire| wire.id.clear(),
            |wire: &mut CommittedSourceWire| wire.tenant_id.clear(),
            |wire: &mut CommittedSourceWire| wire.occurred_at = None,
            |wire: &mut CommittedSourceWire| {
                wire.attributes.remove(SOURCE_RUNTIME_ID_ATTRIBUTE);
            },
        ] {
            let mut wire = source_wire();
            mutate(&mut wire);
            assert!(CommittedSourceEvent::decode(&encode(wire)).is_err());
        }
    }

    #[test]
    fn source_kind_must_belong_to_the_declared_source() {
        let mut wire = source_wire();
        wire.kind = "github.repositories".to_owned();
        assert!(matches!(
            CommittedSourceEvent::decode(&encode(wire)),
            Err(AppendLogDecodeError::Missing(_))
        ));
    }

    #[test]
    fn payload_must_be_json() {
        let mut wire = source_wire();
        wire.payload = b"not-json".to_vec();
        assert!(matches!(
            CommittedSourceEvent::decode(&encode(wire)),
            Err(AppendLogDecodeError::InvalidPayload(_))
        ));
    }

    #[test]
    fn timestamp_must_be_positive_and_normalized() {
        for timestamp in [
            Timestamp {
                seconds: 0,
                nanos: 0,
            },
            Timestamp {
                seconds: 1,
                nanos: -1,
            },
            Timestamp {
                seconds: 1,
                nanos: 1_000_000_000,
            },
        ] {
            let mut wire = source_wire();
            wire.occurred_at = Some(timestamp);
            assert_eq!(
                CommittedSourceEvent::decode(&encode(wire)).unwrap_err(),
                AppendLogDecodeError::InvalidTimestamp
            );
        }
    }

    #[test]
    fn committed_event_builds_the_only_allowed_incremental_batch() {
        let event = CommittedSourceEvent::decode(&encode(source_wire()))
            .unwrap()
            .unwrap();
        let batch = event
            .into_batch("box.asset".to_owned(), "file-1".to_owned())
            .unwrap();
        assert_eq!(batch.scope.receipt().tenant_id().as_str(), "tenant-a");
        assert_eq!(
            batch.scope.receipt().source_runtime_id().as_str(),
            "box-prod"
        );
        assert_eq!(batch.scope.receipt().scope(), "box.content_assets");
        assert_eq!(batch.records[0].provider_kind, "box.asset");
        assert_eq!(batch.records[0].provider_id, "file-1");
    }

    #[test]
    fn empty_payload_is_an_empty_object() {
        let mut wire = source_wire();
        wire.payload.clear();
        let event = CommittedSourceEvent::decode(&encode(wire))
            .unwrap()
            .unwrap();
        assert_eq!(event.payload(), &serde_json::json!({}));
    }

    #[test]
    fn decode_errors_explain_the_boundary_failure() {
        assert!(
            AppendLogDecodeError::Protobuf("bad wire".to_owned())
                .to_string()
                .contains("bad wire")
        );
        assert!(
            AppendLogDecodeError::Missing("tenant_id")
                .to_string()
                .contains("tenant_id")
        );
        assert!(
            AppendLogDecodeError::InvalidPayload("bad json".to_owned())
                .to_string()
                .contains("bad json")
        );
        assert!(
            AppendLogDecodeError::InvalidModel("bad id".to_owned())
                .to_string()
                .contains("bad id")
        );
    }
}
