//! Credential-free Cosmo response decoding and normalization kernel.
//!
//! Callers retain ownership of authenticated HTTP transport, endpoint policy,
//! pagination requests, and credential material. This module accepts a bounded
//! response body and emits the four portable Cosmo source-family records.

use std::{
    collections::BTreeMap,
    error::Error,
    fmt::{self, Write as _},
    str::FromStr,
};

use serde::Deserialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// One portable Cosmo source family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CosmoFamily {
    /// Agent-memory facts.
    Fact,
    /// Scoped message-export events.
    Message,
    /// Agent-memory sessions.
    Session,
    /// Survey responses collected by Cosmo.
    SurveyFeedback,
}

impl CosmoFamily {
    /// Return the source-catalog family identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fact => "fact",
            Self::Message => "message",
            Self::Session => "session",
            Self::SurveyFeedback => "survey_feedback",
        }
    }

    /// Return the emitted provider kind.
    pub const fn provider_kind(self) -> &'static str {
        match self {
            Self::Fact => "cosmo.fact",
            Self::Message => "cosmo.message",
            Self::Session => "cosmo.session",
            Self::SurveyFeedback => "cosmo.survey_feedback",
        }
    }

    /// Return the public payload schema reference.
    pub const fn schema_ref(self) -> &'static str {
        match self {
            Self::Fact => "cosmo/fact/v1",
            Self::Message => "cosmo/message/v1",
            Self::Session => "cosmo/session/v1",
            Self::SurveyFeedback => "cosmo/survey_feedback/v1",
        }
    }
}

impl FromStr for CosmoFamily {
    type Err = CosmoError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim() {
            "fact" => Ok(Self::Fact),
            "message" => Ok(Self::Message),
            "session" => Ok(Self::Session),
            "survey_feedback" => Ok(Self::SurveyFeedback),
            _ => Err(CosmoError::InvalidFamily),
        }
    }
}

/// One normalized Cosmo source record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CosmoRecord {
    /// Source-catalog family identifier.
    pub family: String,
    /// Emitted provider kind.
    pub provider_kind: String,
    /// Public payload schema reference.
    pub schema_ref: String,
    /// Provider-supplied identity before hashing.
    pub record_id: String,
    /// Go-compatible collision-resistant provider identity.
    pub provider_id: String,
    /// Portable scalar attributes used by source mapping.
    pub fields: BTreeMap<String, String>,
    /// Original provider record.
    pub payload: Value,
}

/// One decoded Cosmo provider response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CosmoPage {
    /// Normalized records in provider response order.
    pub records: Vec<CosmoRecord>,
}

/// Credential-free decoder for one Cosmo family response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CosmoKernel {
    family: CosmoFamily,
}

impl CosmoKernel {
    /// Build a decoder for one of the four portable Cosmo families.
    pub const fn new(family: CosmoFamily) -> Self {
        Self { family }
    }

    /// Return whether the owning pull source requires credential material.
    ///
    /// Credentials stay outside this decoder and belong to the caller's
    /// authenticated HTTP boundary.
    pub const fn requires_credentials(&self) -> bool {
        true
    }

    /// Decode a Cosmo response and normalize the configured family.
    pub fn decode(&self, body: &[u8]) -> Result<CosmoPage, CosmoError> {
        let response: ListResponse =
            serde_json::from_slice(body).map_err(|_| CosmoError::InvalidResponse)?;
        let values = match self.family {
            CosmoFamily::Fact => response.facts,
            CosmoFamily::Message => response.messages,
            CosmoFamily::Session => response.sessions,
            CosmoFamily::SurveyFeedback => response.feedback,
        };
        let records = values
            .into_iter()
            .map(|value| record(self.family, value))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(CosmoPage { records })
    }
}

/// Safe Cosmo decoding failures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CosmoError {
    /// Family identifier is not one of the four supported contracts.
    InvalidFamily,
    /// Response bytes are not a structurally valid Cosmo JSON envelope.
    InvalidResponse,
    /// A family collection item is not a JSON object.
    InvalidRecord,
}

impl fmt::Display for CosmoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidFamily => "cosmo family is invalid",
            Self::InvalidResponse => "cosmo response JSON is invalid",
            Self::InvalidRecord => "cosmo response record must be a JSON object",
        })
    }
}

impl Error for CosmoError {}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
struct ListResponse {
    facts: Vec<Value>,
    messages: Vec<Value>,
    sessions: Vec<Value>,
    feedback: Vec<Value>,
}

fn record(family: CosmoFamily, payload: Value) -> Result<CosmoRecord, CosmoError> {
    let values = payload.as_object().ok_or(CosmoError::InvalidRecord)?;
    let record_id = record_id(family, values);
    let mut fields = attributes(family, values);
    insert_nonblank(&mut fields, "record_id", &record_id);
    Ok(CosmoRecord {
        family: family.as_str().to_owned(),
        provider_kind: family.provider_kind().to_owned(),
        schema_ref: family.schema_ref().to_owned(),
        provider_id: stable_external_id(&record_id, "unknown"),
        record_id,
        fields,
        payload,
    })
}

fn record_id(family: CosmoFamily, values: &Map<String, Value>) -> String {
    match family {
        CosmoFamily::Session => first_value(values, &["thread_key", "ticket_id", "id"]),
        CosmoFamily::Fact => first_value(values, &["key", "id"]),
        CosmoFamily::Message => {
            let explicit = first_value(values, &["id"]);
            if explicit.is_empty() {
                stable_join([
                    first_value(values, &["ticket_id"]),
                    first_value(values, &["event_type"]),
                    first_value(values, &["created_at"]),
                ])
            } else {
                explicit
            }
        }
        CosmoFamily::SurveyFeedback => {
            let explicit = first_value(values, &["key"]);
            if explicit.is_empty() {
                stable_join([
                    first_value(values, &["ticketId"]),
                    first_value(values, &["messageTs"]),
                    first_value(values, &["userId"]),
                ])
            } else {
                explicit
            }
        }
    }
}

fn attributes(family: CosmoFamily, values: &Map<String, Value>) -> BTreeMap<String, String> {
    let mut fields = BTreeMap::new();
    match family {
        CosmoFamily::Session => {
            insert_first(&mut fields, "ticket_id", values, &["ticket_id"]);
            insert_first(&mut fields, "thread_key", values, &["thread_key"]);
            insert_first(&mut fields, "user", values, &["user"]);
            insert_first(&mut fields, "agent_type", values, &["agent_type"]);
            insert_first(&mut fields, "status", values, &["status"]);
            insert_first(&mut fields, "source", values, &["source"]);
        }
        CosmoFamily::Fact => {
            insert_first(&mut fields, "key", values, &["key"]);
            insert_first(&mut fields, "category", values, &["category"]);
            insert_first(&mut fields, "source", values, &["source"]);
            insert_first(&mut fields, "confidence", values, &["confidence"]);
            insert_first(&mut fields, "risk_reason", values, &["risk_reason"]);
            insert_first(
                &mut fields,
                "risk_severity",
                values,
                &["risk_severity", "severity"],
            );
        }
        CosmoFamily::Message => {
            insert_first(&mut fields, "ticket_id", values, &["ticket_id"]);
            insert_first(&mut fields, "event_type", values, &["event_type"]);
            insert_first(&mut fields, "role", values, &["role"]);
            insert_first(&mut fields, "user", values, &["user", "username"]);
            insert_first(
                &mut fields,
                "user_id",
                values,
                &["user_id", "userId", "user.id"],
            );
            insert_first(
                &mut fields,
                "email",
                values,
                &["email", "user_email", "userEmail", "user.email"],
            );
            insert_first(&mut fields, "tool_name", values, &["tool_name"]);
            insert_first(&mut fields, "agent_type", values, &["agent_type"]);
            insert_first(&mut fields, "run_url", values, &["run_url"]);
        }
        CosmoFamily::SurveyFeedback => {
            insert_first(&mut fields, "ticket_id", values, &["ticketId"]);
            insert_first(&mut fields, "channel", values, &["channel"]);
            insert_first(&mut fields, "user_id", values, &["userId"]);
            insert_first(&mut fields, "reaction", values, &["reaction"]);
            insert_first(&mut fields, "sentiment", values, &["sentiment"]);
            insert_first(&mut fields, "workflow_run_url", values, &["workflowRunUrl"]);
        }
    }
    fields
}

fn insert_first(
    fields: &mut BTreeMap<String, String>,
    field: &str,
    values: &Map<String, Value>,
    paths: &[&str],
) {
    let value = first_value(values, paths);
    insert_nonblank(fields, field, &value);
}

fn insert_nonblank(fields: &mut BTreeMap<String, String>, field: &str, value: &str) {
    let value = value.trim();
    if !value.is_empty() {
        fields.insert(field.to_owned(), value.to_owned());
    }
}

fn first_value(values: &Map<String, Value>, paths: &[&str]) -> String {
    paths
        .iter()
        .map(|path| value_at(values, path))
        .map(flattened)
        .find(|value| !value.is_empty())
        .unwrap_or_default()
}

fn value_at<'a>(values: &'a Map<String, Value>, path: &str) -> Option<&'a Value> {
    let mut parts = path.split('.');
    let first = parts.next()?;
    let mut value = values.get(first)?;
    for part in parts {
        value = value.as_object()?.get(part)?;
    }
    Some(value)
}

fn flattened(value: Option<&Value>) -> String {
    match value {
        None | Some(Value::Null) | Some(Value::Object(_)) => String::new(),
        Some(Value::String(value)) => value.trim().to_owned(),
        Some(Value::Number(value)) => value.to_string(),
        Some(Value::Bool(value)) => value.to_string(),
        Some(Value::Array(values)) => values
            .iter()
            .map(|value| flattened(Some(value)))
            .filter(|value| !value.is_empty())
            .collect::<Vec<_>>()
            .join(","),
    }
}

fn stable_join<const N: usize>(values: [String; N]) -> String {
    values
        .iter()
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>()
        .join(":")
}

fn stable_external_id(value: &str, empty_fallback: &str) -> String {
    let normalized = value.trim();
    if normalized.is_empty() {
        return empty_fallback.to_owned();
    }
    let digest = Sha256::digest(normalized.as_bytes());
    let mut output = String::with_capacity(35);
    output.push_str("id-");
    for byte in &digest[..16] {
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_session_identity_and_attributes() {
        let page = CosmoKernel::new(CosmoFamily::Session)
            .decode(
                br#"{"ok":true,"sessions":[{"id":1,"ticket_id":"COSMO-1","thread_key":"C123:1","user":"U123","status":"success"}]}"#,
            )
            .expect("session response");
        assert_eq!(page.records.len(), 1);
        let record = &page.records[0];
        assert_eq!(record.record_id, "C123:1");
        assert!(record.provider_id.starts_with("id-"));
        assert_eq!(record.provider_id.len(), 35);
        assert_eq!(record.fields["ticket_id"], "COSMO-1");
        assert_eq!(record.fields["record_id"], "C123:1");
        assert_eq!(record.provider_kind, "cosmo.session");
        assert_eq!(record.schema_ref, "cosmo/session/v1");
    }

    #[test]
    fn decodes_fact_severity_fallback() {
        let page = CosmoKernel::new(CosmoFamily::Fact)
            .decode(
                br#"{"facts":[{"key":"coordination:risk","category":"security","severity":"high","confidence":0.9}]}"#,
            )
            .expect("fact response");
        let record = &page.records[0];
        assert_eq!(record.record_id, "coordination:risk");
        assert_eq!(record.fields["risk_severity"], "high");
        assert_eq!(record.fields["confidence"], "0.9");
    }

    #[test]
    fn message_fallback_identity_and_nested_user_match_go_contract() {
        let page = CosmoKernel::new(CosmoFamily::Message)
            .decode(
                br#"{"messages":[{"ticket_id":"COSMO-2","event_type":"message","created_at":"2026-05-13T01:02:03Z","role":"user","user":{"id":"U2","email":"u2@example.com"}}]}"#,
            )
            .expect("message response");
        let record = &page.records[0];
        assert_eq!(record.record_id, "COSMO-2:message:2026-05-13T01:02:03Z");
        assert_eq!(record.fields["user_id"], "U2");
        assert_eq!(record.fields["email"], "u2@example.com");
    }

    #[test]
    fn survey_feedback_uses_composite_identity_without_key() {
        let page = CosmoKernel::new(CosmoFamily::SurveyFeedback)
            .decode(
                br#"{"feedback":[{"ticketId":"COSMO-3","messageTs":"1710000000.1","userId":"U3","reaction":"thumbsup"}]}"#,
            )
            .expect("feedback response");
        let record = &page.records[0];
        assert_eq!(record.record_id, "COSMO-3:1710000000.1:U3");
        assert_eq!(record.fields["reaction"], "thumbsup");
        assert_eq!(record.provider_kind, "cosmo.survey_feedback");
    }

    #[test]
    fn missing_provider_identity_uses_go_fallback() {
        let page = CosmoKernel::new(CosmoFamily::Fact)
            .decode(br#"{"facts":[{"category":"unknown"}]}"#)
            .expect("fact response");
        assert_eq!(page.records[0].record_id, "");
        assert_eq!(page.records[0].provider_id, "unknown");
        assert!(!page.records[0].fields.contains_key("record_id"));
    }

    #[test]
    fn rejects_non_object_records_and_invalid_envelopes() {
        assert_eq!(
            CosmoKernel::new(CosmoFamily::Session).decode(br#"{"sessions":[1]}"#),
            Err(CosmoError::InvalidRecord)
        );
        assert_eq!(
            CosmoKernel::new(CosmoFamily::Session).decode(b"not-json"),
            Err(CosmoError::InvalidResponse)
        );
    }

    #[test]
    fn parses_only_known_family_identifiers() {
        assert_eq!("message".parse(), Ok(CosmoFamily::Message));
        assert_eq!(
            "virtual".parse::<CosmoFamily>(),
            Err(CosmoError::InvalidFamily)
        );
    }
}
