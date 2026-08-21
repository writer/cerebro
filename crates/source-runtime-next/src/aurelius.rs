//! Credential-free Aurelius NDJSON decoding and cursor kernel.
//!
//! The Go source owns S3 listing, object reads, optional role assumption, and
//! gzip decompression. Callers pass decompressed NDJSON bytes to this module;
//! the kernel enforces the portable record, tenant, family, attribute, and
//! resumable-cursor contracts without opening a network or credential path.

use std::{collections::BTreeMap, error::Error, fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

const CURSOR_SOURCE: &str = "aurelius/s3-ndjson/v1";
const MAX_OBJECT_BYTES: usize = 64 << 20;
const MAX_LINE_BYTES: usize = 1 << 20;

/// One portable Aurelius source family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AureliusFamily {
    /// Image policy verdicts.
    Verdict,
    /// Vulnerability findings.
    Finding,
    /// Image scan completion records.
    ImageScan,
    /// Catalog promotion decisions.
    CatalogPromotion,
    /// Policy exceptions.
    PolicyException,
}

impl AureliusFamily {
    /// Return the source-catalog family identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Verdict => "verdict",
            Self::Finding => "finding",
            Self::ImageScan => "image_scan",
            Self::CatalogPromotion => "catalog_promotion",
            Self::PolicyException => "policy_exception",
        }
    }

    /// Return the emitted provider kind.
    pub const fn provider_kind(self) -> &'static str {
        match self {
            Self::Verdict => "aurelius.verdict",
            Self::Finding => "aurelius.finding",
            Self::ImageScan => "aurelius.image_scan",
            Self::CatalogPromotion => "aurelius.catalog_promotion",
            Self::PolicyException => "aurelius.policy_exception",
        }
    }

    /// Return the canonical payload schema reference.
    pub const fn schema_ref(self) -> &'static str {
        match self {
            Self::Verdict => "aurelius/verdict/v1",
            Self::Finding => "aurelius/finding/v1",
            Self::ImageScan => "aurelius/image_scan/v1",
            Self::CatalogPromotion => "aurelius/catalog_promotion/v1",
            Self::PolicyException => "aurelius/policy_exception/v1",
        }
    }

    fn promoted_attribute_keys(self) -> &'static [&'static str] {
        match self {
            Self::Verdict => &["image_digest", "verdict"],
            Self::Finding => &[
                "image_digest",
                "severity",
                "cve_id",
                "package",
                "installed_version",
                "fixed_version",
            ],
            Self::ImageScan => &["image_digest", "registry"],
            Self::CatalogPromotion => &["track", "image_digest"],
            Self::PolicyException => &["cve_id", "status"],
        }
    }
}

impl FromStr for AureliusFamily {
    type Err = AureliusError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim() {
            "verdict" => Ok(Self::Verdict),
            "finding" => Ok(Self::Finding),
            "image_scan" => Ok(Self::ImageScan),
            "catalog_promotion" => Ok(Self::CatalogPromotion),
            "policy_exception" => Ok(Self::PolicyException),
            _ => Err(AureliusError::InvalidFamily),
        }
    }
}

/// One normalized Aurelius source record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AureliusRecord {
    /// Stable archive event identifier.
    pub provider_id: String,
    /// Tenant after applying the configured tenant default.
    pub tenant_id: String,
    /// Parsed provider occurrence time.
    pub occurred_at: OffsetDateTime,
    /// Source-catalog family identifier.
    pub family: String,
    /// Emitted provider kind.
    pub provider_kind: String,
    /// Canonical payload schema reference.
    pub schema_ref: String,
    /// Sorted scalar attributes, including family-specific promotions.
    pub fields: BTreeMap<String, String>,
    /// Provider payload retained for family-specific mapping.
    pub payload: Value,
}

/// A decoded Aurelius archive page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AureliusPage {
    /// Tenant-scoped records in archive order.
    pub records: Vec<AureliusRecord>,
}

/// Portable Aurelius cursor state.
#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
pub struct AureliusCursor {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    source: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    resumable_checkpoint: bool,
    /// Last fully consumed S3 object key.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub last_key: String,
    /// Object currently being consumed when an archive spans pulls.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub partial_key: String,
    /// Zero-based record offset within `partial_key`.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub record_offset: i64,
    /// Monotonic RFC3339Nano event watermark.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub watermark: String,
}

impl AureliusCursor {
    /// Decode the structured cursor, accepting the legacy raw-key form.
    pub fn decode(opaque: &str) -> Self {
        let opaque = opaque.trim();
        if opaque.is_empty() {
            return Self::default();
        }
        if let Ok(mut decoded) = serde_json::from_str::<Self>(opaque)
            && decoded.source == CURSOR_SOURCE
        {
            decoded.last_key = decoded.last_key.trim().to_owned();
            decoded.partial_key = decoded.partial_key.trim().to_owned();
            decoded.watermark = decoded.watermark.trim().to_owned();
            if decoded.partial_key.is_empty() || decoded.record_offset < 0 {
                decoded.record_offset = 0;
            }
            return decoded;
        }
        Self {
            last_key: opaque.to_owned(),
            ..Self::default()
        }
    }

    /// Encode Go-compatible structured cursor JSON.
    pub fn encode(&self) -> String {
        let mut cursor = self.clone();
        cursor.source = CURSOR_SOURCE.to_owned();
        cursor.resumable_checkpoint = true;
        cursor.last_key = cursor.last_key.trim().to_owned();
        cursor.partial_key = cursor.partial_key.trim().to_owned();
        cursor.watermark = cursor.watermark.trim().to_owned();
        if cursor.partial_key.is_empty() || cursor.record_offset < 0 {
            cursor.record_offset = 0;
        }
        serde_json::to_string(&cursor).unwrap_or(cursor.last_key)
    }
}

const fn is_zero(value: &i64) -> bool {
    *value == 0
}

/// Credential-free Aurelius archive decoder.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AureliusKernel {
    family: AureliusFamily,
    tenant_id: String,
}

impl AureliusKernel {
    /// Build a decoder for one family and required tenant scope.
    pub fn new(
        family: AureliusFamily,
        tenant_id: impl Into<String>,
    ) -> Result<Self, AureliusError> {
        let tenant_id = tenant_id.into();
        let tenant_id = tenant_id.trim();
        if tenant_id.is_empty() {
            return Err(AureliusError::MissingTenantId);
        }
        Ok(Self {
            family,
            tenant_id: tenant_id.to_owned(),
        })
    }

    /// Return whether this portable kernel requires credential material.
    pub const fn requires_credentials(&self) -> bool {
        false
    }

    /// Decode decompressed NDJSON bytes into tenant-scoped records.
    pub fn decode_ndjson(&self, body: &[u8]) -> Result<AureliusPage, AureliusError> {
        if body.len() > MAX_OBJECT_BYTES {
            return Err(AureliusError::ArchiveTooLarge);
        }
        let mut records = Vec::new();
        for (index, raw_line) in body.split(|byte| *byte == b'\n').enumerate() {
            let line_number = index + 1;
            let line = trim_ascii(raw_line);
            if line.is_empty() {
                continue;
            }
            if line.len() > MAX_LINE_BYTES {
                return Err(AureliusError::LineTooLarge { line: line_number });
            }
            let raw: RawRecord = serde_json::from_slice(line)
                .map_err(|_| AureliusError::InvalidJson { line: line_number })?;
            if let Some(record) = self.normalize(raw, line_number)? {
                records.push(record);
            }
        }
        Ok(AureliusPage { records })
    }

    fn normalize(
        &self,
        raw: RawRecord,
        line: usize,
    ) -> Result<Option<AureliusRecord>, AureliusError> {
        if raw.event_id.trim().is_empty() {
            return Err(AureliusError::MissingEventId { line });
        }
        let occurred_at = OffsetDateTime::parse(raw.occurred_at.trim(), &Rfc3339)
            .map_err(|_| AureliusError::InvalidOccurredAt { line })?;
        if raw.occurred_at.trim() == "0001-01-01T00:00:00Z" {
            return Err(AureliusError::InvalidOccurredAt { line });
        }
        let record_tenant = raw.tenant_id.trim();
        if !record_tenant.is_empty() && record_tenant != self.tenant_id {
            return Ok(None);
        }
        let tenant_id = if record_tenant.is_empty() {
            self.tenant_id.clone()
        } else {
            record_tenant.to_owned()
        };
        let mut fields = BTreeMap::new();
        for (key, value) in raw.attributes.unwrap_or_default() {
            let key = key.trim();
            if !key.is_empty() {
                fields.insert(key.to_owned(), value);
            }
        }
        let payload = raw.payload;
        for key in self.family.promoted_attribute_keys() {
            if fields
                .get(*key)
                .is_some_and(|value| !value.trim().is_empty())
            {
                continue;
            }
            if let Some(value) = payload
                .as_ref()
                .and_then(|payload| payload.get(*key))
                .and_then(payload_attribute_string)
            {
                fields.insert((*key).to_owned(), value);
            }
        }
        Ok(Some(AureliusRecord {
            provider_id: raw.event_id,
            tenant_id,
            occurred_at,
            family: self.family.as_str().to_owned(),
            provider_kind: self.family.provider_kind().to_owned(),
            schema_ref: self.family.schema_ref().to_owned(),
            fields,
            payload: payload.map(Value::Object).unwrap_or(Value::Null),
        }))
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawRecord {
    event_id: String,
    occurred_at: String,
    tenant_id: String,
    attributes: Option<BTreeMap<String, String>>,
    payload: Option<Map<String, Value>>,
}

fn payload_attribute_string(value: &Value) -> Option<String> {
    let value = match value {
        Value::String(value) => value.trim().to_owned(),
        Value::Number(value) => value.to_string(),
        Value::Bool(value) => value.to_string(),
        _ => return None,
    };
    (!value.is_empty()).then_some(value)
}

fn trim_ascii(mut value: &[u8]) -> &[u8] {
    while value.first().is_some_and(u8::is_ascii_whitespace) {
        value = &value[1..];
    }
    while value.last().is_some_and(u8::is_ascii_whitespace) {
        value = &value[..value.len() - 1];
    }
    value
}

/// Safe Aurelius decoding failures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AureliusError {
    /// Family identifier is not one of the five supported contracts.
    InvalidFamily,
    /// The kernel lacks an explicit tenant scope.
    MissingTenantId,
    /// Decompressed archive bytes exceed the Go source ceiling.
    ArchiveTooLarge,
    /// A non-empty NDJSON line exceeds the Go source ceiling.
    LineTooLarge {
        /// One-based archive line number.
        line: usize,
    },
    /// A non-empty line is not a valid Aurelius JSON record.
    InvalidJson {
        /// One-based archive line number.
        line: usize,
    },
    /// A record has no non-blank event identifier.
    MissingEventId {
        /// One-based archive line number.
        line: usize,
    },
    /// A record has no valid non-zero RFC3339 occurrence time.
    InvalidOccurredAt {
        /// One-based archive line number.
        line: usize,
    },
}

impl fmt::Display for AureliusError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFamily => formatter.write_str("aurelius family is invalid"),
            Self::MissingTenantId => formatter.write_str("aurelius tenant_id is required"),
            Self::ArchiveTooLarge => formatter.write_str("aurelius archive exceeds 67108864 bytes"),
            Self::LineTooLarge { line } => {
                write!(formatter, "aurelius line {line} exceeds 1048576 bytes")
            }
            Self::InvalidJson { line } => write!(formatter, "aurelius line {line} JSON is invalid"),
            Self::MissingEventId { line } => {
                write!(formatter, "aurelius line {line} event_id is required")
            }
            Self::InvalidOccurredAt { line } => {
                write!(formatter, "aurelius line {line} occurred_at is invalid")
            }
        }
    }
}

impl Error for AureliusError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn kernel(family: AureliusFamily) -> AureliusKernel {
        AureliusKernel::new(family, "writer").expect("valid kernel")
    }

    #[test]
    fn family_contract_is_exact() {
        let cases = [
            (
                AureliusFamily::Verdict,
                "verdict",
                "aurelius.verdict",
                "aurelius/verdict/v1",
            ),
            (
                AureliusFamily::Finding,
                "finding",
                "aurelius.finding",
                "aurelius/finding/v1",
            ),
            (
                AureliusFamily::ImageScan,
                "image_scan",
                "aurelius.image_scan",
                "aurelius/image_scan/v1",
            ),
            (
                AureliusFamily::CatalogPromotion,
                "catalog_promotion",
                "aurelius.catalog_promotion",
                "aurelius/catalog_promotion/v1",
            ),
            (
                AureliusFamily::PolicyException,
                "policy_exception",
                "aurelius.policy_exception",
                "aurelius/policy_exception/v1",
            ),
        ];
        for (family, name, kind, schema_ref) in cases {
            assert_eq!(family.as_str(), name);
            assert_eq!(family.provider_kind(), kind);
            assert_eq!(family.schema_ref(), schema_ref);
            assert_eq!(AureliusFamily::from_str(name), Ok(family));
        }
        assert_eq!(
            AureliusFamily::from_str("unknown"),
            Err(AureliusError::InvalidFamily)
        );
    }

    #[test]
    fn decodes_tenant_scoped_records_and_promotes_attributes() {
        let page = kernel(AureliusFamily::Finding)
            .decode_ndjson(br#"
                {"event_id":"finding-1","occurred_at":"2026-05-22T13:14:15.123Z","tenant_id":"writer","attributes":{" severity ":"HIGH","blank":"kept"," ":"ignored"},"payload":{"image_digest":"sha256:abc","severity":"LOW","cve_id":"CVE-1","package":"openssl","installed_version":"1","fixed_version":"2","ignored":{"nested":true}}}
                {"event_id":"finding-other","occurred_at":"2026-05-22T13:14:16Z","tenant_id":"other","attributes":{},"payload":{"cve_id":"CVE-2"}}
                {"event_id":"finding-default","occurred_at":"2026-05-22T13:14:17+00:00","attributes":{},"payload":{"cve_id":"CVE-3"}}
            "#)
            .expect("valid archive");
        assert_eq!(page.records.len(), 2);
        let first = &page.records[0];
        assert_eq!(first.provider_id, "finding-1");
        assert_eq!(first.tenant_id, "writer");
        assert_eq!(first.family, "finding");
        assert_eq!(first.provider_kind, "aurelius.finding");
        assert_eq!(first.schema_ref, "aurelius/finding/v1");
        assert_eq!(first.fields["severity"], "HIGH");
        assert_eq!(first.fields["image_digest"], "sha256:abc");
        assert_eq!(first.fields["fixed_version"], "2");
        assert!(!first.fields.contains_key("ignored"));
        assert_eq!(page.records[1].tenant_id, "writer");
        assert_eq!(page.records[1].fields["cve_id"], "CVE-3");
    }

    #[test]
    fn promotes_only_go_compatible_payload_scalars() {
        let page = kernel(AureliusFamily::Verdict)
            .decode_ndjson(br#"{"event_id":"verdict-1","occurred_at":"2026-05-22T13:14:15Z","attributes":{"image_digest":"   "},"payload":{"image_digest":42,"verdict":true}}"#)
            .expect("valid archive");
        assert_eq!(page.records[0].fields["image_digest"], "42");
        assert_eq!(page.records[0].fields["verdict"], "true");
    }

    #[test]
    fn missing_and_null_payloads_match_go_nil_maps() {
        let page = kernel(AureliusFamily::Verdict)
            .decode_ndjson(
                br#"{"event_id":"missing","occurred_at":"2026-05-22T13:14:15Z"}
{"event_id":"null","occurred_at":"2026-05-22T13:14:16Z","attributes":null,"payload":null}"#,
            )
            .expect("valid archive");
        assert_eq!(page.records.len(), 2);
        assert_eq!(page.records[0].payload, Value::Null);
        assert_eq!(page.records[1].payload, Value::Null);
        assert!(page.records[0].fields.is_empty());
        assert!(page.records[1].fields.is_empty());
    }

    #[test]
    fn rejects_invalid_record_boundaries() {
        assert_eq!(
            AureliusKernel::new(AureliusFamily::Verdict, " "),
            Err(AureliusError::MissingTenantId)
        );
        assert_eq!(
            kernel(AureliusFamily::Verdict).decode_ndjson(b"not-json"),
            Err(AureliusError::InvalidJson { line: 1 })
        );
        assert_eq!(
            kernel(AureliusFamily::Verdict)
                .decode_ndjson(br#"{"occurred_at":"2026-05-22T13:14:15Z"}"#),
            Err(AureliusError::MissingEventId { line: 1 })
        );
        assert_eq!(
            kernel(AureliusFamily::Verdict)
                .decode_ndjson(br#"{"event_id":"x","occurred_at":"0001-01-01T00:00:00Z"}"#),
            Err(AureliusError::InvalidOccurredAt { line: 1 })
        );
    }

    #[test]
    fn cursor_round_trips_and_accepts_legacy_key() {
        let cursor = AureliusCursor {
            last_key: " verdicts/one.ndjson ".to_owned(),
            partial_key: " verdicts/two.ndjson ".to_owned(),
            record_offset: 1000,
            watermark: " 2026-05-22T13:14:15.123Z ".to_owned(),
            ..AureliusCursor::default()
        };
        let encoded = cursor.encode();
        let decoded = AureliusCursor::decode(&encoded);
        assert_eq!(decoded.last_key, "verdicts/one.ndjson");
        assert_eq!(decoded.partial_key, "verdicts/two.ndjson");
        assert_eq!(decoded.record_offset, 1000);
        assert_eq!(decoded.watermark, "2026-05-22T13:14:15.123Z");
        assert_eq!(
            AureliusCursor::decode(" findings/legacy.ndjson ").last_key,
            "findings/legacy.ndjson"
        );
    }

    #[test]
    fn cursor_clears_offset_without_partial_key() {
        let encoded = AureliusCursor {
            last_key: "findings/one.ndjson".to_owned(),
            record_offset: 55,
            ..AureliusCursor::default()
        }
        .encode();
        assert_eq!(AureliusCursor::decode(&encoded).record_offset, 0);
    }

    #[test]
    fn cursor_clears_negative_offset() {
        let decoded = AureliusCursor::decode(
            r#"{"source":"aurelius/s3-ndjson/v1","resumable_checkpoint":true,"partial_key":"findings/one.ndjson","record_offset":-1}"#,
        );
        assert_eq!(decoded.partial_key, "findings/one.ndjson");
        assert_eq!(decoded.record_offset, 0);
    }
}
