//! Credential-free GCP source normalization kernels.
//!
//! Live GCP collection requires provider authorization, WIF token exchange,
//! and service-specific HTTP adapters. This module owns only the bounded GCS
//! object-content decision that is portable across those adapters: decide
//! whether a capped sample is useful, derive coarse data signals, and discard
//! the sample instead of carrying provider content into the runtime record.

use std::fmt;

/// Ordered data classifications emitted by GCP object inspection.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum GcpDataClassification {
    /// Content explicitly intended for public distribution.
    Public,
    /// Content intended only for the organization.
    Internal,
    /// Content requiring confidential handling.
    Confidential,
    /// Content containing regulated or secret material.
    Restricted,
}

impl GcpDataClassification {
    /// Return the source attribute value used by the Go GCP source.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Internal => "internal",
            Self::Confidential => "confidential",
            Self::Restricted => "restricted",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "public" => Some(Self::Public),
            "internal" => Some(Self::Internal),
            "confidential" => Some(Self::Confidential),
            "restricted" => Some(Self::Restricted),
            _ => None,
        }
    }
}

impl fmt::Display for GcpDataClassification {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Signals derived from one bounded GCS object-content sample.
///
/// The original sample is deliberately absent so callers cannot accidentally
/// persist source object content in a runtime record or receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GcpContentInspection {
    /// Number of sample bytes inspected.
    pub bytes_scanned: usize,
    /// Whether the provider indicated that more object bytes exist.
    pub truncated: bool,
    /// Stable coarse finding names in GCP source order.
    pub findings: Vec<&'static str>,
    /// Strongest classification derived from the sample.
    pub data_classification: Option<GcpDataClassification>,
    /// Whether the sample contains an email address or US SSN pattern.
    pub contains_pii: bool,
    /// Whether the sample contains an assigned secret or private key marker.
    pub contains_secrets: bool,
}

/// Bounded, credential-free GCS object-content inspection kernel.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GcpObjectContentKernel;

impl GcpObjectContentKernel {
    /// Return whether a GCS object is eligible for bounded text inspection.
    pub fn should_inspect(name: &str, content_type: &str) -> bool {
        let content_type = content_type
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        if content_type.starts_with("text/")
            || matches!(
                content_type.as_str(),
                "application/json"
                    | "application/xml"
                    | "application/yaml"
                    | "application/x-yaml"
                    | "application/javascript"
                    | "application/x-www-form-urlencoded"
            )
            || content_type.ends_with("+json")
            || content_type.ends_with("+xml")
        {
            return true;
        }

        let name = name.to_ascii_lowercase();
        [
            ".csv", ".env", ".ini", ".json", ".log", ".md", ".sql", ".tf", ".txt", ".xml", ".yaml",
            ".yml",
        ]
        .iter()
        .any(|suffix| name.ends_with(suffix))
    }

    /// Inspect one already-bounded object sample without retaining its bytes.
    pub fn inspect(sample: &[u8], truncated: bool) -> GcpContentInspection {
        let normalized = String::from_utf8_lossy(sample).to_ascii_lowercase();
        let contains_pii = contains_email(&normalized) || contains_ssn(&normalized);
        let contains_secrets = contains_secret_assignment(&normalized)
            || (normalized.contains("-----begin ") && normalized.contains(" private key-----"));
        let mut findings = Vec::with_capacity(2);
        if contains_pii {
            findings.push("pii");
        }
        if contains_secrets {
            findings.push("secret");
        }
        let detected = find_classification(&normalized);
        let data_classification = if contains_pii || contains_secrets {
            Some(GcpDataClassification::Restricted)
        } else {
            detected
        };
        GcpContentInspection {
            bytes_scanned: sample.len(),
            truncated,
            findings,
            data_classification,
            contains_pii,
            contains_secrets,
        }
    }

    /// Merge metadata with an inspected classification without downgrade.
    ///
    /// Unknown non-empty metadata values are preserved exactly because they may
    /// be tenant-defined labels outside the four ordered classifications.
    pub fn strongest_classification(
        metadata_classification: &str,
        inspected_classification: Option<GcpDataClassification>,
    ) -> String {
        let metadata = metadata_classification.trim();
        let Some(content) = inspected_classification else {
            return metadata.to_owned();
        };
        if metadata.is_empty() {
            return content.as_str().to_owned();
        }
        let Some(metadata_class) = GcpDataClassification::parse(metadata) else {
            return metadata.to_owned();
        };
        metadata_class.max(content).as_str().to_owned()
    }

    /// Merge a metadata indicator with an optional inspection result.
    pub fn merge_contains_indicator(metadata_value: &str, inspected: Option<bool>) -> String {
        let metadata = metadata_value.trim();
        if inspected == Some(true) || truthy_indicator(metadata) {
            return "true".to_owned();
        }
        if !metadata.is_empty() {
            return metadata.to_owned();
        }
        inspected.map(|value| value.to_string()).unwrap_or_default()
    }

    /// Return whether this pure kernel requires credential material.
    pub const fn requires_credentials() -> bool {
        false
    }
}

fn contains_email(value: &str) -> bool {
    value
        .split(|character: char| !is_email_character(character))
        .map(|candidate| candidate.trim_end_matches('.'))
        .any(valid_email_candidate)
}

fn is_email_character(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '%' | '+' | '-' | '@')
}

fn valid_email_candidate(candidate: &str) -> bool {
    let Some((local, domain)) = candidate.split_once('@') else {
        return false;
    };
    if local.is_empty() || domain.is_empty() || domain.contains('@') {
        return false;
    }
    let Some((host, suffix)) = domain.rsplit_once('.') else {
        return false;
    };
    !host.is_empty()
        && suffix.len() >= 2
        && suffix
            .chars()
            .all(|character| character.is_ascii_alphabetic())
}

fn contains_ssn(value: &str) -> bool {
    value
        .as_bytes()
        .windows(11)
        .enumerate()
        .any(|(index, window)| {
            matches!(window, [a, b, c, b'-', d, e, b'-', f, g, h, i]
            if [a, b, c, d, e, f, g, h, i].iter().all(|byte| byte.is_ascii_digit()))
                && left_word_boundary(value.as_bytes(), index)
                && right_word_boundary(value.as_bytes(), index + window.len())
        })
}

fn contains_secret_assignment(value: &str) -> bool {
    [
        "api_key",
        "api-key",
        "apikey",
        "secret",
        "token",
        "password",
        "passwd",
        "private_key",
        "private-key",
        "privatekey",
    ]
    .iter()
    .any(|key| {
        value.match_indices(key).any(|(index, _)| {
            let tail = &value[index + key.len()..];
            let tail = tail.trim_start();
            let Some(tail) = tail.strip_prefix(':').or_else(|| tail.strip_prefix('=')) else {
                return false;
            };
            let tail = tail.trim_start();
            let tail = tail
                .strip_prefix('"')
                .or_else(|| tail.strip_prefix('\''))
                .unwrap_or(tail);
            tail.chars()
                .take_while(|character| is_secret_character(*character))
                .count()
                >= 12
        })
    })
}

fn is_secret_character(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '_' | '.' | '/' | '+' | '=' | '-')
}

fn find_classification(value: &str) -> Option<GcpDataClassification> {
    let mut first = None;
    for classification in [
        GcpDataClassification::Restricted,
        GcpDataClassification::Confidential,
        GcpDataClassification::Internal,
        GcpDataClassification::Public,
    ] {
        for (index, _) in value.match_indices(classification.as_str()) {
            let end = index + classification.as_str().len();
            if left_word_boundary(value.as_bytes(), index)
                && right_word_boundary(value.as_bytes(), end)
            {
                if first.is_none_or(|(first_index, _)| index < first_index) {
                    first = Some((index, classification));
                }
                break;
            }
        }
    }
    first.map(|(_, classification)| classification)
}

fn left_word_boundary(value: &[u8], index: usize) -> bool {
    index == 0 || !is_word_byte(value[index - 1])
}

fn right_word_boundary(value: &[u8], index: usize) -> bool {
    index == value.len() || !is_word_byte(value[index])
}

fn is_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn truthy_indicator(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "true" | "1" | "yes" | "y"
    )
}

#[cfg(test)]
mod tests {
    use super::{GcpDataClassification, GcpObjectContentKernel};

    #[test]
    fn inspection_matches_the_go_gcs_fixture_vector_without_retaining_content() {
        let sample = b"email,token\nadmin@example.com,api_key=abcdefghijklmnopqrstuvwxyz\n";
        let inspection = GcpObjectContentKernel::inspect(sample, false);
        assert_eq!(inspection.bytes_scanned, 65);
        assert!(!inspection.truncated);
        assert_eq!(inspection.findings, vec!["pii", "secret"]);
        assert_eq!(
            inspection.data_classification,
            Some(GcpDataClassification::Restricted)
        );
        assert!(inspection.contains_pii);
        assert!(inspection.contains_secrets);
    }

    #[test]
    fn inspection_uses_whole_words_for_provider_classification() {
        let incidental =
            GcpObjectContentKernel::inspect(b"international publication schedule", false);
        assert_eq!(incidental.data_classification, None);
        let explicit = GcpObjectContentKernel::inspect(b"confidential launch notes", true);
        assert_eq!(
            explicit.data_classification,
            Some(GcpDataClassification::Confidential)
        );
        assert!(explicit.truncated);
    }

    #[test]
    fn inspection_recognizes_ssn_and_private_key_markers() {
        let inspection = GcpObjectContentKernel::inspect(
            b"subject=123-45-6789\n-----BEGIN RSA PRIVATE KEY-----",
            false,
        );
        assert!(inspection.contains_pii);
        assert!(inspection.contains_secrets);
        assert_eq!(inspection.findings, vec!["pii", "secret"]);
    }

    #[test]
    fn short_secret_assignments_do_not_trigger() {
        let inspection = GcpObjectContentKernel::inspect(b"token=short", false);
        assert!(!inspection.contains_secrets);
        assert!(inspection.findings.is_empty());
    }

    #[test]
    fn inspectability_matches_gcs_text_contract() {
        assert!(GcpObjectContentKernel::should_inspect(
            "object.bin",
            "application/ld+json; charset=utf-8"
        ));
        assert!(GcpObjectContentKernel::should_inspect(
            "terraform.tf",
            "application/octet-stream"
        ));
        assert!(!GcpObjectContentKernel::should_inspect(
            "archive.zip",
            "application/octet-stream"
        ));
    }

    #[test]
    fn metadata_classification_is_never_downgraded() {
        assert_eq!(
            GcpObjectContentKernel::strongest_classification(
                "restricted",
                Some(GcpDataClassification::Public)
            ),
            "restricted"
        );
        assert_eq!(
            GcpObjectContentKernel::strongest_classification(
                "internal",
                Some(GcpDataClassification::Restricted)
            ),
            "restricted"
        );
        assert_eq!(
            GcpObjectContentKernel::strongest_classification(
                "tenant-special",
                Some(GcpDataClassification::Restricted)
            ),
            "tenant-special"
        );
    }

    #[test]
    fn content_pii_can_raise_a_false_metadata_indicator() {
        assert_eq!(
            GcpObjectContentKernel::merge_contains_indicator("false", Some(true)),
            "true"
        );
        assert_eq!(
            GcpObjectContentKernel::merge_contains_indicator("custom", None),
            "custom"
        );
        assert_eq!(
            GcpObjectContentKernel::merge_contains_indicator("", Some(false)),
            "false"
        );
    }

    #[test]
    fn kernel_is_credential_free() {
        assert!(!GcpObjectContentKernel::requires_credentials());
    }
}
