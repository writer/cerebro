//! Credential-free Trivy JSON report decoding and normalization kernel.
//!
//! Trivy collection is an offline boundary: callers provide report bytes and
//! this module emits the four portable source families without opening files,
//! resolving environment paths, or using network credentials.

use std::{
    collections::{BTreeMap, HashSet},
    error::Error,
    fmt::{self, Write as _},
    str::FromStr,
};

use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// One portable Trivy source family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrivyFamily {
    /// One summary record for the scanned image.
    ImageScan,
    /// Deduplicated packages installed in the image.
    ImagePackage,
    /// Vulnerabilities reported for installed image packages.
    ImageVulnerability,
    /// Available package-version remediations.
    Fix,
}

impl TrivyFamily {
    /// Return the source-catalog family identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ImageScan => "image_scan",
            Self::ImagePackage => "image_package",
            Self::ImageVulnerability => "image_vulnerability",
            Self::Fix => "fix",
        }
    }

    /// Return the emitted provider kind.
    pub const fn provider_kind(self) -> &'static str {
        match self {
            Self::ImageScan => "trivy.image_scan",
            Self::ImagePackage => "trivy.image_package",
            Self::ImageVulnerability => "trivy.image_vulnerability",
            Self::Fix => "trivy.fix",
        }
    }
}

impl FromStr for TrivyFamily {
    type Err = TrivyError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim() {
            "image_scan" => Ok(Self::ImageScan),
            "image_package" => Ok(Self::ImagePackage),
            "image_vulnerability" => Ok(Self::ImageVulnerability),
            "fix" => Ok(Self::Fix),
            _ => Err(TrivyError::InvalidFamily),
        }
    }
}

/// One normalized Trivy source record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrivyRecord {
    /// Source-catalog family identifier.
    pub family: String,
    /// Emitted provider kind.
    pub provider_kind: String,
    /// Stable Go-compatible record identity.
    pub provider_id: String,
    /// Portable scalar attributes used by source mapping.
    pub fields: BTreeMap<String, String>,
    /// Normalized payload matching the public family contract.
    pub payload: Value,
}

/// A complete offline Trivy family result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrivyPage {
    /// Normalized records in report order.
    pub records: Vec<TrivyRecord>,
    /// Offline reports are complete and never expose a continuation cursor.
    pub next_cursor: Option<String>,
}

/// Credential-free Trivy JSON report decoder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrivyKernel {
    family: TrivyFamily,
}

impl TrivyKernel {
    /// Build a decoder for one of the four portable Trivy families.
    pub const fn new(family: TrivyFamily) -> Self {
        Self { family }
    }

    /// Return whether this offline decoder requires credential material.
    pub const fn requires_credentials(&self) -> bool {
        false
    }

    /// Decode report bytes and emit the configured family.
    pub fn decode(&self, body: &[u8]) -> Result<TrivyPage, TrivyError> {
        let report: Report = serde_json::from_slice(body).map_err(|_| TrivyError::InvalidReport)?;
        let image_digest = image_digest(&report).ok_or(TrivyError::MissingImageDigest)?;
        let records = match self.family {
            TrivyFamily::ImageScan => scan_records(&report, &image_digest),
            TrivyFamily::ImagePackage => package_records(&report, &image_digest),
            TrivyFamily::ImageVulnerability => vulnerability_records(&report, &image_digest),
            TrivyFamily::Fix => fix_records(&report, &image_digest),
        };
        Ok(TrivyPage {
            records,
            next_cursor: None,
        })
    }
}

/// Safe Trivy decoding failures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TrivyError {
    /// Family identifier is not one of the four supported contracts.
    InvalidFamily,
    /// Input bytes are not a structurally valid Trivy JSON report.
    InvalidReport,
    /// Report lacks every supported image-digest source.
    MissingImageDigest,
}

impl fmt::Display for TrivyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidFamily => "trivy family is invalid",
            Self::InvalidReport => "trivy report JSON is invalid",
            Self::MissingImageDigest => {
                "trivy report must include a repository digest, artifact digest, or image ID"
            }
        })
    }
}

impl Error for TrivyError {}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
struct Report {
    #[serde(rename = "SchemaVersion")]
    _schema_version: u64,
    #[serde(rename = "ArtifactName")]
    artifact_name: String,
    #[serde(rename = "ArtifactType")]
    artifact_type: String,
    #[serde(rename = "Metadata")]
    metadata: Metadata,
    #[serde(rename = "Results")]
    results: Vec<ScanResult>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
struct Metadata {
    #[serde(rename = "ImageID")]
    image_id: String,
    #[serde(rename = "RepoTags")]
    repo_tags: Vec<String>,
    #[serde(rename = "RepoDigests")]
    repo_digests: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
struct ScanResult {
    #[serde(rename = "Class")]
    class: String,
    #[serde(rename = "Type")]
    ecosystem: String,
    #[serde(rename = "Vulnerabilities")]
    vulnerabilities: Vec<Vulnerability>,
    #[serde(rename = "Packages")]
    packages: Vec<Package>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
struct Vulnerability {
    #[serde(rename = "VulnerabilityID")]
    vulnerability_id: String,
    #[serde(rename = "PkgName")]
    package_name: String,
    #[serde(rename = "InstalledVersion")]
    installed_version: String,
    #[serde(rename = "FixedVersion")]
    fixed_version: String,
    #[serde(rename = "Status")]
    status: String,
    #[serde(rename = "Severity")]
    severity: String,
    #[serde(rename = "Title")]
    title: String,
    #[serde(rename = "Description")]
    description: String,
    #[serde(rename = "PrimaryURL")]
    primary_url: String,
    #[serde(rename = "PkgIdentifier")]
    package_identifier: PackageIdentifier,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
struct Package {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Version")]
    version: String,
    #[serde(rename = "Identifier")]
    identifier: PackageIdentifier,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
struct PackageIdentifier {
    #[serde(rename = "PURL")]
    purl: String,
}

fn scan_records(report: &Report, image_digest: &str) -> Vec<TrivyRecord> {
    let fields = compact([
        ("image_digest", image_digest),
        ("image_uri", image_uri(report)),
        ("scanner", "trivy"),
    ]);
    let payload = json!({
        "image_digest": image_digest,
        "artifact_name": report.artifact_name,
        "artifact_type": report.artifact_type,
        "repo_tags": report.metadata.repo_tags,
        "repo_digests": report.metadata.repo_digests,
    });
    vec![record(
        TrivyFamily::ImageScan,
        format!("trivy-image-scan-{}", stable_id(image_digest)),
        fields,
        payload,
    )]
}

fn package_records(report: &Report, image_digest: &str) -> Vec<TrivyRecord> {
    let mut seen = HashSet::new();
    let mut records = Vec::new();
    for scan in &report.results {
        for vulnerability in &scan.vulnerabilities {
            add_package(
                &mut records,
                &mut seen,
                report,
                image_digest,
                scan,
                &vulnerability.package_name,
                &vulnerability.installed_version,
                &vulnerability.package_identifier.purl,
            );
        }
        for package in &scan.packages {
            add_package(
                &mut records,
                &mut seen,
                report,
                image_digest,
                scan,
                &package.name,
                &package.version,
                &package.identifier.purl,
            );
        }
    }
    records
}

#[allow(clippy::too_many_arguments)]
fn add_package(
    records: &mut Vec<TrivyRecord>,
    seen: &mut HashSet<String>,
    report: &Report,
    image_digest: &str,
    scan: &ScanResult,
    name: &str,
    version: &str,
    purl: &str,
) {
    if name.trim().is_empty() || version.trim().is_empty() {
        return;
    }
    let key = format!("{}|{name}|{version}", scan.ecosystem);
    if !seen.insert(key.clone()) {
        return;
    }
    let fields = package_fields(report, image_digest, scan, name, version, purl);
    records.push(record(
        TrivyFamily::ImagePackage,
        format!(
            "trivy-image-package-{}",
            stable_id(&format!("{image_digest}|{key}"))
        ),
        fields.clone(),
        fields_payload(&fields),
    ));
}

fn vulnerability_records(report: &Report, image_digest: &str) -> Vec<TrivyRecord> {
    let mut records = Vec::new();
    for scan in &report.results {
        for vulnerability in &scan.vulnerabilities {
            let fields = vulnerability_fields(report, image_digest, scan, vulnerability);
            records.push(record(
                TrivyFamily::ImageVulnerability,
                format!(
                    "trivy-image-vulnerability-{}",
                    stable_id(&format!(
                        "{image_digest}|{}|{}|{}",
                        vulnerability.vulnerability_id,
                        vulnerability.package_name,
                        vulnerability.installed_version
                    ))
                ),
                fields.clone(),
                fields_payload(&fields),
            ));
        }
    }
    records
}

fn fix_records(report: &Report, image_digest: &str) -> Vec<TrivyRecord> {
    let mut records = Vec::new();
    for scan in &report.results {
        for vulnerability in &scan.vulnerabilities {
            if vulnerability.fixed_version.trim().is_empty() {
                continue;
            }
            let mut fields = vulnerability_fields(report, image_digest, scan, vulnerability);
            fields.insert(
                "fixed_version".to_owned(),
                vulnerability.fixed_version.trim().to_owned(),
            );
            records.push(record(
                TrivyFamily::Fix,
                format!(
                    "trivy-fix-{}",
                    stable_id(&format!(
                        "{image_digest}|{}|{}|{}",
                        vulnerability.vulnerability_id,
                        vulnerability.package_name,
                        vulnerability.fixed_version
                    ))
                ),
                fields.clone(),
                fields_payload(&fields),
            ));
        }
    }
    records
}

fn vulnerability_fields(
    report: &Report,
    image_digest: &str,
    scan: &ScanResult,
    vulnerability: &Vulnerability,
) -> BTreeMap<String, String> {
    let mut fields = package_fields(
        report,
        image_digest,
        scan,
        &vulnerability.package_name,
        &vulnerability.installed_version,
        &vulnerability.package_identifier.purl,
    );
    insert_nonblank(
        &mut fields,
        "vulnerability_id",
        &vulnerability.vulnerability_id,
    );
    insert_nonblank(&mut fields, "cve_id", &vulnerability.vulnerability_id);
    insert_nonblank(&mut fields, "severity", &vulnerability.severity);
    insert_nonblank(&mut fields, "title", &vulnerability.title);
    insert_nonblank(&mut fields, "description", &vulnerability.description);
    insert_nonblank(&mut fields, "primary_url", &vulnerability.primary_url);
    insert_nonblank(&mut fields, "fixed_version", &vulnerability.fixed_version);
    fields.insert(
        "status".to_owned(),
        normalize_vulnerability_status(&vulnerability.status),
    );
    if !vulnerability.fixed_version.trim().is_empty() {
        fields.insert("fix_available".to_owned(), "true".to_owned());
    }
    fields
}

fn package_fields(
    report: &Report,
    image_digest: &str,
    scan: &ScanResult,
    name: &str,
    version: &str,
    purl: &str,
) -> BTreeMap<String, String> {
    let mut fields = compact([
        ("image_digest", image_digest),
        ("image_uri", image_uri(report)),
        ("package", name),
        ("package_name", name),
        ("installed_version", version),
        ("version", version),
        ("class", &scan.class),
        ("ecosystem", &scan.ecosystem),
        ("type", &scan.ecosystem),
        ("purl", purl),
    ]);
    if let Some(normalized) = normalized_package_id(purl, &scan.ecosystem, name, version) {
        fields.insert("normalized_id".to_owned(), normalized);
    }
    fields
}

fn record(
    family: TrivyFamily,
    provider_id: String,
    fields: BTreeMap<String, String>,
    payload: Value,
) -> TrivyRecord {
    TrivyRecord {
        family: family.as_str().to_owned(),
        provider_kind: family.provider_kind().to_owned(),
        provider_id,
        fields,
        payload,
    }
}

fn image_digest(report: &Report) -> Option<String> {
    report
        .metadata
        .repo_digests
        .iter()
        .find_map(|value| sha256_reference(value))
        .or_else(|| sha256_reference(&report.artifact_name))
        .or_else(|| nonblank(&report.metadata.image_id).map(str::to_owned))
}

fn sha256_reference(value: &str) -> Option<String> {
    value
        .rfind("@sha256:")
        .map(|index| value[index + 1..].trim())
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn image_uri(report: &Report) -> &str {
    nonblank(&report.artifact_name)
        .or_else(|| {
            report
                .metadata
                .repo_digests
                .first()
                .and_then(|value| nonblank(value))
        })
        .unwrap_or_default()
}

fn normalize_vulnerability_status(status: &str) -> String {
    let normalized = status.trim().to_lowercase();
    if normalized.is_empty() {
        "affected".to_owned()
    } else {
        normalized
    }
}

fn normalized_package_id(purl: &str, ecosystem: &str, name: &str, version: &str) -> Option<String> {
    if let Some(body) = purl.trim().strip_prefix("pkg:") {
        let body = body.split(['?', '#']).next().unwrap_or_default();
        if let Some((package_type, package_path)) = body.split_once('/') {
            let (package_name, purl_version) = package_path
                .rsplit_once('@')
                .map_or((package_path, ""), |(name, version)| (name, version));
            if !package_type.trim().is_empty()
                && !package_name.trim_matches('/').trim().is_empty()
                && !package_type.chars().any(char::is_whitespace)
                && !package_name.chars().any(char::is_whitespace)
            {
                let resolved_version = nonblank(purl_version).or_else(|| nonblank(version))?;
                return Some(
                    format!(
                        "{}|{}|{}",
                        package_type.trim(),
                        package_name.trim_matches('/').trim(),
                        resolved_version
                    )
                    .to_lowercase(),
                );
            }
        }
    }
    let name = nonblank(name)?;
    let version = nonblank(version)?;
    Some(
        format!(
            "{}|{name}|{version}",
            nonblank(ecosystem).unwrap_or("unknown")
        )
        .to_lowercase(),
    )
}

fn compact<'a>(values: impl IntoIterator<Item = (&'a str, &'a str)>) -> BTreeMap<String, String> {
    values
        .into_iter()
        .filter_map(|(key, value)| {
            let key = nonblank(key)?;
            let value = nonblank(value)?;
            Some((key.to_owned(), value.to_owned()))
        })
        .collect()
}

fn insert_nonblank(fields: &mut BTreeMap<String, String>, key: &str, value: &str) {
    if let Some(value) = nonblank(value) {
        fields.insert(key.to_owned(), value.to_owned());
    }
}

fn fields_payload(fields: &BTreeMap<String, String>) -> Value {
    serde_json::to_value(fields).expect("string maps always serialize")
}

fn stable_id(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut encoded, "{byte:02x}").expect("writing to a string cannot fail");
    }
    encoded
}

fn nonblank(value: &str) -> Option<&str> {
    let value = value.trim();
    (!value.is_empty()).then_some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    const REPORT: &[u8] = br#"{
      "SchemaVersion": 2,
      "ArtifactName": "registry.example/app:latest",
      "ArtifactType": "container_image",
      "Metadata": {
        "ImageID": "sha256:imageid",
        "RepoTags": ["registry.example/app:latest"],
        "RepoDigests": ["registry.example/app@sha256:deadbeef"]
      },
      "Results": [{
        "Target": "registry.example/app (debian 12)",
        "Class": "os-pkgs",
        "Type": "debian",
        "Packages": [
          {"Name":"openssl","Version":"1.0.0","Identifier":{"PURL":"pkg:deb/debian/openssl@1.0.0"}}
        ],
        "Vulnerabilities": [{
          "VulnerabilityID":"CVE-2026-0001",
          "PkgName":"openssl",
          "InstalledVersion":"1.0.0",
          "FixedVersion":"1.0.1",
          "Status":"FIXED",
          "Severity":"HIGH",
          "Title":"OpenSSL flaw",
          "PrimaryURL":"https://example.test/CVE-2026-0001",
          "PkgIdentifier":{"PURL":"pkg:deb/debian/openssl@1.0.0"}
        }]
      }]
    }"#;

    fn decode(family: TrivyFamily) -> TrivyPage {
        TrivyKernel::new(family).decode(REPORT).unwrap()
    }

    #[test]
    fn all_four_families_emit_go_compatible_kinds_and_stable_ids() {
        let cases = [
            (
                TrivyFamily::ImageScan,
                "trivy.image_scan",
                "trivy-image-scan-1ea61af0d052bf8800a1bb082be22ebb27f1ef80e4a7d0fdd5a1927717aa9537",
            ),
            (
                TrivyFamily::ImagePackage,
                "trivy.image_package",
                "trivy-image-package-4f82fd9c34f8465cc6b2e72ba503d8117518bdb6deb10c2061ec32fb5c4360e9",
            ),
            (
                TrivyFamily::ImageVulnerability,
                "trivy.image_vulnerability",
                "trivy-image-vulnerability-4d7ef9fbc9e2ef246911e6b7cd25b809800d82051b72ab6ac2dbc1cd202b00ea",
            ),
            (
                TrivyFamily::Fix,
                "trivy.fix",
                "trivy-fix-9d66788ffa4f86e8af485cae16e0e12273b657e1f981b98c93453262d6c1d90b",
            ),
        ];
        for (family, kind, identity) in cases {
            let page = decode(family);
            assert_eq!(page.next_cursor, None);
            assert_eq!(page.records.len(), 1);
            assert_eq!(page.records[0].family, family.as_str());
            assert_eq!(page.records[0].provider_kind, kind);
            assert_eq!(page.records[0].provider_id, identity);
        }
        assert!(!TrivyKernel::new(TrivyFamily::ImageScan).requires_credentials());
    }

    #[test]
    fn digest_precedence_matches_repo_artifact_then_image_id() {
        let scan = |body: &[u8]| {
            TrivyKernel::new(TrivyFamily::ImageScan)
                .decode(body)
                .unwrap()
                .records
                .remove(0)
                .fields
                .remove("image_digest")
                .unwrap()
        };
        assert_eq!(
            scan(br#"{"ArtifactName":"repo@sha256:artifact","Metadata":{"ImageID":"sha256:id","RepoDigests":["repo@sha256:repo"]}}"#),
            "sha256:repo"
        );
        assert_eq!(
            scan(br#"{"ArtifactName":"repo@sha256:artifact","Metadata":{"ImageID":"sha256:id"}}"#),
            "sha256:artifact"
        );
        assert_eq!(
            scan(br#"{"ArtifactName":"repo:tag","Metadata":{"ImageID":"sha256:id"}}"#),
            "sha256:id"
        );
    }

    #[test]
    fn package_family_suppresses_vulnerability_and_inventory_duplicates() {
        let page = decode(TrivyFamily::ImagePackage);
        assert_eq!(page.records.len(), 1);
        let fields = &page.records[0].fields;
        assert_eq!(fields.get("package").map(String::as_str), Some("openssl"));
        assert_eq!(
            fields.get("installed_version").map(String::as_str),
            Some("1.0.0")
        );
        assert_eq!(
            fields.get("normalized_id").map(String::as_str),
            Some("deb|debian/openssl|1.0.0")
        );
    }

    #[test]
    fn status_and_fix_semantics_are_explicit() {
        let report = br#"{
          "ArtifactName":"repo@sha256:one",
          "Results":[{"Type":"debian","Vulnerabilities":[
            {"VulnerabilityID":"CVE-1","PkgName":"curl","InstalledVersion":"1","Status":" Not_Affected "},
            {"VulnerabilityID":"CVE-2","PkgName":"ssl","InstalledVersion":"2","FixedVersion":"3"}
          ]}]
        }"#;
        let vulnerabilities = TrivyKernel::new(TrivyFamily::ImageVulnerability)
            .decode(report)
            .unwrap();
        assert_eq!(vulnerabilities.records.len(), 2);
        assert_eq!(
            vulnerabilities.records[0]
                .fields
                .get("status")
                .map(String::as_str),
            Some("not_affected")
        );
        assert_eq!(vulnerabilities.records[0].fields.get("fix_available"), None);
        assert_eq!(
            vulnerabilities.records[1]
                .fields
                .get("status")
                .map(String::as_str),
            Some("affected")
        );
        assert_eq!(
            vulnerabilities.records[1]
                .fields
                .get("fix_available")
                .map(String::as_str),
            Some("true")
        );
        let fixes = TrivyKernel::new(TrivyFamily::Fix).decode(report).unwrap();
        assert_eq!(fixes.records.len(), 1);
        assert_eq!(
            fixes.records[0]
                .fields
                .get("fixed_version")
                .map(String::as_str),
            Some("3")
        );
    }

    #[test]
    fn vulnerability_payload_matches_normalized_attributes() {
        let page = decode(TrivyFamily::ImageVulnerability);
        let record = &page.records[0];
        for (key, expected) in [
            ("image_digest", "sha256:deadbeef"),
            ("vulnerability_id", "CVE-2026-0001"),
            ("package", "openssl"),
            ("severity", "HIGH"),
            ("status", "fixed"),
            ("fix_available", "true"),
        ] {
            assert_eq!(record.fields.get(key).map(String::as_str), Some(expected));
            assert_eq!(record.payload[key], expected);
        }
    }

    #[test]
    fn scan_payload_preserves_report_identity_material() {
        let record = decode(TrivyFamily::ImageScan).records.remove(0);
        assert_eq!(
            record.fields.get("scanner").map(String::as_str),
            Some("trivy")
        );
        assert_eq!(
            record.payload["artifact_name"],
            "registry.example/app:latest"
        );
        assert_eq!(record.payload["artifact_type"], "container_image");
        assert_eq!(
            record.payload["repo_digests"][0],
            "registry.example/app@sha256:deadbeef"
        );
    }

    #[test]
    fn malformed_reports_and_missing_digests_fail_closed() {
        let kernel = TrivyKernel::new(TrivyFamily::ImageScan);
        assert_eq!(kernel.decode(b"not-json"), Err(TrivyError::InvalidReport));
        assert_eq!(
            kernel.decode(br#"{"Results":"not-an-array"}"#),
            Err(TrivyError::InvalidReport)
        );
        assert_eq!(
            kernel.decode(br#"{"ArtifactName":"repo:tag","Metadata":{}}"#),
            Err(TrivyError::MissingImageDigest)
        );
    }

    #[test]
    fn family_parser_rejects_unknown_contracts() {
        assert_eq!("image_scan".parse(), Ok(TrivyFamily::ImageScan));
        assert_eq!("fix".parse(), Ok(TrivyFamily::Fix));
        assert_eq!(
            "package".parse::<TrivyFamily>(),
            Err(TrivyError::InvalidFamily)
        );
    }
}
