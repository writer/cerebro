//! Credential-free email-domain DNS planning and health evaluation kernel.
//!
//! The host owns bounded DNS I/O. This module validates the domain, produces
//! the exact TXT/MX query plan, and deterministically evaluates returned
//! answers without reading credentials, environment variables, or routes.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::Serialize;
use serde_json::Value;

const STATUS_HEALTHY: &str = "HEALTHY";
const STATUS_WARNING: &str = "WARNING";
const STATUS_FAILING: &str = "FAILING";
const STATUS_UNKNOWN: &str = "UNKNOWN";

const DEFAULT_DKIM_SELECTORS: [&str; 10] = [
    "default",
    "google",
    "selector1",
    "selector2",
    "s1",
    "s2",
    "k1",
    "k2",
    "mail",
    "mx",
];

/// DNS record type required by an email-domain health collection.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum EmailDomainDnsQueryKind {
    /// A DNS TXT lookup.
    Txt,
    /// A DNS MX lookup.
    Mx,
}

/// One credential-free DNS request in the provider query plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EmailDomainDnsQuery {
    /// Record type to resolve.
    pub kind: EmailDomainDnsQueryKind,
    /// Canonical public DNS name to resolve.
    pub name: String,
}

/// One MX answer supplied by the host resolver.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EmailDomainMxRecord {
    /// MX preference; lower values have higher priority.
    pub preference: u16,
    /// Exchange hostname returned by DNS.
    pub host: String,
}

/// Resolver output for one domain query plan.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EmailDomainDnsSnapshot {
    /// Domain whose query plan produced these answers.
    pub domain: String,
    /// Successful TXT answers keyed by queried DNS name.
    pub txt_records: BTreeMap<String, Vec<String>>,
    /// TXT lookup failures keyed by queried DNS name.
    pub txt_failures: BTreeMap<String, String>,
    /// Successful MX answers for `domain`.
    pub mx_records: Vec<EmailDomainMxRecord>,
    /// MX lookup failure for `domain`, when resolution failed.
    pub mx_failure: Option<String>,
}

/// One normalized DKIM selector assessment.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EmailDomainDkimSelector {
    /// Selector label queried below `_domainkey`.
    pub selector: String,
    /// Health classification for this selector.
    pub status: String,
    /// Decoded public-key length in bits.
    pub key_bits: usize,
    /// Canonical DKIM TXT record.
    pub record: String,
}

/// One email-authentication issue found in DNS evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EmailDomainHealthIssue {
    /// Stable protocol-and-code identity.
    pub id: String,
    /// Protocol or DNS area that produced the issue.
    pub protocol: String,
    /// `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW`.
    pub severity: String,
    /// Stable machine-readable issue code.
    pub code: String,
    /// Short operator-facing issue title.
    pub title: String,
    /// Concrete observed condition.
    pub detail: String,
    /// Concrete remediation action.
    pub recommendation: String,
}

/// Portable `email_domain_health/health/v1` payload.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EmailDomainHealth {
    /// Canonical evaluated domain.
    pub domain: String,
    /// Overall health status.
    pub status: String,
    /// Score from zero to one hundred.
    pub score: i32,
    /// SPF protocol status.
    pub spf_status: String,
    /// DKIM protocol status.
    pub dkim_status: String,
    /// DMARC protocol status.
    pub dmarc_status: String,
    /// Total issue count.
    pub issue_count: usize,
    /// Count of issues at HIGH or CRITICAL severity.
    pub failing_issue_count: usize,
    /// Canonical SPF records.
    pub spf_records: Vec<String>,
    /// Terminal SPF policy.
    pub spf_policy: String,
    /// Estimated SPF DNS lookup count.
    pub spf_lookup_count: usize,
    /// Canonical DMARC records.
    pub dmarc_records: Vec<String>,
    /// Uppercase DMARC policy.
    pub dmarc_policy: String,
    /// DMARC policy application percentage.
    pub dmarc_pct: i32,
    /// Sorted DMARC aggregate-report addresses.
    pub dmarc_rua: Vec<String>,
    /// Sorted MX records in `preference host` form.
    pub mx_records: Vec<String>,
    /// DKIM selector assessments in configured selector order.
    pub dkim_selectors: Vec<EmailDomainDkimSelector>,
    /// Sorted MTA-STS, TLS reporting, and BIMI TXT evidence.
    pub related_records: Vec<String>,
    /// Issues ordered by severity, protocol, and code.
    pub issues: Vec<EmailDomainHealthIssue>,
}

/// One normalized email-domain health source record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EmailDomainHealthRecord {
    /// Source-catalog family identifier.
    pub family: String,
    /// Emitted provider kind.
    pub provider_kind: String,
    /// Canonical provider-owned domain identity.
    pub provider_id: String,
    /// Portable scalar attributes used by source mapping.
    pub fields: BTreeMap<String, String>,
    /// Structured health payload matching the Go event contract.
    pub payload: Value,
}

/// Complete result for one domain; DNS health has no continuation cursor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EmailDomainHealthPage {
    /// The single normalized domain-health record.
    pub records: Vec<EmailDomainHealthRecord>,
    /// Always `None` because one snapshot is a complete domain evaluation.
    pub next_cursor: Option<String>,
}

/// Credential-free email-domain DNS planner and evaluator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EmailDomainHealthKernel {
    selectors: Vec<String>,
}

impl EmailDomainHealthKernel {
    /// Build a kernel with normalized selectors, or common defaults when empty.
    pub fn new<I, S>(selectors: I) -> Result<Self, EmailDomainHealthError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut normalized = BTreeSet::new();
        for selector in selectors {
            let selector = selector.as_ref().trim().to_lowercase();
            if selector.is_empty() {
                continue;
            }
            if !valid_label(&selector) {
                return Err(EmailDomainHealthError::InvalidSelector);
            }
            normalized.insert(selector);
        }
        let selectors = if normalized.is_empty() {
            DEFAULT_DKIM_SELECTORS
                .iter()
                .map(|value| (*value).to_owned())
                .collect()
        } else {
            normalized.into_iter().collect()
        };
        Ok(Self { selectors })
    }

    /// Return whether DNS collection requires credential material.
    pub const fn requires_credentials(&self) -> bool {
        false
    }

    /// Build the complete DNS query plan for one canonicalized domain.
    pub fn queries(
        &self,
        raw_domain: &str,
    ) -> Result<Vec<EmailDomainDnsQuery>, EmailDomainHealthError> {
        let domain = normalize_domain(raw_domain).ok_or(EmailDomainHealthError::InvalidDomain)?;
        let mut queries = vec![txt_query(&domain), txt_query(&format!("_dmarc.{domain}"))];
        queries.extend(
            self.selectors
                .iter()
                .map(|selector| txt_query(&format!("{selector}._domainkey.{domain}"))),
        );
        queries.push(EmailDomainDnsQuery {
            kind: EmailDomainDnsQueryKind::Mx,
            name: domain.clone(),
        });
        queries.extend([
            txt_query(&format!("_mta-sts.{domain}")),
            txt_query(&format!("_smtp._tls.{domain}")),
            txt_query(&format!("default._bimi.{domain}")),
        ]);
        Ok(queries)
    }

    /// Evaluate one host-resolved snapshot into the portable health contract.
    pub fn evaluate(
        &self,
        snapshot: &EmailDomainDnsSnapshot,
    ) -> Result<EmailDomainHealthPage, EmailDomainHealthError> {
        let domain =
            normalize_domain(&snapshot.domain).ok_or(EmailDomainHealthError::InvalidDomain)?;
        let mut health = empty_health(domain.clone());
        evaluate_spf(snapshot, &domain, &mut health);
        evaluate_dmarc(snapshot, &domain, &mut health);
        evaluate_dkim(snapshot, &domain, &self.selectors, &mut health);
        evaluate_mx(snapshot, &mut health);
        evaluate_related(snapshot, &domain, &mut health);
        finish_health(&mut health);

        let payload =
            serde_json::to_value(&health).map_err(|_| EmailDomainHealthError::SerializeHealth)?;
        let fields = health_fields(&health);
        Ok(EmailDomainHealthPage {
            records: vec![EmailDomainHealthRecord {
                family: "health".to_owned(),
                provider_kind: "email_domain_health.health".to_owned(),
                provider_id: domain,
                fields,
                payload,
            }],
            next_cursor: None,
        })
    }
}

/// Safe email-domain planning and evaluation failures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EmailDomainHealthError {
    /// Domain is not a canonicalizable public DNS name.
    InvalidDomain,
    /// DKIM selector is not a valid DNS label.
    InvalidSelector,
    /// The normalized health payload could not be serialized.
    SerializeHealth,
}

impl fmt::Display for EmailDomainHealthError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidDomain => "email domain is invalid",
            Self::InvalidSelector => "DKIM selector is invalid",
            Self::SerializeHealth => "email domain health payload serialization failed",
        })
    }
}

impl Error for EmailDomainHealthError {}

fn txt_query(name: &str) -> EmailDomainDnsQuery {
    EmailDomainDnsQuery {
        kind: EmailDomainDnsQueryKind::Txt,
        name: name.to_owned(),
    }
}

fn empty_health(domain: String) -> EmailDomainHealth {
    EmailDomainHealth {
        domain,
        status: String::new(),
        score: 0,
        spf_status: String::new(),
        dkim_status: String::new(),
        dmarc_status: String::new(),
        issue_count: 0,
        failing_issue_count: 0,
        spf_records: Vec::new(),
        spf_policy: String::new(),
        spf_lookup_count: 0,
        dmarc_records: Vec::new(),
        dmarc_policy: String::new(),
        dmarc_pct: 0,
        dmarc_rua: Vec::new(),
        mx_records: Vec::new(),
        dkim_selectors: Vec::new(),
        related_records: Vec::new(),
        issues: Vec::new(),
    }
}

fn evaluate_spf(snapshot: &EmailDomainDnsSnapshot, domain: &str, health: &mut EmailDomainHealth) {
    let mut records = prefixed_records(snapshot.txt_records.get(domain), "v=spf1");
    health.spf_records.append(&mut records);
    if let Some(error) = snapshot.txt_failures.get(domain) {
        health.issues.push(issue(
            "SPF",
            "MEDIUM",
            "spf_lookup_failed",
            "SPF lookup failed",
            error,
            "Confirm authoritative DNS responds for SPF TXT records.",
        ));
    }
    if health.spf_records.is_empty() {
        health.issues.push(issue(
            "SPF",
            "HIGH",
            "spf_missing",
            "SPF record missing",
            "No SPF TXT record was found for this domain.",
            "Publish a single SPF TXT record that ends with '-all'.",
        ));
        return;
    }
    if health.spf_records.len() > 1 {
        health.issues.push(issue(
            "SPF",
            "HIGH",
            "spf_multiple",
            "Multiple SPF records found",
            &format!("Detected {} SPF records.", health.spf_records.len()),
            "Collapse to one SPF record to avoid permerror behavior.",
        ));
    }
    health.spf_policy = spf_terminal_policy(&health.spf_records[0]);
    health.spf_lookup_count = spf_lookup_count(&health.spf_records[0]);
    match health.spf_policy.as_str() {
        "+all" | "all" => health.issues.push(issue(
            "SPF", "CRITICAL", "spf_permissive_all", "SPF allows all senders",
            "SPF ends in '+all' which permits spoofing.",
            "Replace '+all' with '-all' after validating legitimate senders.",
        )),
        "?all" => health.issues.push(issue(
            "SPF", "HIGH", "spf_neutral_all", "SPF uses neutral all",
            "SPF ends in '?all' which neither passes nor fails senders and offers no spoofing protection.",
            "Replace '?all' with '-all' after validating legitimate senders.",
        )),
        "~all" => health.issues.push(issue(
            "SPF", "MEDIUM", "spf_softfail", "SPF uses soft-fail",
            "SPF ends in '~all' which is not strict enforcement.",
            "Move to '-all' when sender inventory is complete.",
        )),
        "" => health.issues.push(issue(
            "SPF", "MEDIUM", "spf_no_terminal_policy", "SPF terminal policy missing",
            "SPF record does not include an all-mechanism policy.",
            "Add a terminal '-all' policy.",
        )),
        _ => {}
    }
    if health.spf_lookup_count > 10 {
        health.issues.push(issue(
            "SPF",
            "HIGH",
            "spf_lookup_limit_exceeded",
            "SPF lookup count exceeds RFC limit",
            &format!("Estimated lookup count is {}.", health.spf_lookup_count),
            "Reduce include/redirect mechanisms to 10 or fewer DNS lookups.",
        ));
    }
}

fn evaluate_dmarc(snapshot: &EmailDomainDnsSnapshot, domain: &str, health: &mut EmailDomainHealth) {
    let name = format!("_dmarc.{domain}");
    health.dmarc_records = prefixed_records(snapshot.txt_records.get(&name), "v=dmarc1");
    if let Some(error) = snapshot.txt_failures.get(&name) {
        health.issues.push(issue(
            "DMARC",
            "MEDIUM",
            "dmarc_lookup_failed",
            "DMARC lookup failed",
            error,
            "Confirm _dmarc TXT records resolve.",
        ));
    }
    if health.dmarc_records.is_empty() {
        health.issues.push(issue(
            "DMARC", "HIGH", "dmarc_missing", "DMARC record missing",
            "No DMARC TXT record was found.",
            "Publish a DMARC record with at least p=none and reporting, then move to p=quarantine/reject.",
        ));
        return;
    }
    if health.dmarc_records.len() > 1 {
        health.issues.push(issue(
            "DMARC",
            "HIGH",
            "dmarc_multiple",
            "Multiple DMARC records found",
            &format!("Detected {} DMARC records.", health.dmarc_records.len()),
            "Keep exactly one DMARC TXT record at _dmarc.<domain>.",
        ));
    }
    let tags = parse_tags(&health.dmarc_records[0]);
    let policy = tags
        .get("p")
        .map_or("", String::as_str)
        .trim()
        .to_lowercase();
    health.dmarc_policy = policy.to_uppercase();
    match policy.as_str() {
        "" => health.issues.push(issue(
            "DMARC", "HIGH", "dmarc_policy_missing", "DMARC policy missing",
            "The p= tag is missing in the DMARC record.",
            "Add p=quarantine or p=reject after baseline monitoring.",
        )),
        "none" => health.issues.push(issue(
            "DMARC", "MEDIUM", "dmarc_policy_none", "DMARC policy is monitoring-only",
            "DMARC policy is set to p=none.",
            "Move to p=quarantine or p=reject for enforcement.",
        )),
        "quarantine" | "reject" => {}
        _ => health.issues.push(issue(
            "DMARC", "HIGH", "dmarc_policy_invalid", "DMARC policy value is invalid",
            &format!("p={policy} is not one of none|quarantine|reject and will be treated as p=none by receivers."),
            "Set p= to none, quarantine, or reject per RFC 7489.",
        )),
    }
    health.dmarc_pct = 100;
    if let Some(Ok(percent)) = tags.get("pct").map(|value| value.trim().parse::<i32>()) {
        health.dmarc_pct = percent;
        if percent < 100 {
            health.issues.push(issue(
                "DMARC",
                "LOW",
                "dmarc_partial_pct",
                "DMARC enforcement is partial",
                &format!("pct={percent} applies policy to only part of traffic."),
                "Set pct=100 once confidence is high.",
            ));
        }
    }
    health.dmarc_rua = tags.get("rua").map_or_else(Vec::new, |value| {
        let mut values: Vec<_> = value
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .collect();
        values.sort();
        values
    });
    if health.dmarc_rua.is_empty() {
        health.issues.push(issue(
            "DMARC",
            "LOW",
            "dmarc_rua_missing",
            "DMARC aggregate reporting missing",
            "No rua reporting address is configured.",
            "Configure rua=mailto:... to collect aggregate authentication reports.",
        ));
    }
}

fn evaluate_dkim(
    snapshot: &EmailDomainDnsSnapshot,
    domain: &str,
    selectors: &[String],
    health: &mut EmailDomainHealth,
) {
    for selector in selectors {
        let name = format!("{selector}._domainkey.{domain}");
        if snapshot.txt_failures.contains_key(&name) {
            continue;
        }
        let records = prefixed_records(snapshot.txt_records.get(&name), "v=dkim1");
        let Some(record) = records.first() else {
            continue;
        };
        let tags = parse_tags(record);
        let key = tags.get("p").map_or("", String::as_str).trim();
        let algorithm = tags
            .get("k")
            .map_or("rsa", String::as_str)
            .trim()
            .to_lowercase();
        let decoded = if key.is_empty() {
            Ok(Vec::new())
        } else {
            STANDARD.decode(key.replace(' ', ""))
        };
        let (key_bits, valid) = decoded.as_ref().map_or((0, false), |bytes| {
            let bits = if algorithm == "rsa" {
                rsa_public_key_bits(bytes).unwrap_or(bytes.len() * 8)
            } else {
                bytes.len() * 8
            };
            (bits, true)
        });
        let mut status = STATUS_HEALTHY;
        match () {
            () if key.is_empty() => {
                status = STATUS_FAILING;
                health.issues.push(issue(
                    "DKIM",
                    "HIGH",
                    "dkim_missing_key",
                    "DKIM public key missing",
                    &format!("Selector {selector} is missing p= key material."),
                    "Publish valid DKIM public key material in p=.",
                ));
            }
            () if !valid => {
                status = STATUS_FAILING;
                health.issues.push(issue(
                    "DKIM",
                    "HIGH",
                    "dkim_invalid_key",
                    "DKIM public key is not valid base64",
                    &format!("Selector {selector} p= value did not decode as base64 key material."),
                    "Republish the DKIM selector with valid base64-encoded key material.",
                ));
            }
            () if algorithm == "ed25519" && key_bits != 256 => {
                status = STATUS_FAILING;
                health.issues.push(issue(
                    "DKIM", "HIGH", "dkim_invalid_ed25519_key", "DKIM Ed25519 key length is invalid",
                    &format!("Selector {selector} Ed25519 key size is {key_bits} bits; expected 256 bits."),
                    "Republish the Ed25519 selector with a 32-byte public key.",
                ));
            }
            () if algorithm == "rsa" && key_bits < 1024 => {
                status = STATUS_FAILING;
                health.issues.push(issue(
                    "DKIM",
                    "CRITICAL",
                    "dkim_weak_key",
                    "DKIM RSA key is too weak",
                    &format!("Selector {selector} RSA key size is {key_bits} bits."),
                    "Rotate selector to at least 2048-bit RSA key material.",
                ));
            }
            () if algorithm == "rsa" && key_bits < 2048 => {
                status = STATUS_WARNING;
                health.issues.push(issue(
                    "DKIM",
                    "MEDIUM",
                    "dkim_key_short",
                    "DKIM RSA key length below recommended",
                    &format!("Selector {selector} RSA key size is {key_bits} bits."),
                    "Rotate selector to a 2048-bit RSA key.",
                ));
            }
            () => {}
        }
        health.dkim_selectors.push(EmailDomainDkimSelector {
            selector: selector.clone(),
            status: status.to_owned(),
            key_bits,
            record: record.clone(),
        });
    }
    if health.dkim_selectors.is_empty() {
        health.issues.push(issue(
            "DKIM",
            "HIGH",
            "dkim_missing",
            "No DKIM selectors discovered",
            "No known DKIM selector records were found.",
            "Publish DKIM selectors (for example default/selector1) with valid public keys.",
        ));
    }
}

fn evaluate_mx(snapshot: &EmailDomainDnsSnapshot, health: &mut EmailDomainHealth) {
    if let Some(error) = &snapshot.mx_failure {
        health.issues.push(issue(
            "MX",
            "MEDIUM",
            "mx_lookup_failed",
            "MX lookup failed",
            error,
            "Verify MX records exist and can be resolved publicly.",
        ));
    }
    if snapshot.mx_records.is_empty() {
        health.issues.push(issue(
            "MX",
            "MEDIUM",
            "mx_missing",
            "MX records missing",
            "No MX records were found for this domain.",
            "Publish MX records for inbound mail delivery.",
        ));
        return;
    }
    let mut records = snapshot.mx_records.clone();
    records
        .sort_by(|left, right| (left.preference, &left.host).cmp(&(right.preference, &right.host)));
    health.mx_records = records
        .into_iter()
        .map(|record| {
            format!(
                "{} {}",
                record.preference,
                record.host.trim_end_matches('.')
            )
        })
        .collect();
}

fn evaluate_related(
    snapshot: &EmailDomainDnsSnapshot,
    domain: &str,
    health: &mut EmailDomainHealth,
) {
    for name in [
        format!("_mta-sts.{domain}"),
        format!("_smtp._tls.{domain}"),
        format!("default._bimi.{domain}"),
    ] {
        if snapshot.txt_failures.contains_key(&name) {
            continue;
        }
        if let Some(records) = snapshot.txt_records.get(&name) {
            health.related_records.extend(
                records
                    .iter()
                    .map(|record| format!("{name} TXT {}", record.trim())),
            );
        }
    }
    health.related_records.sort();
}

fn finish_health(health: &mut EmailDomainHealth) {
    health.issues.sort_by(|left, right| {
        severity_rank(&right.severity)
            .cmp(&severity_rank(&left.severity))
            .then_with(|| left.protocol.cmp(&right.protocol))
            .then_with(|| left.code.cmp(&right.code))
    });
    health.issue_count = health.issues.len();
    health.failing_issue_count = health
        .issues
        .iter()
        .filter(|issue| severity_rank(&issue.severity) >= 3)
        .count();
    health.spf_status = protocol_status("SPF", &health.issues, !health.spf_records.is_empty());
    health.dkim_status = protocol_status("DKIM", &health.issues, !health.dkim_selectors.is_empty());
    health.dmarc_status =
        protocol_status("DMARC", &health.issues, !health.dmarc_records.is_empty());
    health.score = (100
        - health
            .issues
            .iter()
            .map(|issue| match severity_rank(&issue.severity) {
                4 => 30,
                3 => 20,
                2 => 10,
                1 => 5,
                _ => 2,
            })
            .sum::<i32>())
    .max(0);
    health.status = if health
        .issues
        .iter()
        .any(|issue| severity_rank(&issue.severity) >= 3)
    {
        STATUS_FAILING
    } else if health
        .issues
        .iter()
        .any(|issue| severity_rank(&issue.severity) >= 1)
    {
        STATUS_WARNING
    } else if health.spf_status == STATUS_UNKNOWN
        && health.dkim_status == STATUS_UNKNOWN
        && health.dmarc_status == STATUS_UNKNOWN
    {
        STATUS_UNKNOWN
    } else {
        STATUS_HEALTHY
    }
    .to_owned();
}

fn health_fields(health: &EmailDomainHealth) -> BTreeMap<String, String> {
    let issue_codes: Vec<_> = health
        .issues
        .iter()
        .map(|issue| issue.code.as_str())
        .collect();
    let failing_codes: Vec<_> = health
        .issues
        .iter()
        .filter(|issue| severity_rank(&issue.severity) >= 3)
        .map(|issue| issue.code.as_str())
        .collect();
    let highest = health
        .issues
        .iter()
        .map(|issue| issue.severity.as_str())
        .max_by_key(|severity| severity_rank(severity))
        .unwrap_or_default();
    let mut fields = BTreeMap::from([
        ("event_type".to_owned(), "email_domain_health".to_owned()),
        ("outcome_result".to_owned(), health.status.to_lowercase()),
        ("resource_type".to_owned(), "email_domain".to_owned()),
        ("resource_id".to_owned(), health.domain.clone()),
        ("domain".to_owned(), health.domain.clone()),
        ("status".to_owned(), health.status.clone()),
        ("score".to_owned(), health.score.to_string()),
        ("spf_status".to_owned(), health.spf_status.clone()),
        ("dkim_status".to_owned(), health.dkim_status.clone()),
        ("dmarc_status".to_owned(), health.dmarc_status.clone()),
        ("issue_count".to_owned(), health.issue_count.to_string()),
        (
            "failing_issue_count".to_owned(),
            health.failing_issue_count.to_string(),
        ),
        ("highest_severity".to_owned(), highest.to_owned()),
    ]);
    if !issue_codes.is_empty() {
        let mut values = issue_codes;
        values.sort_unstable();
        fields.insert("issue_codes".to_owned(), values.join(","));
    }
    if !failing_codes.is_empty() {
        let mut values = failing_codes;
        values.sort_unstable();
        fields.insert("failing_issue_codes".to_owned(), values.join(","));
    }
    fields.retain(|_, value| !value.trim().is_empty());
    fields
}

fn issue(
    protocol: &str,
    severity: &str,
    code: &str,
    title: &str,
    detail: &str,
    recommendation: &str,
) -> EmailDomainHealthIssue {
    EmailDomainHealthIssue {
        id: format!("{protocol}:{code}"),
        protocol: protocol.to_owned(),
        severity: severity.to_owned(),
        code: code.to_owned(),
        title: title.to_owned(),
        detail: detail.to_owned(),
        recommendation: recommendation.to_owned(),
    }
}

fn prefixed_records(records: Option<&Vec<String>>, prefix: &str) -> Vec<String> {
    let mut values: Vec<_> = records
        .into_iter()
        .flatten()
        .map(|record| record.trim())
        .filter(|record| record.to_lowercase().starts_with(&prefix.to_lowercase()))
        .map(str::to_owned)
        .collect();
    values.sort();
    values
}

fn parse_tags(record: &str) -> BTreeMap<String, String> {
    record
        .split(';')
        .filter_map(|part| part.trim().split_once('='))
        .map(|(key, value)| (key.trim().to_lowercase(), value.trim().to_owned()))
        .collect()
}

fn spf_terminal_policy(record: &str) -> String {
    let fields: Vec<_> = record
        .to_lowercase()
        .split_whitespace()
        .map(str::to_owned)
        .collect();
    let mut redirect = false;
    for field in fields.iter().rev() {
        if field
            .strip_prefix("redirect=")
            .is_some_and(|value| !value.trim().is_empty())
        {
            redirect = true;
            continue;
        }
        if !field.ends_with("all") {
            continue;
        }
        return match field.chars().next() {
            Some('+') => "+all",
            Some('-') => "-all",
            Some('~') => "~all",
            Some('?') => "?all",
            _ => "all",
        }
        .to_owned();
    }
    if redirect {
        "redirect".to_owned()
    } else {
        String::new()
    }
}

fn spf_lookup_count(record: &str) -> usize {
    record
        .to_lowercase()
        .split_whitespace()
        .filter(|field| {
            field.starts_with("include:")
                || field.starts_with("exists:")
                || field.starts_with("redirect=")
                || *field == "a"
                || field.starts_with("a:")
                || *field == "mx"
                || field.starts_with("mx:")
                || *field == "ptr"
                || field.starts_with("ptr:")
        })
        .count()
}

fn protocol_status(protocol: &str, issues: &[EmailDomainHealthIssue], has_records: bool) -> String {
    let rank = issues
        .iter()
        .filter(|issue| issue.protocol.eq_ignore_ascii_case(protocol))
        .map(|issue| severity_rank(&issue.severity))
        .max();
    match rank {
        Some(value) if value >= 3 => STATUS_FAILING,
        Some(value) if value >= 1 => STATUS_WARNING,
        _ if has_records => STATUS_HEALTHY,
        _ => STATUS_UNKNOWN,
    }
    .to_owned()
}

fn severity_rank(severity: &str) -> u8 {
    match severity.trim().to_uppercase().as_str() {
        "CRITICAL" => 4,
        "HIGH" => 3,
        "MEDIUM" => 2,
        "LOW" => 1,
        _ => 0,
    }
}

fn normalize_domain(raw: &str) -> Option<String> {
    let mut candidate = raw.trim().to_lowercase();
    if let Some((_, domain)) = candidate.rsplit_once('@') {
        candidate = domain.to_owned()
    }
    if let Some((_, rest)) = candidate.split_once("://") {
        candidate = rest.to_owned()
    }
    if let Some((host, _)) = candidate.split_once('/') {
        candidate = host.to_owned()
    }
    candidate = candidate
        .trim_matches(['[', ']'])
        .trim_end_matches('.')
        .to_owned();
    if let Some((host, port)) = candidate.rsplit_once(':')
        && !host.is_empty()
        && port.chars().all(|character| character.is_ascii_digit())
    {
        candidate = host.to_owned();
    }
    while let Some(stripped) = candidate.strip_prefix("www.") {
        candidate = stripped.to_owned()
    }
    if candidate.ends_with(".local")
        || candidate.ends_with(".internal")
        || candidate.parse::<std::net::IpAddr>().is_ok()
        || candidate.len() > 253
    {
        return None;
    }
    let labels: Vec<_> = candidate.split('.').collect();
    (labels.len() >= 2 && labels.into_iter().all(valid_label)).then_some(candidate)
}

fn valid_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && label
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && label
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
        && label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn rsa_public_key_bits(der: &[u8]) -> Option<usize> {
    let sequence = der_value(der, 0x30)?;
    if sequence.first() == Some(&0x02) {
        return integer_bits(der_value(sequence, 0x02)?);
    }
    let (_, rest) = take_der(sequence, 0x30)?;
    let bit_string = der_value(rest, 0x03)?;
    let key = bit_string.strip_prefix(&[0])?;
    integer_bits(der_value(key, 0x30).and_then(|value| der_value(value, 0x02))?)
}

fn integer_bits(value: &[u8]) -> Option<usize> {
    let value = value.strip_prefix(&[0]).unwrap_or(value);
    let first = *value.first()?;
    Some(value.len() * 8 - first.leading_zeros() as usize)
}

fn der_value(input: &[u8], tag: u8) -> Option<&[u8]> {
    take_der(input, tag).map(|(value, _)| value)
}

fn take_der(input: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
    if input.first().copied()? != tag {
        return None;
    }
    let first_len = *input.get(1)?;
    let (length, offset) = if first_len & 0x80 == 0 {
        (usize::from(first_len), 2)
    } else {
        let octets = usize::from(first_len & 0x7f);
        if octets == 0 || octets > std::mem::size_of::<usize>() {
            return None;
        }
        let mut length = 0usize;
        for byte in input.get(2..2 + octets)? {
            length = length.checked_mul(256)?.checked_add(usize::from(*byte))?
        }
        (length, 2 + octets)
    };
    let end = offset.checked_add(length)?;
    Some((input.get(offset..end)?, input.get(end..)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kernel() -> EmailDomainHealthKernel {
        EmailDomainHealthKernel::new(["default"]).unwrap()
    }

    #[test]
    fn query_plan_is_complete_normalized_and_credential_free() {
        let kernel = EmailDomainHealthKernel::new(Vec::<String>::new()).unwrap();
        let queries = kernel.queries("Security@WWW.Example.COM:443/path").unwrap();
        assert_eq!(queries.len(), 16);
        assert_eq!(queries[0], txt_query("example.com"));
        assert!(queries.contains(&txt_query("default._domainkey.example.com")));
        assert!(queries.contains(&EmailDomainDnsQuery {
            kind: EmailDomainDnsQueryKind::Mx,
            name: "example.com".to_owned(),
        }));
        assert!(!kernel.requires_credentials());
    }

    #[test]
    fn healthy_snapshot_emits_the_health_contract() {
        let key = STANDARD.encode(vec![0_u8; 256]);
        let snapshot = EmailDomainDnsSnapshot {
            domain: "example.com".to_owned(),
            txt_records: BTreeMap::from([
                (
                    "example.com".to_owned(),
                    vec!["v=spf1 include:_spf.example.com -all".to_owned()],
                ),
                (
                    "_dmarc.example.com".to_owned(),
                    vec!["v=DMARC1; p=reject; pct=100; rua=mailto:dmarc@example.com".to_owned()],
                ),
                (
                    "default._domainkey.example.com".to_owned(),
                    vec![format!("v=DKIM1; k=rsa; p={key}")],
                ),
            ]),
            mx_records: vec![EmailDomainMxRecord {
                preference: 10,
                host: "mx.example.com.".to_owned(),
            }],
            ..EmailDomainDnsSnapshot::default()
        };
        let page = kernel().evaluate(&snapshot).unwrap();
        assert_eq!(page.next_cursor, None);
        assert_eq!(page.records.len(), 1);
        let record = &page.records[0];
        assert_eq!(record.family, "health");
        assert_eq!(record.provider_kind, "email_domain_health.health");
        assert_eq!(record.provider_id, "example.com");
        assert_eq!(
            record.fields.get("status").map(String::as_str),
            Some("HEALTHY")
        );
        assert_eq!(record.fields.get("score").map(String::as_str), Some("100"));
        assert_eq!(record.payload["dkim_selectors"][0]["key_bits"], 2048);
        assert_eq!(record.payload["mx_records"][0], "10 mx.example.com");
    }

    #[test]
    fn failing_snapshot_matches_go_issue_and_attribute_semantics() {
        let key = STANDARD.encode(vec![0_u8; 64]);
        let snapshot = EmailDomainDnsSnapshot {
            domain: "risky.example.com".to_owned(),
            txt_records: BTreeMap::from([
                (
                    "risky.example.com".to_owned(),
                    vec!["v=spf1 +all".to_owned()],
                ),
                (
                    "default._domainkey.risky.example.com".to_owned(),
                    vec![format!("v=DKIM1; p={key}")],
                ),
            ]),
            txt_failures: BTreeMap::from([(
                "_dmarc.risky.example.com".to_owned(),
                "not found".to_owned(),
            )]),
            ..EmailDomainDnsSnapshot::default()
        };
        let record = kernel().evaluate(&snapshot).unwrap().records.remove(0);
        assert_eq!(
            record.fields.get("status").map(String::as_str),
            Some("FAILING")
        );
        assert_eq!(
            record.fields.get("highest_severity").map(String::as_str),
            Some("CRITICAL")
        );
        let codes = record.fields.get("failing_issue_codes").unwrap();
        for code in ["spf_permissive_all", "dmarc_missing", "dkim_weak_key"] {
            assert!(codes.contains(code), "missing {code} from {codes}");
        }
        assert_eq!(record.payload["spf_policy"], "+all");
        assert_eq!(record.payload["dkim_selectors"][0]["key_bits"], 512);
    }

    #[test]
    fn dkim_txt_failure_discards_coexisting_records() {
        let name = "default._domainkey.example.com".to_owned();
        let key = STANDARD.encode(vec![0_u8; 256]);
        let snapshot = EmailDomainDnsSnapshot {
            domain: "example.com".to_owned(),
            txt_records: BTreeMap::from([(name.clone(), vec![format!("v=DKIM1; k=rsa; p={key}")])]),
            txt_failures: BTreeMap::from([(name, "temporary DNS failure".to_owned())]),
            ..EmailDomainDnsSnapshot::default()
        };

        let record = kernel().evaluate(&snapshot).unwrap().records.remove(0);
        assert_eq!(record.payload["dkim_selectors"], serde_json::json!([]));
        assert!(record.fields["failing_issue_codes"].contains("dkim_missing"));
    }

    #[test]
    fn invalid_scope_and_selectors_fail_closed() {
        assert_eq!(
            kernel().queries("tenant-id-without-dot"),
            Err(EmailDomainHealthError::InvalidDomain)
        );
        assert_eq!(
            kernel().queries("192.168.0.1"),
            Err(EmailDomainHealthError::InvalidDomain)
        );
        assert_eq!(
            EmailDomainHealthKernel::new(["bad selector"]),
            Err(EmailDomainHealthError::InvalidSelector)
        );
    }
}
