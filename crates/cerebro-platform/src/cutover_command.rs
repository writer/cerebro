use std::{
    env,
    error::Error,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use cerebro_organizational_store::{CutoverPolicy, PostgresLedger, ProjectionPromotionRequest};
use cerebro_source_catalog::AuthorityQualificationEvidence;
use cerebro_source_catalog::SourceCatalog;
use serde::Serialize;

use crate::{
    CatalogFamilyFilter, catalog_family_records,
    cutover_evidence::{
        authority_qualification_root, load_family_authority_qualification,
        load_single_authority_qualification,
    },
    load_catalog, required_env,
};

fn promotion_request(
    tenant_id: String,
    source_id: String,
    family_id: String,
    promoted_at_unix_ms: i64,
    qualification: AuthorityQualificationEvidence,
) -> Result<ProjectionPromotionRequest, Box<dyn Error>> {
    Ok(ProjectionPromotionRequest::new(
        tenant_id,
        source_id,
        family_id,
        CutoverPolicy::new(3, 0)?,
        0,
        promoted_at_unix_ms,
        qualification,
    )?)
}

/// Resolve one family-scope identifier from a positional argument or, when no
/// argument is supplied, an environment variable. A positional argument takes
/// precedence so the cutover commands can be driven over a batch of families
/// (for example the output of `list-catalog-families`); the environment
/// variable remains the fallback so existing invocations stay valid.
fn family_scope_identifier(
    argument: Option<String>,
    environment: Option<String>,
    env_name: &str,
    label: &str,
) -> Result<String, Box<dyn Error>> {
    if let Some(argument) = argument {
        let trimmed = argument.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_owned());
        }
    }
    match environment.map(|value| value.trim().to_owned()) {
        Some(value) if !value.is_empty() => Ok(value),
        _ => Err(format!(
            "family {label} is required: pass it as a positional argument or set {env_name}"
        )
        .into()),
    }
}

/// Read the `(tenant, source, family)` cutover scope from positional arguments
/// after the subcommand, falling back to the existing environment variables.
fn family_scope() -> Result<(String, String, String), Box<dyn Error>> {
    let mut args = env::args().skip(2);
    let tenant_id = family_scope_identifier(
        args.next(),
        env::var("CEREBRO_TENANT_ID").ok(),
        "CEREBRO_TENANT_ID",
        "tenant",
    )?;
    let source_id = family_scope_identifier(
        args.next(),
        env::var("CEREBRO_SOURCE_ID").ok(),
        "CEREBRO_SOURCE_ID",
        "source",
    )?;
    let family_id = family_scope_identifier(
        args.next(),
        env::var("CEREBRO_SOURCE_FAMILY").ok(),
        "CEREBRO_SOURCE_FAMILY",
        "family",
    )?;
    Ok((tenant_id, source_id, family_id))
}

async fn ledger_and_request() -> Result<(PostgresLedger, ProjectionPromotionRequest), Box<dyn Error>>
{
    let (tenant_id, source_id, family_id) = family_scope()?;
    let connection_string = required_env("CEREBRO_POSTGRES_DSN")?;
    let ledger = PostgresLedger::connect_tls(&connection_string).await?;
    ledger.migrate().await?;
    let evaluated_at_unix_ms =
        i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
    let qualification = load_single_authority_qualification()?;
    Ok((
        ledger,
        promotion_request(
            tenant_id,
            source_id,
            family_id,
            evaluated_at_unix_ms,
            qualification,
        )?,
    ))
}

pub(crate) async fn evaluate_family() -> Result<(), Box<dyn Error>> {
    let (ledger, request) = ledger_and_request().await?;
    let decision = ledger
        .evaluate_projection_authority(&load_catalog()?, &request)
        .await?;
    serde_json::to_writer(std::io::stdout(), &decision)?;
    println!();
    Ok(())
}

pub(crate) async fn promote_family() -> Result<(), Box<dyn Error>> {
    let (ledger, request) = ledger_and_request().await?;
    let authority = ledger
        .evaluate_and_promote_projection_authority(&load_catalog()?, &request)
        .await?;
    serde_json::to_writer(std::io::stdout(), &authority)?;
    println!();
    Ok(())
}

pub(crate) async fn show_authority() -> Result<(), Box<dyn Error>> {
    let (tenant_id, source_id, family_id) = family_scope()?;
    let connection_string = required_env("CEREBRO_POSTGRES_DSN")?;
    let ledger = PostgresLedger::connect_tls(&connection_string).await?;
    ledger.migrate().await?;
    let authority = ledger
        .projection_authority(&tenant_id, &source_id, &family_id)
        .await?;
    serde_json::to_writer(std::io::stdout(), &authority)?;
    println!();
    Ok(())
}

/// Filtered catalog family scopes (`(source_id, family_id)`) for batch cutover.
/// The tenant is supplied separately because the checked-in catalog is
/// tenant-agnostic; it is not part of the family address.
fn catalog_family_scopes(
    catalog: &SourceCatalog,
    filter: &CatalogFamilyFilter,
) -> Vec<(String, String)> {
    catalog_family_records(catalog)
        .into_iter()
        .filter(|record| filter.matches(record))
        .map(|record| (record.source_id.to_owned(), record.family_id.to_owned()))
        .collect()
}

/// Parsed arguments for `evaluate-all-families`: the catalog cohort filter plus
/// the `--promote-ready` switch. `--promote-ready` is separated before the
/// filter parse so the filter stays strict about unknown flags.
struct EvaluateAllFamiliesArgs {
    filter: CatalogFamilyFilter,
    promote_ready: bool,
}

fn parse_evaluate_all_families_args(
    arguments: impl Iterator<Item = String>,
) -> Result<EvaluateAllFamiliesArgs, Box<dyn Error>> {
    let mut filter_args = Vec::new();
    let mut promote_ready = false;
    for argument in arguments {
        if argument == "--promote-ready" {
            promote_ready = true;
        } else {
            filter_args.push(argument);
        }
    }
    Ok(EvaluateAllFamiliesArgs {
        filter: CatalogFamilyFilter::parse(filter_args.into_iter())?,
        promote_ready,
    })
}

/// One family's cutover outcome, serialized as one JSONL record. `allowed` is
/// `None` when evaluation itself failed; `promoted` is true only when
/// `--promote-ready` promoted an allowed family.
#[derive(Debug, Serialize)]
struct FamilyCutoverOutcome {
    source_id: String,
    family_id: String,
    allowed: Option<bool>,
    promoted: bool,
    reasons: Vec<String>,
    evidence_digest: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Default, Serialize)]
struct CutoverBatchSummary {
    tenant_id: String,
    evaluated: usize,
    ready: usize,
    not_ready: usize,
    errors: usize,
    promoted: usize,
}

impl CutoverBatchSummary {
    fn new(tenant_id: String) -> Self {
        Self {
            tenant_id,
            ..Default::default()
        }
    }

    fn record(&mut self, outcome: &FamilyCutoverOutcome) {
        self.evaluated += 1;
        match outcome.allowed {
            Some(true) => self.ready += 1,
            Some(false) => self.not_ready += 1,
            None => self.errors += 1,
        }
        if outcome.promoted {
            self.promoted += 1;
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn evaluate_one_family(
    ledger: &PostgresLedger,
    catalog: &SourceCatalog,
    tenant_id: &str,
    source_id: &str,
    family_id: &str,
    evaluated_at_unix_ms: i64,
    promote_ready: bool,
    qualification_root: &Path,
) -> FamilyCutoverOutcome {
    let mut outcome = FamilyCutoverOutcome {
        source_id: source_id.to_owned(),
        family_id: family_id.to_owned(),
        allowed: None,
        promoted: false,
        reasons: Vec::new(),
        evidence_digest: None,
        error: None,
    };
    let qualification =
        match load_family_authority_qualification(qualification_root, source_id, family_id) {
            Ok(qualification) => qualification,
            Err(error) => {
                outcome.error = Some(error.to_string());
                return outcome;
            }
        };
    let request = match promotion_request(
        tenant_id.to_owned(),
        source_id.to_owned(),
        family_id.to_owned(),
        evaluated_at_unix_ms,
        qualification,
    ) {
        Ok(request) => request,
        Err(error) => {
            outcome.error = Some(error.to_string());
            return outcome;
        }
    };
    match ledger
        .evaluate_projection_authority(catalog, &request)
        .await
    {
        Ok(decision) => {
            outcome.allowed = Some(decision.is_allowed());
            outcome.reasons = decision.reasons().to_vec();
            outcome.evidence_digest = Some(decision.evidence_digest().to_owned());
            if promote_ready && decision.is_allowed() {
                match ledger
                    .evaluate_and_promote_projection_authority(catalog, &request)
                    .await
                {
                    Ok(_) => outcome.promoted = true,
                    Err(error) => outcome.error = Some(error.to_string()),
                }
            }
        }
        Err(error) => outcome.error = Some(error.to_string()),
    }
    outcome
}

/// Evaluate projection cutover authority for every family in a filtered catalog
/// cohort for one tenant, emitting one JSONL outcome per family and a summary
/// on stderr. With `--promote-ready`, families that pass the gate are promoted
/// in the same pass. The tenant (`CEREBRO_TENANT_ID`) and ledger
/// (`CEREBRO_POSTGRES_DSN`) come from the environment; the source/family cohort
/// comes from the checked-in catalog, optionally narrowed by the same filters as
/// `list-catalog-families`.
pub(crate) async fn evaluate_all_families() -> Result<(), Box<dyn Error>> {
    use std::io::Write;

    let args = parse_evaluate_all_families_args(env::args().skip(2))?;
    let tenant_id = required_env("CEREBRO_TENANT_ID")?;
    let connection_string = required_env("CEREBRO_POSTGRES_DSN")?;
    let catalog = load_catalog()?;
    let ledger = PostgresLedger::connect_tls(&connection_string).await?;
    ledger.migrate().await?;
    let evaluated_at_unix_ms =
        i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
    let qualification_root = authority_qualification_root()?;

    let scopes = catalog_family_scopes(&catalog, &args.filter);
    let stdout = std::io::stdout();
    let mut writer = std::io::BufWriter::new(stdout.lock());
    let mut summary = CutoverBatchSummary::new(tenant_id);
    for (source_id, family_id) in scopes {
        let outcome = evaluate_one_family(
            &ledger,
            &catalog,
            &summary.tenant_id,
            &source_id,
            &family_id,
            evaluated_at_unix_ms,
            args.promote_ready,
            &qualification_root,
        )
        .await;
        summary.record(&outcome);
        serde_json::to_writer(&mut writer, &outcome)?;
        writeln!(&mut writer)?;
    }
    eprintln!("{}", serde_json::to_string_pretty(&summary)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use cerebro_organizational_store::ProjectionAuthority;

    use super::*;
    use crate::cutover_evidence;

    #[tokio::test]
    #[ignore = "requires disposable PostgreSQL"]
    async fn unverifiable_asana_receipts_cannot_select_rust_authority() {
        let postgres_dsn = env::var("CEREBRO_TEST_POSTGRES_DSN").unwrap();
        let authority = PostgresLedger::connect_tls(&postgres_dsn).await.unwrap();
        authority.migrate().await.unwrap();
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
            .to_string();
        let tenant_id = format!("platform-promotion-evidence-{suffix}");
        let mut parity_digests = Vec::new();
        for index in 1..=3 {
            let receipt = cerebro_organizational_store::ParityReceipt::compare_scoped(
                tenant_id.clone(),
                "asana-runtime",
                "asana",
                "users",
                format!("corpus-{suffix}-{index}"),
                "sha256:equal",
                "sha256:equal",
                true,
                index,
            )
            .unwrap();
            parity_digests.push(receipt.receipt_digest().to_owned());
            authority.record_parity(&receipt).await.unwrap();
        }
        let catalog = load_catalog().unwrap();
        let mut qualification = cutover_evidence::authority_qualification_fixture(
            &catalog,
            "asana",
            "users",
            &format!("corpus-{suffix}-3"),
        );
        qualification.parity_receipt_digests = parity_digests;
        let decision = authority
            .evaluate_projection_authority(
                &catalog,
                &cerebro_organizational_store::ProjectionPromotionRequest::new(
                    tenant_id.clone(),
                    "asana",
                    "users",
                    cerebro_organizational_store::CutoverPolicy::new(3, 0).unwrap(),
                    0,
                    100,
                    qualification,
                )
                .unwrap(),
            )
            .await
            .unwrap();
        assert!(!decision.is_allowed());
        assert!(
            decision
                .reasons()
                .iter()
                .any(|reason| { reason == "product-read receipt verifier is unavailable" })
        );
        assert_eq!(
            authority
                .projection_authority(&tenant_id, "asana", "users")
                .await
                .unwrap()
                .authority,
            ProjectionAuthority::Legacy
        );
    }

    #[test]
    fn family_scope_identifier_prefers_argument_then_environment() {
        // A positional argument wins over an environment variable.
        assert_eq!(
            family_scope_identifier(
                Some("tenant-a".to_owned()),
                Some("env-tenant".to_owned()),
                "CEREBRO_TENANT_ID",
                "tenant",
            )
            .unwrap(),
            "tenant-a",
        );
        // Without an argument, the environment variable is used.
        assert_eq!(
            family_scope_identifier(
                None,
                Some("env-tenant".to_owned()),
                "CEREBRO_TENANT_ID",
                "tenant",
            )
            .unwrap(),
            "env-tenant",
        );
        // A blank argument falls through to the environment variable.
        assert_eq!(
            family_scope_identifier(
                Some("   ".to_owned()),
                Some("env-tenant".to_owned()),
                "CEREBRO_TENANT_ID",
                "tenant",
            )
            .unwrap(),
            "env-tenant",
        );
        // Surrounding whitespace is trimmed from either source.
        assert_eq!(
            family_scope_identifier(
                Some("  tenant-a  ".to_owned()),
                None,
                "CEREBRO_TENANT_ID",
                "tenant",
            )
            .unwrap(),
            "tenant-a",
        );
        // Neither source present fails closed and names the missing variable.
        let missing =
            family_scope_identifier(None, None, "CEREBRO_TENANT_ID", "tenant").unwrap_err();
        assert!(missing.to_string().contains("CEREBRO_TENANT_ID"));
    }

    #[test]
    fn catalog_family_scopes_applies_the_filter() {
        let catalog = crate::load_catalog().expect("checked-in catalog must load");
        let all = catalog_family_scopes(&catalog, &CatalogFamilyFilter::default());
        assert!(!all.is_empty(), "catalog must compile at least one family");
        assert!(
            all.iter()
                .all(|(source, family)| !source.is_empty() && !family.is_empty())
        );
        let filtered = catalog_family_scopes(
            &catalog,
            &CatalogFamilyFilter::parse(["--can-be-authoritative=false".to_owned()].into_iter())
                .unwrap(),
        );
        assert!(
            filtered.len() < all.len(),
            "can_be_authoritative=false must narrow the cohort"
        );
    }

    #[test]
    fn parse_evaluate_all_families_args_separates_promote_ready() {
        let args = parse_evaluate_all_families_args(
            [
                "--promote-ready".to_owned(),
                "--authoritative=false".to_owned(),
                "--projection-class=identity".to_owned(),
            ]
            .into_iter(),
        )
        .unwrap();
        assert!(args.promote_ready);
        assert_eq!(args.filter.authoritative, Some(false));
        // --promote-ready with no filters is valid.
        let bare =
            parse_evaluate_all_families_args(["--promote-ready".to_owned()].into_iter()).unwrap();
        assert!(bare.promote_ready);
        assert_eq!(bare.filter, CatalogFamilyFilter::default());
        // Unknown filter flags still fail closed (delegated to CatalogFamilyFilter::parse).
        assert!(parse_evaluate_all_families_args(["--bogus".to_owned()].into_iter()).is_err());
    }

    #[test]
    fn cutover_batch_summary_classifies_outcomes() {
        let mut summary = CutoverBatchSummary::new("tenant-a".to_owned());
        summary.record(&FamilyCutoverOutcome {
            source_id: "s1".to_owned(),
            family_id: "f1".to_owned(),
            allowed: Some(true),
            promoted: false,
            reasons: Vec::new(),
            evidence_digest: Some("sha256:1".to_owned()),
            error: None,
        });
        summary.record(&FamilyCutoverOutcome {
            source_id: "s2".to_owned(),
            family_id: "f2".to_owned(),
            allowed: Some(false),
            promoted: false,
            reasons: Vec::new(),
            evidence_digest: Some("sha256:2".to_owned()),
            error: None,
        });
        summary.record(&FamilyCutoverOutcome {
            source_id: "s3".to_owned(),
            family_id: "f3".to_owned(),
            allowed: Some(true),
            promoted: true,
            reasons: Vec::new(),
            evidence_digest: Some("sha256:3".to_owned()),
            error: None,
        });
        summary.record(&FamilyCutoverOutcome {
            source_id: "s4".to_owned(),
            family_id: "f4".to_owned(),
            allowed: None,
            promoted: false,
            reasons: Vec::new(),
            evidence_digest: None,
            error: Some("ledger unavailable".to_owned()),
        });
        assert_eq!(summary.tenant_id, "tenant-a");
        assert_eq!(summary.evaluated, 4);
        assert_eq!(summary.ready, 2);
        assert_eq!(summary.not_ready, 1);
        assert_eq!(summary.errors, 1);
        assert_eq!(summary.promoted, 1);
    }
}
