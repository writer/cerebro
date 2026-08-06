use std::{
    env,
    error::Error,
    time::{SystemTime, UNIX_EPOCH},
};

use cerebro_organizational_store::{CutoverPolicy, PostgresLedger, ProjectionPromotionRequest};

use crate::{load_catalog, required_env};

fn promotion_request(
    tenant_id: String,
    source_id: String,
    family_id: String,
    promoted_at_unix_ms: i64,
) -> Result<ProjectionPromotionRequest, Box<dyn Error>> {
    Ok(ProjectionPromotionRequest::new(
        tenant_id,
        source_id,
        family_id,
        CutoverPolicy::new(3, 0)?,
        0,
        promoted_at_unix_ms,
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
    Ok((
        ledger,
        promotion_request(tenant_id, source_id, family_id, evaluated_at_unix_ms)?,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn promotion_request_keeps_the_production_gate_strict() {
        let request = promotion_request(
            "tenant-a".to_owned(),
            "box".to_owned(),
            "users".to_owned(),
            1,
        )
        .unwrap();
        assert_eq!(request.tenant_id(), "tenant-a");
        assert_eq!(request.source_id(), "box");
        assert_eq!(request.family_id(), "users");
        assert_eq!(request.projection_lag(), 0);
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
}
