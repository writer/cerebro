use std::{
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

async fn ledger_and_request() -> Result<(PostgresLedger, ProjectionPromotionRequest), Box<dyn Error>>
{
    let tenant_id = required_env("CEREBRO_TENANT_ID")?;
    let source_id = required_env("CEREBRO_SOURCE_ID")?;
    let family_id = required_env("CEREBRO_SOURCE_FAMILY")?;
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
    let tenant_id = required_env("CEREBRO_TENANT_ID")?;
    let source_id = required_env("CEREBRO_SOURCE_ID")?;
    let family_id = required_env("CEREBRO_SOURCE_FAMILY")?;
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
}
