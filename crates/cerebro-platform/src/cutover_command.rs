use std::{
    error::Error,
    time::{SystemTime, UNIX_EPOCH},
};

use cerebro_organizational_store::{CutoverPolicy, PostgresLedger, ProjectionPromotionRequest};

use crate::{load_catalog, required_env};

pub(crate) async fn promote_family() -> Result<(), Box<dyn Error>> {
    let tenant_id = required_env("CEREBRO_TENANT_ID")?;
    let source_id = required_env("CEREBRO_SOURCE_ID")?;
    let family_id = required_env("CEREBRO_SOURCE_FAMILY")?;
    let connection_string = required_env("CEREBRO_POSTGRES_DSN")?;
    let ledger = PostgresLedger::connect_tls(&connection_string).await?;
    ledger.migrate().await?;
    let promoted_at_unix_ms =
        i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
    let authority = ledger
        .evaluate_and_promote_projection_authority(
            &load_catalog()?,
            &ProjectionPromotionRequest::new(
                tenant_id,
                source_id,
                family_id,
                CutoverPolicy::new(3, 0)?,
                0,
                promoted_at_unix_ms,
            )?,
        )
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
