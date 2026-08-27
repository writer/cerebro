use std::{collections::BTreeMap, error::Error};

use cerebro_organizational_model::{SourceRuntimeId, TenantId};
use cerebro_organizational_store::StoredSourceRuntime;

#[test]
fn qdrant_runtime_rejects_oversized_durable_cursor() -> Result<(), Box<dyn Error>> {
    assert!(
        StoredSourceRuntime::new(
            SourceRuntimeId::parse("qdrant-cursor-bound")?,
            TenantId::parse("tenant-qdrant-cursor-bound")?,
            "qdrant_cloud".to_owned(),
            BTreeMap::from([("family".to_owned(), "clusters".to_owned())]),
            None,
            Some(serde_json::json!({"opaque": "x".repeat((64 * 1024) + 1)})),
            None,
        )
        .is_err()
    );
    Ok(())
}
