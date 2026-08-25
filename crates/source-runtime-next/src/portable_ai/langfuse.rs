use serde::Deserialize;
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

use crate::source_execution::SourceExecutionError;

const MAX_QUERY_BYTES: usize = 16 * 1024;
const MAX_METRICS: usize = 16;

#[derive(Deserialize)]
struct MetricsQuery {
    view: String,
    dimensions: Vec<Dimension>,
    metrics: Vec<Metric>,
    #[serde(rename = "fromTimestamp")]
    from_timestamp: String,
    #[serde(rename = "toTimestamp")]
    to_timestamp: String,
    #[serde(default)]
    config: serde_json::Value,
}

#[derive(Deserialize)]
struct Dimension {
    field: String,
}

#[derive(Deserialize)]
struct Metric {
    measure: String,
    aggregation: String,
}

pub(super) fn validate_metrics_query(raw: &str) -> Result<(), SourceExecutionError> {
    if raw.is_empty() || raw.len() > MAX_QUERY_BYTES {
        return Err(SourceExecutionError::MissingConfiguration);
    }
    let query: MetricsQuery =
        serde_json::from_str(raw).map_err(|_| SourceExecutionError::MissingConfiguration)?;
    if !matches!(
        query.view.as_str(),
        "observations" | "scores-numeric" | "scores-boolean" | "scores-categorical"
    ) || query.metrics.is_empty()
        || query.metrics.len() > MAX_METRICS
        || !query
            .dimensions
            .iter()
            .any(|dimension| dimension.field == "name")
        || query
            .metrics
            .iter()
            .any(|metric| metric.measure.trim().is_empty() || metric.aggregation.trim().is_empty())
        || !(query.config.is_null() || query.config.is_object())
    {
        return Err(SourceExecutionError::MissingConfiguration);
    }
    let from = OffsetDateTime::parse(&query.from_timestamp, &Rfc3339)
        .map_err(|_| SourceExecutionError::MissingConfiguration)?;
    let to = OffsetDateTime::parse(&query.to_timestamp, &Rfc3339)
        .map_err(|_| SourceExecutionError::MissingConfiguration)?;
    if to <= from || to - from > Duration::days(31) {
        return Err(SourceExecutionError::MissingConfiguration);
    }
    Ok(())
}
