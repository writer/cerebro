use cerebro_platform_sdk::{AnalysisPluginManifest, ResourceBudget, ResourceUsage, SdkError};

pub fn validate_plugin_execution(
    manifest: &AnalysisPluginManifest,
    budget: &ResourceBudget,
    usage: &ResourceUsage,
) -> Result<(), SdkError> {
    manifest.validate()?;
    if manifest.limits.memory_bytes > budget.max_plugin_memory_bytes
        || manifest.limits.execution_millis > budget.max_plugin_millis
    {
        return Err(SdkError::OutOfRange("plugin manifest budget"));
    }
    usage
        .validate(budget)
        .map_err(|_| SdkError::OutOfRange("plugin execution budget"))
}
