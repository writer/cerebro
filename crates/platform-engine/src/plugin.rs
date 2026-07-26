use cerebro_platform_sdk::{AnalysisPluginManifest, ResourceBudget, ResourceUsage, SdkError};

pub fn validate_plugin_execution(
    manifest: &AnalysisPluginManifest,
    budget: &ResourceBudget,
    usage: &ResourceUsage,
) -> Result<(), SdkError> {
    manifest.validate()?;
    if manifest.limits.memory_bytes > budget.max_plugin_memory_bytes
        || manifest.limits.execution_millis > budget.max_plugin_millis
        || usage.plugin_memory_bytes > manifest.limits.memory_bytes
        || usage.plugin_millis > manifest.limits.execution_millis
    {
        return Err(SdkError::OutOfRange("plugin execution budget"));
    }
    usage
        .validate(budget)
        .map_err(|_| SdkError::OutOfRange("plugin execution budget"))
}
