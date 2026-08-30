//! Preflight validation for bounded analysis-plugin execution.
//!
//! This module compares a manifest and measured usage with platform resource
//! policy. Artifact loading, digest verification, capability authorization, ABI
//! negotiation, isolation, and runtime metering belong to the execution host.

use cerebro_platform_sdk::{AnalysisPluginManifest, ResourceBudget, ResourceUsage, SdkError};

/// Validates manifest memory/time ceilings and observed usage against a budget.
///
/// Manifest memory and execution-time limits must fit within the corresponding
/// platform budget, while observed plugin memory and time must fit both the
/// manifest and platform limits. [`ResourceUsage::validate`] also enforces every
/// non-plugin budget dimension represented in `usage`.
///
/// Input and output byte limits are validated as non-zero manifest values but
/// are not represented by [`ResourceUsage`] and therefore are not metered here.
/// The host must enforce them before passing bytes into or out of the sandbox.
/// This function also does not prove the artifact's zero-import or deterministic
/// properties; manifest validation only requires those declarations to be true.
///
/// # Errors
///
/// Returns manifest validation errors, or [`SdkError::OutOfRange`] when a
/// manifest ceiling exceeds platform policy or any measured usage exceeds its
/// applicable ceiling. Usage validation errors are deliberately collapsed to
/// the plugin-execution budget category at this boundary.
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

#[cfg(test)]
mod tests {
    use cerebro_platform_sdk::{
        AnalysisPluginManifest, ContentDigest, PluginCapability, PluginId, PluginLimits,
        ResourceBudget, ResourceUsage,
    };

    use super::*;

    #[test]
    fn execution_rejects_manifests_without_both_safety_requirements() {
        let manifest = AnalysisPluginManifest {
            plugin_id: PluginId::parse("plugin:test").unwrap(),
            abi_version: "v1".to_owned(),
            artifact_digest: ContentDigest::of_bytes("artifact"),
            capabilities: vec![PluginCapability::AssertionEvaluation],
            limits: PluginLimits {
                memory_bytes: 512,
                execution_millis: 50,
                input_bytes: 1,
                output_bytes: 1,
            },
            zero_imports_required: false,
            deterministic_output_required: true,
        };
        let budget = ResourceBudget::new(10, 1, 100, 1, 1, 10, 1_024, 100).expect("valid budget");
        let usage = ResourceUsage {
            query_results: 0,
            query_depth: 0,
            query_millis: 0,
            concurrent_queries: 0,
            subscription_batch: 0,
            snapshot_entities: 0,
            plugin_memory_bytes: 0,
            plugin_millis: 0,
        };

        assert_eq!(
            validate_plugin_execution(&manifest, &budget, &usage),
            Err(SdkError::Invalid("plugin safety requirements"))
        );
    }
}
