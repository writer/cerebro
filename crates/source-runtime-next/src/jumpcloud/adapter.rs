//! Provider-local source-execution adapter contract.
//!
//! The shared dispatcher and wire remain separately owned. This module exposes
//! the exact seven registration tuples plus body/header capabilities that the
//! shared registration follow-up must carry without redefining wire messages.

use super::{
    JumpCloudError, JumpCloudFamily, JumpCloudKernel, JumpCloudPage, JumpCloudRequest,
    JumpCloudResponseMetadata, JumpCloudRuntimeDefinition,
};

/// Provider-local contract required by the shared source-execution registry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct JumpCloudSourceExecutionContract {
    pub(crate) source_id: &'static str,
    pub(crate) family_id: &'static str,
    pub(crate) provider_kernel: &'static str,
    pub(crate) method: &'static str,
    pub(crate) origin: &'static str,
    pub(crate) path: &'static str,
    pub(crate) credential_operation: &'static str,
    pub(crate) request_body: bool,
    pub(crate) response_cursor_header: Option<&'static str>,
}

/// Stateless provider-local adapter for one exact JumpCloud family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct JumpCloudSourceExecutionAdapter {
    family: JumpCloudFamily,
}

/// Exact provider-local adapter set awaiting shared registry registration.
pub(crate) const JUMPCLOUD_SOURCE_EXECUTION_ADAPTERS: [JumpCloudSourceExecutionAdapter; 7] = [
    JumpCloudSourceExecutionAdapter::new(JumpCloudFamily::Users),
    JumpCloudSourceExecutionAdapter::new(JumpCloudFamily::Groups),
    JumpCloudSourceExecutionAdapter::new(JumpCloudFamily::Systems),
    JumpCloudSourceExecutionAdapter::new(JumpCloudFamily::Applications),
    JumpCloudSourceExecutionAdapter::new(JumpCloudFamily::SystemGroups),
    JumpCloudSourceExecutionAdapter::new(JumpCloudFamily::GroupMembers),
    JumpCloudSourceExecutionAdapter::new(JumpCloudFamily::AuditEvents),
];

impl JumpCloudSourceExecutionAdapter {
    pub(crate) const fn new(family: JumpCloudFamily) -> Self {
        Self { family }
    }

    pub(crate) const fn family(self) -> JumpCloudFamily {
        self.family
    }

    pub(crate) fn contract(self) -> Result<JumpCloudSourceExecutionContract, JumpCloudError> {
        let definition = JumpCloudRuntimeDefinition::compile(self.family)?;
        Ok(JumpCloudSourceExecutionContract {
            source_id: definition.source_id,
            family_id: self.family.as_str(),
            provider_kernel: match self.family {
                JumpCloudFamily::Users => "jumpcloud.users",
                JumpCloudFamily::Groups => "jumpcloud.groups",
                JumpCloudFamily::Systems => "jumpcloud.systems",
                JumpCloudFamily::Applications => "jumpcloud.applications",
                JumpCloudFamily::SystemGroups => "jumpcloud.system_groups",
                JumpCloudFamily::GroupMembers => "jumpcloud.group_members",
                JumpCloudFamily::AuditEvents => "jumpcloud.audit_events",
            },
            method: definition.method,
            origin: definition.origin,
            path: definition.path,
            credential_operation: "jumpcloud.x_api_key",
            request_body: self.family == JumpCloudFamily::AuditEvents,
            response_cursor_header: (self.family == JumpCloudFamily::AuditEvents)
                .then_some("X-Search_after"),
        })
    }

    pub(crate) fn plan(
        self,
        kernel: &JumpCloudKernel,
        prior_cursor: Option<&str>,
        prior_watermark: Option<&str>,
    ) -> Result<JumpCloudRequest, JumpCloudError> {
        if kernel.family != self.family {
            return Err(JumpCloudError::RequestScopeMismatch);
        }
        kernel.plan_with_checkpoint(prior_cursor, prior_watermark)
    }

    pub(crate) fn decode(
        self,
        kernel: &JumpCloudKernel,
        request: &JumpCloudRequest,
        status: u16,
        metadata: &JumpCloudResponseMetadata,
        response_body: &[u8],
    ) -> Result<JumpCloudPage, JumpCloudError> {
        if kernel.family != self.family || request.family() != self.family {
            return Err(JumpCloudError::RequestScopeMismatch);
        }
        kernel.decode(request, status, metadata, response_body)
    }
}
