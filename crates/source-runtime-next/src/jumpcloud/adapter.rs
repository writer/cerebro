//! Provider-local source-execution adapter contract.
//!
//! The shared dispatcher and wire remain separately owned. This module exposes
//! the exact seven registration tuples plus body/header capabilities that the
//! shared registration follow-up must carry without redefining wire messages.

use std::collections::BTreeSet;

use sha2::{Digest, Sha256};

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
    pub(crate) check_scope: &'static str,
    pub(crate) discover_scope: &'static str,
    pub(crate) max_fanout_scopes: Option<usize>,
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

/// Bounded all-page Discover accumulator for group membership URNs.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct JumpCloudGroupMemberDiscovery {
    pages: usize,
    seen: BTreeSet<String>,
    urns: Vec<String>,
}

impl JumpCloudGroupMemberDiscovery {
    pub(crate) const MAX_PAGES: usize = 1_000;

    pub(crate) fn admit_page(
        &mut self,
        adapter: JumpCloudSourceExecutionAdapter,
        page: &JumpCloudPage,
    ) -> Result<(), JumpCloudError> {
        self.pages = self
            .pages
            .checked_add(1)
            .filter(|pages| *pages <= Self::MAX_PAGES)
            .ok_or(JumpCloudError::TooManyRecords)?;
        for urn in adapter.page_discovery_urns(page)? {
            if self.seen.insert(urn.clone()) {
                self.urns.push(urn);
            }
        }
        Ok(())
    }

    pub(crate) fn urns(&self) -> &[String] {
        &self.urns
    }
}

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
            check_scope: if self.family == JumpCloudFamily::GroupMembers {
                "first_configured_group"
            } else {
                "family_endpoint"
            },
            discover_scope: if self.family == JumpCloudFamily::GroupMembers {
                "all_configured_groups"
            } else {
                "family_endpoint"
            },
            max_fanout_scopes: (self.family == JumpCloudFamily::GroupMembers).then_some(1_000),
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

    /// Plan the bounded Check operation. Group membership checks intentionally
    /// use only the first ordered configured group, matching the Go source.
    pub(crate) fn plan_check(
        self,
        kernel: &JumpCloudKernel,
    ) -> Result<JumpCloudRequest, JumpCloudError> {
        self.plan(kernel, None, None)
    }

    /// Plan one Discover page. Repeating this with each returned cursor visits
    /// every configured group and every provider page in deterministic order.
    pub(crate) fn plan_discover(
        self,
        kernel: &JumpCloudKernel,
        prior_cursor: Option<&str>,
    ) -> Result<JumpCloudRequest, JumpCloudError> {
        self.plan(kernel, prior_cursor, None)
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

    /// Convert decoded membership records into the exact Go Discover URNs.
    fn page_discovery_urns(self, page: &JumpCloudPage) -> Result<Vec<String>, JumpCloudError> {
        if self.family != JumpCloudFamily::GroupMembers {
            return Err(JumpCloudError::RequestScopeMismatch);
        }
        let mut seen = BTreeSet::new();
        let mut urns = Vec::new();
        for record in &page.records {
            if record.family != self.family {
                return Err(JumpCloudError::RequestScopeMismatch);
            }
            let group_id = record
                .attributes
                .get("group_id")
                .filter(|value| !value.trim().is_empty())
                .ok_or(JumpCloudError::InvalidProviderRecord)?;
            let member_id = record
                .attributes
                .get("member_id")
                .filter(|value| !value.trim().is_empty())
                .ok_or(JumpCloudError::InvalidProviderRecord)?;
            let digest = Sha256::digest(format!("{}\0{}", group_id.trim(), member_id.trim()));
            let stable_id = format!("id-{}", hex_prefix(&digest, 16));
            let urn = format!(
                "urn:cerebro:{}:jumpcloud_group_members:{stable_id}",
                record.tenant_id
            );
            if seen.insert(urn.clone()) {
                urns.push(urn);
            }
        }
        Ok(urns)
    }
}

fn hex_prefix(bytes: &[u8], count: usize) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .take(count)
        .flat_map(|byte| {
            [
                char::from(HEX[usize::from(byte >> 4)]),
                char::from(HEX[usize::from(byte & 0x0f)]),
            ]
        })
        .collect()
}
