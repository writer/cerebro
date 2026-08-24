//! Google Workspace request, response, and role-assignee fanout kernel.
//!
//! The kernel plans credential-free Admin SDK requests and decodes bounded
//! provider pages. Live egress and OAuth credential ownership remain outside
//! this module. Role assignment pages preserve the Go provider's per-page
//! user lookup cache without moving provider calls into the kernel.
//! Materialized events deliberately require the identity used by Go Discover.
//! This fails closed for fallback-only records that Go Read can emit but Go
//! Discover cannot turn into a canonical source URN.

use std::{collections::BTreeMap, str::FromStr};

use reqwest::Url;
use serde_json::Value;

mod error;
mod materialization;
mod normalization;
// Shared dispatcher registration lands separately so this provider slice does
// not collide with another branch that currently owns the shared registry.
#[allow(dead_code)]
mod source_execution;
mod user_adapter;

#[cfg(test)]
mod source_execution_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod user_adapter_tests;

pub use error::GoogleWorkspaceError;
use normalization::*;
#[allow(unused_imports)]
pub(crate) use source_execution::{
    GOOGLE_WORKSPACE_USER_SOURCE_EXECUTION_ADAPTER, durable_checkpoint_cursor,
};

const SOURCE_ID: &str = "google_workspace";
const DEFAULT_CUSTOMER_ID: &str = "my_customer";
const DEFAULT_APPLICATION: &str = "admin";
const DEFAULT_PAGE_SIZE: usize = 10;
const MAX_PAGE_SIZE: usize = 200;

/// A Google Workspace Admin SDK family with a provider-owned collection contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GoogleWorkspaceFamily {
    /// Reports API administrative activity.
    Audit,
    /// Directory groups.
    Group,
    /// Directory members for one configured group.
    GroupMember,
    /// Directory administrative role assignments.
    RoleAssignment,
    /// Directory users.
    User,
}

impl GoogleWorkspaceFamily {
    /// Return the source-catalog family identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Audit => "audit",
            Self::Group => "group",
            Self::GroupMember => "group_member",
            Self::RoleAssignment => "role_assignment",
            Self::User => "user",
        }
    }

    /// Return the emitted provider kind.
    pub const fn provider_kind(self) -> &'static str {
        match self {
            Self::Audit => "google_workspace.audit",
            Self::Group => "google_workspace.group",
            Self::GroupMember => "google_workspace.group_member",
            Self::RoleAssignment => "google_workspace.role_assignment",
            Self::User => "google_workspace.user",
        }
    }

    /// Return the public Go source event schema reference.
    pub const fn schema_ref(self) -> &'static str {
        match self {
            Self::Audit => "google_workspace/audit/v1",
            Self::Group => "google_workspace/group/v1",
            Self::GroupMember => "google_workspace/group_member/v1",
            Self::RoleAssignment => "google_workspace/role_assignment/v1",
            Self::User => "google_workspace/user/v1",
        }
    }

    const fn response_field(self) -> &'static str {
        match self {
            Self::User => "users",
            Self::Group => "groups",
            Self::GroupMember => "members",
            Self::RoleAssignment | Self::Audit => "items",
        }
    }
}

impl FromStr for GoogleWorkspaceFamily {
    type Err = GoogleWorkspaceError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim() {
            "audit" => Ok(Self::Audit),
            "group" => Ok(Self::Group),
            "group_member" => Ok(Self::GroupMember),
            "role_assignment" => Ok(Self::RoleAssignment),
            "user" => Ok(Self::User),
            _ => Err(GoogleWorkspaceError::InvalidFamily),
        }
    }
}

/// Provider scopes accepted by Google Workspace collection families.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GoogleWorkspaceFilters {
    /// Admin SDK customer identifier; defaults to `my_customer`.
    pub customer_id: Option<String>,
    /// Group key required for the `group_member` family.
    pub group_key: Option<String>,
    /// Reports API application name; defaults to `admin`.
    pub application: Option<String>,
}

/// One credential-free HTTP request planned by the Google Workspace kernel.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GoogleWorkspaceRequest {
    url: Url,
    family: GoogleWorkspaceFamily,
    stage: RequestStage,
    role_state: Option<Box<RoleAssignmentState>>,
}

impl GoogleWorkspaceRequest {
    /// Return the exact provider URL. The caller must authorize it before I/O.
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Return the required `Authorization` scheme without credential material.
    pub const fn authorization_scheme(&self) -> &'static str {
        "Bearer"
    }

    /// Return the required response media type.
    pub const fn accept(&self) -> &'static str {
        "application/json"
    }
}

/// One normalized Google Workspace provider record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GoogleWorkspaceRecord {
    /// Source-catalog family identifier.
    pub family: String,
    /// Emitted provider kind.
    pub provider_kind: String,
    /// Stable provider-owned identity, group-scoped for memberships.
    pub provider_id: String,
    /// Provider-specific scalar fields used by source mapping.
    pub fields: BTreeMap<String, String>,
    /// Original provider record, with no credentials added.
    pub payload: Value,
}

/// A bounded Google Workspace page and its opaque provider cursor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GoogleWorkspacePage {
    /// Normalized records in provider order.
    pub records: Vec<GoogleWorkspaceRecord>,
    /// `nextPageToken` for the next provider page.
    pub next_cursor: Option<String>,
}

/// Result of decoding one Google Workspace response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GoogleWorkspaceOutcome {
    /// Role-assignee enrichment requires one bounded user lookup.
    Request(GoogleWorkspaceRequest),
    /// The provider response completed one source-runtime page.
    Page(GoogleWorkspacePage),
}

/// Provider-specific Google Workspace request and response state machine.
#[derive(Clone, Debug)]
pub struct GoogleWorkspaceKernel {
    base_url: Url,
    domain: String,
    family: GoogleWorkspaceFamily,
    customer_id: String,
    group_key: Option<String>,
    application: String,
    page_size: usize,
}

impl GoogleWorkspaceKernel {
    /// Build a kernel for one Admin SDK origin, tenant domain, and family.
    ///
    /// The returned requests still require the shared live-egress decision and
    /// an operation-scoped bearer credential before network access.
    pub fn new(
        base_url: &str,
        domain: &str,
        family: GoogleWorkspaceFamily,
        filters: GoogleWorkspaceFilters,
        page_size: Option<usize>,
    ) -> Result<Self, GoogleWorkspaceError> {
        let base_url = validate_origin(base_url)?;
        let domain = required_value(domain, GoogleWorkspaceError::MissingDomain)?;
        let customer_id = optional_value(filters.customer_id, DEFAULT_CUSTOMER_ID);
        let group_key = nonblank(filters.group_key);
        if family == GoogleWorkspaceFamily::GroupMember && group_key.is_none() {
            return Err(GoogleWorkspaceError::MissingGroupKey);
        }
        let application = optional_value(filters.application, DEFAULT_APPLICATION);
        let page_size = page_size.unwrap_or(DEFAULT_PAGE_SIZE);
        if !(1..=MAX_PAGE_SIZE).contains(&page_size) {
            return Err(GoogleWorkspaceError::InvalidPageSize);
        }
        Ok(Self {
            base_url,
            domain,
            family,
            customer_id,
            group_key,
            application,
            page_size,
        })
    }

    /// Plan the credential-free request for one provider page.
    pub fn plan(
        &self,
        cursor: Option<&str>,
    ) -> Result<GoogleWorkspaceRequest, GoogleWorkspaceError> {
        let cursor = cursor.map(str::trim).filter(|value| !value.is_empty());
        let mut url = match self.family {
            GoogleWorkspaceFamily::User => self.endpoint(&["admin", "directory", "v1", "users"])?,
            GoogleWorkspaceFamily::Group => {
                self.endpoint(&["admin", "directory", "v1", "groups"])?
            }
            GoogleWorkspaceFamily::GroupMember => self.endpoint(&[
                "admin",
                "directory",
                "v1",
                "groups",
                self.group_key
                    .as_deref()
                    .ok_or(GoogleWorkspaceError::MissingGroupKey)?,
                "members",
            ])?,
            GoogleWorkspaceFamily::RoleAssignment => self.endpoint(&[
                "admin",
                "directory",
                "v1",
                "customer",
                &self.customer_id,
                "roleassignments",
            ])?,
            GoogleWorkspaceFamily::Audit => self.endpoint(&[
                "admin",
                "reports",
                "v1",
                "activity",
                "users",
                "all",
                "applications",
                &self.application,
            ])?,
        };
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("maxResults", &self.page_size.to_string());
            if let Some(cursor) = cursor {
                query.append_pair("pageToken", cursor);
            }
            match self.family {
                GoogleWorkspaceFamily::User | GoogleWorkspaceFamily::Group => {
                    query.append_pair("customer", &self.customer_id);
                }
                GoogleWorkspaceFamily::Audit => {
                    query.append_pair("customerId", &self.customer_id);
                }
                GoogleWorkspaceFamily::GroupMember | GoogleWorkspaceFamily::RoleAssignment => {}
            }
        }
        Ok(GoogleWorkspaceRequest {
            url,
            family: self.family,
            stage: RequestStage::Direct,
            role_state: None,
        })
    }

    /// Decode a response for a request produced by this kernel.
    pub fn decode(
        &self,
        request: &GoogleWorkspaceRequest,
        body: &[u8],
    ) -> Result<GoogleWorkspaceOutcome, GoogleWorkspaceError> {
        if request.family != self.family || request.url.origin() != self.base_url.origin() {
            return Err(GoogleWorkspaceError::RequestScopeMismatch);
        }
        match request.stage {
            RequestStage::Direct => self.decode_direct(body),
            RequestStage::ResolveRoleUser => self.decode_role_user(request, body),
        }
    }

    fn decode_direct(&self, body: &[u8]) -> Result<GoogleWorkspaceOutcome, GoogleWorkspaceError> {
        let decoded = decode_page(body, self.family.response_field())?;
        if self.family != GoogleWorkspaceFamily::RoleAssignment {
            return self
                .normalize_page(decoded.records, decoded.next_cursor, &BTreeMap::new())
                .map(GoogleWorkspaceOutcome::Page);
        }
        let lookups = role_user_lookups(&decoded.records)?;
        if lookups.is_empty() {
            return self
                .normalize_page(decoded.records, decoded.next_cursor, &BTreeMap::new())
                .map(GoogleWorkspaceOutcome::Page);
        }
        self.role_user_request(RoleAssignmentState {
            records: decoded.records,
            next_cursor: decoded.next_cursor,
            lookups,
            lookup_index: 0,
            users: BTreeMap::new(),
        })
        .map(GoogleWorkspaceOutcome::Request)
    }

    fn decode_role_user(
        &self,
        request: &GoogleWorkspaceRequest,
        body: &[u8],
    ) -> Result<GoogleWorkspaceOutcome, GoogleWorkspaceError> {
        let mut state = request
            .role_state
            .as_deref()
            .cloned()
            .ok_or(GoogleWorkspaceError::MissingRoleState)?;
        let lookup = state
            .lookups
            .get(state.lookup_index)
            .cloned()
            .ok_or(GoogleWorkspaceError::MissingRoleState)?;
        let user = decode_object(body)?;
        state.users.insert(
            lookup,
            ResolvedUser {
                email: nested_scalar(&user, &["primaryEmail"]).unwrap_or_default(),
                name: nested_scalar(&user, &["name", "fullName"]).unwrap_or_default(),
            },
        );
        state.lookup_index += 1;
        if state.lookup_index < state.lookups.len() {
            return self
                .role_user_request(state)
                .map(GoogleWorkspaceOutcome::Request);
        }
        self.normalize_page(state.records, state.next_cursor, &state.users)
            .map(GoogleWorkspaceOutcome::Page)
    }

    fn role_user_request(
        &self,
        state: RoleAssignmentState,
    ) -> Result<GoogleWorkspaceRequest, GoogleWorkspaceError> {
        let user_key = state
            .lookups
            .get(state.lookup_index)
            .ok_or(GoogleWorkspaceError::MissingRoleState)?;
        Ok(GoogleWorkspaceRequest {
            url: self.endpoint(&["admin", "directory", "v1", "users", user_key])?,
            family: self.family,
            stage: RequestStage::ResolveRoleUser,
            role_state: Some(Box::new(state)),
        })
    }

    fn normalize_page(
        &self,
        payloads: Vec<Value>,
        next_cursor: Option<String>,
        users: &BTreeMap<String, ResolvedUser>,
    ) -> Result<GoogleWorkspacePage, GoogleWorkspaceError> {
        let records = payloads
            .into_iter()
            .map(|payload| self.normalize_record(payload, users))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(GoogleWorkspacePage {
            records,
            next_cursor,
        })
    }

    fn normalize_record(
        &self,
        payload: Value,
        users: &BTreeMap<String, ResolvedUser>,
    ) -> Result<GoogleWorkspaceRecord, GoogleWorkspaceError> {
        let object = payload
            .as_object()
            .ok_or(GoogleWorkspaceError::InvalidRecord)?;
        let mut fields = BTreeMap::new();
        insert(&mut fields, "domain", self.domain.clone());
        insert(&mut fields, "family", self.family.as_str().to_owned());
        let provider_id = match self.family {
            GoogleWorkspaceFamily::User => normalize_user(object, &mut fields)?,
            GoogleWorkspaceFamily::Group => normalize_group(object, &mut fields)?,
            GoogleWorkspaceFamily::GroupMember => {
                normalize_group_member(object, &mut fields, self.group_key.as_deref())?
            }
            GoogleWorkspaceFamily::RoleAssignment => {
                normalize_role_assignment(object, &mut fields, users)?
            }
            GoogleWorkspaceFamily::Audit => normalize_audit(object, &mut fields)?,
        };
        Ok(GoogleWorkspaceRecord {
            family: self.family.as_str().to_owned(),
            provider_kind: self.family.provider_kind().to_owned(),
            provider_id,
            fields,
            payload,
        })
    }

    fn endpoint(&self, segments: &[&str]) -> Result<Url, GoogleWorkspaceError> {
        let mut url = self.base_url.clone();
        url.set_path("/");
        let mut path = url
            .path_segments_mut()
            .map_err(|_| GoogleWorkspaceError::InvalidBaseUrl)?;
        path.pop_if_empty();
        path.extend(segments.iter().copied());
        drop(path);
        Ok(url)
    }
}
