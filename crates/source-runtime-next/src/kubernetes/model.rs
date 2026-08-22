//! Public Kubernetes normalized page contracts.

use std::collections::BTreeMap;

use serde_json::Value;

use super::KubernetesFamily;

/// One normalized Kubernetes provider object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KubernetesRecord {
    /// Closed source family.
    pub family: KubernetesFamily,
    /// Stable provider UID or declared composite identity.
    pub provider_id: String,
    /// Go-compatible event identity within the tenant envelope.
    pub event_id: String,
    /// Collision-resistant tenant-scoped canonical identity.
    pub canonical_urn: String,
    /// Exact source event kind.
    pub event_kind: String,
    /// Exact source event schema.
    pub schema_ref: String,
    /// Normalized source and projection attributes.
    pub attributes: BTreeMap<String, String>,
    /// Go-compatible normalized payload.
    pub payload: Value,
    /// Provider creation time or caller-supplied observation time.
    pub occurred_at: String,
}

/// One bounded Kubernetes page and its Go-compatible continuation/checkpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KubernetesPage {
    /// Deduplicated records in provider order.
    pub records: Vec<KubernetesRecord>,
    /// Exact continuation accepted by the Go source.
    pub next_cursor: Option<String>,
    /// Proposed durable checkpoint, never committed by this kernel.
    pub proposed_checkpoint: Option<String>,
}
