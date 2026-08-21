//! Archetype request, response, and enrichment-fanout runtime kernel.
//!
//! Archetype is a credentialed pull source. This module plans its portable
//! provider requests and decodes responses without performing network I/O,
//! accepting credential material, or owning durable checkpoint advancement.

mod cursor;
mod error;
mod family;
mod normalization;
mod request;
mod types;
mod wire;

pub use cursor::ArchetypePage;
pub use error::ArchetypeError;
pub use family::{ArchetypeFamily, VulnerabilityCollectionState};
pub use request::{ArchetypeKernel, ArchetypeRequest, ArchetypeRequestKind};
pub use types::{ArchetypeRecord, ArchetypeRepository, ArchetypeScan};

#[cfg(test)]
mod tests;
