#![forbid(unsafe_code)]

mod catalog;
mod error;
mod filesystem;
mod generate;
mod render;
mod render_rust;
#[cfg(test)]
mod tests;

pub use catalog::{ActionCatalog, ActionCatalogEntry, definition_digest, validate_catalog};
pub use error::{CatalogError, Error, Result};
pub use filesystem::{
    DEFAULT_CATALOG_PATH, DEFAULT_OUTPUT_PATH, DEFAULT_RUST_OUTPUT_PATH, MAX_GENERATED_FILE_BYTES,
    ensure_supported_platform, read_generated_file, write_generated_file,
};
pub use generate::{generate, generate_rust};
pub use render::render_catalog;
pub use render_rust::render_rust_catalog;

#[cfg(test)]
use filesystem::read_limited;
