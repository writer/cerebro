#![forbid(unsafe_code)]

mod catalog;
mod error;
mod filesystem;
mod render;
#[cfg(test)]
mod tests;

pub use catalog::{ActionCatalog, ActionCatalogEntry, validate_catalog};
pub use error::{CatalogError, Error, Result};
pub use filesystem::{
    DEFAULT_CATALOG_PATH, DEFAULT_OUTPUT_PATH, MAX_GENERATED_FILE_BYTES, ensure_supported_platform,
    read_generated_file, write_generated_file,
};
pub use render::render_catalog;

use filesystem::read_bounded_file;
use std::path::Path;

#[cfg(test)]
use filesystem::read_limited;

pub fn generate(root: &Path, catalog_path: &Path) -> Result<Vec<u8>> {
    let path = root.join(catalog_path);
    let content = read_bounded_file(&path)?;
    let catalog: ActionCatalog =
        serde_saphyr::from_slice(&content).map_err(|error| Error::CatalogDecode {
            path: catalog_path.to_path_buf(),
            message: error.to_string(),
        })?;
    validate_catalog(&catalog)?;
    render_catalog(&catalog)
}
