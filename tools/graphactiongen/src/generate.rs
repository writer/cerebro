use std::path::Path;

use crate::{
    ActionCatalog, Error, Result, filesystem::read_bounded_file, render_catalog,
    render_rust_catalog, validate_catalog,
};

pub fn generate(root: &Path, catalog_path: &Path) -> Result<Vec<u8>> {
    let catalog = load_catalog(root, catalog_path)?;
    render_catalog(&catalog)
}

pub fn generate_rust(root: &Path, catalog_path: &Path) -> Result<Vec<u8>> {
    let catalog = load_catalog(root, catalog_path)?;
    render_rust_catalog(&catalog)
}

fn load_catalog(root: &Path, catalog_path: &Path) -> Result<ActionCatalog> {
    let path = root.join(catalog_path);
    let content = read_bounded_file(&path)?;
    let catalog: ActionCatalog =
        serde_saphyr::from_slice(&content).map_err(|error| Error::CatalogDecode {
            path: catalog_path.to_path_buf(),
            message: error.to_string(),
        })?;
    validate_catalog(&catalog)?;
    Ok(catalog)
}
