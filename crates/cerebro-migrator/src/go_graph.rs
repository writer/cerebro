use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;

use serde::{Deserialize, Serialize};

use crate::digest::canonical_digest;
use crate::{CondensedGoGraph, MigratorError};

/// One repository-owned package from a `go list` package stream.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GoPackage {
    import_path: String,
    repository_path: String,
    module_path: Option<String>,
    imports: Vec<String>,
    source_files: Vec<String>,
}

impl GoPackage {
    /// Returns the canonical Go import path.
    #[must_use]
    pub fn import_path(&self) -> &str {
        &self.import_path
    }

    /// Returns the portable repository-relative package directory.
    ///
    /// The module root is represented as `.`. Absolute `go list` directories
    /// never enter the graph or its digest.
    #[must_use]
    pub fn repository_path(&self) -> &str {
        &self.repository_path
    }

    /// Returns the owning Go module, when one was reported.
    #[must_use]
    pub fn module_path(&self) -> Option<&str> {
        self.module_path.as_deref()
    }

    /// Returns direct imports that are also present in this graph.
    #[must_use]
    pub fn imports(&self) -> &[String] {
        &self.imports
    }

    /// Returns production and test source filenames reported for the package.
    #[must_use]
    pub fn source_files(&self) -> &[String] {
        &self.source_files
    }
}

/// A deterministic repository-owned Go package and direct-import graph.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GoPackageGraph {
    schema_version: String,
    packages: BTreeMap<String, GoPackage>,
    graph_digest: String,
}

impl GoPackageGraph {
    /// Ingests a concatenated `go list -deps -json` stream.
    ///
    /// Standard-library packages are always excluded. When `owned_module` is
    /// supplied, only packages whose module path exactly matches it are retained.
    /// Edges to packages outside the retained set are omitted.
    pub fn from_go_list_json<R: Read>(
        reader: R,
        owned_module: Option<&str>,
    ) -> Result<Self, MigratorError> {
        let mut raw_packages = BTreeMap::new();
        let stream = serde_json::Deserializer::from_reader(reader).into_iter::<GoListPackage>();
        for decoded in stream {
            let raw = decoded?;
            if let Some(error) = raw.error {
                return Err(MigratorError::GoListPackage {
                    package: raw.import_path,
                    error: error.err,
                });
            }
            if raw.standard
                || owned_module.is_some_and(|module| {
                    raw.module.as_ref().map(|item| item.path.as_str()) != Some(module)
                })
            {
                continue;
            }
            validate_nonempty(&raw.import_path, "Go import path")?;
            let import_path = raw.import_path.clone();
            if raw_packages.insert(import_path.clone(), raw).is_some() {
                return Err(MigratorError::DuplicatePackage(import_path));
            }
        }

        let retained: BTreeSet<String> = raw_packages.keys().cloned().collect();
        let mut packages = BTreeMap::new();
        for (import_path, raw) in raw_packages {
            let repository_path = repository_path(&import_path, owned_module)?;
            let mut imports: Vec<String> = raw
                .imports
                .into_iter()
                .filter(|dependency| retained.contains(dependency))
                .collect();
            imports.sort();
            imports.dedup();

            let mut source_files = raw.go_files;
            source_files.extend(raw.cgo_files);
            source_files.extend(raw.test_go_files);
            source_files.extend(raw.x_test_go_files);
            source_files.sort();
            source_files.dedup();

            packages.insert(
                import_path.clone(),
                GoPackage {
                    import_path,
                    repository_path,
                    module_path: raw.module.map(|module| module.path),
                    imports,
                    source_files,
                },
            );
        }

        let graph_digest = canonical_digest(&packages)?;
        Ok(Self {
            schema_version: "cerebro.migrator.go-package-graph/v2".to_owned(),
            packages,
            graph_digest,
        })
    }

    /// Returns packages in canonical import-path order.
    #[must_use]
    pub fn packages(&self) -> &BTreeMap<String, GoPackage> {
        &self.packages
    }

    /// Returns the canonical digest of the package graph.
    #[must_use]
    pub fn graph_digest(&self) -> &str {
        &self.graph_digest
    }

    /// Condenses direct-import cycles into deterministic atomic components.
    pub fn condense(&self) -> Result<CondensedGoGraph, MigratorError> {
        CondensedGoGraph::from_package_graph(self)
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct GoListPackage {
    import_path: String,
    #[serde(default)]
    standard: bool,
    module: Option<GoListModule>,
    #[serde(default)]
    imports: Vec<String>,
    #[serde(default)]
    go_files: Vec<String>,
    #[serde(default)]
    cgo_files: Vec<String>,
    #[serde(default)]
    test_go_files: Vec<String>,
    #[serde(default)]
    x_test_go_files: Vec<String>,
    error: Option<GoListError>,
}

fn repository_path(import_path: &str, owned_module: Option<&str>) -> Result<String, MigratorError> {
    let Some(module) = owned_module else {
        return Ok(import_path.to_owned());
    };
    if import_path == module {
        return Ok(".".to_owned());
    }
    let Some(relative) = import_path
        .strip_prefix(module)
        .and_then(|suffix| suffix.strip_prefix('/'))
    else {
        return Err(MigratorError::InvalidField {
            field: "Go import path",
            reason: format!("{import_path:?} is outside declared module {module:?}"),
        });
    };
    if relative.is_empty()
        || relative
            .split('/')
            .any(|part| part.is_empty() || matches!(part, "." | ".."))
    {
        return Err(MigratorError::InvalidField {
            field: "Go import path",
            reason: format!("{import_path:?} does not identify a portable module-relative package"),
        });
    }
    Ok(relative.to_owned())
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct GoListModule {
    path: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct GoListError {
    err: String,
}

fn validate_nonempty(value: &str, field: &'static str) -> Result<(), MigratorError> {
    if value.trim().is_empty() {
        return Err(MigratorError::InvalidField {
            field,
            reason: "must not be empty".to_owned(),
        });
    }
    Ok(())
}
