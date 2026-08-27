use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::digest::canonical_digest;
use crate::{GoPackageGraph, MigratorError};

/// One atomic strongly connected component in the Go import graph.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StrongComponent {
    id: String,
    packages: Vec<String>,
    dependencies: Vec<String>,
    source_file_count: u64,
}

impl StrongComponent {
    /// Returns the content-derived component identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns package import paths in lexical order.
    #[must_use]
    pub fn packages(&self) -> &[String] {
        &self.packages
    }

    /// Returns component identifiers imported by this component.
    #[must_use]
    pub fn dependencies(&self) -> &[String] {
        &self.dependencies
    }

    /// Returns the number of Go source filenames reported in the component.
    #[must_use]
    pub fn source_file_count(&self) -> u64 {
        self.source_file_count
    }
}

/// A cycle-free package graph whose nodes are atomic Go deletion components.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CondensedGoGraph {
    schema_version: String,
    source_graph_digest: String,
    components: Vec<StrongComponent>,
    graph_digest: String,
}

impl CondensedGoGraph {
    pub(crate) fn from_package_graph(graph: &GoPackageGraph) -> Result<Self, MigratorError> {
        let package_names: Vec<String> = graph.packages().keys().cloned().collect();
        let package_indexes: BTreeMap<&str, usize> = package_names
            .iter()
            .enumerate()
            .map(|(index, package)| (package.as_str(), index))
            .collect();
        let adjacency: Vec<Vec<usize>> = package_names
            .iter()
            .map(|package| {
                graph.packages()[package]
                    .imports()
                    .iter()
                    .filter_map(|dependency| package_indexes.get(dependency.as_str()).copied())
                    .collect()
            })
            .collect();

        let mut tarjan = Tarjan::new(&adjacency);
        for index in 0..package_names.len() {
            if tarjan.indexes[index].is_none() {
                tarjan.visit(index);
            }
        }

        let mut raw_components: Vec<Vec<String>> = tarjan
            .components
            .into_iter()
            .map(|component| {
                let mut packages: Vec<String> = component
                    .into_iter()
                    .map(|index| package_names[index].clone())
                    .collect();
                packages.sort();
                packages
            })
            .collect();
        raw_components.sort();

        let mut package_component = BTreeMap::new();
        let mut component_ids = Vec::with_capacity(raw_components.len());
        for packages in &raw_components {
            let id = format!(
                "scc:{}",
                canonical_digest(packages)?.trim_start_matches("sha256:")
            );
            for package in packages {
                package_component.insert(package.clone(), id.clone());
            }
            component_ids.push(id);
        }

        let mut components = Vec::with_capacity(raw_components.len());
        for (packages, id) in raw_components.into_iter().zip(component_ids) {
            let mut dependencies = BTreeSet::new();
            let mut source_file_count = 0_u64;
            for package in &packages {
                let package_node = &graph.packages()[package];
                source_file_count = source_file_count
                    .checked_add(package_node.source_files().len() as u64)
                    .ok_or(MigratorError::ScoreOverflow)?;
                for dependency in package_node.imports() {
                    let dependency_component = &package_component[dependency];
                    if dependency_component != &id {
                        dependencies.insert(dependency_component.clone());
                    }
                }
            }
            components.push(StrongComponent {
                id,
                packages,
                dependencies: dependencies.into_iter().collect(),
                source_file_count,
            });
        }
        components.sort_by(|left, right| left.id.cmp(&right.id));
        let source_graph_digest = graph.graph_digest().to_owned();
        let graph_digest = canonical_digest(&(source_graph_digest.as_str(), &components))?;
        Ok(Self {
            schema_version: "cerebro.migrator.condensed-go-graph/v1".to_owned(),
            source_graph_digest,
            components,
            graph_digest,
        })
    }

    /// Returns components in stable content-identifier order.
    #[must_use]
    pub fn components(&self) -> &[StrongComponent] {
        &self.components
    }

    /// Returns the canonical digest of the condensed graph.
    #[must_use]
    pub fn graph_digest(&self) -> &str {
        &self.graph_digest
    }
}

struct Tarjan<'a> {
    adjacency: &'a [Vec<usize>],
    next_index: usize,
    indexes: Vec<Option<usize>>,
    low_links: Vec<usize>,
    stack: Vec<usize>,
    on_stack: Vec<bool>,
    components: Vec<Vec<usize>>,
}

impl<'a> Tarjan<'a> {
    fn new(adjacency: &'a [Vec<usize>]) -> Self {
        Self {
            adjacency,
            next_index: 0,
            indexes: vec![None; adjacency.len()],
            low_links: vec![0; adjacency.len()],
            stack: Vec::new(),
            on_stack: vec![false; adjacency.len()],
            components: Vec::new(),
        }
    }

    fn visit(&mut self, node: usize) {
        let node_index = self.next_index;
        self.next_index += 1;
        self.indexes[node] = Some(node_index);
        self.low_links[node] = node_index;
        self.stack.push(node);
        self.on_stack[node] = true;

        for &dependency in &self.adjacency[node] {
            if self.indexes[dependency].is_none() {
                self.visit(dependency);
                self.low_links[node] = self.low_links[node].min(self.low_links[dependency]);
            } else if self.on_stack[dependency] {
                self.low_links[node] = self.low_links[node].min(
                    self.indexes[dependency].expect("an on-stack Tarjan node always has an index"),
                );
            }
        }

        if self.low_links[node] == node_index {
            let mut component = Vec::new();
            loop {
                let member = self
                    .stack
                    .pop()
                    .expect("the active Tarjan node is present on the stack");
                self.on_stack[member] = false;
                component.push(member);
                if member == node {
                    break;
                }
            }
            self.components.push(component);
        }
    }
}
