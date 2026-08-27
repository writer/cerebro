use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};

use crate::digest::canonical_digest;
use crate::{DeletionBenefit, MigrationStatus, MigrationUnit, MigrationUnitSpec, MigratorError};

/// Explicit weights used to score deletion benefit against migration effort.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlanObjective {
    /// Score per production Go line removed.
    pub production_line_weight: u64,
    /// Score per Go test line removed.
    pub test_line_weight: u64,
    /// Score per complete Go package removed.
    pub package_weight: u64,
    /// Score per deployable Go entry point removed.
    pub runtime_entrypoint_weight: u64,
    /// Score deducted per unit of estimated implementation/evidence effort.
    pub effort_weight: u64,
}

impl Default for PlanObjective {
    fn default() -> Self {
        Self {
            production_line_weight: 1,
            test_line_weight: 1,
            package_weight: 0,
            runtime_entrypoint_weight: 0,
            effort_weight: 0,
        }
    }
}

/// JSON input accepted by the `plan` command.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlanRequest {
    /// Explicit objective weights.
    #[serde(default)]
    pub objective: PlanObjective,
    /// Unbound migration units to normalize and content-bind before planning.
    pub units: Vec<MigrationUnitSpec>,
}

impl PlanRequest {
    /// Binds every input unit and computes the maximum-deletion closed plan.
    pub fn plan(self) -> Result<BatchPlan, MigratorError> {
        let units = self
            .units
            .into_iter()
            .map(MigrationUnit::bind)
            .collect::<Result<Vec<_>, _>>()?;
        plan_maximum_deletion(&units, self.objective)
    }
}

/// Aggregate deletion and objective values for a selected batch.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BatchTotals {
    /// Number of selected migration units.
    pub units: u64,
    /// Aggregate production Go lines removed.
    pub production_lines: u64,
    /// Aggregate Go test lines removed.
    pub test_lines: u64,
    /// Aggregate complete Go packages removed.
    pub packages: u64,
    /// Aggregate deployable Go entry points removed.
    pub runtime_entrypoints: u64,
    /// Aggregate migration effort.
    pub effort: u64,
    /// Signed objective score after effort deductions.
    pub objective_score: i128,
}

/// One unit excluded from a maximum-deletion batch and its stable reason.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExcludedUnit {
    /// Stable migration-unit identifier.
    pub id: String,
    /// Stable machine-readable exclusion reason.
    pub reason: String,
}

/// Immutable, content-addressed maximum-deletion batch plan.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BatchPlan {
    schema_version: String,
    content_digest: String,
    base_sha: String,
    input_digest: String,
    objective: PlanObjective,
    selected_unit_ids: Vec<String>,
    selected_unit_digests: Vec<String>,
    excluded_units: Vec<ExcludedUnit>,
    totals: BatchTotals,
}

impl BatchPlan {
    /// Parses and verifies a previously emitted batch-plan document.
    pub fn from_json_slice(bytes: &[u8]) -> Result<Self, MigratorError> {
        let document: Self = serde_json::from_slice(bytes)?;
        document.verify()?;
        Ok(document)
    }

    /// Returns the exact repository revision shared by all units.
    #[must_use]
    pub fn base_sha(&self) -> &str {
        &self.base_sha
    }

    /// Returns selected unit identifiers in lexical order.
    #[must_use]
    pub fn selected_unit_ids(&self) -> &[String] {
        &self.selected_unit_ids
    }

    /// Returns excluded units in lexical unit order.
    #[must_use]
    pub fn excluded_units(&self) -> &[ExcludedUnit] {
        &self.excluded_units
    }

    /// Returns aggregate selected benefit, effort, and score.
    #[must_use]
    pub fn totals(&self) -> BatchTotals {
        self.totals
    }

    /// Returns the digest of the normalized planning inputs.
    #[must_use]
    pub fn input_digest(&self) -> &str {
        &self.input_digest
    }

    /// Returns the digest binding the complete plan payload.
    #[must_use]
    pub fn content_digest(&self) -> &str {
        &self.content_digest
    }

    /// Verifies the plan document has not changed after construction.
    pub fn verify(&self) -> Result<(), MigratorError> {
        if self.schema_version != "cerebro.migrator.batch-plan/v1" {
            return Err(MigratorError::InvalidField {
                field: "batch plan schema_version",
                reason: format!("unsupported value {}", self.schema_version),
            });
        }
        validate_git_sha(&self.base_sha)?;
        validate_digest(&self.input_digest, "batch plan input digest")?;
        validate_digest(&self.content_digest, "batch plan content digest")?;
        if self
            .selected_unit_ids
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        {
            return Err(MigratorError::InvalidField {
                field: "selected unit ids",
                reason: "values must be sorted and unique".to_owned(),
            });
        }
        if self.selected_unit_ids.len() != self.selected_unit_digests.len() {
            return Err(MigratorError::InvalidField {
                field: "selected unit digests",
                reason: "must contain exactly one digest per selected unit".to_owned(),
            });
        }
        for digest in &self.selected_unit_digests {
            validate_digest(digest, "selected unit digest")?;
        }
        if self
            .excluded_units
            .windows(2)
            .any(|pair| pair[0].id >= pair[1].id)
            || self
                .excluded_units
                .iter()
                .any(|unit| unit.id.trim().is_empty() || unit.reason.trim().is_empty())
        {
            return Err(MigratorError::InvalidField {
                field: "excluded units",
                reason: "unit ids must be sorted and unique with non-empty reasons".to_owned(),
            });
        }
        let excluded_ids: BTreeSet<&str> = self
            .excluded_units
            .iter()
            .map(|unit| unit.id.as_str())
            .collect();
        if self
            .selected_unit_ids
            .iter()
            .any(|id| excluded_ids.contains(id.as_str()))
        {
            return Err(MigratorError::InvalidField {
                field: "batch plan units",
                reason: "a unit cannot be both selected and excluded".to_owned(),
            });
        }
        if self.totals.units != self.selected_unit_ids.len() as u64 {
            return Err(MigratorError::InvalidField {
                field: "batch totals units",
                reason: "must equal the number of selected unit ids".to_owned(),
            });
        }
        let actual = canonical_digest(&BatchPlanPayload::from(self))?;
        if actual != self.content_digest {
            return Err(MigratorError::DigestMismatch {
                expected: self.content_digest.clone(),
                actual,
            });
        }
        Ok(())
    }
}

fn validate_git_sha(value: &str) -> Result<(), MigratorError> {
    if value.len() != 40 || !value.bytes().all(is_lower_hex) {
        return Err(MigratorError::InvalidField {
            field: "batch plan base SHA",
            reason: "must be a full lowercase 40-character hexadecimal Git commit".to_owned(),
        });
    }
    Ok(())
}

fn validate_digest(value: &str, field: &'static str) -> Result<(), MigratorError> {
    let Some(encoded) = value.strip_prefix("sha256:") else {
        return Err(MigratorError::InvalidField {
            field,
            reason: "must start with sha256:".to_owned(),
        });
    };
    if encoded.len() != 64 || !encoded.bytes().all(is_lower_hex) {
        return Err(MigratorError::InvalidField {
            field,
            reason: "must contain exactly 64 lowercase hexadecimal characters".to_owned(),
        });
    }
    Ok(())
}

fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')
}

#[derive(Serialize)]
struct BatchPlanPayload<'a> {
    base_sha: &'a str,
    input_digest: &'a str,
    objective: PlanObjective,
    selected_unit_ids: &'a [String],
    selected_unit_digests: &'a [String],
    excluded_units: &'a [ExcludedUnit],
    totals: BatchTotals,
}

impl<'a> From<&'a BatchPlan> for BatchPlanPayload<'a> {
    fn from(plan: &'a BatchPlan) -> Self {
        Self {
            base_sha: &plan.base_sha,
            input_digest: &plan.input_digest,
            objective: plan.objective,
            selected_unit_ids: &plan.selected_unit_ids,
            selected_unit_digests: &plan.selected_unit_digests,
            excluded_units: &plan.excluded_units,
            totals: plan.totals,
        }
    }
}

#[derive(Serialize)]
struct PlanningInput<'a> {
    objective: PlanObjective,
    units: Vec<(&'a str, &'a str)>,
}

/// Computes an exact maximum-weight prerequisite closure using a deterministic
/// source/sink minimum cut.
///
/// Blocked units are forced out. Selecting a unit forces all of its declared
/// prerequisites into the same batch, including negative-score shared
/// capabilities when their downstream deletion benefit justifies the cost.
pub fn plan_maximum_deletion(
    units: &[MigrationUnit],
    objective: PlanObjective,
) -> Result<BatchPlan, MigratorError> {
    if units.is_empty() {
        return Err(MigratorError::InvalidField {
            field: "migration units",
            reason: "at least one unit is required".to_owned(),
        });
    }

    let mut ordered = BTreeMap::new();
    for unit in units {
        unit.verify()?;
        if ordered.insert(unit.id().to_owned(), unit).is_some() {
            return Err(MigratorError::DuplicateUnit(unit.id().to_owned()));
        }
    }
    let base_sha = ordered
        .first_key_value()
        .expect("non-empty units have a first item")
        .1
        .base_sha()
        .to_owned();
    for unit in ordered.values() {
        if unit.base_sha() != base_sha {
            return Err(MigratorError::MixedBaseSha {
                expected: base_sha,
                actual: unit.base_sha().to_owned(),
            });
        }
        for prerequisite in unit.prerequisites() {
            if !ordered.contains_key(prerequisite) {
                return Err(MigratorError::MissingPrerequisite {
                    unit: unit.id().to_owned(),
                    prerequisite: prerequisite.clone(),
                });
            }
        }
    }

    let unit_ids: Vec<&str> = ordered.keys().map(String::as_str).collect();
    let indexes: BTreeMap<&str, usize> = unit_ids
        .iter()
        .enumerate()
        .map(|(index, id)| (*id, index))
        .collect();
    let mut scores = Vec::with_capacity(ordered.len());
    let mut total_positive = 0_u128;
    for unit in ordered.values() {
        let score = unit_score(unit, objective)?;
        if score > 0 {
            total_positive = total_positive
                .checked_add(score.unsigned_abs())
                .ok_or(MigratorError::ScoreOverflow)?;
        }
        scores.push(score);
    }
    let infinite = total_positive
        .checked_add(1)
        .ok_or(MigratorError::ScoreOverflow)?;

    let source = ordered.len();
    let sink = source + 1;
    let mut flow = FlowNetwork::new(sink + 1);
    for (index, unit) in ordered.values().enumerate() {
        match scores[index].cmp(&0) {
            std::cmp::Ordering::Greater => {
                flow.add_edge(source, index, scores[index].unsigned_abs());
            }
            std::cmp::Ordering::Less => {
                flow.add_edge(index, sink, scores[index].unsigned_abs());
            }
            std::cmp::Ordering::Equal => {}
        }
        if unit.status() == MigrationStatus::Blocked {
            flow.add_edge(index, sink, infinite);
        }
        for prerequisite in unit.prerequisites() {
            flow.add_edge(index, indexes[prerequisite.as_str()], infinite);
        }
    }
    flow.maximum_flow(source, sink);
    let reachable = flow.residual_reachable(source);

    let mut selected_unit_ids = Vec::new();
    let mut selected_unit_digests = Vec::new();
    let mut excluded_units = Vec::new();
    let mut totals = BatchTotals::default();
    for (index, unit) in ordered.values().enumerate() {
        if reachable.contains(&index) {
            selected_unit_ids.push(unit.id().to_owned());
            selected_unit_digests.push(unit.content_digest().to_owned());
            add_totals(&mut totals, unit, scores[index])?;
        } else {
            let reason = if unit.status() == MigrationStatus::Blocked {
                format!("blocked:{}", unit.blockers().join(","))
            } else {
                "not_selected_by_objective".to_owned()
            };
            excluded_units.push(ExcludedUnit {
                id: unit.id().to_owned(),
                reason,
            });
        }
    }

    let input_digest = canonical_digest(&PlanningInput {
        objective,
        units: ordered
            .values()
            .map(|unit| (unit.id(), unit.content_digest()))
            .collect(),
    })?;
    let provisional = BatchPlan {
        schema_version: "cerebro.migrator.batch-plan/v1".to_owned(),
        content_digest: String::new(),
        base_sha,
        input_digest,
        objective,
        selected_unit_ids,
        selected_unit_digests,
        excluded_units,
        totals,
    };
    let content_digest = canonical_digest(&BatchPlanPayload::from(&provisional))?;
    Ok(BatchPlan {
        content_digest,
        ..provisional
    })
}

fn unit_score(unit: &MigrationUnit, objective: PlanObjective) -> Result<i128, MigratorError> {
    let benefit = unit.benefit();
    let production = weighted(benefit.production_lines, objective.production_line_weight)?;
    let tests = weighted(benefit.test_lines, objective.test_line_weight)?;
    let packages = weighted(benefit.packages, objective.package_weight)?;
    let entrypoints = weighted(
        benefit.runtime_entrypoints,
        objective.runtime_entrypoint_weight,
    )?;
    let positive = production
        .checked_add(tests)
        .and_then(|value| value.checked_add(packages))
        .and_then(|value| value.checked_add(entrypoints))
        .ok_or(MigratorError::ScoreOverflow)?;
    let negative = weighted(unit.effort(), objective.effort_weight)?;
    let positive = i128::try_from(positive).map_err(|_| MigratorError::ScoreOverflow)?;
    let negative = i128::try_from(negative).map_err(|_| MigratorError::ScoreOverflow)?;
    positive
        .checked_sub(negative)
        .ok_or(MigratorError::ScoreOverflow)
}

fn weighted(value: u64, weight: u64) -> Result<u128, MigratorError> {
    u128::from(value)
        .checked_mul(u128::from(weight))
        .ok_or(MigratorError::ScoreOverflow)
}

fn add_totals(
    totals: &mut BatchTotals,
    unit: &MigrationUnit,
    score: i128,
) -> Result<(), MigratorError> {
    let DeletionBenefit {
        production_lines,
        test_lines,
        packages,
        runtime_entrypoints,
    } = unit.benefit();
    totals.units = totals
        .units
        .checked_add(1)
        .ok_or(MigratorError::ScoreOverflow)?;
    totals.production_lines = totals
        .production_lines
        .checked_add(production_lines)
        .ok_or(MigratorError::ScoreOverflow)?;
    totals.test_lines = totals
        .test_lines
        .checked_add(test_lines)
        .ok_or(MigratorError::ScoreOverflow)?;
    totals.packages = totals
        .packages
        .checked_add(packages)
        .ok_or(MigratorError::ScoreOverflow)?;
    totals.runtime_entrypoints = totals
        .runtime_entrypoints
        .checked_add(runtime_entrypoints)
        .ok_or(MigratorError::ScoreOverflow)?;
    totals.effort = totals
        .effort
        .checked_add(unit.effort())
        .ok_or(MigratorError::ScoreOverflow)?;
    totals.objective_score = totals
        .objective_score
        .checked_add(score)
        .ok_or(MigratorError::ScoreOverflow)?;
    Ok(())
}

#[derive(Clone, Copy)]
struct FlowEdge {
    target: usize,
    reverse: usize,
    capacity: u128,
}

struct FlowNetwork {
    edges: Vec<Vec<FlowEdge>>,
}

impl FlowNetwork {
    fn new(nodes: usize) -> Self {
        Self {
            edges: vec![Vec::new(); nodes],
        }
    }

    fn add_edge(&mut self, source: usize, target: usize, capacity: u128) {
        let forward = FlowEdge {
            target,
            reverse: self.edges[target].len(),
            capacity,
        };
        let reverse = FlowEdge {
            target: source,
            reverse: self.edges[source].len(),
            capacity: 0,
        };
        self.edges[source].push(forward);
        self.edges[target].push(reverse);
    }

    fn maximum_flow(&mut self, source: usize, sink: usize) -> u128 {
        let mut total = 0_u128;
        loop {
            let levels = self.levels(source);
            if levels[sink] == usize::MAX {
                return total;
            }
            let mut next_edges = vec![0_usize; self.edges.len()];
            loop {
                let pushed = self.push(source, sink, u128::MAX, &levels, &mut next_edges);
                if pushed == 0 {
                    break;
                }
                total = total.saturating_add(pushed);
            }
        }
    }

    fn levels(&self, source: usize) -> Vec<usize> {
        let mut levels = vec![usize::MAX; self.edges.len()];
        levels[source] = 0;
        let mut queue = VecDeque::from([source]);
        while let Some(node) = queue.pop_front() {
            for edge in &self.edges[node] {
                if edge.capacity > 0 && levels[edge.target] == usize::MAX {
                    levels[edge.target] = levels[node] + 1;
                    queue.push_back(edge.target);
                }
            }
        }
        levels
    }

    fn push(
        &mut self,
        node: usize,
        sink: usize,
        available: u128,
        levels: &[usize],
        next_edges: &mut [usize],
    ) -> u128 {
        if node == sink {
            return available;
        }
        while next_edges[node] < self.edges[node].len() {
            let edge_index = next_edges[node];
            let edge = self.edges[node][edge_index];
            if edge.capacity > 0 && levels[edge.target] == levels[node] + 1 {
                let pushed = self.push(
                    edge.target,
                    sink,
                    available.min(edge.capacity),
                    levels,
                    next_edges,
                );
                if pushed > 0 {
                    self.edges[node][edge_index].capacity -= pushed;
                    self.edges[edge.target][edge.reverse].capacity += pushed;
                    return pushed;
                }
            }
            next_edges[node] += 1;
        }
        0
    }

    fn residual_reachable(&self, source: usize) -> BTreeSet<usize> {
        let mut reachable = BTreeSet::from([source]);
        let mut queue = VecDeque::from([source]);
        while let Some(node) = queue.pop_front() {
            for edge in &self.edges[node] {
                if edge.capacity > 0 && reachable.insert(edge.target) {
                    queue.push_back(edge.target);
                }
            }
        }
        reachable
    }
}
