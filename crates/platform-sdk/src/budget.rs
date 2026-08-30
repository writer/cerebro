//! Shared resource ceilings and usage validation for platform capabilities.
//!
//! Budgets are explicit data passed to engines and adapters; this module does
//! not meter work or cancel execution itself. Each consumer must enforce the
//! relevant limit at its allocation, scheduling, query, or plugin boundary and
//! may report the resulting usage through [`ResourceUsage`].

use serde::Serialize;

/// Reason a resource budget or usage sample failed validation.
///
/// Each variant carries the stable field label used by contract tests and
/// operator-facing adapters.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BudgetError {
    /// A required positive limit was configured as zero.
    Zero(&'static str),
    /// A configured limit exceeds a repository-wide safety ceiling.
    ExceedsMaximum(&'static str),
    /// Observed or requested usage exceeds its corresponding configured limit.
    UsageExceedsLimit(&'static str),
}

/// Positive resource limits shared by platform engines and host adapters.
///
/// Query results, query depth, subscription batch size, and snapshot entity
/// count also have repository-wide hard maxima enforced by [`Self::new`]. The
/// time, concurrency, and plugin-memory fields have no additional ceiling in
/// this transport contract; deployment policy may impose stricter bounds.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ResourceBudget {
    /// Maximum number of fact-query matches returned by one operation.
    pub max_query_results: u32,
    /// Maximum number of required graph edges traversed by one query.
    pub max_query_depth: u8,
    /// Maximum wall-clock duration of one query, in milliseconds.
    pub max_query_millis: u32,
    /// Maximum number of queries executing concurrently for the governed scope.
    pub max_concurrent_queries: u16,
    /// Maximum number of events returned in one subscription page.
    pub max_subscription_batch: u16,
    /// Maximum entities included in one temporal snapshot operation.
    pub max_snapshot_entities: u32,
    /// Maximum linear memory available to one analysis-plugin execution.
    pub max_plugin_memory_bytes: u64,
    /// Maximum wall-clock duration of one analysis-plugin execution.
    pub max_plugin_millis: u32,
}

impl ResourceBudget {
    /// Constructs a positive budget within the platform's hard safety ceilings.
    ///
    /// The constructor performs validation only; it does not reserve resources
    /// or prove that a host can supply the requested capacity.
    ///
    /// # Errors
    ///
    /// Returns [`BudgetError::Zero`] when any limit is zero. Returns
    /// [`BudgetError::ExceedsMaximum`] when query results exceed 500, query
    /// depth exceeds 6, subscription batch size exceeds 500, or snapshot
    /// entity count exceeds 10,000.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        max_query_results: u32,
        max_query_depth: u8,
        max_query_millis: u32,
        max_concurrent_queries: u16,
        max_subscription_batch: u16,
        max_snapshot_entities: u32,
        max_plugin_memory_bytes: u64,
        max_plugin_millis: u32,
    ) -> Result<Self, BudgetError> {
        // Zero never means "unlimited" or "disabled". Rejecting it here avoids
        // capability-specific interpretations that could weaken a host limit.
        for (value, field) in [
            (u64::from(max_query_results), "max query results"),
            (u64::from(max_query_depth), "max query depth"),
            (u64::from(max_query_millis), "max query millis"),
            (u64::from(max_concurrent_queries), "max concurrent queries"),
            (u64::from(max_subscription_batch), "max subscription batch"),
            (u64::from(max_snapshot_entities), "max snapshot entities"),
            (max_plugin_memory_bytes, "max plugin memory bytes"),
            (u64::from(max_plugin_millis), "max plugin millis"),
        ] {
            if value == 0 {
                return Err(BudgetError::Zero(field));
            }
        }

        // These ceilings are product safety invariants, not deployment
        // defaults. A deployment may lower them but cannot raise them through
        // this constructor.
        for (value, maximum, field) in [
            (u64::from(max_query_results), 500, "max query results"),
            (u64::from(max_query_depth), 6, "max query depth"),
            (
                u64::from(max_subscription_batch),
                500,
                "max subscription batch",
            ),
            (
                u64::from(max_snapshot_entities),
                10_000,
                "max snapshot entities",
            ),
        ] {
            if value > maximum {
                return Err(BudgetError::ExceedsMaximum(field));
            }
        }
        Ok(Self {
            max_query_results,
            max_query_depth,
            max_query_millis,
            max_concurrent_queries,
            max_subscription_batch,
            max_snapshot_entities,
            max_plugin_memory_bytes,
            max_plugin_millis,
        })
    }
}

/// Measured or requested resource consumption for one bounded operation set.
///
/// A usage value is inert until [`Self::validate`] compares every dimension to
/// a [`ResourceBudget`]. The type intentionally preserves zeros because an
/// operation may consume none of a particular resource.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ResourceUsage {
    /// Query matches produced or requested.
    pub query_results: u32,
    /// Required graph edges traversed or requested.
    pub query_depth: u8,
    /// Query wall-clock time consumed, in milliseconds.
    pub query_millis: u32,
    /// Peak concurrently executing query count.
    pub concurrent_queries: u16,
    /// Events included in the subscription page.
    pub subscription_batch: u16,
    /// Entities included in the snapshot operation.
    pub snapshot_entities: u32,
    /// Peak plugin linear-memory consumption, in bytes.
    pub plugin_memory_bytes: u64,
    /// Plugin wall-clock time consumed, in milliseconds.
    pub plugin_millis: u32,
}

impl ResourceUsage {
    /// Checks every usage dimension against the corresponding inclusive limit.
    ///
    /// Equality is permitted. The method returns the first over-budget field in
    /// declaration order, making the rejection deterministic. It does not
    /// revalidate a budget built with a struct literal; callers should construct
    /// budgets through [`ResourceBudget::new`].
    ///
    /// # Errors
    ///
    /// Returns [`BudgetError::UsageExceedsLimit`] naming the first dimension
    /// whose usage is greater than its configured limit.
    pub fn validate(&self, budget: &ResourceBudget) -> Result<(), BudgetError> {
        // Compare through one lossless width so fields with different integer
        // representations share identical inclusive-limit semantics.
        for (usage, limit, field) in [
            (
                u64::from(self.query_results),
                u64::from(budget.max_query_results),
                "query results",
            ),
            (
                u64::from(self.query_depth),
                u64::from(budget.max_query_depth),
                "query depth",
            ),
            (
                u64::from(self.query_millis),
                u64::from(budget.max_query_millis),
                "query millis",
            ),
            (
                u64::from(self.concurrent_queries),
                u64::from(budget.max_concurrent_queries),
                "concurrent queries",
            ),
            (
                u64::from(self.subscription_batch),
                u64::from(budget.max_subscription_batch),
                "subscription batch",
            ),
            (
                u64::from(self.snapshot_entities),
                u64::from(budget.max_snapshot_entities),
                "snapshot entities",
            ),
            (
                self.plugin_memory_bytes,
                budget.max_plugin_memory_bytes,
                "plugin memory bytes",
            ),
            (
                u64::from(self.plugin_millis),
                u64::from(budget.max_plugin_millis),
                "plugin millis",
            ),
        ] {
            if usage > limit {
                return Err(BudgetError::UsageExceedsLimit(field));
            }
        }
        Ok(())
    }
}
