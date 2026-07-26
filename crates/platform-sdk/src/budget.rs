use serde::Serialize;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BudgetError {
    Zero(&'static str),
    UsageExceedsLimit(&'static str),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ResourceBudget {
    pub max_query_results: u32,
    pub max_query_depth: u8,
    pub max_query_millis: u32,
    pub max_concurrent_queries: u16,
    pub max_subscription_batch: u16,
    pub max_snapshot_entities: u32,
    pub max_plugin_memory_bytes: u64,
    pub max_plugin_millis: u32,
}

impl ResourceBudget {
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ResourceUsage {
    pub query_results: u32,
    pub query_depth: u8,
    pub query_millis: u32,
    pub concurrent_queries: u16,
    pub subscription_batch: u16,
    pub snapshot_entities: u32,
    pub plugin_memory_bytes: u64,
    pub plugin_millis: u32,
}

impl ResourceUsage {
    pub fn validate(&self, budget: &ResourceBudget) -> Result<(), BudgetError> {
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
