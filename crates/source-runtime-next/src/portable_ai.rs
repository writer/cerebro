//! Credential-free execution for catalog-defined AI provider families.

mod adapter;
mod catalog;
mod langfuse;
mod normalize;
mod pagination;

pub(crate) use adapter::PORTABLE_AI_SOURCE_EXECUTION_ADAPTERS;

#[cfg(test)]
mod tests;
