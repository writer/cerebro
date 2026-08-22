use std::str::FromStr;

use super::DeepSeekError;

/// Closed DeepSeek catalog family vocabulary.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DeepSeekFamily {
    /// Available provider models.
    ModelCatalog,
    /// Account balance by currency.
    AccountBalances,
}

impl DeepSeekFamily {
    /// Every supported family in catalog order.
    pub const ALL: [Self; 2] = [Self::AccountBalances, Self::ModelCatalog];

    /// Exact catalog family identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ModelCatalog => "model_catalog",
            Self::AccountBalances => "account_balances",
        }
    }

    /// Exact provider operation path.
    pub const fn path(self) -> &'static str {
        match self {
            Self::ModelCatalog => "/models",
            Self::AccountBalances => "/user/balance",
        }
    }

    /// Exact response record selector.
    pub const fn record_selector(self) -> &'static str {
        match self {
            Self::ModelCatalog => "$.data[*]",
            Self::AccountBalances => "$.balance_infos[*]",
        }
    }

    /// Exact top-level response array key.
    pub const fn list_key(self) -> &'static str {
        match self {
            Self::ModelCatalog => "data",
            Self::AccountBalances => "balance_infos",
        }
    }

    /// Stable provider identity field.
    pub const fn identity_field(self) -> &'static str {
        match self {
            Self::ModelCatalog => "id",
            Self::AccountBalances => "currency",
        }
    }

    /// Exact event kind admitted by the catalog.
    pub const fn event_kind(self) -> &'static str {
        match self {
            Self::ModelCatalog => "deepseek.model_catalog",
            Self::AccountBalances => "deepseek.account_balances",
        }
    }

    /// Exact event schema admitted by the catalog.
    pub const fn schema_ref(self) -> &'static str {
        match self {
            Self::ModelCatalog => "deepseek/model_catalog/v1",
            Self::AccountBalances => "deepseek/account_balances/v1",
        }
    }

    pub(super) const fn urn_kind(self) -> &'static str {
        match self {
            Self::ModelCatalog => "deepseek_model_catalog",
            Self::AccountBalances => "deepseek_account_balances",
        }
    }
}

impl FromStr for DeepSeekFamily {
    type Err = DeepSeekError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|family| family.as_str() == value.trim())
            .ok_or(DeepSeekError::InvalidFamily)
    }
}
