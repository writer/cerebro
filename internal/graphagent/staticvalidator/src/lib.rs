#![deny(unsafe_code)]

mod lexer;
mod policy;
mod syntax;
#[cfg(target_arch = "wasm32")]
mod wasm_abi;

pub const ABI_VERSION: u32 = 2;
pub const MAX_QUERY_BYTES: usize = 64 * 1024;

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Decision {
    Allow = 0,
    CypherRequired = 1,
    UnsafeClause = 2,
    UnsafeApoc = 3,
    ApocNotAllowed = 4,
    ProcedureCallNotAllowed = 5,
    VariableLengthRelationshipNotAllowed = 6,
    ExpansionNotAllowed = 7,
    LimitRequired = 8,
    LimitExceeded = 9,
    TenantScopeRequired = 10,
    QueryTooLarge = 11,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Validation {
    pub decision: Decision,
    pub limit: u64,
    pub detail: u64,
}

impl Validation {
    pub(crate) const fn allow(limit: u64) -> Self {
        Self {
            decision: Decision::Allow,
            limit,
            detail: 0,
        }
    }

    pub(crate) const fn refuse(decision: Decision) -> Self {
        Self {
            decision,
            limit: 0,
            detail: 0,
        }
    }

    pub(crate) const fn refuse_with_detail(decision: Decision, detail: u64) -> Self {
        Self {
            decision,
            limit: 0,
            detail,
        }
    }
}

pub use policy::validate;
