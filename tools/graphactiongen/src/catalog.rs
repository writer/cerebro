use cerebro_action_catalog::ActionDefinition;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};

use crate::{CatalogError, Result};

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionCatalog {
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub actions: Vec<ActionCatalogEntry>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionCatalogEntry {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub const_name: String,
    #[serde(default)]
    pub provider: String,
    #[serde(default)]
    pub provider_const: String,
    #[serde(default)]
    pub provider_action: String,
    #[serde(default)]
    pub provider_action_const: String,
    #[serde(default)]
    pub target_kind: String,
    #[serde(default)]
    pub target_kind_const: String,
    #[serde(default)]
    pub target_resolver: String,
    #[serde(default)]
    pub eligibility_checker: String,
    #[serde(default)]
    pub effect: String,
    #[serde(default)]
    pub destructive: bool,
    #[serde(default)]
    pub reversible_by: String,
}

pub fn validate_catalog(catalog: &ActionCatalog) -> Result<()> {
    if catalog.version.trim() != "graph-actions.cerebro/v1alpha1" {
        return Err(CatalogError::UnsupportedVersion(catalog.version.clone()).into());
    }
    if catalog.actions.is_empty() {
        return Err(CatalogError::NoActions.into());
    }

    let mut ids = HashSet::new();
    let mut const_names = HashSet::new();
    let mut provider_const_values = HashMap::<&str, &str>::new();
    let mut provider_action_const_values = HashMap::<&str, &str>::new();
    let mut target_kind_const_values = HashMap::<&str, &str>::new();

    for (index, action) in catalog.actions.iter().enumerate() {
        validate_action(index, action)?;
        if !ids.insert(action.id.as_str()) {
            return Err(CatalogError::DuplicateActionId(action.id.clone()).into());
        }
        if !const_names.insert(action.const_name.as_str()) {
            return Err(CatalogError::DuplicateConstName(action.const_name.clone()).into());
        }
        insert_consistent(
            &mut provider_const_values,
            action.provider_const.as_str(),
            action.provider.as_str(),
            &action.id,
            "provider_const",
        )?;
        insert_consistent(
            &mut provider_action_const_values,
            action.provider_action_const.as_str(),
            action.provider_action.as_str(),
            &action.id,
            "provider_action_const",
        )?;
        insert_consistent(
            &mut target_kind_const_values,
            action.target_kind_const.as_str(),
            action.target_kind.as_str(),
            &action.id,
            "target_kind_const",
        )?;
    }

    for action in &catalog.actions {
        if !action.reversible_by.is_empty() && !ids.contains(action.reversible_by.as_str()) {
            return Err(CatalogError::UnknownReversibleAction {
                action_id: action.id.clone(),
                reversible_by: action.reversible_by.clone(),
            }
            .into());
        }
    }
    Ok(())
}

pub fn definition_digest(action: &ActionCatalogEntry) -> Result<String> {
    ActionDefinition {
        id: &action.id,
        provider: &action.provider,
        provider_action: &action.provider_action,
        target_kind: &action.target_kind,
        effect: &action.effect,
        destructive: action.destructive,
        reversible_by: &action.reversible_by,
        definition_digest: "",
    }
    .computed_digest()
    .map_err(crate::Error::Json)
}

fn insert_consistent<'a>(
    values: &mut HashMap<&'a str, &'a str>,
    constant: &'a str,
    value: &'a str,
    action_id: &str,
    field: &'static str,
) -> Result<()> {
    if let Some(prior) = values.get(constant)
        && *prior != value
    {
        return Err(CatalogError::ConflictingConstant {
            action_id: action_id.to_owned(),
            field,
            constant: constant.to_owned(),
            prior: (*prior).to_owned(),
            value: value.to_owned(),
        }
        .into());
    }
    values.insert(constant, value);
    Ok(())
}

fn validate_action(index: usize, action: &ActionCatalogEntry) -> Result<()> {
    let required = [
        ("id", action.id.as_str()),
        ("const_name", action.const_name.as_str()),
        ("provider", action.provider.as_str()),
        ("provider_const", action.provider_const.as_str()),
        ("provider_action", action.provider_action.as_str()),
        (
            "provider_action_const",
            action.provider_action_const.as_str(),
        ),
        ("target_kind", action.target_kind.as_str()),
        ("target_kind_const", action.target_kind_const.as_str()),
        ("target_resolver", action.target_resolver.as_str()),
        ("eligibility_checker", action.eligibility_checker.as_str()),
        ("effect", action.effect.as_str()),
    ];
    for (field, value) in required {
        if value.trim().is_empty() {
            return Err(CatalogError::RequiredField { index, field }.into());
        }
    }

    let identifiers = [
        ("const_name", action.const_name.as_str()),
        ("provider_const", action.provider_const.as_str()),
        (
            "provider_action_const",
            action.provider_action_const.as_str(),
        ),
        ("target_kind_const", action.target_kind_const.as_str()),
        ("target_resolver", action.target_resolver.as_str()),
        ("eligibility_checker", action.eligibility_checker.as_str()),
    ];
    for (field, value) in identifiers {
        if !is_go_identifier(value) {
            return Err(CatalogError::InvalidGoIdentifier {
                index,
                field,
                value: value.to_owned(),
            }
            .into());
        }
    }
    Ok(())
}

fn is_go_identifier(value: &str) -> bool {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    (first == b'_' || first.is_ascii_alphabetic())
        && bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
}
