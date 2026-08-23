use std::str::FromStr;

use super::{AkeneoError, types::AkeneoScope};

/// Closed Akeneo catalog family vocabulary.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AkeneoFamily {
    /// Assets.
    Asset,
    /// One asset-family attribute.
    AssetFamiliesAttribute,
    /// Asset families.
    AssetFamily,
    /// Asset-family attributes.
    Attribute,
    /// Attribute groups.
    AttributeGroup,
    /// Reference-entity attribute options.
    AttributesOption,
    /// Product-model drafts.
    Draft,
    /// Asset-family attribute options.
    Option,
    /// Product drafts addressed by code.
    ProductsDraft,
    /// Product drafts addressed by UUID.
    ProductsUuidDraft,
    /// Reference-entity attributes.
    ReferenceEntitiesAttribute,
    /// One standard attribute.
    V1Attribute,
}

impl AkeneoFamily {
    /// Every provider-declared family in catalog order.
    pub const ALL: [Self; 12] = [
        Self::Asset,
        Self::AssetFamiliesAttribute,
        Self::AssetFamily,
        Self::Attribute,
        Self::AttributeGroup,
        Self::AttributesOption,
        Self::Draft,
        Self::Option,
        Self::ProductsDraft,
        Self::ProductsUuidDraft,
        Self::ReferenceEntitiesAttribute,
        Self::V1Attribute,
    ];

    /// Exact catalog identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Asset => "asset",
            Self::AssetFamiliesAttribute => "asset_families_attribute",
            Self::AssetFamily => "asset_family",
            Self::Attribute => "attribute",
            Self::AttributeGroup => "attribute_group",
            Self::AttributesOption => "attributes_option",
            Self::Draft => "draft",
            Self::Option => "option",
            Self::ProductsDraft => "products_draft",
            Self::ProductsUuidDraft => "products_uuid_draft",
            Self::ReferenceEntitiesAttribute => "reference_entities_attribute",
            Self::V1Attribute => "v1_attribute",
        }
    }

    /// Concrete provider path for validated public scope.
    pub fn path(self, scope: &AkeneoScope) -> Result<String, AkeneoError> {
        Ok(match self {
            Self::Asset => format!("/api/rest/v1/assets/{}", scope.code()?),
            Self::AssetFamiliesAttribute => format!(
                "/api/rest/v1/asset-families/{}/attributes/{}",
                scope.asset_family_code()?,
                scope.code()?
            ),
            Self::AssetFamily => format!("/api/rest/v1/asset-families/{}", scope.code()?),
            Self::Attribute => format!(
                "/api/rest/v1/asset-families/{}/attributes",
                scope.asset_family_code()?
            ),
            Self::AttributeGroup => format!("/api/rest/v1/attribute-groups/{}", scope.code()?),
            Self::AttributesOption => format!(
                "/api/rest/v1/reference-entities/{}/attributes/{}/options",
                scope.reference_entity_code()?,
                scope.attribute_code()?
            ),
            Self::Draft => format!("/api/rest/v1/product-models/{}/draft", scope.code()?),
            Self::Option => format!(
                "/api/rest/v1/asset-families/{}/attributes/{}/options",
                scope.asset_family_code()?,
                scope.attribute_code()?
            ),
            Self::ProductsDraft => format!("/api/rest/v1/products/{}/draft", scope.code()?),
            Self::ProductsUuidDraft => {
                format!("/api/rest/v1/products-uuid/{}/draft", scope.uuid()?)
            }
            Self::ReferenceEntitiesAttribute => format!(
                "/api/rest/v1/reference-entities/{}/attributes",
                scope.reference_entity_code()?
            ),
            Self::V1Attribute => format!("/api/rest/v1/attributes/{}", scope.code()?),
        })
    }

    /// Catalog path template retained in parity attributes.
    pub const fn path_template(self) -> &'static str {
        match self {
            Self::Asset => "/api/rest/v1/assets/${config.code}",
            Self::AssetFamiliesAttribute => {
                "/api/rest/v1/asset-families/${config.asset_family_code}/attributes/${config.code}"
            }
            Self::AssetFamily => "/api/rest/v1/asset-families/${config.code}",
            Self::Attribute => "/api/rest/v1/asset-families/${config.asset_family_code}/attributes",
            Self::AttributeGroup => "/api/rest/v1/attribute-groups/${config.code}",
            Self::AttributesOption => {
                "/api/rest/v1/reference-entities/${config.reference_entity_code}/attributes/${config.attribute_code}/options"
            }
            Self::Draft => "/api/rest/v1/product-models/${config.code}/draft",
            Self::Option => {
                "/api/rest/v1/asset-families/${config.asset_family_code}/attributes/${config.attribute_code}/options"
            }
            Self::ProductsDraft => "/api/rest/v1/products/${config.code}/draft",
            Self::ProductsUuidDraft => "/api/rest/v1/products-uuid/${config.uuid}/draft",
            Self::ReferenceEntitiesAttribute => {
                "/api/rest/v1/reference-entities/${config.reference_entity_code}/attributes"
            }
            Self::V1Attribute => "/api/rest/v1/attributes/${config.code}",
        }
    }

    /// Whether the endpoint returns a record collection.
    pub const fn collection(self) -> bool {
        matches!(
            self,
            Self::Attribute
                | Self::AttributesOption
                | Self::Option
                | Self::ReferenceEntitiesAttribute
        )
    }

    /// Exact event kind.
    pub const fn event_kind(self) -> &'static str {
        match self {
            Self::Asset => "akeneo.asset",
            Self::AssetFamiliesAttribute => "akeneo.asset_families_attribute",
            Self::AssetFamily => "akeneo.asset_family",
            Self::Attribute => "akeneo.attribute",
            Self::AttributeGroup => "akeneo.attribute_group",
            Self::AttributesOption => "akeneo.attributes_option",
            Self::Draft => "akeneo.draft",
            Self::Option => "akeneo.option",
            Self::ProductsDraft => "akeneo.products_draft",
            Self::ProductsUuidDraft => "akeneo.products_uuid_draft",
            Self::ReferenceEntitiesAttribute => "akeneo.reference_entities_attribute",
            Self::V1Attribute => "akeneo.v1_attribute",
        }
    }

    /// Exact schema reference.
    pub const fn schema_ref(self) -> &'static str {
        match self {
            Self::Asset => "akeneo/asset/v1",
            Self::AssetFamiliesAttribute => "akeneo/asset_families_attribute/v1",
            Self::AssetFamily => "akeneo/asset_family/v1",
            Self::Attribute => "akeneo/attribute/v1",
            Self::AttributeGroup => "akeneo/attribute_group/v1",
            Self::AttributesOption => "akeneo/attributes_option/v1",
            Self::Draft => "akeneo/draft/v1",
            Self::Option => "akeneo/option/v1",
            Self::ProductsDraft => "akeneo/products_draft/v1",
            Self::ProductsUuidDraft => "akeneo/products_uuid_draft/v1",
            Self::ReferenceEntitiesAttribute => "akeneo/reference_entities_attribute/v1",
            Self::V1Attribute => "akeneo/v1_attribute/v1",
        }
    }

    pub(super) const fn record_selector(self) -> &'static str {
        match self {
            Self::Asset | Self::Draft | Self::ProductsDraft | Self::ProductsUuidDraft => {
                "$.categories[*]"
            }
            Self::AssetFamiliesAttribute | Self::V1Attribute => "$.allowed_extensions[*]",
            Self::AssetFamily => "$.product_link_rules[*]",
            Self::AttributeGroup => "$.attributes[*]",
            Self::Attribute
            | Self::AttributesOption
            | Self::Option
            | Self::ReferenceEntitiesAttribute => "$[*]",
        }
    }

    pub(super) const fn resource_type(self) -> &'static str {
        match self {
            Self::Asset => "asset",
            Self::AssetFamily => "asset_family",
            Self::Attribute
            | Self::AssetFamiliesAttribute
            | Self::ReferenceEntitiesAttribute
            | Self::V1Attribute => "attribute",
            Self::AttributeGroup => "attribute_group",
            Self::AttributesOption | Self::Option => "option",
            Self::Draft | Self::ProductsDraft | Self::ProductsUuidDraft => "draft",
        }
    }

    pub(super) const fn copies_name_attribute(self) -> bool {
        matches!(
            self,
            Self::AssetFamily
                | Self::Attribute
                | Self::AttributesOption
                | Self::Option
                | Self::ReferenceEntitiesAttribute
        )
    }

    pub(super) const fn required_attributes(self) -> &'static [&'static str] {
        if matches!(self, Self::AttributeGroup) {
            &["tenant_id", "source_event_id", "group_id"]
        } else {
            &[
                "tenant_id",
                "source_event_id",
                "resource_urn",
                "resource_type",
                "resource_id",
            ]
        }
    }

    pub(super) const fn required_payload_fields(self) -> &'static [&'static str] {
        match self {
            Self::Attribute | Self::ReferenceEntitiesAttribute => &["allowed_extensions"],
            Self::Option | Self::AttributesOption => &["code"],
            Self::AssetFamily => &["assign_assets_to"],
            _ => &["id"],
        }
    }
}

impl FromStr for AkeneoFamily {
    type Err = AkeneoError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|family| family.as_str() == value.trim())
            .ok_or(AkeneoError::InvalidFamily)
    }
}
