use std::path::PathBuf;

use cerebro_source_catalog::{PathParameterBinding, SourceCatalog};

#[test]
fn group_membership_binds_the_provider_group_path_parameter() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let catalog = SourceCatalog::load(
        root.join("internal/connectorcatalog/catalog"),
        root.join("sources"),
    )
    .expect("load source catalog");
    let family = catalog
        .get("okta")
        .expect("Okta source")
        .families()
        .iter()
        .find(|family| family.id() == "group_membership")
        .expect("Okta group_membership family");

    assert_eq!(family.path(), "/api/v1/groups/{group_id}/users");
    assert_eq!(
        family.path_parameters().get("group_id"),
        Some(&PathParameterBinding::ScalarConfig {
            field: "group_id".to_owned(),
        })
    );
}
