use std::path::PathBuf;

use cerebro_source_catalog::{
    AuthModel, CollectionAuthority, HttpMethod, Pagination, PathParameterBinding, SourceCatalog,
    UnsupportedReasonCode,
};

#[test]
fn mailchimp_compiles_the_provider_shapes_but_stays_unpromoted() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let catalog = SourceCatalog::load(
        root.join("internal/connectorcatalog/catalog"),
        root.join("sources"),
    )
    .expect("load source catalog");
    let source = catalog.get("mailchimp").expect("Mailchimp source");

    assert_eq!(source.authority(), CollectionAuthority::ShadowOnly);
    assert_eq!(source.auth(), &AuthModel::Basic);
    assert_eq!(source.token_header(), "Authorization");
    assert_eq!(source.token_scheme(), "Basic");
    for (family_id, path, selector) in [
        ("lists", "/lists", "$.lists[*]"),
        (
            "members",
            "/lists/${config.list_id}/members",
            "$.members[*]",
        ),
        (
            "audit_events",
            "/activity-feed/chimp-chatter",
            "$.chimp_chatter[*]",
        ),
    ] {
        let family = source
            .families()
            .iter()
            .find(|family| family.id() == family_id)
            .unwrap_or_else(|| panic!("Mailchimp {family_id} family"));
        assert_eq!(family.method(), HttpMethod::Get);
        assert_eq!(family.path(), path);
        assert_eq!(family.record_selector(), selector);
        assert_eq!(
            family.pagination(),
            &Pagination::Offset {
                parameter: "offset".to_owned(),
                limit_parameter: "count".to_owned(),
                page_size: 100,
            }
        );
        assert!(
            family
                .unsupported_reasons()
                .contains(&UnsupportedReasonCode::UnboundConfigAttribute),
            "Mailchimp {family_id} must stay shadow-only until authenticated tenant binding is compiled"
        );
    }

    let members = source
        .families()
        .iter()
        .find(|family| family.id() == "members")
        .expect("Mailchimp members family");
    assert_eq!(members.id_field(), "id|email_address");
    assert_eq!(
        members.path_parameters().get("list_id"),
        Some(&PathParameterBinding::ScalarConfig {
            field: "list_id".to_owned(),
        })
    );

    let readiness = catalog.authority_readiness_report();
    for family_id in ["lists", "members", "audit_events"] {
        let row = readiness
            .families
            .iter()
            .find(|row| row.source_id == "mailchimp" && row.family_id == family_id)
            .unwrap_or_else(|| panic!("Mailchimp {family_id} readiness row"));
        assert_eq!(row.engine, "go_or_shadow_only");
        assert_eq!(row.authority_epoch, 0);
        assert!(
            row.blocking_reasons
                .contains(&"promotion_receipt".to_owned())
        );
    }
}
