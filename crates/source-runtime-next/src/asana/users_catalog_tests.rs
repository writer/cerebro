use std::path::Path;

use cerebro_source_catalog::{AuthModel, HttpMethod, Pagination, SourceCatalog};

use crate::source_execution::SourceExecutionError;

use super::{AsanaError, AsanaFamily, AsanaKernel, users_test_support as support};

#[test]
fn asana_users_catalog_and_runtime_config_are_exact() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let catalog = SourceCatalog::load(
        root.join("internal/connectorcatalog/catalog"),
        root.join("sources"),
    )
    .expect("compiled source catalog");
    let source = catalog.get("asana").expect("compiled Asana source");
    assert_eq!(source.auth(), &AuthModel::BearerToken);
    assert_eq!(source.token_header(), "Authorization");
    assert_eq!(source.token_scheme(), "Bearer");
    let users = source
        .families()
        .iter()
        .find(|family| family.id() == "users")
        .expect("compiled asana.users family");
    assert_eq!(users.method(), HttpMethod::Get);
    assert_eq!(users.path(), "/users");
    assert_eq!(users.record_selector(), "$.data[*]");
    assert_eq!(users.id_field(), "gid");
    assert_eq!(users.projection().template(), "identity_user");
    assert_eq!(
        users.pagination(),
        &Pagination::Cursor {
            parameter: "offset".to_owned(),
            response_path: "$.next_page.offset".to_owned(),
            page_size_parameter: Some("limit".to_owned()),
            page_size: 100,
        }
    );

    assert!(matches!(
        AsanaKernel::new(
            "https://app.asana.com/api/1.0",
            "tenant-a",
            "workspace-1",
            AsanaFamily::Users,
            Some(0),
        ),
        Err(AsanaError::InvalidConfiguration("page_size"))
    ));
    assert!(matches!(
        AsanaKernel::new(
            "https://127.0.0.1",
            "tenant-a",
            "workspace-1",
            AsanaFamily::Users,
            Some(2),
        ),
        Err(AsanaError::UnsafeOrigin)
    ));

    let plan = support::plan();
    let context = support::context("tenant-a", "", 1);
    let mut missing_workspace = support::metadata();
    missing_workspace.public_config.remove("workspace_gid");
    assert_eq!(
        support::plan_page(&plan, &context, &missing_workspace),
        Err(SourceExecutionError::MissingConfiguration)
    );
    let mut invalid_page_size = support::metadata();
    invalid_page_size
        .public_config
        .insert("page_size".to_owned(), "101".to_owned());
    assert_eq!(
        support::plan_page(&plan, &context, &invalid_page_size),
        Err(SourceExecutionError::MissingConfiguration)
    );
}
