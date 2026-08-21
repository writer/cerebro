use super::{
    cursor::{APPLICATION_CURSOR_PREFIX, MAX_APPLICATION_CURSOR_BYTES, MAX_PROVIDER_CURSOR_BYTES},
    response::application_identity,
    *,
};
use std::collections::BTreeMap;

const APPLICATION_RESPONSE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../sources/sentinelone/testdata/api/application/list_applications/response.json"
));

fn kernel(family: SentinelOneFamily) -> SentinelOneKernel {
    SentinelOneKernel::new(
        "https://sentinelone.example.test",
        family,
        SentinelOneFilters::default(),
        Some(2),
    )
    .unwrap()
}

#[test]
fn all_seven_families_plan_exact_provider_paths_and_auth_contract() {
    let cases = [
        (SentinelOneFamily::Activity, "/web/api/v2.1/activities"),
        (SentinelOneFamily::Agent, "/web/api/v2.1/agents"),
        (SentinelOneFamily::Application, "/web/api/v2.1/agents"),
        (SentinelOneFamily::Exclusion, "/web/api/v2.1/exclusions"),
        (SentinelOneFamily::Group, "/web/api/v2.1/groups"),
        (SentinelOneFamily::Site, "/web/api/v2.1/sites"),
        (SentinelOneFamily::Threat, "/web/api/v2.1/threats"),
    ];
    for (family, path) in cases {
        let request = kernel(family).plan(None).unwrap();
        assert_eq!(request.url().path(), path);
        assert_eq!(request.authorization_scheme(), "ApiToken");
        assert_eq!(request.accept(), "application/json");
    }
}

#[test]
fn family_filters_and_provider_cursor_are_bound_to_the_request() {
    let kernel = SentinelOneKernel::new(
        "https://sentinelone.example.test",
        SentinelOneFamily::Activity,
        SentinelOneFilters {
            site_id: Some("site-1".to_owned()),
            group_id: Some("group-1".to_owned()),
            since: Some("2026-04-01T00:00:00Z".to_owned()),
            until: Some("2026-04-30T00:00:00Z".to_owned()),
            activity_type: Some("27".to_owned()),
            ..SentinelOneFilters::default()
        },
        Some(50),
    )
    .unwrap();
    let request = kernel.plan(Some("provider-next")).unwrap();
    let query = request
        .url()
        .query_pairs()
        .into_owned()
        .collect::<BTreeMap<_, _>>();
    assert_eq!(query.get("limit").map(String::as_str), Some("50"));
    assert_eq!(
        query.get("cursor").map(String::as_str),
        Some("provider-next")
    );
    assert_eq!(query.get("siteIds").map(String::as_str), Some("site-1"));
    assert_eq!(query.get("groupIds").map(String::as_str), Some("group-1"));
    assert_eq!(query.get("activityTypes").map(String::as_str), Some("27"));
}

#[test]
fn exclusion_request_preserves_the_go_site_scope() {
    let kernel = SentinelOneKernel::new(
        "https://sentinelone.example.test",
        SentinelOneFamily::Exclusion,
        SentinelOneFilters {
            site_id: Some("site-1".to_owned()),
            ..SentinelOneFilters::default()
        },
        Some(25),
    )
    .unwrap();
    let request = kernel.plan(None).unwrap();
    let query = request
        .url()
        .query_pairs()
        .into_owned()
        .collect::<BTreeMap<_, _>>();
    assert_eq!(request.url().path(), "/web/api/v2.1/exclusions");
    assert_eq!(query.get("limit").map(String::as_str), Some("25"));
    assert_eq!(query.get("siteIds").map(String::as_str), Some("site-1"));
}

#[test]
fn decode_rejects_requests_from_kernels_with_different_filters_or_page_sizes() {
    let scoped = SentinelOneKernel::new(
        "https://sentinelone.example.test",
        SentinelOneFamily::Activity,
        SentinelOneFilters {
            site_id: Some("site-1".to_owned()),
            ..SentinelOneFilters::default()
        },
        Some(25),
    )
    .unwrap();
    let request = scoped.plan(None).unwrap();

    let wrong_filter = SentinelOneKernel::new(
        "https://sentinelone.example.test",
        SentinelOneFamily::Activity,
        SentinelOneFilters {
            site_id: Some("site-2".to_owned()),
            ..SentinelOneFilters::default()
        },
        Some(25),
    )
    .unwrap();
    assert!(matches!(
        wrong_filter.decode(&request, br#"{"data":[]}"#),
        Err(SentinelOneError::RequestScopeMismatch)
    ));

    let wrong_page_size = SentinelOneKernel::new(
        "https://sentinelone.example.test",
        SentinelOneFamily::Activity,
        SentinelOneFilters {
            site_id: Some("site-1".to_owned()),
            ..SentinelOneFilters::default()
        },
        Some(50),
    )
    .unwrap();
    assert!(matches!(
        wrong_page_size.decode(&request, br#"{"data":[]}"#),
        Err(SentinelOneError::RequestScopeMismatch)
    ));
}

#[test]
fn provider_cursors_are_bounded_on_plan_and_response() {
    let kernel = kernel(SentinelOneFamily::Threat);
    assert!(
        kernel
            .plan(Some(&"x".repeat(MAX_PROVIDER_CURSOR_BYTES)))
            .is_ok()
    );
    assert!(matches!(
        kernel.plan(Some(&"x".repeat(MAX_PROVIDER_CURSOR_BYTES + 1))),
        Err(SentinelOneError::InvalidCursor)
    ));
    assert!(matches!(
        kernel.plan(Some("provider\ncursor")),
        Err(SentinelOneError::InvalidCursor)
    ));

    let request = kernel.plan(None).unwrap();
    let oversized = serde_json::json!({
        "data": [],
        "pagination": {"nextCursor": "x".repeat(MAX_PROVIDER_CURSOR_BYTES + 1)}
    });
    assert!(matches!(
        kernel.decode(&request, &serde_json::to_vec(&oversized).unwrap()),
        Err(SentinelOneError::InvalidCursor)
    ));
    assert!(matches!(
        kernel.decode(
            &request,
            br#"{"data":[],"pagination":{"nextCursor":"bad\ncursor"}}"#
        ),
        Err(SentinelOneError::InvalidCursor)
    ));
}

#[test]
fn direct_family_decodes_flexible_data_envelope_and_cursor() {
    let kernel = kernel(SentinelOneFamily::Threat);
    let request = kernel.plan(None).unwrap();
    let outcome = kernel
            .decode(
                &request,
                br#"{"data":{"threats":[{"id":"threat-1","threatInfo":{"incidentStatus":"unresolved"}}],"pagination":{"nextCursor":"next-1"}}}"#,
            )
            .unwrap();
    let SentinelOneOutcome::Page(page) = outcome else {
        panic!("expected page")
    };
    assert_eq!(page.next_cursor.as_deref(), Some("next-1"));
    assert_eq!(page.records[0].provider_id, "threat-1");
    assert_eq!(page.records[0].provider_kind, "sentinelone.threat");
    assert_eq!(
        page.records[0]
            .fields
            .get("threatInfo.incidentStatus")
            .map(String::as_str),
        Some("unresolved")
    );
}

#[test]
fn genuine_application_response_preserves_agent_scoped_go_identity() {
    let kernel = SentinelOneKernel::new(
        "https://sentinelone.example.test",
        SentinelOneFamily::Application,
        SentinelOneFilters {
            agent_id: Some("agent-fixture-1".to_owned()),
            ..SentinelOneFilters::default()
        },
        Some(10),
    )
    .unwrap();
    let request = kernel.plan(None).unwrap();
    assert_eq!(request.url().path(), "/web/api/v2.1/agents/applications");
    assert_eq!(request.url().query(), Some("ids=agent-fixture-1"));
    let outcome = kernel.decode(&request, APPLICATION_RESPONSE).unwrap();
    let SentinelOneOutcome::Page(page) = outcome else {
        panic!("expected page")
    };
    assert_eq!(page.next_cursor, None);
    assert_eq!(page.records.len(), 1);
    assert_eq!(
        page.records[0].provider_id,
        "agent-fixture-1::p.RXhhbXBsZSBJbmM.n.RXhhbXBsZSBBcHA.v.MS4wLjA"
    );
    assert_eq!(
        page.records[0]
            .fields
            .get("application_id")
            .map(String::as_str),
        Some("p.RXhhbXBsZSBJbmM.n.RXhhbXBsZSBBcHA.v.MS4wLjA")
    );
}

#[test]
fn application_identity_does_not_alias_spacing_delimiters_or_empty_components() {
    let spaced = serde_json::json!({
        "publisher": "A B",
        "name": "App",
        "version": "1"
    });
    let underscored = serde_json::json!({
        "publisher": "A_B",
        "name": "App",
        "version": "1"
    });
    assert_ne!(
        application_identity(&spaced),
        application_identity(&underscored)
    );

    let publisher_delimiter = serde_json::json!({
        "publisher": "A::B",
        "name": "C",
        "version": ""
    });
    let name_delimiter = serde_json::json!({
        "publisher": "A",
        "name": "B::C"
    });
    assert_ne!(
        application_identity(&publisher_delimiter),
        application_identity(&name_delimiter)
    );

    let missing_publisher = serde_json::json!({"name": "App", "version": "1"});
    let missing_name = serde_json::json!({"publisher": "App", "version": "1"});
    assert_ne!(
        application_identity(&missing_publisher),
        application_identity(&missing_name)
    );
}

#[test]
fn application_fanout_resolves_agent_and_bounds_children_with_versioned_cursor() {
    let kernel = kernel(SentinelOneFamily::Application);
    let resolve = kernel.plan(Some("agents-next-0")).unwrap();
    assert_eq!(resolve.url().query(), Some("limit=1&cursor=agents-next-0"));
    let next = kernel
        .decode(
            &resolve,
            br#"{"data":[{"id":"agent-1"}],"pagination":{"nextCursor":"agents-next-1"}}"#,
        )
        .unwrap();
    let SentinelOneOutcome::Request(applications) = next else {
        panic!("expected application request")
    };
    assert_eq!(applications.url().query(), Some("ids=agent-1"));
    let first = kernel
            .decode(
                &applications,
                br#"{"data":[{"name":"Zulu","publisher":"P","version":"1"},{"name":"Alpha","publisher":"P","version":"1"},{"name":"Middle","publisher":"P","version":"1"}]}"#,
            )
            .unwrap();
    let SentinelOneOutcome::Page(first) = first else {
        panic!("expected first page")
    };
    assert_eq!(
        first
            .records
            .iter()
            .map(|record| record.provider_id.as_str())
            .collect::<Vec<_>>(),
        vec![
            "agent-1::p.UA.n.QWxwaGE.v.MQ",
            "agent-1::p.UA.n.TWlkZGxl.v.MQ"
        ]
    );
    let cursor = first.next_cursor.expect("versioned cursor");
    assert!(cursor.starts_with(APPLICATION_CURSOR_PREFIX));
    assert!(cursor.len() <= MAX_APPLICATION_CURSOR_BYTES);

    let resumed = kernel.plan(Some(&cursor)).unwrap();
    let second = kernel
            .decode(
                &resumed,
                br#"{"data":[{"name":"Zulu","publisher":"P","version":"1"},{"name":"Alpha","publisher":"P","version":"1"},{"name":"Middle","publisher":"P","version":"1"}]}"#,
            )
            .unwrap();
    let SentinelOneOutcome::Page(second) = second else {
        panic!("expected second page")
    };
    assert_eq!(second.records[0].provider_id, "agent-1::p.UA.n.WnVsdQ.v.MQ");
    assert_eq!(second.next_cursor.as_deref(), Some("agents-next-1"));
}

#[test]
fn kernel_fails_closed_on_unsafe_origins_filters_cursors_and_duplicate_apps() {
    assert!(matches!(
        SentinelOneKernel::new(
            "http://169.254.169.254",
            SentinelOneFamily::Agent,
            SentinelOneFilters::default(),
            None,
        ),
        Err(SentinelOneError::InvalidBaseUrl)
    ));
    assert!(matches!(
        SentinelOneKernel::new(
            "https://sentinelone.example.test",
            SentinelOneFamily::Site,
            SentinelOneFilters {
                since: Some("2026-04-01T00:00:00Z".to_owned()),
                ..SentinelOneFilters::default()
            },
            None,
        ),
        Err(SentinelOneError::UnsupportedTimeFilter)
    ));
    assert!(matches!(
        kernel(SentinelOneFamily::Application)
            .plan(Some("cerebro-sentinelone-application-v1:not-base64")),
        Err(SentinelOneError::InvalidCursor)
    ));
    let agent_request = kernel(SentinelOneFamily::Agent).plan(None).unwrap();
    assert!(matches!(
        kernel(SentinelOneFamily::Threat).decode(&agent_request, br#"{"data":[]}"#),
        Err(SentinelOneError::RequestScopeMismatch)
    ));

    let kernel = SentinelOneKernel::new(
        "https://sentinelone.example.test",
        SentinelOneFamily::Application,
        SentinelOneFilters {
            agent_id: Some("agent-1".to_owned()),
            ..SentinelOneFilters::default()
        },
        None,
    )
    .unwrap();
    let request = kernel.plan(None).unwrap();
    assert!(matches!(
            kernel.decode(
                &request,
                br#"{"data":[{"name":"App","publisher":"P","version":"1"},{"name":"App","publisher":"P","version":"1"}]}"#,
            ),
            Err(SentinelOneError::DuplicateApplicationIdentity)
        ));
}
