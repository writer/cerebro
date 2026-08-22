use super::*;
use std::collections::HashMap;

#[test]
fn public_runtime_metadata_consumes_all_group_aliases_without_credentials() {
    let public_config = HashMap::from([
        (
            "group_ids".to_owned(),
            "group-1, group-2, group-1".to_owned(),
        ),
        ("user_group_ids".to_owned(), "group-3".to_owned()),
        ("group_id".to_owned(), "group-4".to_owned()),
        ("user_group_id".to_owned(), "group-5".to_owned()),
    ]);
    let kernel = JumpCloudKernel::new(
        "https://console.jumpcloud.com/api",
        "https://api.jumpcloud.com/insights/directory/v1",
        "tenant",
        JumpCloudFamily::GroupMembers,
        JumpCloudFilters::default().with_group_member_public_config(&public_config),
        Some(2),
        "2026-06-01T00:00:00Z",
    )
    .unwrap();
    assert_eq!(
        kernel.filters.group_ids,
        ["group-1", "group-2", "group-3", "group-4", "group-5"]
    );

    let adapter = adapter::JUMPCLOUD_SOURCE_EXECUTION_ADAPTERS[5];
    let check = adapter.plan_check(&kernel).unwrap();
    assert_eq!(check.group_id(), Some("group-1"));
    assert!(!check.contains_credentials());

    let terminal_first_group = adapter
        .decode(
            &kernel,
            &check,
            200,
            &JumpCloudResponseMetadata::default(),
            br#"[]"#,
        )
        .unwrap();
    let second_group = adapter
        .plan_discover(&kernel, terminal_first_group.next_cursor.as_deref())
        .unwrap();
    assert_eq!(second_group.group_id(), Some("group-2"));
    assert!(!second_group.contains_credentials());
}

#[test]
fn aliases_are_ordered_deduplicated_bounded_and_path_safe() {
    let filters = JumpCloudFilters::default().with_group_member_config(
        Some(" group/a , group-b,group/a"),
        Some("group-c,group-b"),
        Some("group-d"),
        Some("group-e"),
    );
    let fanout = JumpCloudKernel::new(
        "https://console.jumpcloud.com/api",
        "https://api.jumpcloud.com/insights/directory/v1",
        "tenant",
        JumpCloudFamily::GroupMembers,
        filters,
        Some(2),
        "2026-06-01T00:00:00Z",
    )
    .unwrap();
    assert_eq!(
        fanout.filters.group_ids,
        ["group/a", "group-b", "group-c", "group-d", "group-e"]
    );
    let request = fanout.plan(None).unwrap();
    assert_eq!(request.group_id(), Some("group/a"));
    assert!(
        request
            .url()
            .as_str()
            .contains("/usergroups/group%2Fa/members")
    );

    let too_many = (0..=cursor::MAX_GROUP_FANOUT)
        .map(|index| format!("group-{index}"))
        .collect::<Vec<_>>();
    assert!(matches!(
        JumpCloudKernel::new(
            "https://console.jumpcloud.com/api",
            "https://api.jumpcloud.com/insights/directory/v1",
            "tenant",
            JumpCloudFamily::GroupMembers,
            JumpCloudFilters {
                group_ids: too_many,
                ..JumpCloudFilters::default()
            },
            Some(2),
            "2026-06-01T00:00:00Z",
        ),
        Err(JumpCloudError::InvalidConfiguration("group_ids"))
    ));
}

#[test]
fn check_and_discover_match_go_fanout_restart_contract() {
    let fanout = JumpCloudKernel::new(
        "https://console.jumpcloud.com/api",
        "https://api.jumpcloud.com/insights/directory/v1",
        "tenant",
        JumpCloudFamily::GroupMembers,
        JumpCloudFilters::default().with_group_member_config(
            Some("group-1, group-2, group-1"),
            Some("group-3"),
            None,
            None,
        ),
        Some(2),
        "2026-06-01T00:00:00Z",
    )
    .unwrap();
    let adapter = adapter::JUMPCLOUD_SOURCE_EXECUTION_ADAPTERS[5];

    let check = adapter.plan_check(&fanout).unwrap();
    assert_eq!(check.group_id(), Some("group-1"));
    assert_eq!(check.url().path(), "/api/v2/usergroups/group-1/members");
    assert_eq!(
        check
            .url()
            .query_pairs()
            .find(|(key, _)| key == "skip")
            .unwrap()
            .1,
        "0"
    );

    let mut discovery = adapter::JumpCloudGroupMemberDiscovery::default();
    let first = adapter
        .decode(
            &fanout,
            &check,
            200,
            &JumpCloudResponseMetadata::default(),
            br#"[{"to":{"id":"user-1","type":"user"}},{"to":{"id":"user-2","type":"user"}}]"#,
        )
        .unwrap();
    discovery.admit_page(adapter, &first).unwrap();
    assert_eq!(
        first.next_cursor.as_deref(),
        Some(
            r#"{"version":1,"source":"jumpcloud","mode":"fanout_path_param","token":"{\"index\":0,\"cursor\":\"2\"}"}"#
        )
    );

    let second_request = adapter
        .plan_discover(&fanout, first.next_cursor.as_deref())
        .unwrap();
    assert_eq!(second_request.group_id(), Some("group-1"));
    assert_eq!(
        second_request
            .url()
            .query_pairs()
            .find(|(key, _)| key == "skip")
            .unwrap()
            .1,
        "2"
    );
    let second = adapter
        .decode(
            &fanout,
            &second_request,
            200,
            &JumpCloudResponseMetadata::default(),
            br#"[{"to":{"id":"user-3","type":"user"}}]"#,
        )
        .unwrap();
    discovery.admit_page(adapter, &second).unwrap();
    assert_eq!(
        second.next_cursor.as_deref(),
        Some(
            r#"{"version":1,"source":"jumpcloud","mode":"fanout_path_param","token":"{\"index\":1}"}"#
        )
    );

    let third_request = adapter
        .plan_discover(&fanout, second.next_cursor.as_deref())
        .unwrap();
    assert_eq!(third_request.group_id(), Some("group-2"));
    let third = adapter
        .decode(
            &fanout,
            &third_request,
            200,
            &JumpCloudResponseMetadata::default(),
            br#"[]"#,
        )
        .unwrap();
    discovery.admit_page(adapter, &third).unwrap();
    assert_eq!(
        third.next_cursor.as_deref(),
        Some(
            r#"{"version":1,"source":"jumpcloud","mode":"fanout_path_param","token":"{\"index\":2}"}"#
        )
    );

    let fourth_request = adapter
        .plan_discover(&fanout, third.next_cursor.as_deref())
        .unwrap();
    assert_eq!(fourth_request.group_id(), Some("group-3"));
    let fourth = adapter
        .decode(
            &fanout,
            &fourth_request,
            200,
            &JumpCloudResponseMetadata::default(),
            br#"[{"to":{"id":"user-4","type":"user"}}]"#,
        )
        .unwrap();
    discovery.admit_page(adapter, &fourth).unwrap();
    assert_eq!(fourth.next_cursor, None);
    assert_eq!(discovery.urns().len(), 4);
    assert_eq!(
        discovery.urns()[0],
        "urn:cerebro:tenant:jumpcloud_group_members:id-3136bc9e0fb2e9df9ed3b7b56fd78448"
    );

    assert!(matches!(
        fanout.plan(Some(
            r#"{"version":1,"source":"other","mode":"fanout_path_param","token":"{\"index\":0}"}"#
        )),
        Err(JumpCloudError::InvalidCursor)
    ));
    assert!(matches!(
        fanout.plan(Some(
            r#"{"version":1,"source":"jumpcloud","mode":"fanout_path_param","token":"{\"index\":3}"}"#
        )),
        Err(JumpCloudError::InvalidCursor)
    ));
    let legacy = fanout.plan(Some("2")).unwrap();
    assert_eq!(legacy.group_id(), Some("group-1"));
}
