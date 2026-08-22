use super::*;

#[test]
fn knowledge_uses_repository_fallbacks_and_go_query_escape_identity() {
    let kernel = kernel(ArchetypeFamily::Vulnerability);
    let scan = scan(&kernel);
    let repository = ArchetypeRepository {
        id: 7,
        owner: "WriterInternal".to_owned(),
        name: "Archetype".to_owned(),
    };
    let request = kernel.plan_knowledge(scan.repository_id).unwrap();
    let records = kernel
            .decode_knowledge(
                &request,
                br#"{"entries":[{"slug":"security:sql/injection","title":"SQL injection","summary":"context","topics":[" security ","sql"],"source_files":["state.json"],"metadata":{"context_pack":"repository_context_pack_v2","health_score":72,"context_stale":true}}]}"#,
                &scan,
                Some(&repository),
                OBSERVED_AT,
            )
            .unwrap();
    assert_eq!(
        records[0].provider_id,
        "archetype-library-7-security%3Asql%2Finjection"
    );
    assert_eq!(records[0].family, "vulnerability");
    assert_eq!(records[0].provider_kind, "archetype.library_note");
    assert_eq!(
        records[0].fields.get("knowledge_slug").map(String::as_str),
        Some("security:sql/injection")
    );
    assert_eq!(
        records[0].fields.get("owner").map(String::as_str),
        Some("WriterInternal")
    );
    assert_eq!(
        records[0].fields.get("topics").map(String::as_str),
        Some(" security ,sql")
    );
    assert_eq!(
        records[0].fields.get("health_score").map(String::as_str),
        Some("72")
    );
    assert_eq!(
        records[0].fields.get("context_stale").map(String::as_str),
        Some("true")
    );
    assert_eq!(records[0].payload["slug"], "security:sql/injection");
    assert_eq!(records[0].payload["title"], "SQL injection");
    assert_eq!(records[0].payload["summary"], "context");
    assert_eq!(records[0].payload["repository_id"], 7);
}

#[test]
fn knowledge_rejects_repository_and_entry_scope_mismatches() {
    let kernel = kernel(ArchetypeFamily::Vulnerability);
    let scan = scan(&kernel);
    let request = kernel.plan_knowledge(scan.repository_id).unwrap();
    let wrong_repository = ArchetypeRepository {
        id: 999,
        owner: "Other".to_owned(),
        name: "Repository".to_owned(),
    };
    assert_eq!(
        kernel
            .decode_knowledge(
                &request,
                br#"{"entries":[]}"#,
                &scan,
                Some(&wrong_repository),
                OBSERVED_AT,
            )
            .unwrap_err(),
        ArchetypeError::ResponseScopeMismatch
    );

    assert_eq!(
        kernel
            .decode_knowledge(
                &request,
                br#"{"entries":[{"slug":"scope-mismatch","repository_id":999,"owner":"Other","repository_name":"Repository"}]}"#,
                &scan,
                None,
                OBSERVED_AT,
            )
            .unwrap_err(),
        ArchetypeError::ResponseScopeMismatch
    );
}
