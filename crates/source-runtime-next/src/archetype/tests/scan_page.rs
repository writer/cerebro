use super::*;
use crate::archetype::request::SCAN_PAGE_LIMIT;

#[test]
fn scan_page_is_ascending_and_emits_go_compatible_record() {
    let kernel = kernel(ArchetypeFamily::Vulnerability);
    let request = kernel.plan_scans(None).unwrap();
    let page = kernel
            .decode_scans(
                &request,
                br#"[
                  {"id":9,"repository_id":7,"status":"completed","completed_at":"2026-08-20T01:02:03Z"},
                  {"id":8,"repository_id":7,"status":"running","started_at":"2026-08-20T01:01:00Z"}
                ]"#,
            )
            .unwrap();
    assert_eq!(
        page.scans.iter().map(|scan| scan.id).collect::<Vec<_>>(),
        [8, 9]
    );
    assert_eq!(page.next_before_id, None);
    let repository = ArchetypeRepository {
        id: 7,
        owner: "WriterInternal".to_owned(),
        name: "Archetype".to_owned(),
    };
    let record = kernel
        .scan_record(
            &page.scans[1],
            Some(&repository),
            VulnerabilityCollectionState::Complete,
        )
        .unwrap();
    assert_eq!(record.family, "vulnerability");
    assert_eq!(record.provider_kind, "archetype.scan");
    assert_eq!(record.provider_id, "archetype-scan-9");
    assert_eq!(record.occurred_at.as_deref(), Some("2026-08-20T01:02:03Z"));
    assert_eq!(
        record.fields.get("owner").map(String::as_str),
        Some("WriterInternal")
    );
    assert_eq!(
        record
            .fields
            .get("vulnerability_collection_state")
            .map(String::as_str),
        Some("complete")
    );
}

#[test]
fn full_scan_page_exposes_the_oldest_id_without_owning_the_checkpoint() {
    let kernel = kernel(ArchetypeFamily::Scan);
    let request = kernel.plan_scans(None).unwrap();
    let body = serde_json::to_vec(
        &(1..=SCAN_PAGE_LIMIT)
            .rev()
            .map(|id| {
                serde_json::json!({
                    "id": id,
                    "repository_id": 7,
                    "status": "completed"
                })
            })
            .collect::<Vec<_>>(),
    )
    .unwrap();
    let page = kernel.decode_scans(&request, &body).unwrap();
    assert_eq!(page.scans.len(), SCAN_PAGE_LIMIT);
    assert_eq!(page.scans.first().map(|scan| scan.id), Some(1));
    assert_eq!(page.scans.last().map(|scan| scan.id), Some(100));
    assert_eq!(page.next_before_id, Some(1));
}
