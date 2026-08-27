use cerebro_platform_sdk::{PlatformEvent, SubscriptionEventFilter};

pub fn event_matches(filter: &SubscriptionEventFilter, event: &PlatformEvent) -> bool {
    (filter.event_kinds.is_empty() || filter.event_kinds.contains(&event.kind))
        && (filter.entity_kinds.is_empty()
            || event
                .entity_kind
                .as_ref()
                .is_some_and(|kind| filter.entity_kinds.contains(kind)))
        && (filter.entity_ids.is_empty()
            || event
                .entity_id
                .as_ref()
                .is_some_and(|id| filter.entity_ids.contains(id)))
        && (filter.assertion_ids.is_empty()
            || event
                .assertion_id
                .as_ref()
                .is_some_and(|id| filter.assertion_ids.contains(id)))
}

#[cfg(test)]
mod tests {
    use cerebro_platform_sdk::{ContentDigest, DurableCursor, PlatformEventKind, TenantId};

    use super::*;

    fn event() -> PlatformEvent {
        PlatformEvent {
            cursor: DurableCursor::new(1),
            tenant_id: TenantId::parse("tenant-a").unwrap(),
            kind: PlatformEventKind::GraphChanged,
            graph_revision: None,
            entity_kind: None,
            entity_id: None,
            assertion_id: None,
            occurred_at_unix_millis: 1,
            payload_digest: ContentDigest::of_bytes("event"),
        }
    }

    #[test]
    fn unconstrained_filters_match_optional_event_dimensions_but_constraints_fail_closed() {
        let event = event();
        assert!(event_matches(
            &SubscriptionEventFilter {
                event_kinds: Vec::new(),
                entity_kinds: Vec::new(),
                entity_ids: Vec::new(),
                assertion_ids: Vec::new(),
            },
            &event,
        ));
        assert!(!event_matches(
            &SubscriptionEventFilter {
                event_kinds: Vec::new(),
                entity_kinds: vec![cerebro_platform_sdk::EntityKind::Repository],
                entity_ids: Vec::new(),
                assertion_ids: Vec::new(),
            },
            &event,
        ));
    }
}
