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
