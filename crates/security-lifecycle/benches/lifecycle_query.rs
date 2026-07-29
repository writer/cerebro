use std::{
    collections::{BTreeMap, BTreeSet},
    hint::black_box,
    time::{Duration, Instant},
};

use cerebro_organizational_model::TenantId;
use cerebro_security_lifecycle::{
    LifecycleQuery, LifecycleState, ProjectedResource, QuerySource, SubjectKind,
    canonical_resource_urn, query_records_with_source,
};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, StatsAlloc};

const AS_OF: &str = "2026-07-26T12:00:00Z";
const ITERATIONS: u32 = 10;

#[global_allocator]
static GLOBAL: &StatsAlloc<std::alloc::System> = &INSTRUMENTED_SYSTEM;

fn main() {
    if cfg!(debug_assertions) {
        eprintln!("run with cargo bench -p cerebro-security-lifecycle --bench lifecycle_query");
        return;
    }
    let tenant = TenantId::parse("benchmark-tenant").expect("tenant");
    for count in [500, 10_000, 100_000] {
        let entities = fixture(count);
        report(&format!("optimized_core_{count}"), || {
            let result = query_records_with_source(
                &tenant,
                &LifecycleQuery {
                    limit: Some(100),
                    ..LifecycleQuery::default()
                },
                black_box(entities.clone()),
                AS_OF,
                QuerySource {
                    scanned_entities: count,
                    graph_revision: 17,
                    ..QuerySource::default()
                },
            )
            .expect("query");
            black_box((result.records.len(), result.aggregates.matched_records));
        });
    }

    let generic_resources = generic_fixture(10_000);
    report("naive_generic_scan_10000", || {
        let selected = generic_resources
            .iter()
            .filter(|resource| resource.properties.contains_key("lifecycle_state"))
            .cloned()
            .collect::<Vec<_>>();
        black_box(selected);
    });

    let index = LifecycleBenchIndex::new(fixture(100_000));
    report("indexed_keyset_page_100000", || {
        let page = index.page(None, 100);
        black_box((page.len(), index.total, &index.state_counts));
    });
}

fn report(name: &str, operation: impl Fn()) {
    operation();
    let region = Region::new(GLOBAL);
    let started = Instant::now();
    for _ in 0..ITERATIONS {
        operation();
    }
    let elapsed = started.elapsed() / ITERATIONS;
    let stats = region.change();
    let iterations = usize::try_from(ITERATIONS).expect("iteration count fits usize");
    let allocations = stats.allocations / iterations;
    let bytes = stats.bytes_allocated / iterations;
    println!(
        "{name}\t{} ns/op\t{allocations} allocs/op\t{bytes} bytes/op",
        nanos(elapsed)
    );
}

fn nanos(duration: Duration) -> u128 {
    duration.as_nanos()
}

fn fixture(count: usize) -> Vec<ProjectedResource> {
    (0..count)
        .map(|index| {
            let subject_kind = if index % 4 == 0 {
                SubjectKind::Certificate
            } else {
                SubjectKind::Credential
            };
            let state = match index % 7 {
                0 => LifecycleState::Expired,
                1 => LifecycleState::Expiring,
                2 => LifecycleState::Rotated,
                3 => LifecycleState::Revoked,
                4 => LifecycleState::Inactive,
                5 => LifecycleState::Unknown,
                _ => LifecycleState::Active,
            };
            let stable_locator = format!("slot/{index:06}");
            let resource_urn = canonical_resource_urn(
                "benchmark-tenant",
                subject_kind,
                "benchmark/authority",
                &stable_locator,
            )
            .expect("resource urn");
            let properties = BTreeMap::from([
                ("resource_urn".to_owned(), resource_urn.clone()),
                ("material_revision".to_owned(), format!("revision-{index}")),
                (
                    "subject_kind".to_owned(),
                    match subject_kind {
                        SubjectKind::Credential => "credential",
                        SubjectKind::Certificate => "certificate",
                    }
                    .to_owned(),
                ),
                (
                    "lifecycle_state".to_owned(),
                    match state {
                        LifecycleState::Active => "active",
                        LifecycleState::Expiring => "expiring",
                        LifecycleState::Expired => "expired",
                        LifecycleState::Rotated => "rotated",
                        LifecycleState::Revoked => "revoked",
                        LifecycleState::Inactive => "inactive",
                        LifecycleState::Unknown => "unknown",
                    }
                    .to_owned(),
                ),
                ("provider".to_owned(), "benchmark".to_owned()),
                ("authority_id".to_owned(), "benchmark/authority".to_owned()),
                ("stable_locator".to_owned(), stable_locator),
                ("observed_at".to_owned(), AS_OF.to_owned()),
                (
                    "expires_at".to_owned(),
                    if matches!(state, LifecycleState::Expired) {
                        "2026-07-01T12:00:00Z"
                    } else {
                        "2027-07-01T12:00:00Z"
                    }
                    .to_owned(),
                ),
                (
                    "owner_urn".to_owned(),
                    "urn:cerebro:benchmark-tenant:team:security".to_owned(),
                ),
            ]);
            ProjectedResource {
                agent_key: resource_urn,
                label: format!("Lifecycle subject {index}"),
                properties,
            }
        })
        .collect()
}

fn generic_fixture(count: usize) -> Vec<ProjectedResource> {
    let lifecycle = fixture(count / 20);
    let lifecycle_indexes = (0..lifecycle.len()).collect::<BTreeSet<_>>();
    let mut lifecycle = lifecycle.into_iter();
    (0..count)
        .map(|index| {
            if lifecycle_indexes.contains(&index) {
                lifecycle.next().expect("lifecycle fixture")
            } else {
                ProjectedResource {
                    agent_key: format!("urn:cerebro:benchmark-tenant:resource:{index}"),
                    label: format!("Generic resource {index}"),
                    properties: BTreeMap::from([(
                        "resource_urn".to_owned(),
                        format!("urn:cerebro:benchmark-tenant:resource:{index}"),
                    )]),
                }
            }
        })
        .collect()
}

struct LifecycleBenchIndex {
    by_subject: BTreeMap<String, ProjectedResource>,
    total: usize,
    state_counts: BTreeMap<String, usize>,
}

impl LifecycleBenchIndex {
    fn new(entities: Vec<ProjectedResource>) -> Self {
        let mut by_subject = BTreeMap::new();
        let mut state_counts = BTreeMap::new();
        for entity in entities {
            if let (Some(subject), Some(state)) = (
                entity.properties.get("resource_urn"),
                entity.properties.get("lifecycle_state"),
            ) {
                *state_counts.entry(state.clone()).or_insert(0) += 1;
                by_subject.insert(subject.clone(), entity);
            }
        }
        Self {
            total: by_subject.len(),
            by_subject,
            state_counts,
        }
    }

    fn page(&self, after: Option<&str>, limit: usize) -> Vec<&ProjectedResource> {
        match after {
            Some(after) => self
                .by_subject
                .range((
                    std::ops::Bound::Excluded(after.to_owned()),
                    std::ops::Bound::Unbounded,
                ))
                .take(limit)
                .map(|(_, entity)| entity)
                .collect(),
            None => self.by_subject.values().take(limit).collect(),
        }
    }
}
