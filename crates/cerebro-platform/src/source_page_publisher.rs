//! Ordered JetStream publication and restart recovery for durable source pages.

use std::{env, error::Error, fmt, sync::Arc};

use async_nats::jetstream::{self, message::PublishMessage};
use async_trait::async_trait;
use cerebro_organizational_model::TenantId;
use cerebro_organizational_store::{PagePublicationOutbox, PostgresLedger, StoreError};
use cerebro_source_runtime_next::{
    CommittedSourceEvent, PageAppendReceipt, PagePublication, PagePublicationError,
    PagePublicationState, PublishClaim,
};
use serde::Serialize;
use time::OffsetDateTime;

const DEFAULT_STREAM: &str = "CEREBRO_EVENTS";
const DEFAULT_SUBJECT_PREFIX: &str = "events";
const DEFAULT_RECOVERY_LIMIT: usize = 100;

#[derive(Clone, Debug, Eq, PartialEq)]
struct PagePublishAck {
    stream: String,
    sequence: u64,
}

#[async_trait]
trait PublicationStore: Send + Sync {
    async fn persist(
        &self,
        expected_revision: u64,
        page: &PagePublication,
    ) -> Result<(), StoreError>;
}

#[async_trait]
impl PublicationStore for PostgresLedger {
    async fn persist(
        &self,
        expected_revision: u64,
        page: &PagePublication,
    ) -> Result<(), StoreError> {
        self.persist_page_publication(expected_revision, page).await
    }
}

#[async_trait]
trait PageEventPublisher: Send + Sync {
    fn subject_prefix(&self) -> &str;

    async fn publish(
        &self,
        subject: &str,
        message_id: &str,
        envelope: &[u8],
    ) -> Result<PagePublishAck, String>;
}

struct JetStreamPublisher {
    context: jetstream::Context,
    stream: String,
    subject_prefix: String,
}

impl JetStreamPublisher {
    fn new(
        context: jetstream::Context,
        stream: String,
        subject_prefix: String,
    ) -> Result<Self, SourcePagePublishError> {
        validate_nats_token("JetStream stream", &stream)?;
        validate_nats_token("JetStream subject prefix", &subject_prefix)?;
        Ok(Self {
            context,
            stream,
            subject_prefix,
        })
    }
}

#[async_trait]
impl PageEventPublisher for JetStreamPublisher {
    fn subject_prefix(&self) -> &str {
        &self.subject_prefix
    }

    async fn publish(
        &self,
        subject: &str,
        message_id: &str,
        envelope: &[u8],
    ) -> Result<PagePublishAck, String> {
        let acknowledgement = self
            .context
            .send_publish(
                subject.to_owned(),
                PublishMessage::build()
                    .payload(envelope.to_vec().into())
                    .message_id(message_id)
                    .expected_stream(self.stream.clone()),
            )
            .await
            .map_err(|error| error.to_string())?
            .await
            .map_err(|error| error.to_string())?;
        if acknowledgement.stream != self.stream || acknowledgement.sequence == 0 {
            return Err(
                "JetStream acknowledgement does not match the configured stream".to_owned(),
            );
        }
        Ok(PagePublishAck {
            stream: acknowledgement.stream,
            sequence: acknowledgement.sequence,
        })
    }
}

#[derive(Debug)]
enum SourcePagePublishError {
    Invalid(String),
    State(PagePublicationError),
    Store(StoreError),
    Publish(String),
}

impl fmt::Display for SourcePagePublishError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => formatter.write_str(message),
            Self::State(error) => {
                write!(formatter, "source page state rejected publication: {error}")
            }
            Self::Store(error) => write!(formatter, "source page persistence failed: {error}"),
            Self::Publish(message) => write!(formatter, "source page append failed: {message}"),
        }
    }
}

impl Error for SourcePagePublishError {}

impl From<PagePublicationError> for SourcePagePublishError {
    fn from(value: PagePublicationError) -> Self {
        Self::State(value)
    }
}

impl From<StoreError> for SourcePagePublishError {
    fn from(value: StoreError) -> Self {
        Self::Store(value)
    }
}

#[derive(Default, Serialize)]
struct PublicationSummary {
    pages_examined: usize,
    pages_advanced: usize,
    events_published: usize,
}

#[derive(Default)]
struct PublicationOutcome {
    page_advanced: bool,
    events_published: usize,
}

pub(crate) async fn run() -> Result<(), Box<dyn Error>> {
    let tenant_id = TenantId::parse(required("CEREBRO_TENANT_ID")?)?;
    let ledger = Arc::new(PostgresLedger::connect_tls(&required("CEREBRO_POSTGRES_DSN")?).await?);
    ledger.migrate().await?;
    let client = async_nats::connect(required("CEREBRO_JETSTREAM_URL")?).await?;
    let publisher = JetStreamPublisher::new(
        jetstream::new(client),
        optional("CEREBRO_JETSTREAM_STREAM_NAME", DEFAULT_STREAM),
        optional("CEREBRO_JETSTREAM_SUBJECT_PREFIX", DEFAULT_SUBJECT_PREFIX),
    )?;
    let owner = publication_owner();
    let limit = env::var("CEREBRO_SOURCE_PAGE_RECOVERY_LIMIT")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(|value| value.parse::<usize>())
        .transpose()?
        .unwrap_or(DEFAULT_RECOVERY_LIMIT);
    if limit == 0 || limit > 500 {
        return Err("CEREBRO_SOURCE_PAGE_RECOVERY_LIMIT must be between 1 and 500".into());
    }
    let outboxes = ledger
        .publishable_page_publications(&tenant_id, limit)
        .await?;
    let mut summary = PublicationSummary {
        pages_examined: outboxes.len(),
        ..PublicationSummary::default()
    };
    for outbox in outboxes {
        let outcome = publish_outbox(ledger.as_ref(), &publisher, outbox, &owner).await?;
        if outcome.page_advanced {
            summary.pages_advanced += 1;
        }
        summary.events_published += outcome.events_published;
    }
    serde_json::to_writer(std::io::stdout(), &summary)?;
    println!();
    Ok(())
}

async fn publish_outbox<S, P>(
    store: &S,
    publisher: &P,
    outbox: PagePublicationOutbox,
    owner: &str,
) -> Result<PublicationOutcome, SourcePagePublishError>
where
    S: PublicationStore,
    P: PageEventPublisher,
{
    let (page, envelopes) = outbox.into_parts();
    publish_page(store, publisher, page, envelopes, owner).await
}

async fn publish_page<S, P>(
    store: &S,
    publisher: &P,
    mut page: PagePublication,
    envelopes: Vec<Vec<u8>>,
    owner: &str,
) -> Result<PublicationOutcome, SourcePagePublishError>
where
    S: PublicationStore,
    P: PageEventPublisher,
{
    if page.events().len() != envelopes.len() {
        return Err(SourcePagePublishError::Invalid(
            "source page outbox is incomplete".to_owned(),
        ));
    }
    let claim = match page.state() {
        PagePublicationState::Prepared => {
            let claim = PublishClaim::new(owner, 1)?;
            let expected_revision = page.revision();
            page.begin_publishing(claim.clone())?;
            store.persist(expected_revision, &page).await?;
            claim
        }
        PagePublicationState::Publishing => {
            let current = page
                .publish_claim()
                .cloned()
                .ok_or(SourcePagePublishError::Invalid(
                    "publishing page has no publish claim".to_owned(),
                ))?;
            let generation =
                current
                    .generation()
                    .checked_add(1)
                    .ok_or(SourcePagePublishError::Invalid(
                        "publish claim generation overflow".to_owned(),
                    ))?;
            let successor = PublishClaim::new(owner, generation)?;
            let expected_revision = page.revision();
            page.transfer_claim(&current, successor.clone())?;
            store.persist(expected_revision, &page).await?;
            successor
        }
        PagePublicationState::Published | PagePublicationState::Projected => {
            return Ok(PublicationOutcome::default());
        }
        PagePublicationState::Committed
        | PagePublicationState::Superseded
        | PagePublicationState::Quarantined => {
            return Err(SourcePagePublishError::Invalid(
                "terminal source page cannot be published".to_owned(),
            ));
        }
    };
    let first_unacknowledged = page.append_receipts().len();
    let mut published = 0;
    for (index, envelope) in envelopes.iter().enumerate().skip(first_unacknowledged) {
        let intent = page.events()[index].clone();
        let subject = subject_for_event(publisher.subject_prefix(), &page, &intent, envelope)?;
        let acknowledgement = publisher
            .publish(&subject, intent.message_id(), envelope)
            .await
            .map_err(SourcePagePublishError::Publish)?;
        let expected_revision = page.revision();
        page.record_append(
            &claim,
            PageAppendReceipt {
                ordinal: intent.ordinal(),
                event_id: intent.event_id().clone(),
                message_id: intent.message_id().to_owned(),
                stream: acknowledgement.stream,
                stream_sequence: acknowledgement.sequence,
            },
        )?;
        store.persist(expected_revision, &page).await?;
        published += 1;
    }
    Ok(PublicationOutcome {
        page_advanced: true,
        events_published: published,
    })
}

fn subject_for_event(
    prefix: &str,
    page: &PagePublication,
    intent: &cerebro_source_runtime_next::PageEventIntent,
    envelope: &[u8],
) -> Result<String, SourcePagePublishError> {
    validate_nats_token("JetStream subject prefix", prefix)?;
    let event = CommittedSourceEvent::decode(envelope)
        .map_err(|_| SourcePagePublishError::Invalid("source page envelope is invalid".to_owned()))?
        .ok_or(SourcePagePublishError::Invalid(
            "source page envelope is not a source event".to_owned(),
        ))?;
    if event.tenant_id() != page.tenant_id()
        || event.source_runtime_id() != page.source_runtime_id()
        || event.source_id() != page.source_id()
        || event.family_id() != page.family_id()
        || event.observation_id() != intent.event_id()
    {
        return Err(SourcePagePublishError::Invalid(
            "source page envelope does not match its page intent".to_owned(),
        ));
    }
    validate_nats_token("source id", event.source_id())?;
    validate_nats_token("family id", event.family_id())?;
    Ok(format!(
        "{prefix}.{}.{}",
        event.source_id(),
        event.family_id()
    ))
}

fn validate_nats_token(label: &'static str, value: &str) -> Result<(), SourcePagePublishError> {
    if value.is_empty()
        || value.len() > 255
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(SourcePagePublishError::Invalid(format!(
            "{label} is not a valid JetStream routing token"
        )));
    }
    Ok(())
}

fn publication_owner() -> String {
    format!(
        "cerebro-rust-page-publisher:{}:{}",
        std::process::id(),
        OffsetDateTime::now_utc().unix_timestamp_nanos()
    )
}

fn required(name: &'static str) -> Result<String, Box<dyn Error>> {
    env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("{name} is required").into())
}

fn optional(name: &str, default: &str) -> String {
    env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| default.to_owned())
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::Mutex};

    use cerebro_organizational_model::{ObservationId, SourceRuntimeId};
    use cerebro_source_runtime_next::{PageEventInput, PagePublicationInput};
    use prost::Message;
    use prost_types::Timestamp;
    use sha2::{Digest, Sha256};

    use super::*;

    #[derive(Clone, PartialEq, Message)]
    struct EventWire {
        #[prost(string, tag = "1")]
        id: String,
        #[prost(string, tag = "2")]
        tenant_id: String,
        #[prost(string, tag = "3")]
        source_id: String,
        #[prost(string, tag = "4")]
        kind: String,
        #[prost(message, optional, tag = "5")]
        occurred_at: Option<Timestamp>,
        #[prost(string, tag = "6")]
        schema_ref: String,
        #[prost(bytes = "vec", tag = "7")]
        payload: Vec<u8>,
        #[prost(map = "string, string", tag = "8")]
        attributes: HashMap<String, String>,
    }

    #[derive(Default)]
    struct MemoryStore {
        revisions: Mutex<Vec<(u64, u64)>>,
    }

    #[async_trait]
    impl PublicationStore for MemoryStore {
        async fn persist(
            &self,
            expected_revision: u64,
            page: &PagePublication,
        ) -> Result<(), StoreError> {
            self.revisions
                .lock()
                .unwrap()
                .push((expected_revision, page.revision()));
            Ok(())
        }
    }

    #[derive(Default)]
    struct MemoryPublisher {
        message_ids: Mutex<Vec<String>>,
    }

    #[async_trait]
    impl PageEventPublisher for MemoryPublisher {
        fn subject_prefix(&self) -> &str {
            DEFAULT_SUBJECT_PREFIX
        }

        async fn publish(
            &self,
            subject: &str,
            message_id: &str,
            _envelope: &[u8],
        ) -> Result<PagePublishAck, String> {
            assert_eq!(subject, "events.github.audit");
            let mut message_ids = self.message_ids.lock().unwrap();
            message_ids.push(message_id.to_owned());
            Ok(PagePublishAck {
                stream: DEFAULT_STREAM.to_owned(),
                sequence: message_ids.len() as u64,
            })
        }
    }

    fn envelope(event_id: &str) -> Vec<u8> {
        EventWire {
            id: event_id.to_owned(),
            tenant_id: "tenant-a".to_owned(),
            source_id: "github".to_owned(),
            kind: "github.audit".to_owned(),
            occurred_at: Some(Timestamp {
                seconds: 1_720_000_000,
                nanos: 0,
            }),
            schema_ref: "github/audit/v1".to_owned(),
            payload: br#"{"id":"provider-event"}"#.to_vec(),
            attributes: HashMap::from([("source_runtime_id".to_owned(), "runtime-a".to_owned())]),
        }
        .encode_to_vec()
    }

    fn page(envelopes: &[Vec<u8>]) -> PagePublication {
        PagePublication::prepare(
            PagePublicationInput {
                logical_page_id: "page:runtime-a:audit:1".to_owned(),
                tenant_id: TenantId::parse("tenant-a").unwrap(),
                source_runtime_id: SourceRuntimeId::parse("runtime-a").unwrap(),
                source_id: "github".to_owned(),
                family_id: "audit".to_owned(),
                lease_generation: 1,
                authority_epoch: 1,
                request_intent_sha256: "a".repeat(64),
                input_progress_sha256: "a".repeat(64),
                target_progress_sha256: "b".repeat(64),
                result_sha256: "b".repeat(64),
            },
            envelopes
                .iter()
                .enumerate()
                .map(|(index, envelope)| PageEventInput {
                    event_id: ObservationId::parse(format!("event-{index}")).unwrap(),
                    envelope_sha256: hex_digest(&Sha256::digest(envelope)),
                })
                .collect(),
        )
        .unwrap()
    }

    fn hex_digest(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[tokio::test]
    async fn prepared_page_publishes_in_order_and_persists_every_revision() {
        let envelopes = vec![envelope("event-0"), envelope("event-1")];
        let store = MemoryStore::default();
        let publisher = MemoryPublisher::default();
        let outcome = publish_page(&store, &publisher, page(&envelopes), envelopes, "worker-a")
            .await
            .unwrap();
        assert!(outcome.page_advanced);
        assert_eq!(outcome.events_published, 2);
        assert_eq!(
            *store.revisions.lock().unwrap(),
            vec![(1, 2), (2, 3), (3, 4)]
        );
        assert_eq!(publisher.message_ids.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn restart_transfers_claim_and_resumes_after_the_last_receipt() {
        let envelopes = vec![envelope("event-0"), envelope("event-1")];
        let mut page = page(&envelopes);
        let first = PublishClaim::new("worker-a", 1).unwrap();
        page.begin_publishing(first.clone()).unwrap();
        let intent = page.events()[0].clone();
        page.record_append(
            &first,
            PageAppendReceipt {
                ordinal: intent.ordinal(),
                event_id: intent.event_id().clone(),
                message_id: intent.message_id().to_owned(),
                stream: DEFAULT_STREAM.to_owned(),
                stream_sequence: 1,
            },
        )
        .unwrap();
        let store = MemoryStore::default();
        let publisher = MemoryPublisher::default();
        let outcome = publish_page(&store, &publisher, page, envelopes, "worker-b")
            .await
            .unwrap();
        assert!(outcome.page_advanced);
        assert_eq!(outcome.events_published, 1);
        assert_eq!(*store.revisions.lock().unwrap(), vec![(3, 4), (4, 5)]);
        assert_eq!(publisher.message_ids.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn empty_page_advances_to_published_without_a_jetstream_message() {
        let store = MemoryStore::default();
        let publisher = MemoryPublisher::default();
        let outcome = publish_page(&store, &publisher, page(&[]), Vec::new(), "worker-a")
            .await
            .unwrap();
        assert!(outcome.page_advanced);
        assert_eq!(outcome.events_published, 0);
        assert_eq!(*store.revisions.lock().unwrap(), vec![(1, 2)]);
        assert!(publisher.message_ids.lock().unwrap().is_empty());
    }
}
