use std::{
    collections::BTreeMap,
    env,
    error::Error,
    io,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use async_nats::jetstream::{
    AckKind,
    consumer::{AckPolicy, DeliverPolicy, pull},
};
use cerebro_organizational_store::{
    ConsumerMessageOutcome, ConsumerRunReceiptState, ConsumerSkipCategory, PostgresLedger,
};
use cerebro_source_runtime_next::{AppendLogDecodeError, CommittedSourceEvent};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::ProjectionRuntime;

const DEFAULT_STREAM: &str = "CEREBRO_EVENTS";
const DEFAULT_SUBJECT_PREFIX: &str = "events";
const DEFAULT_CONSUMER: &str = "organizational-graph-v1";
const ACK_WAIT: Duration = Duration::from_secs(120);
const RETRY_DELAY: Duration = Duration::from_secs(30);
const DEFAULT_REPLAY_MAX_MESSAGES: u64 = 100_000;
const DEFAULT_REPLAY_MAX_RUNTIME_SECONDS: u64 = 3_600;
const DIAGNOSTIC_SCHEMA_VERSION: &str = "cerebro.organizational-diagnostic/v1";
const DIAGNOSTIC_EVENT_LIMIT: u64 = 1_024;
const ECS_METADATA_PREFIX: &str = "http://169.254.170.2/";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ConsumerMode {
    Forward,
    Replay,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FailureDisposition {
    Retry,
    Reject,
}

#[derive(Debug)]
enum EventDecodeError {
    Boundary(AppendLogDecodeError),
    LifecycleSubjectMismatch {
        event_kind: String,
        expected_subject: String,
    },
    CatalogOwnedWithoutEnvelope {
        subject: String,
    },
    SourceMismatch {
        subject_source: String,
        event_source: String,
    },
}

impl std::fmt::Display for EventDecodeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Boundary(error) => error.fmt(formatter),
            Self::LifecycleSubjectMismatch {
                event_kind,
                expected_subject,
            } => write!(
                formatter,
                "append-log lifecycle event {event_kind} must use subject {expected_subject}"
            ),
            Self::CatalogOwnedWithoutEnvelope { subject } => write!(
                formatter,
                "append-log subject {subject} is catalog-owned but has no source envelope"
            ),
            Self::SourceMismatch {
                subject_source,
                event_source,
            } => write!(
                formatter,
                "append-log subject source {subject_source} does not match envelope source {event_source}"
            ),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ConsumerConfig {
    nats_url: String,
    stream: String,
    subject_prefix: String,
    durable_name: String,
    deliver_policy: DeliverPolicy,
    mode: ConsumerMode,
    run_id: String,
    end_sequence_override: Option<u64>,
    max_messages: Option<u64>,
    max_runtime: Option<Duration>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DiagnosticIdentity {
    environment: String,
    task_definition: String,
    image_digest: String,
}

#[derive(Deserialize)]
struct EcsContainerMetadata {
    #[serde(rename = "ImageID")]
    image_id: String,
}

#[derive(Deserialize)]
struct EcsTaskMetadata {
    #[serde(rename = "TaskARN")]
    task_arn: String,
    #[serde(rename = "Family")]
    family: String,
    #[serde(rename = "Revision")]
    revision: String,
}

impl DiagnosticIdentity {
    async fn resolve() -> Result<Option<Self>, Box<dyn Error>> {
        reject_environment_claim(env::var_os("CEREBRO_DEPLOYMENT_ENVIRONMENT").as_deref())?;
        let Some(metadata_uri) = env::var("ECS_CONTAINER_METADATA_URI_V4").ok() else {
            return Ok(None);
        };
        if !metadata_uri.starts_with(ECS_METADATA_PREFIX)
            || metadata_uri.len() > 256
            || metadata_uri.contains('?')
            || metadata_uri.contains('#')
        {
            return Err("ECS_CONTAINER_METADATA_URI_V4 is invalid".into());
        }
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()?;
        let base = metadata_uri.trim_end_matches('/');
        let container = client
            .get(base)
            .send()
            .await?
            .error_for_status()?
            .json::<EcsContainerMetadata>()
            .await?;
        let task = client
            .get(format!("{base}/task"))
            .send()
            .await?
            .error_for_status()?
            .json::<EcsTaskMetadata>()
            .await?;
        Self::from_metadata(container, task).map(Some)
    }

    fn from_metadata(
        container: EcsContainerMetadata,
        task: EcsTaskMetadata,
    ) -> Result<Self, Box<dyn Error>> {
        if container.image_id.len() != 71
            || !container.image_id.starts_with("sha256:")
            || !container.image_id[7..]
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err("ECS container image digest is invalid".into());
        }
        validate_identity("task definition family", &task.family)?;
        let environment = task
            .family
            .strip_prefix("cerebro-")
            .and_then(|value| {
                value
                    .strip_suffix("-rust-platform")
                    .or_else(|| value.strip_suffix("-rust-platform-replay"))
            })
            .filter(|value| {
                !value.is_empty()
                    && value.len() <= 64
                    && value.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                    })
            })
            .ok_or("ECS task definition family does not bind a deployment environment")?
            .to_owned();
        if task.revision.is_empty() || !task.revision.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err("ECS task definition revision is invalid".into());
        }
        let (arn_prefix, _) = task
            .task_arn
            .split_once(":task/")
            .ok_or("ECS task ARN is invalid")?;
        let task_definition = format!(
            "{arn_prefix}:task-definition/{}:{}",
            task.family, task.revision
        );
        if task_definition.len() > 512 {
            return Err("ECS task definition ARN is too long".into());
        }
        Ok(Self {
            environment,
            task_definition,
            image_digest: container.image_id,
        })
    }
}

struct DiagnosticEmitter {
    identity: Option<DiagnosticIdentity>,
    emitted: u64,
    checkpoint_emitted: bool,
    retry_emitted: bool,
}

impl ConsumerConfig {
    fn from_env() -> Result<Self, Box<dyn Error>> {
        let mode = match optional("CEREBRO_ORGANIZATIONAL_CONSUMER_MODE", "forward").as_str() {
            "forward" => ConsumerMode::Forward,
            "replay" => ConsumerMode::Replay,
            _ => {
                return Err(
                    "CEREBRO_ORGANIZATIONAL_CONSUMER_MODE must be forward or replay".into(),
                );
            }
        };
        let deliver_policy = match optional("CEREBRO_ORGANIZATIONAL_CONSUMER_DELIVER_POLICY", "new")
            .as_str()
        {
            "new" => DeliverPolicy::New,
            "all" => DeliverPolicy::All,
            "by_start_sequence" => DeliverPolicy::ByStartSequence {
                start_sequence: required_u64("CEREBRO_ORGANIZATIONAL_CONSUMER_START_SEQUENCE")?,
            },
            _ => {
                return Err(
                    "CEREBRO_ORGANIZATIONAL_CONSUMER_DELIVER_POLICY must be new, all, or by_start_sequence"
                        .into(),
                );
            }
        };
        let durable_name = optional("CEREBRO_ORGANIZATIONAL_CONSUMER_NAME", DEFAULT_CONSUMER);
        let run_id = match mode {
            ConsumerMode::Forward => optional(
                "CEREBRO_ORGANIZATIONAL_CONSUMER_RUN_ID",
                "forward-organizational-graph-v1",
            ),
            ConsumerMode::Replay => required("CEREBRO_ORGANIZATIONAL_CONSUMER_RUN_ID")?,
        };
        let end_sequence_override =
            optional_positive_u64("CEREBRO_ORGANIZATIONAL_CONSUMER_END_SEQUENCE")?;
        if mode == ConsumerMode::Forward && end_sequence_override.is_some() {
            return Err("CEREBRO_ORGANIZATIONAL_CONSUMER_END_SEQUENCE is replay-only".into());
        }
        validate_delivery_identity(mode, deliver_policy, &durable_name, &run_id)?;
        Ok(Self {
            nats_url: required("CEREBRO_JETSTREAM_URL")?,
            stream: optional("CEREBRO_JETSTREAM_STREAM_NAME", DEFAULT_STREAM),
            subject_prefix: optional("CEREBRO_JETSTREAM_SUBJECT_PREFIX", DEFAULT_SUBJECT_PREFIX),
            durable_name,
            deliver_policy,
            mode,
            run_id,
            end_sequence_override,
            max_messages: (mode == ConsumerMode::Replay)
                .then(|| {
                    optional_u64(
                        "CEREBRO_ORGANIZATIONAL_CONSUMER_MAX_MESSAGES",
                        DEFAULT_REPLAY_MAX_MESSAGES,
                    )
                })
                .transpose()?,
            max_runtime: (mode == ConsumerMode::Replay)
                .then(|| {
                    optional_u64(
                        "CEREBRO_ORGANIZATIONAL_CONSUMER_MAX_RUNTIME_SECONDS",
                        DEFAULT_REPLAY_MAX_RUNTIME_SECONDS,
                    )
                    .map(Duration::from_secs)
                })
                .transpose()?,
        })
    }

    fn filter_subject(&self) -> String {
        format!("{}.>", self.subject_prefix)
    }

    fn pull_config(&self) -> pull::Config {
        pull::Config {
            durable_name: Some(self.durable_name.clone()),
            name: Some(self.durable_name.clone()),
            description: Some(
                "Projects committed Cerebro source events into the organizational ledger"
                    .to_owned(),
            ),
            deliver_policy: self.deliver_policy,
            ack_policy: AckPolicy::Explicit,
            ack_wait: ACK_WAIT,
            max_deliver: -1,
            filter_subject: self.filter_subject(),
            max_ack_pending: 1,
            ..Default::default()
        }
    }
}

fn validate_delivery_identity(
    mode: ConsumerMode,
    deliver_policy: DeliverPolicy,
    durable_name: &str,
    run_id: &str,
) -> Result<(), Box<dyn Error>> {
    validate_identity("consumer name", durable_name)?;
    validate_identity("consumer run id", run_id)?;
    if mode == ConsumerMode::Replay && deliver_policy == DeliverPolicy::New {
        return Err("replay mode requires all or by_start_sequence delivery".into());
    }
    if mode == ConsumerMode::Replay && durable_name == DEFAULT_CONSUMER {
        return Err(
            "replay delivery requires an explicit CEREBRO_ORGANIZATIONAL_CONSUMER_NAME".into(),
        );
    }
    if mode == ConsumerMode::Forward && deliver_policy == DeliverPolicy::All {
        return Err("forward mode does not permit all-history delivery".into());
    }
    Ok(())
}

fn validate_identity(label: &str, value: &str) -> Result<(), Box<dyn Error>> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(
            format!("{label} must contain 1-128 letters, digits, hyphens, or underscores").into(),
        );
    }
    Ok(())
}

pub(crate) async fn run(runtime: Arc<ProjectionRuntime>) -> Result<(), Box<dyn Error>> {
    let config = ConsumerConfig::from_env()?;
    let mut diagnostics = DiagnosticEmitter {
        identity: DiagnosticIdentity::resolve().await?,
        emitted: 0,
        checkpoint_emitted: false,
        retry_emitted: false,
    };
    let client = async_nats::connect(&config.nats_url).await?;
    let jetstream = async_nats::jetstream::new(client);
    let mut stream = jetstream.get_stream(&config.stream).await?;
    let stream_state = stream.info().await?.state.clone();
    let proposed_start_sequence = match config.deliver_policy {
        DeliverPolicy::New => stream_state.last_sequence.saturating_add(1),
        DeliverPolicy::All => stream_state.first_sequence,
        DeliverPolicy::ByStartSequence { start_sequence } => start_sequence,
        _ => return Err("organizational consumer delivery policy is unsupported".into()),
    };
    let proposed_end_sequence = (config.mode == ConsumerMode::Replay).then_some(
        config
            .end_sequence_override
            .unwrap_or(stream_state.last_sequence),
    );
    if proposed_start_sequence == 0
        || (config.mode == ConsumerMode::Replay
            && proposed_start_sequence < stream_state.first_sequence)
        || proposed_end_sequence.is_some_and(|end| end < proposed_start_sequence)
        || proposed_end_sequence.is_some_and(|end| end > stream_state.last_sequence)
    {
        return Err("organizational replay fence does not contain retained messages".into());
    }
    let stored_fence = runtime
        .authority
        .start_consumer_run(
            &config.durable_name,
            &config.run_id,
            mode_name(config.mode),
            proposed_start_sequence,
            proposed_end_sequence,
        )
        .await?;
    let start_sequence = stored_fence.start_sequence;
    let end_sequence = stored_fence.end_sequence;
    let mut counters = ConsumerCounters::default();
    let persisted = load_receipt_state(&runtime, &config).await?;
    let persisted_counters = ConsumerCounters::from(&persisted);
    let next_unprocessed =
        next_unprocessed_sequence(start_sequence, persisted_counters.last_delivered_sequence);
    if retention_gap(stream_state.first_sequence, next_unprocessed, end_sequence) {
        runtime
            .authority
            .finish_consumer_run(&config.durable_name, &config.run_id, "failed", None)
            .await?;
        return Err(format!(
            "retention advanced to sequence {} before replay could resume at {}",
            stream_state.first_sequence, next_unprocessed
        )
        .into());
    }
    emit_receipt(
        "started",
        &config,
        start_sequence,
        end_sequence,
        persisted_counters.covered_sequence,
        &persisted,
        None,
    )?;
    let expected = config.pull_config();
    let consumer = stream
        .get_or_create_consumer(&config.durable_name, expected.clone())
        .await?;
    let actual = consumer.get_info().await?;
    validate_server_config(&actual.config, &expected)?;
    let retained_after_consumer_create = stream.info().await?.state.first_sequence;
    if retention_gap(
        retained_after_consumer_create,
        next_unprocessed,
        end_sequence,
    ) {
        runtime
            .authority
            .finish_consumer_run(&config.durable_name, &config.run_id, "failed", None)
            .await?;
        return Err(format!(
            "retention advanced to sequence {retained_after_consumer_create} before replay consumer creation completed at {next_unprocessed}"
        )
        .into());
    }
    let mut messages = consumer.messages().await?;
    let started = Instant::now();
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);
    loop {
        if config
            .max_messages
            .is_some_and(|limit| counters.messages_seen >= limit)
            || config
                .max_runtime
                .is_some_and(|limit| started.elapsed() >= limit)
        {
            runtime
                .authority
                .finish_consumer_run(&config.durable_name, &config.run_id, "stopped", None)
                .await?;
            let persisted = load_receipt_state(&runtime, &config).await?;
            let persisted_counters = ConsumerCounters::from(&persisted);
            emit_receipt(
                "stopped",
                &config,
                start_sequence,
                end_sequence,
                persisted_counters.covered_sequence,
                &persisted,
                None,
            )?;
            return Ok(());
        }
        let next = tokio::select! {
            next = messages.next() => next,
            () = &mut shutdown => {
                runtime
                    .authority
                    .finish_consumer_run(&config.durable_name, &config.run_id, "stopped", None)
                    .await?;
                let persisted = load_receipt_state(&runtime, &config).await?;
                let persisted_counters = ConsumerCounters::from(&persisted);
                emit_receipt(
                    "stopped",
                    &config,
                    start_sequence,
                    end_sequence,
                    persisted_counters.covered_sequence,
                    &persisted,
                    None,
                )?;
                return Ok(());
            }
        };
        let Some(next) = next else {
            runtime
                .authority
                .finish_consumer_run(&config.durable_name, &config.run_id, "failed", None)
                .await?;
            return Err("organizational append-log consumer stopped receiving messages".into());
        };
        let message = next?;
        let info = message.info().map_err(consumer_io)?;
        let stream_sequence = info.stream_sequence;
        let pending = info.pending;
        if end_sequence.is_some_and(|end| stream_sequence > end) {
            return finish_replay(
                &runtime,
                &config,
                start_sequence,
                end_sequence.expect("replay has an end fence"),
                &counters,
            )
            .await;
        }
        let subject = message.message.subject.to_string();
        let message_sha256 = digest_bytes(&message.message.payload);
        let Some((subject_source, subject_family)) =
            source_family_from_subject(&subject, &config.subject_prefix)
        else {
            record_progress(
                &runtime,
                &config,
                stream_sequence,
                ConsumerMessageOutcome::Skipped(
                    ConsumerSkipCategory::SubjectOutsideProjectionContract,
                ),
                None,
                None,
                &mut counters,
            )
            .await?;
            message.double_ack().await.map_err(consumer_io)?;
            if replay_drained(&config, end_sequence, stream_sequence, pending) {
                return finish_replay(
                    &runtime,
                    &config,
                    start_sequence,
                    end_sequence.expect("replay has an end fence"),
                    &counters,
                )
                .await;
            }
            continue;
        };
        let event = match decode_event(
            &message.message.payload,
            subject_source,
            &subject,
            &config.subject_prefix,
            runtime
                .catalog
                .admits_event_family(subject_source, subject_family),
        ) {
            Ok(Some(event)) => event,
            Ok(None) => {
                record_progress(
                    &runtime,
                    &config,
                    stream_sequence,
                    ConsumerMessageOutcome::Skipped(
                        ConsumerSkipCategory::SourceOutsideCompiledCatalog,
                    ),
                    Some((subject_source, subject_family)),
                    None,
                    &mut counters,
                )
                .await?;
                message.double_ack().await.map_err(consumer_io)?;
                if replay_drained(&config, end_sequence, stream_sequence, pending) {
                    return finish_replay(
                        &runtime,
                        &config,
                        start_sequence,
                        end_sequence.expect("replay has an end fence"),
                        &counters,
                    )
                    .await;
                }
                continue;
            }
            Err(error) => {
                if let Some(reason) =
                    legacy_decode_skip(config.mode, subject_source, subject_family, &error)
                {
                    record_progress(
                        &runtime,
                        &config,
                        stream_sequence,
                        ConsumerMessageOutcome::Skipped(skip_category(reason)),
                        Some((subject_source, subject_family)),
                        None,
                        &mut counters,
                    )
                    .await?;
                    diagnostics.emit(
                        &config,
                        stream_sequence,
                        subject_source,
                        subject_family,
                        "compatibility_skip",
                        decode_skip_category(reason),
                        &message_sha256,
                        None,
                    )?;
                    message.double_ack().await.map_err(consumer_io)?;
                    if replay_drained(&config, end_sequence, stream_sequence, pending) {
                        return finish_replay(
                            &runtime,
                            &config,
                            start_sequence,
                            end_sequence.expect("replay has an end fence"),
                            &counters,
                        )
                        .await;
                    }
                    continue;
                }
                record_progress(
                    &runtime,
                    &config,
                    stream_sequence,
                    ConsumerMessageOutcome::Rejected,
                    Some((subject_source, subject_family)),
                    None,
                    &mut counters,
                )
                .await?;
                if let Some(category) = decode_error_category(&error) {
                    diagnostics.emit(
                        &config,
                        stream_sequence,
                        subject_source,
                        subject_family,
                        "message_rejected",
                        category,
                        &message_sha256,
                        None,
                    )?;
                }
                message.double_ack().await.map_err(consumer_io)?;
                if replay_drained(&config, end_sequence, stream_sequence, pending) {
                    return finish_replay(
                        &runtime,
                        &config,
                        start_sequence,
                        end_sequence.expect("replay has an end fence"),
                        &counters,
                    )
                    .await;
                }
                continue;
            }
        };
        let event_source = event.source_id().to_owned();
        let event_family = event.family_id().to_owned();
        let record_digest = diagnostic_record_digest(&event);
        match runtime.project_committed_shadow(event).await {
            Ok(response) => {
                if !response.projected {
                    return Err("recognized append-log event was not projected".into());
                }
                let outcome = ConsumerMessageOutcome::Projected;
                record_progress(
                    &runtime,
                    &config,
                    stream_sequence,
                    outcome,
                    Some((&event_source, &event_family)),
                    response.graph_revision,
                    &mut counters,
                )
                .await?;
                if checkpoint_eligible(outcome) {
                    diagnostics.emit_checkpoint(&config, stream_sequence, &message_sha256)?;
                }
                message.double_ack().await.map_err(consumer_io)?;
                if replay_drained(&config, end_sequence, stream_sequence, pending) {
                    return finish_replay(
                        &runtime,
                        &config,
                        start_sequence,
                        end_sequence.expect("replay has an end fence"),
                        &counters,
                    )
                    .await;
                }
            }
            Err(error) => match failure_disposition(error.is_retryable()) {
                FailureDisposition::Retry => {
                    diagnostics.emit_retry(&config, stream_sequence, &message_sha256)?;
                    message
                        .ack_with(AckKind::Nak(Some(RETRY_DELAY)))
                        .await
                        .map_err(consumer_io)?;
                }
                FailureDisposition::Reject => {
                    record_progress(
                        &runtime,
                        &config,
                        stream_sequence,
                        ConsumerMessageOutcome::Rejected,
                        Some((&event_source, &event_family)),
                        None,
                        &mut counters,
                    )
                    .await?;
                    if let Some(category) =
                        projection_error_category(&event_source, &event_family, &error)
                    {
                        diagnostics.emit(
                            &config,
                            stream_sequence,
                            &event_source,
                            &event_family,
                            "projection_rejected",
                            category,
                            &message_sha256,
                            Some(&record_digest),
                        )?;
                    }
                    message.double_ack().await.map_err(consumer_io)?;
                    if replay_drained(&config, end_sequence, stream_sequence, pending) {
                        return finish_replay(
                            &runtime,
                            &config,
                            start_sequence,
                            end_sequence.expect("replay has an end fence"),
                            &counters,
                        )
                        .await;
                    }
                }
            },
        }
    }
}

fn next_unprocessed_sequence(start_sequence: u64, last_delivered_sequence: u64) -> u64 {
    if last_delivered_sequence == 0 {
        start_sequence
    } else {
        last_delivered_sequence.saturating_add(1)
    }
}

fn retention_gap(
    first_retained_sequence: u64,
    next_unprocessed_sequence: u64,
    end_sequence: Option<u64>,
) -> bool {
    end_sequence.is_some_and(|end| {
        next_unprocessed_sequence <= end && first_retained_sequence > next_unprocessed_sequence
    })
}

pub(crate) async fn inspect() -> Result<(), Box<dyn Error>> {
    let nats_url = required("CEREBRO_JETSTREAM_URL")?;
    let stream_name = optional("CEREBRO_JETSTREAM_STREAM_NAME", DEFAULT_STREAM);
    let subject_prefix = optional("CEREBRO_JETSTREAM_SUBJECT_PREFIX", DEFAULT_SUBJECT_PREFIX);
    let client = async_nats::connect(&nats_url).await?;
    let jetstream = async_nats::jetstream::new(client);
    let mut stream = jetstream.get_stream(&stream_name).await?;
    let state = stream.info().await?.state.clone();
    println!(
        "{}",
        serde_json::json!({
            "schema_version": "cerebro.organizational-consumer-fence/v1",
            "stream": stream_name,
            "filter_subject": format!("{subject_prefix}.>"),
            "first_sequence": state.first_sequence,
            "end_sequence": state.last_sequence,
            "captured_messages": state.messages,
        })
    );
    Ok(())
}

pub(crate) async fn inspect_run() -> Result<(), Box<dyn Error>> {
    let consumer_name = required("CEREBRO_ORGANIZATIONAL_CONSUMER_NAME")?;
    let run_id = required("CEREBRO_ORGANIZATIONAL_CONSUMER_RUN_ID")?;
    let ledger = PostgresLedger::connect_tls(&required("CEREBRO_POSTGRES_DSN")?).await?;
    let inspection = ledger.inspect_consumer_run(&consumer_name, &run_id).await?;
    let observed_source_families = inspection.families.len();
    let projected_source_families = inspection
        .families
        .iter()
        .filter(|family| family.messages_projected > 0)
        .count();
    let latest_graph_revision = inspection
        .families
        .iter()
        .filter_map(|family| family.latest_graph_revision)
        .max();
    let inspected_at_unix_ms = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
    let payload = serde_json::json!({
        "schema_version": "cerebro.organizational-materialization-receipt/v1",
        "run": inspection,
        "observed_source_families": observed_source_families,
        "projected_source_families": projected_source_families,
        "latest_graph_revision": latest_graph_revision,
        "inspected_at_unix_ms": inspected_at_unix_ms,
        "deployment_environment": optional("CEREBRO_DEPLOYMENT_ENVIRONMENT", "unknown"),
        "image_tag": optional("CEREBRO_IMAGE_TAG", "unknown"),
    });
    let canonical = serde_json::to_vec(&payload)?;
    let digest = Sha256::digest(canonical)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    println!(
        "{}",
        serde_json::json!({
            "receipt": payload,
            "receipt_sha256": digest,
        })
    );
    Ok(())
}

#[derive(Default, Serialize)]
struct ConsumerCounters {
    last_delivered_sequence: u64,
    covered_sequence: u64,
    messages_seen: u64,
    messages_projected: u64,
    messages_skipped: u64,
    messages_rejected: u64,
}

impl From<&ConsumerRunReceiptState> for ConsumerCounters {
    fn from(value: &ConsumerRunReceiptState) -> Self {
        Self {
            last_delivered_sequence: value.progress.last_delivered_sequence,
            covered_sequence: value.progress.covered_sequence,
            messages_seen: value.progress.messages_seen,
            messages_projected: value.progress.messages_projected,
            messages_skipped: value.progress.messages_skipped,
            messages_rejected: value.progress.messages_rejected,
        }
    }
}

async fn load_receipt_state(
    runtime: &ProjectionRuntime,
    config: &ConsumerConfig,
) -> Result<ConsumerRunReceiptState, Box<dyn Error>> {
    Ok(runtime
        .authority
        .consumer_run_receipt_state(&config.durable_name, &config.run_id)
        .await?)
}

async fn record_progress(
    runtime: &ProjectionRuntime,
    config: &ConsumerConfig,
    stream_sequence: u64,
    outcome: ConsumerMessageOutcome,
    source_family: Option<(&str, &str)>,
    graph_revision: Option<u64>,
    counters: &mut ConsumerCounters,
) -> Result<(), Box<dyn Error>> {
    runtime
        .authority
        .record_consumer_progress(
            &config.durable_name,
            &config.run_id,
            stream_sequence,
            outcome,
            source_family,
            graph_revision,
        )
        .await?;
    counters.covered_sequence = counters.covered_sequence.max(stream_sequence);
    counters.last_delivered_sequence = counters.last_delivered_sequence.max(stream_sequence);
    counters.messages_seen += 1;
    match outcome {
        ConsumerMessageOutcome::Projected => counters.messages_projected += 1,
        ConsumerMessageOutcome::Skipped(_) => counters.messages_skipped += 1,
        ConsumerMessageOutcome::Rejected => counters.messages_rejected += 1,
    }
    Ok(())
}

fn replay_drained(
    config: &ConsumerConfig,
    end_sequence: Option<u64>,
    stream_sequence: u64,
    pending: u64,
) -> bool {
    config.mode == ConsumerMode::Replay
        && (end_sequence.is_some_and(|end| stream_sequence >= end) || pending == 0)
}

async fn finish_replay(
    runtime: &ProjectionRuntime,
    config: &ConsumerConfig,
    start_sequence: u64,
    end_sequence: u64,
    _counters: &ConsumerCounters,
) -> Result<(), Box<dyn Error>> {
    let persisted_before_finish = load_receipt_state(runtime, config).await?;
    let persisted_before_finish_counters = ConsumerCounters::from(&persisted_before_finish);
    if persisted_before_finish_counters.last_delivered_sequence < end_sequence {
        let first_retained_sequence = current_first_sequence(config).await?;
        let next_unprocessed = next_unprocessed_sequence(
            start_sequence,
            persisted_before_finish_counters.last_delivered_sequence,
        );
        if retention_gap(
            first_retained_sequence,
            next_unprocessed,
            Some(end_sequence),
        ) {
            runtime
                .authority
                .finish_consumer_run(&config.durable_name, &config.run_id, "failed", None)
                .await?;
            emit_receipt(
                "failed",
                config,
                start_sequence,
                Some(end_sequence),
                persisted_before_finish_counters.covered_sequence,
                &persisted_before_finish,
                Some("retention_gap"),
            )?;
            return Err(format!(
                "retention advanced to sequence {first_retained_sequence} before replay covered {next_unprocessed}"
            )
            .into());
        }
    }
    let completion_basis =
        if persisted_before_finish_counters.last_delivered_sequence >= end_sequence {
            "delivered_end_sequence"
        } else {
            "zero_eligible_pending"
        };
    let status = if persisted_before_finish_counters.messages_rejected == 0
        && persisted_before_finish_counters.messages_projected > 0
    {
        "completed"
    } else {
        "failed"
    };
    runtime
        .authority
        .finish_consumer_run(
            &config.durable_name,
            &config.run_id,
            status,
            (status == "completed").then_some(end_sequence),
        )
        .await?;
    let persisted = load_receipt_state(runtime, config).await?;
    let persisted_counters = ConsumerCounters::from(&persisted);
    emit_receipt(
        status,
        config,
        start_sequence,
        Some(end_sequence),
        if status == "completed" {
            end_sequence
        } else {
            persisted_counters.covered_sequence
        },
        &persisted,
        Some(completion_basis),
    )?;
    if status == "completed" {
        Ok(())
    } else {
        Err("organizational replay reached its fence without clean projected coverage".into())
    }
}

async fn current_first_sequence(config: &ConsumerConfig) -> Result<u64, Box<dyn Error>> {
    let client = async_nats::connect(&config.nats_url).await?;
    let jetstream = async_nats::jetstream::new(client);
    let mut stream = jetstream.get_stream(&config.stream).await?;
    Ok(stream.info().await?.state.first_sequence)
}

#[derive(Serialize)]
struct ConsumerReceipt<'a> {
    schema_version: &'static str,
    status: &'a str,
    mode: ConsumerMode,
    stream: &'a str,
    filter_subject: String,
    consumer_name: &'a str,
    run_id: &'a str,
    start_sequence: u64,
    end_sequence: Option<u64>,
    covered_sequence: u64,
    last_delivered_sequence: u64,
    completion_basis: Option<&'a str>,
    counters: &'a ConsumerCounters,
    skip_categories: &'a BTreeMap<String, u64>,
}

fn emit_receipt(
    status: &str,
    config: &ConsumerConfig,
    start_sequence: u64,
    end_sequence: Option<u64>,
    covered_sequence: u64,
    state: &ConsumerRunReceiptState,
    completion_basis: Option<&str>,
) -> Result<(), Box<dyn Error>> {
    let counters = ConsumerCounters::from(state);
    let skip_categories = &state.skip_categories;
    validate_receipt_skip_categories(counters.messages_skipped, skip_categories)?;
    println!(
        "{}",
        serde_json::to_string(&ConsumerReceipt {
            schema_version: "cerebro.organizational-consumer-run/v1",
            status,
            mode: config.mode,
            stream: &config.stream,
            filter_subject: config.filter_subject(),
            consumer_name: &config.durable_name,
            run_id: &config.run_id,
            start_sequence,
            end_sequence,
            covered_sequence,
            last_delivered_sequence: counters.last_delivered_sequence,
            completion_basis,
            counters: &counters,
            skip_categories,
        })?
    );
    Ok(())
}

fn validate_receipt_skip_categories(
    messages_skipped: u64,
    categories: &BTreeMap<String, u64>,
) -> Result<(), Box<dyn Error>> {
    if categories.len() > ConsumerSkipCategory::ALL.len()
        || categories.keys().any(|category| {
            !ConsumerSkipCategory::ALL
                .iter()
                .any(|known| known.as_str() == category)
        })
        || categories.values().any(|count| *count == 0)
        || categories
            .values()
            .try_fold(0_u64, |total, count| total.checked_add(*count))
            != Some(messages_skipped)
    {
        return Err("consumer skip categories do not match messages_skipped".into());
    }
    Ok(())
}

fn mode_name(mode: ConsumerMode) -> &'static str {
    match mode {
        ConsumerMode::Forward => "forward",
        ConsumerMode::Replay => "replay",
    }
}

#[derive(Serialize)]
struct DiagnosticEvent<'a> {
    schema_version: &'static str,
    environment: &'a str,
    mode: &'static str,
    consumer_name: &'a str,
    consumer_run_id: &'a str,
    task_definition: &'a str,
    image_digest: &'a str,
    source_id: &'a str,
    family_id: &'a str,
    outcome: &'a str,
    error_category: &'a str,
    stream_sequence: u64,
    message_sha256: &'a str,
    event_identity_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    record_digest: Option<&'a str>,
}

impl DiagnosticEmitter {
    #[allow(clippy::too_many_arguments)]
    fn emit(
        &mut self,
        config: &ConsumerConfig,
        stream_sequence: u64,
        source_id: &str,
        family_id: &str,
        outcome: &str,
        error_category: &str,
        message_sha256: &str,
        record_digest: Option<&str>,
    ) -> Result<(), Box<dyn Error>> {
        let Some(identity) = self.identity.as_ref() else {
            return Ok(());
        };
        if self.emitted >= DIAGNOSTIC_EVENT_LIMIT {
            return Ok(());
        }
        println!(
            "{}",
            serde_json::to_string(&diagnostic_event(
                identity,
                config,
                stream_sequence,
                source_id,
                family_id,
                outcome,
                error_category,
                message_sha256,
                record_digest,
            ))?
        );
        self.emitted += 1;
        Ok(())
    }

    fn emit_checkpoint(
        &mut self,
        config: &ConsumerConfig,
        stream_sequence: u64,
        message_sha256: &str,
    ) -> Result<(), Box<dyn Error>> {
        if self.checkpoint_emitted || self.identity.is_none() {
            return Ok(());
        }
        self.emit(
            config,
            stream_sequence,
            "cerebro",
            "append_log_checkpoint",
            "run_checkpoint",
            "none",
            checkpoint_message_sha256(message_sha256),
            None,
        )?;
        self.checkpoint_emitted = true;
        Ok(())
    }

    fn emit_retry(
        &mut self,
        config: &ConsumerConfig,
        stream_sequence: u64,
        message_sha256: &str,
    ) -> Result<bool, Box<dyn Error>> {
        if self.retry_emitted {
            return Ok(false);
        }
        let Some(identity) = self.identity.as_ref() else {
            return Ok(false);
        };
        println!(
            "{}",
            retry_event(identity, config, stream_sequence, message_sha256)
        );
        self.retry_emitted = true;
        Ok(true)
    }
}

fn reject_environment_claim(value: Option<&std::ffi::OsStr>) -> Result<(), Box<dyn Error>> {
    if value.is_some() {
        Err("CEREBRO_DEPLOYMENT_ENVIRONMENT must not claim diagnostic identity".into())
    } else {
        Ok(())
    }
}

fn retry_event(
    identity: &DiagnosticIdentity,
    config: &ConsumerConfig,
    stream_sequence: u64,
    message_sha256: &str,
) -> serde_json::Value {
    serde_json::json!({
        "kind": "organizational_projection_retry",
        "environment": identity.environment,
        "mode": mode_name(config.mode),
        "consumer_name": config.durable_name,
        "consumer_run_id": config.run_id,
        "task_definition": identity.task_definition,
        "image_digest": identity.image_digest,
        "stream_sequence": stream_sequence,
        "message_sha256": message_sha256,
    })
}

#[allow(clippy::too_many_arguments)]
fn diagnostic_event<'a>(
    identity: &'a DiagnosticIdentity,
    config: &'a ConsumerConfig,
    stream_sequence: u64,
    source_id: &'a str,
    family_id: &'a str,
    outcome: &'a str,
    error_category: &'a str,
    message_sha256: &'a str,
    record_digest: Option<&'a str>,
) -> DiagnosticEvent<'a> {
    let event_identity_sha256 =
        diagnostic_identity_digest(config, stream_sequence, error_category, message_sha256);
    DiagnosticEvent {
        schema_version: DIAGNOSTIC_SCHEMA_VERSION,
        environment: &identity.environment,
        mode: mode_name(config.mode),
        consumer_name: &config.durable_name,
        consumer_run_id: &config.run_id,
        task_definition: &identity.task_definition,
        image_digest: &identity.image_digest,
        source_id,
        family_id,
        outcome,
        error_category,
        stream_sequence,
        message_sha256,
        event_identity_sha256,
        record_digest,
    }
}

fn digest_bytes(bytes: &[u8]) -> String {
    let hex = Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("sha256:{hex}")
}

fn diagnostic_record_digest(event: &CommittedSourceEvent) -> String {
    format!("sha256:{}", event.record_digest())
}

fn checkpoint_message_sha256(message_sha256: &str) -> &str {
    message_sha256
}

#[allow(clippy::too_many_arguments)]
fn diagnostic_identity_digest(
    config: &ConsumerConfig,
    stream_sequence: u64,
    error_category: &str,
    message_sha256: &str,
) -> String {
    let identity = serde_json::json!({
        "mode": mode_name(config.mode),
        "consumer_name": config.durable_name,
        "consumer_run_id": config.run_id,
        "stream_sequence": stream_sequence,
        "error_category": error_category,
        "message_sha256": message_sha256,
    });
    digest_bytes(&serde_json::to_vec(&identity).expect("diagnostic identity serializes"))
}

fn checkpoint_eligible(outcome: ConsumerMessageOutcome) -> bool {
    matches!(outcome, ConsumerMessageOutcome::Projected)
}

fn decode_skip_category(reason: &str) -> &'static str {
    match reason {
        "legacy_invalid_observation_id" => "invalid_observation_id",
        _ => "unsupported_legacy_record",
    }
}

fn skip_category(reason: &str) -> ConsumerSkipCategory {
    match reason {
        "legacy_invalid_observation_id" => ConsumerSkipCategory::LegacyInvalidObservationId,
        "legacy_catalog_canary_without_source_envelope" => {
            ConsumerSkipCategory::LegacyCatalogCanaryWithoutSourceEnvelope
        }
        "legacy_missing_source_owned_kind" => ConsumerSkipCategory::LegacyMissingSourceOwnedKind,
        "legacy_retired_family_projection_incompatible" => {
            ConsumerSkipCategory::LegacyRetiredFamilyProjectionIncompatible
        }
        _ => unreachable!("closed legacy skip reason"),
    }
}

fn decode_error_category(error: &EventDecodeError) -> Option<&'static str> {
    match error {
        EventDecodeError::Boundary(AppendLogDecodeError::InvalidModel(message))
            if message == "observation id is invalid" =>
        {
            Some("invalid_observation_id")
        }
        _ => None,
    }
}

fn projection_error_category(
    source_id: &str,
    family_id: &str,
    error: &crate::ProjectionFailure,
) -> Option<&'static str> {
    match error {
        crate::ProjectionFailure::Store(cerebro_organizational_store::StoreError::Conflict(
            message,
        )) if source_id == "okta"
            && family_id == "threat_insight"
            && message.starts_with("source event ")
            && message.ends_with(" conflicts with the stored record") =>
        {
            Some("stored_record_conflict")
        }
        crate::ProjectionFailure::Invalid(message)
            if source_id == "okta"
                && family_id == "application"
                && message == "catalog projection is invalid: entity label is invalid" =>
        {
            Some("invalid_entity_label")
        }
        _ => None,
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut terminate = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

fn decode_event(
    payload: &[u8],
    subject_source: &str,
    subject: &str,
    subject_prefix: &str,
    catalog_source_known: bool,
) -> Result<Option<CommittedSourceEvent>, EventDecodeError> {
    match CommittedSourceEvent::decode(payload) {
        Ok(Some(event))
            if event.is_portable_security_lifecycle()
                && subject == format!("{subject_prefix}.{}", event.event_kind()) =>
        {
            Ok(Some(event))
        }
        Ok(Some(event)) if event.is_portable_security_lifecycle() => {
            Err(EventDecodeError::LifecycleSubjectMismatch {
                event_kind: event.event_kind().to_owned(),
                expected_subject: format!("{subject_prefix}.{}", event.event_kind()),
            })
        }
        Ok(Some(_)) if !catalog_source_known => Ok(None),
        Ok(Some(event)) if event.source_id() == subject_source => Ok(Some(event)),
        Ok(Some(event)) => Err(EventDecodeError::SourceMismatch {
            subject_source: subject_source.to_owned(),
            event_source: event.source_id().to_owned(),
        }),
        Ok(None) => Err(EventDecodeError::CatalogOwnedWithoutEnvelope {
            subject: subject.to_owned(),
        }),
        Err(error) => Err(EventDecodeError::Boundary(error)),
    }
}

fn legacy_decode_skip(
    mode: ConsumerMode,
    source_id: &str,
    family_id: &str,
    error: &EventDecodeError,
) -> Option<&'static str> {
    match (source_id, family_id, error) {
        (
            "asset",
            "data_sensitivity",
            EventDecodeError::Boundary(AppendLogDecodeError::Missing(
                "a source-owned kind in source.family form",
            )),
        ) if matches!(mode, ConsumerMode::Forward | ConsumerMode::Replay) => {
            Some("legacy_missing_source_owned_kind")
        }
        (
            "cerebro",
            "health.jetstream_canary",
            EventDecodeError::CatalogOwnedWithoutEnvelope { .. },
        ) if matches!(mode, ConsumerMode::Forward | ConsumerMode::Replay) => {
            Some("legacy_catalog_canary_without_source_envelope")
        }
        _ => None,
    }
}

fn failure_disposition(retryable: bool) -> FailureDisposition {
    if retryable {
        FailureDisposition::Retry
    } else {
        FailureDisposition::Reject
    }
}

fn validate_server_config(
    actual: &async_nats::jetstream::consumer::Config,
    expected: &pull::Config,
) -> Result<(), Box<dyn Error>> {
    if actual.durable_name != expected.durable_name
        || actual.name != expected.name
        || actual.deliver_policy != expected.deliver_policy
        || actual.ack_policy != AckPolicy::Explicit
        || actual.ack_wait != ACK_WAIT
        || actual.max_deliver != -1
        || actual.filter_subject != expected.filter_subject
        || actual.max_ack_pending != 1
    {
        return Err(
            "existing organizational JetStream consumer has an incompatible configuration".into(),
        );
    }
    Ok(())
}

fn source_family_from_subject<'a>(subject: &'a str, prefix: &str) -> Option<(&'a str, &'a str)> {
    let remainder = subject.strip_prefix(prefix)?.strip_prefix('.')?;
    let (source, family) = remainder.split_once('.')?;
    if source.is_empty() || family.is_empty() {
        None
    } else {
        Some((source, family))
    }
}

fn required(name: &str) -> Result<String, Box<dyn Error>> {
    let value = env::var(name)?;
    if value.trim().is_empty() {
        Err(format!("{name} is required").into())
    } else {
        Ok(value)
    }
}

fn optional(name: &str, default: &str) -> String {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| default.to_owned())
}

fn required_u64(name: &str) -> Result<u64, Box<dyn Error>> {
    let value = required(name)?;
    parse_required_u64(name, &value)
}

fn optional_u64(name: &str, default: u64) -> Result<u64, Box<dyn Error>> {
    match env::var(name) {
        Ok(value) if !value.trim().is_empty() => parse_required_u64(name, &value),
        _ => Ok(default),
    }
}

fn optional_positive_u64(name: &str) -> Result<Option<u64>, Box<dyn Error>> {
    match env::var(name) {
        Ok(value) if !value.trim().is_empty() => parse_required_u64(name, &value).map(Some),
        _ => Ok(None),
    }
}

fn parse_required_u64(name: &str, value: &str) -> Result<u64, Box<dyn Error>> {
    let parsed = value
        .trim()
        .parse::<u64>()
        .map_err(|_| format!("{name} must be an unsigned integer"))?;
    if parsed == 0 {
        return Err(format!("{name} must be greater than zero").into());
    }
    Ok(parsed)
}

fn consumer_io(error: impl std::fmt::Display) -> io::Error {
    io::Error::other(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cerebro_source_catalog::SourceCatalog;
    use prost::Message;
    use prost_types::Timestamp;
    use std::collections::HashMap;

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

    fn encoded_event(source_id: &str, kind: &str, schema_ref: &str, payload: Vec<u8>) -> Vec<u8> {
        encoded_event_with_id("event-1", source_id, kind, schema_ref, payload)
    }

    fn encoded_event_with_id(
        id: &str,
        source_id: &str,
        kind: &str,
        schema_ref: &str,
        payload: Vec<u8>,
    ) -> Vec<u8> {
        EventWire {
            id: id.to_owned(),
            tenant_id: "tenant-a".to_owned(),
            source_id: source_id.to_owned(),
            kind: kind.to_owned(),
            occurred_at: Some(Timestamp {
                seconds: 1_720_000_000,
                nanos: 0,
            }),
            schema_ref: schema_ref.to_owned(),
            payload,
            attributes: HashMap::from([("source_runtime_id".to_owned(), "runtime-a".to_owned())]),
        }
        .encode_to_vec()
    }

    #[test]
    fn consumer_starts_at_new_events_and_never_exhausts_delivery() {
        let config = ConsumerConfig {
            nats_url: "nats://localhost:4222".to_owned(),
            stream: DEFAULT_STREAM.to_owned(),
            subject_prefix: DEFAULT_SUBJECT_PREFIX.to_owned(),
            durable_name: DEFAULT_CONSUMER.to_owned(),
            deliver_policy: DeliverPolicy::New,
            mode: ConsumerMode::Forward,
            run_id: "forward-organizational-graph-v1".to_owned(),
            end_sequence_override: None,
            max_messages: None,
            max_runtime: None,
        };
        let pull = config.pull_config();
        assert_eq!(pull.durable_name.as_deref(), Some(DEFAULT_CONSUMER));
        assert_eq!(pull.deliver_policy, DeliverPolicy::New);
        assert_eq!(pull.ack_policy, AckPolicy::Explicit);
        assert_eq!(pull.ack_wait, ACK_WAIT);
        assert_eq!(pull.max_deliver, -1);
        assert_eq!(pull.max_ack_pending, 1);
        assert_eq!(pull.filter_subject, "events.>");
    }

    #[test]
    fn subject_parser_claims_only_source_family_subjects() {
        assert_eq!(
            source_family_from_subject("events.box.content_assets", "events"),
            Some(("box", "content_assets"))
        );
        assert_eq!(
            source_family_from_subject("events.google_workspace.users", "events"),
            Some(("google_workspace", "users"))
        );
        assert_eq!(source_family_from_subject("events.box", "events"), None);
        assert_eq!(
            source_family_from_subject("sec.findings.v1", "events"),
            None
        );
        assert_eq!(source_family_from_subject("events..users", "events"), None);
    }

    #[test]
    fn existing_consumer_must_match_the_hard_delivery_contract() {
        let expected = ConsumerConfig {
            nats_url: "nats://localhost:4222".to_owned(),
            stream: DEFAULT_STREAM.to_owned(),
            subject_prefix: DEFAULT_SUBJECT_PREFIX.to_owned(),
            durable_name: DEFAULT_CONSUMER.to_owned(),
            deliver_policy: DeliverPolicy::New,
            mode: ConsumerMode::Forward,
            run_id: "forward-organizational-graph-v1".to_owned(),
            end_sequence_override: None,
            max_messages: None,
            max_runtime: None,
        }
        .pull_config();
        let mut actual = async_nats::jetstream::consumer::Config {
            durable_name: expected.durable_name.clone(),
            name: expected.name.clone(),
            deliver_policy: expected.deliver_policy,
            ack_policy: expected.ack_policy,
            ack_wait: expected.ack_wait,
            max_deliver: expected.max_deliver,
            filter_subject: expected.filter_subject.clone(),
            max_ack_pending: expected.max_ack_pending,
            ..Default::default()
        };
        assert!(validate_server_config(&actual, &expected).is_ok());
        actual.max_deliver = 5;
        assert!(validate_server_config(&actual, &expected).is_err());
    }

    #[test]
    fn poison_messages_are_rejected_while_transient_failures_are_retried() {
        assert!(
            decode_event(
                b"not-a-source-envelope",
                "box",
                "events.box.users",
                "events",
                true
            )
            .is_err()
        );
        assert_eq!(failure_disposition(false), FailureDisposition::Reject);
        assert_eq!(failure_disposition(true), FailureDisposition::Retry);
    }

    #[test]
    fn compatibility_skips_only_observed_legacy_decode_shapes() {
        let cases = [
            (
                "asset",
                "data_sensitivity",
                EventDecodeError::Boundary(AppendLogDecodeError::Missing(
                    "a source-owned kind in source.family form",
                )),
                "legacy_missing_source_owned_kind",
            ),
            (
                "cerebro",
                "health.jetstream_canary",
                EventDecodeError::CatalogOwnedWithoutEnvelope {
                    subject: "events.cerebro.health.jetstream_canary".to_owned(),
                },
                "legacy_catalog_canary_without_source_envelope",
            ),
        ];
        for (source, family, error, reason) in cases {
            assert_eq!(
                legacy_decode_skip(ConsumerMode::Replay, source, family, &error),
                Some(reason)
            );
            assert_eq!(
                legacy_decode_skip(ConsumerMode::Forward, source, family, &error),
                Some(reason)
            );
        }
        assert_eq!(
            skip_category("legacy_missing_source_owned_kind"),
            ConsumerSkipCategory::LegacyMissingSourceOwnedKind
        );
        assert_eq!(
            skip_category("legacy_invalid_observation_id"),
            ConsumerSkipCategory::LegacyInvalidObservationId
        );
        assert_eq!(
            skip_category("legacy_catalog_canary_without_source_envelope"),
            ConsumerSkipCategory::LegacyCatalogCanaryWithoutSourceEnvelope
        );
        assert_eq!(
            skip_category("legacy_retired_family_projection_incompatible"),
            ConsumerSkipCategory::LegacyRetiredFamilyProjectionIncompatible
        );
    }

    #[test]
    fn gcp_legacy_principals_decode_then_skip_outside_the_compiled_catalog() {
        let cases = [
            (
                "gcp.iam_role_assignment",
                "gcp/iam_role_assignment/v1",
                "gcp-iam-role-assignment-user@example.test-roles-owner",
            ),
            (
                "gcp.iam_role_assignment",
                "gcp/iam_role_assignment/v1",
                "gcp-iam-role-assignment-allUsers-roles-viewer",
            ),
            (
                "gcp.iam_role_assignment",
                "gcp/iam_role_assignment/v1",
                "gcp-iam-role-assignment-allAuthenticatedUsers-roles-viewer",
            ),
            (
                "gcp.iam_role_assignment",
                "gcp/iam_role_assignment/v1",
                "gcp-iam-role-assignment-writer.com-roles-viewer",
            ),
            (
                "gcp.iam_role_assignment",
                "gcp/iam_role_assignment/v1",
                "gcp-iam-role-assignment-principal[workload-identity]-roles-viewer",
            ),
            (
                "gcp.effective_permission",
                "gcp/effective_permission/v1",
                "gcp-effective-permission-user@example.test-roles-owner",
            ),
            (
                "gcp.effective_permission",
                "gcp/effective_permission/v1",
                "gcp-effective-permission-allUsers-roles-viewer",
            ),
            (
                "gcp.effective_permission",
                "gcp/effective_permission/v1",
                "gcp-effective-permission-allAuthenticatedUsers-roles-viewer",
            ),
            (
                "gcp.effective_permission",
                "gcp/effective_permission/v1",
                "gcp-effective-permission-writer.com-roles-viewer",
            ),
            (
                "gcp.effective_permission",
                "gcp/effective_permission/v1",
                "gcp-effective-permission-principal[workload-identity]-roles-viewer",
            ),
        ];

        for (kind, schema_ref, id) in cases {
            let family = kind
                .strip_prefix("gcp.")
                .expect("GCP event kind has a source prefix");
            let payload = encoded_event_with_id(
                id,
                "gcp",
                kind,
                schema_ref,
                br#"{"project_id":"writer-prod"}"#.to_vec(),
            );
            assert!(
                decode_event(
                    &payload,
                    "gcp",
                    &format!("events.gcp.{family}"),
                    "events",
                    true,
                )
                .unwrap()
                .is_some()
            );
            assert_eq!(
                decode_event(
                    &payload,
                    "gcp",
                    &format!("events.gcp.{family}"),
                    "events",
                    false,
                )
                .unwrap(),
                None,
                "decoded compatibility event should be a catalog skip: {id}"
            );
        }
    }

    #[test]
    fn malformed_gcp_legacy_principals_are_rejected_before_catalog_skip() {
        let cases = [
            (
                "gcp.iam_role_assignment",
                "gcp/iam_role_assignment/v1",
                "gcp-iam-role-assignment-user@example.test?",
            ),
            (
                "gcp.iam_role_assignment",
                "gcp/iam_role_assignment/v1",
                "gcp-iam-role-assignment-user\\alias@example.test-roles-owner",
            ),
            (
                "gcp.effective_permission",
                "gcp/effective_permission/v1",
                "gcp-effective-permission-user@example.test-roles-owner?",
            ),
            (
                "gcp.iam_role_assignment",
                "gcp/iam_role_assignment/v1",
                "gcp-iam-role-assignment-principal[workload-identity-roles-owner",
            ),
            (
                "gcp.effective_permission",
                "gcp/effective_permission/v1",
                "gcp-effective-permission-principal[]-roles-owner",
            ),
            (
                "gcp.effective_permission",
                "gcp/effective_permission/v1",
                "gcp-effective-permission-principal[[workload]]-roles-owner",
            ),
        ];
        for (kind, schema_ref, id) in cases {
            let family = kind
                .strip_prefix("gcp.")
                .expect("GCP event kind has a source prefix");
            let payload = encoded_event_with_id(
                id,
                "gcp",
                kind,
                schema_ref,
                br#"{"project_id":"writer-prod"}"#.to_vec(),
            );
            assert!(
                matches!(
                    decode_event(
                        &payload,
                        "gcp",
                        &format!("events.gcp.{family}"),
                        "events",
                        false,
                    ),
                    Err(EventDecodeError::Boundary(
                        AppendLogDecodeError::InvalidModel(message)
                    )) if message == "observation id is invalid"
                ),
                "malformed compatibility event must reject: {id}"
            );
        }
    }

    #[test]
    fn invalid_observation_ids_are_not_replay_only_skips() {
        let error = EventDecodeError::Boundary(AppendLogDecodeError::InvalidModel(
            "observation id is invalid".to_owned(),
        ));
        for (source, family) in [
            ("gcp", "iam_role_assignment"),
            ("gcp", "effective_permission"),
            ("aws", "public_endpoint"),
        ] {
            assert_eq!(
                legacy_decode_skip(ConsumerMode::Replay, source, family, &error),
                None
            );
            assert_eq!(
                legacy_decode_skip(ConsumerMode::Forward, source, family, &error),
                None
            );
        }
    }

    #[test]
    fn legacy_decode_skip_does_not_widen_the_boundary() {
        let invalid_observation = EventDecodeError::Boundary(AppendLogDecodeError::InvalidModel(
            "observation id is invalid".to_owned(),
        ));
        assert_eq!(
            legacy_decode_skip(
                ConsumerMode::Replay,
                "gcp",
                "project_bindings",
                &invalid_observation,
            ),
            None
        );
        assert_eq!(
            legacy_decode_skip(
                ConsumerMode::Replay,
                "aws",
                "public_endpoint",
                &EventDecodeError::Boundary(AppendLogDecodeError::InvalidModel(
                    "tenant id is invalid".to_owned(),
                )),
            ),
            None
        );
        assert_eq!(
            legacy_decode_skip(
                ConsumerMode::Replay,
                "asset",
                "data_sensitivity",
                &EventDecodeError::Boundary(AppendLogDecodeError::Missing("tenant_id")),
            ),
            None
        );
        assert_eq!(
            legacy_decode_skip(
                ConsumerMode::Replay,
                "cerebro",
                "health.jetstream_canary",
                &EventDecodeError::Boundary(AppendLogDecodeError::Protobuf(
                    "invalid wire type".to_owned(),
                )),
            ),
            None
        );
    }

    #[test]
    fn exact_lifecycle_contract_bypasses_catalog_while_unknown_sources_do_not() {
        let lifecycle = encoded_event(
            "expiry_tracker",
            "security.credential.lifecycle",
            "cerebro/security/credential-lifecycle/v1",
            vec![0x0a, 0x00],
        );
        let admitted = decode_event(
            &lifecycle,
            "security",
            "events.security.credential.lifecycle",
            "events",
            false,
        )
        .unwrap();
        assert!(admitted.is_some());
        assert!(
            decode_event(
                &lifecycle,
                "security",
                "events.security.lifecycle",
                "events",
                false,
            )
            .is_err()
        );

        let unknown = encoded_event(
            "unknown",
            "unknown.assets",
            "unknown/assets/v1",
            br#"{"id":"asset-1"}"#.to_vec(),
        );
        assert!(
            decode_event(
                &unknown,
                "unknown",
                "events.unknown.assets",
                "events",
                false,
            )
            .unwrap()
            .is_none()
        );
    }

    #[test]
    fn trusted_endpoint_push_contract_prevents_catalog_absence_skip() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap();
        let catalog = SourceCatalog::load(
            root.join("internal/connectorcatalog/catalog"),
            root.join("sources"),
        )
        .unwrap();
        assert!(catalog.get("trusted_endpoint").is_none());

        let payload = encoded_event(
            "trusted_endpoint",
            "trusted_endpoint.host_posture",
            "trusted_endpoint/host_posture/v1",
            br#"{"agent_id":"device-1","observation_table":"host_posture"}"#.to_vec(),
        );
        let admitted = catalog.admits_event_family("trusted_endpoint", "host_posture");
        assert!(admitted);
        assert!(
            decode_event(
                &payload,
                "trusted_endpoint",
                "events.trusted_endpoint.host_posture",
                "events",
                admitted,
            )
            .unwrap()
            .is_some()
        );

        assert!(!catalog.admits_event_family("trusted_endpoint", "unknown"));
    }

    #[test]
    fn replay_policies_preserve_an_explicit_start_boundary() {
        let all = ConsumerConfig {
            nats_url: "nats://localhost:4222".to_owned(),
            stream: DEFAULT_STREAM.to_owned(),
            subject_prefix: DEFAULT_SUBJECT_PREFIX.to_owned(),
            durable_name: "organizational-graph-bootstrap".to_owned(),
            deliver_policy: DeliverPolicy::All,
            mode: ConsumerMode::Replay,
            run_id: "bootstrap-20260729".to_owned(),
            end_sequence_override: None,
            max_messages: Some(100),
            max_runtime: Some(Duration::from_secs(60)),
        }
        .pull_config();
        assert_eq!(all.deliver_policy, DeliverPolicy::All);

        let from_sequence = ConsumerConfig {
            nats_url: "nats://localhost:4222".to_owned(),
            stream: DEFAULT_STREAM.to_owned(),
            subject_prefix: DEFAULT_SUBJECT_PREFIX.to_owned(),
            durable_name: "organizational-graph-replay-42".to_owned(),
            deliver_policy: DeliverPolicy::ByStartSequence { start_sequence: 42 },
            mode: ConsumerMode::Replay,
            run_id: "replay-42".to_owned(),
            end_sequence_override: Some(50),
            max_messages: Some(100),
            max_runtime: Some(Duration::from_secs(60)),
        }
        .pull_config();
        assert_eq!(
            from_sequence.deliver_policy,
            DeliverPolicy::ByStartSequence { start_sequence: 42 }
        );
        assert!(
            validate_delivery_identity(
                ConsumerMode::Replay,
                DeliverPolicy::All,
                DEFAULT_CONSUMER,
                "bootstrap-20260729",
            )
            .is_err()
        );
        assert!(
            validate_delivery_identity(
                ConsumerMode::Replay,
                DeliverPolicy::ByStartSequence { start_sequence: 42 },
                "organizational-graph-replay-42",
                "replay-42",
            )
            .is_ok()
        );
        assert!(
            validate_delivery_identity(
                ConsumerMode::Forward,
                DeliverPolicy::ByStartSequence { start_sequence: 43 },
                "organizational-graph-forward-v1",
                "forward-handoff-42",
            )
            .is_ok()
        );
    }

    #[test]
    fn replay_start_sequence_accepts_operator_whitespace() {
        assert_eq!(
            parse_required_u64("CEREBRO_ORGANIZATIONAL_CONSUMER_START_SEQUENCE", " 42 \n")
                .expect("whitespace-wrapped sequence"),
            42
        );
        assert!(
            parse_required_u64("CEREBRO_ORGANIZATIONAL_CONSUMER_START_SEQUENCE", " 0 ").is_err()
        );
    }

    #[test]
    fn replay_completion_accepts_filtered_sequence_gaps_only_after_consumer_drain() {
        let config = ConsumerConfig {
            nats_url: "nats://localhost:4222".to_owned(),
            stream: DEFAULT_STREAM.to_owned(),
            subject_prefix: DEFAULT_SUBJECT_PREFIX.to_owned(),
            durable_name: "organizational-graph-replay".to_owned(),
            deliver_policy: DeliverPolicy::All,
            mode: ConsumerMode::Replay,
            run_id: "replay-gap-proof".to_owned(),
            end_sequence_override: Some(50),
            max_messages: Some(100),
            max_runtime: Some(Duration::from_secs(60)),
        };
        assert!(!replay_drained(&config, Some(50), 41, 1));
        assert!(replay_drained(&config, Some(50), 41, 0));
        assert!(replay_drained(&config, Some(50), 50, 10));
    }

    #[test]
    fn replay_resume_rejects_expired_unprocessed_sequences() {
        assert_eq!(next_unprocessed_sequence(10, 0), 10);
        assert_eq!(next_unprocessed_sequence(10, 41), 42);
        assert!(retention_gap(43, 42, Some(50)));
        assert!(!retention_gap(42, 42, Some(50)));
        assert!(!retention_gap(51, 51, Some(50)));
        assert!(!retention_gap(43, 42, None));
    }

    #[test]
    fn run_receipt_is_machine_readable_and_accounts_for_skips() {
        let counters = ConsumerCounters {
            last_delivered_sequence: 41,
            covered_sequence: 41,
            messages_seen: 3,
            messages_projected: 1,
            messages_skipped: 2,
            messages_rejected: 0,
        };
        let skip_categories = BTreeMap::from([
            ("legacy_invalid_observation_id".to_owned(), 1),
            ("legacy_missing_source_owned_kind".to_owned(), 1),
        ]);
        let receipt = ConsumerReceipt {
            schema_version: "cerebro.organizational-consumer-run/v1",
            status: "completed",
            mode: ConsumerMode::Replay,
            stream: DEFAULT_STREAM,
            filter_subject: "events.>".to_owned(),
            consumer_name: "organizational-graph-replay",
            run_id: "replay-gap-proof",
            start_sequence: 1,
            end_sequence: Some(50),
            covered_sequence: 50,
            last_delivered_sequence: 41,
            completion_basis: Some("zero_eligible_pending"),
            counters: &counters,
            skip_categories: &skip_categories,
        };
        let value = serde_json::to_value(receipt).unwrap();
        assert_eq!(value["status"], "completed");
        assert_eq!(value["end_sequence"], 50);
        assert_eq!(value["covered_sequence"], 50);
        assert_eq!(value["counters"]["messages_skipped"], 2);
        assert_eq!(value["counters"]["messages_rejected"], 0);
        assert_eq!(
            value["skip_categories"],
            serde_json::json!({
                "legacy_invalid_observation_id": 1,
                "legacy_missing_source_owned_kind": 1,
            })
        );
    }

    #[test]
    fn run_receipt_skip_categories_fail_closed() {
        let cases = [
            (2, BTreeMap::new()),
            (
                2,
                BTreeMap::from([(
                    "legacy_catalog_canary_without_source_envelope".to_owned(),
                    1,
                )]),
            ),
            (1, BTreeMap::from([("unknown".to_owned(), 1)])),
            (
                4,
                BTreeMap::from([
                    (
                        "legacy_catalog_canary_without_source_envelope".to_owned(),
                        1,
                    ),
                    ("legacy_invalid_observation_id".to_owned(), 1),
                    ("legacy_missing_source_owned_kind".to_owned(), 1),
                    (
                        "legacy_retired_family_projection_incompatible".to_owned(),
                        1,
                    ),
                    ("source_outside_compiled_catalog".to_owned(), 1),
                    ("subject_outside_projection_contract".to_owned(), 1),
                    ("unknown".to_owned(), 1),
                ]),
            ),
        ];
        for (messages_skipped, categories) in cases {
            assert!(
                validate_receipt_skip_categories(messages_skipped, &categories).is_err(),
                "unexpected categories {categories:?}"
            );
        }
        assert!(validate_receipt_skip_categories(0, &BTreeMap::new()).is_ok());
    }

    #[test]
    fn diagnostic_identity_is_derived_from_ecs_metadata() {
        let image_digest =
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        for family in [
            "cerebro-test-rust-platform",
            "cerebro-test-rust-platform-replay",
        ] {
            let identity = DiagnosticIdentity::from_metadata(
                EcsContainerMetadata {
                    image_id: image_digest.to_owned(),
                },
                EcsTaskMetadata {
                    task_arn: "arn:aws:ecs:us-east-1:123456789012:task/cerebro-test/task-id"
                        .to_owned(),
                    family: family.to_owned(),
                    revision: "28".to_owned(),
                },
            )
            .unwrap();
            assert_eq!(
                identity.task_definition,
                format!("arn:aws:ecs:us-east-1:123456789012:task-definition/{family}:28")
            );
            assert_eq!(identity.environment, "test");
        }
        assert!(
            DiagnosticIdentity::from_metadata(
                EcsContainerMetadata {
                    image_id: image_digest.to_owned(),
                },
                EcsTaskMetadata {
                    task_arn: "arn:aws:ecs:us-east-1:123456789012:task/other/task-id".to_owned(),
                    family: "unbound-family".to_owned(),
                    revision: "1".to_owned(),
                },
            )
            .is_err()
        );
        assert!(
            DiagnosticIdentity::from_metadata(
                EcsContainerMetadata {
                    image_id: image_digest.to_owned(),
                },
                EcsTaskMetadata {
                    task_arn: "arn:aws:ecs:us-east-1:123456789012:task/other/task-id".to_owned(),
                    family: "cerebro-test-rust-platform-replay-other".to_owned(),
                    revision: "1".to_owned(),
                },
            )
            .is_err()
        );
        assert!(reject_environment_claim(Some(std::ffi::OsStr::new("injected"))).is_err());
    }

    #[test]
    fn diagnostics_are_bounded_payload_free_and_digest_bound() {
        assert_eq!(
            digest_bytes(b"abc"),
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let identity = DiagnosticIdentity {
            environment: "test".to_owned(),
            task_definition: "arn:aws:ecs:us-east-1:123456789012:task-definition/cerebro-rust:28"
                .to_owned(),
            image_digest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_owned(),
        };
        let config = ConsumerConfig {
            nats_url: "nats://localhost:4222".to_owned(),
            stream: DEFAULT_STREAM.to_owned(),
            subject_prefix: DEFAULT_SUBJECT_PREFIX.to_owned(),
            durable_name: "organizational-graph-forward".to_owned(),
            deliver_policy: DeliverPolicy::New,
            mode: ConsumerMode::Forward,
            run_id: "forward-cutover-v4".to_owned(),
            end_sequence_override: None,
            max_messages: None,
            max_runtime: None,
        };
        let message_digest = digest_bytes(b"sensitive wire payload");
        let record_digest = digest_bytes(b"committed record");
        let value = serde_json::to_value(diagnostic_event(
            &identity,
            &config,
            42,
            "okta",
            "threat_insight",
            "projection_rejected",
            "stored_record_conflict",
            &message_digest,
            Some(&record_digest),
        ))
        .unwrap();
        assert_eq!(value["schema_version"], DIAGNOSTIC_SCHEMA_VERSION);
        assert_eq!(value["consumer_name"], config.durable_name);
        assert_eq!(value["consumer_run_id"], config.run_id);
        assert_eq!(value["stream_sequence"], 42);
        assert_eq!(value["message_sha256"], message_digest);
        assert_eq!(value["record_digest"], record_digest);
        assert!(
            value["event_identity_sha256"]
                .as_str()
                .is_some_and(|digest| digest.len() == 71 && digest.starts_with("sha256:"))
        );
        let encoded = serde_json::to_string(&value).unwrap();
        for forbidden in [
            "sensitive wire payload",
            "tenant_id",
            "payload",
            "authorization",
            "root_urn",
            "raw_error",
            "incoming_record_digest",
            "stored_record_digest",
        ] {
            assert!(!encoded.contains(forbidden), "unexpected {forbidden}");
        }
    }

    #[test]
    fn committed_record_digest_uses_the_diagnostic_sha256_contract() {
        let event = CommittedSourceEvent::decode(&encoded_event(
            "box",
            "box.content_assets",
            "box/content_assets/v1",
            br#"{"id":"file-1"}"#.to_vec(),
        ))
        .unwrap()
        .unwrap();

        let digest = diagnostic_record_digest(&event);
        assert_eq!(digest, format!("sha256:{}", event.record_digest()));
        assert_eq!(digest.len(), 71);
        assert!(digest.starts_with("sha256:"));
        assert!(
            digest[7..]
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
    }

    #[test]
    fn checkpoint_is_only_eligible_after_a_recognized_projection() {
        assert!(checkpoint_eligible(ConsumerMessageOutcome::Projected));
        assert!(!checkpoint_eligible(ConsumerMessageOutcome::Skipped(
            ConsumerSkipCategory::LegacyMissingSourceOwnedKind,
        )));
        assert!(!checkpoint_eligible(ConsumerMessageOutcome::Rejected));
        let raw = b"projected append-log bytes";
        let actual = digest_bytes(raw);
        assert_eq!(checkpoint_message_sha256(&actual), digest_bytes(raw));
    }

    #[test]
    fn diagnostic_cap_suppresses_output_without_failing_processing() {
        let mut emitter = DiagnosticEmitter {
            identity: Some(DiagnosticIdentity {
                environment: "test".to_owned(),
                task_definition:
                    "arn:aws:ecs:us-east-1:123456789012:task-definition/cerebro-test-rust-platform:1"
                        .to_owned(),
                image_digest:
                    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                        .to_owned(),
            }),
            emitted: DIAGNOSTIC_EVENT_LIMIT,
            checkpoint_emitted: false,
            retry_emitted: false,
        };
        let config = ConsumerConfig {
            nats_url: "nats://localhost:4222".to_owned(),
            stream: DEFAULT_STREAM.to_owned(),
            subject_prefix: DEFAULT_SUBJECT_PREFIX.to_owned(),
            durable_name: "organizational-graph-forward".to_owned(),
            deliver_policy: DeliverPolicy::New,
            mode: ConsumerMode::Forward,
            run_id: "forward-cutover-v4".to_owned(),
            end_sequence_override: None,
            max_messages: None,
            max_runtime: None,
        };
        assert!(
            emitter
                .emit(
                    &config,
                    1_025,
                    "okta",
                    "application",
                    "projection_rejected",
                    "invalid_entity_label",
                    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                    None,
                )
                .is_ok()
        );
        assert_eq!(emitter.emitted, DIAGNOSTIC_EVENT_LIMIT);
    }

    #[test]
    fn retry_observability_is_bounded_digest_only() {
        let identity = DiagnosticIdentity {
            environment: "test".to_owned(),
            task_definition:
                "arn:aws:ecs:us-east-1:123456789012:task-definition/cerebro-test-rust-platform:1"
                    .to_owned(),
            image_digest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_owned(),
        };
        let config = ConsumerConfig {
            nats_url: "nats://localhost:4222".to_owned(),
            stream: DEFAULT_STREAM.to_owned(),
            subject_prefix: DEFAULT_SUBJECT_PREFIX.to_owned(),
            durable_name: "organizational-graph-forward".to_owned(),
            deliver_policy: DeliverPolicy::New,
            mode: ConsumerMode::Forward,
            run_id: "forward-cutover-v4".to_owned(),
            end_sequence_override: None,
            max_messages: None,
            max_runtime: None,
        };
        let digest = digest_bytes(b"secret retry payload");
        let value = retry_event(&identity, &config, 42, &digest);
        let encoded = serde_json::to_string(&value).unwrap();
        assert_eq!(value["message_sha256"], digest);
        assert!(!encoded.contains("secret retry payload"));
        assert!(value.get("error").is_none());
        let mut emitter = DiagnosticEmitter {
            identity: Some(identity),
            emitted: 0,
            checkpoint_emitted: false,
            retry_emitted: false,
        };
        assert!(!emitter.retry_emitted);
        assert!(emitter.emit_retry(&config, 42, &digest).unwrap());
        assert!(emitter.retry_emitted);
        assert!(!emitter.emit_retry(&config, 42, &digest).unwrap());
        assert!(emitter.retry_emitted);
    }

    #[test]
    fn redelivery_identity_is_idempotent_and_conflicting_material_is_distinct() {
        let config = ConsumerConfig {
            nats_url: "nats://localhost:4222".to_owned(),
            stream: DEFAULT_STREAM.to_owned(),
            subject_prefix: DEFAULT_SUBJECT_PREFIX.to_owned(),
            durable_name: "organizational-graph-forward".to_owned(),
            deliver_policy: DeliverPolicy::New,
            mode: ConsumerMode::Forward,
            run_id: "forward-cutover-v4".to_owned(),
            end_sequence_override: None,
            max_messages: None,
            max_runtime: None,
        };
        let message = digest_bytes(b"same redelivered message");
        let first = diagnostic_identity_digest(&config, 42, "invalid_entity_label", &message);
        let after_restart =
            diagnostic_identity_digest(&config, 42, "invalid_entity_label", &message);
        let conflicting = diagnostic_identity_digest(
            &config,
            42,
            "invalid_entity_label",
            &digest_bytes(b"different redelivery material"),
        );
        assert_eq!(first, after_restart);
        assert_ne!(first, conflicting);
    }

    #[test]
    fn diagnostic_categories_do_not_change_failure_disposition() {
        let conflict =
            crate::ProjectionFailure::Store(cerebro_organizational_store::StoreError::Conflict(
                "source event digest-id conflicts with the stored record".to_owned(),
            ));
        assert_eq!(
            projection_error_category("okta", "threat_insight", &conflict),
            Some("stored_record_conflict")
        );
        assert_eq!(
            failure_disposition(conflict.is_retryable()),
            FailureDisposition::Reject
        );
        assert_eq!(
            projection_error_category("okta", "application", &conflict),
            None
        );
        assert_eq!(
            decode_error_category(&EventDecodeError::Boundary(
                AppendLogDecodeError::InvalidModel("observation id is invalid".to_owned())
            )),
            Some("invalid_observation_id")
        );
    }
}
