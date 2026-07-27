use std::{env, error::Error, io, sync::Arc, time::Duration};

use async_nats::jetstream::{
    AckKind,
    consumer::{AckPolicy, DeliverPolicy, pull},
};
use cerebro_source_runtime_next::CommittedSourceEvent;
use futures_util::StreamExt;

use crate::{ProjectionAuthority, ProjectionRuntime};

const DEFAULT_STREAM: &str = "CEREBRO_EVENTS";
const DEFAULT_SUBJECT_PREFIX: &str = "events";
const DEFAULT_CONSUMER: &str = "organizational-graph-v1";
const ACK_WAIT: Duration = Duration::from_secs(120);
const RETRY_DELAY: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FailureDisposition {
    Retry,
    Reject,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ConsumerConfig {
    nats_url: String,
    stream: String,
    subject_prefix: String,
    durable_name: String,
    deliver_policy: DeliverPolicy,
}

impl ConsumerConfig {
    fn from_env() -> Result<Self, Box<dyn Error>> {
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
        validate_delivery_identity(deliver_policy, &durable_name)?;
        Ok(Self {
            nats_url: required("CEREBRO_JETSTREAM_URL")?,
            stream: optional("CEREBRO_JETSTREAM_STREAM_NAME", DEFAULT_STREAM),
            subject_prefix: optional("CEREBRO_JETSTREAM_SUBJECT_PREFIX", DEFAULT_SUBJECT_PREFIX),
            durable_name,
            deliver_policy,
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
    deliver_policy: DeliverPolicy,
    durable_name: &str,
) -> Result<(), Box<dyn Error>> {
    if deliver_policy != DeliverPolicy::New && durable_name == DEFAULT_CONSUMER {
        return Err(
            "replay delivery requires an explicit CEREBRO_ORGANIZATIONAL_CONSUMER_NAME".into(),
        );
    }
    Ok(())
}

pub(crate) async fn run(runtime: Arc<ProjectionRuntime>) -> Result<(), Box<dyn Error>> {
    let config = ConsumerConfig::from_env()?;
    let client = async_nats::connect(&config.nats_url).await?;
    let jetstream = async_nats::jetstream::new(client);
    let stream = jetstream.get_stream(&config.stream).await?;
    let expected = config.pull_config();
    let consumer = stream
        .get_or_create_consumer(&config.durable_name, expected.clone())
        .await?;
    let actual = consumer.get_info().await?;
    validate_server_config(&actual.config, &expected)?;
    println!(
        "organizational append-log consumer ready stream={} consumer={} filter={}",
        config.stream,
        config.durable_name,
        config.filter_subject()
    );
    let mut messages = consumer.messages().await?;
    while let Some(next) = messages.next().await {
        let message = next?;
        let subject = message.message.subject.to_string();
        let Some(subject_source) = source_from_subject(&subject, &config.subject_prefix) else {
            message.double_ack().await.map_err(consumer_io)?;
            continue;
        };
        let event = match decode_event(
            &message.message.payload,
            subject_source,
            &subject,
            &config.subject_prefix,
            runtime.catalog.get(subject_source).is_some(),
        ) {
            Ok(Some(event)) => event,
            Ok(None) => {
                message.double_ack().await.map_err(consumer_io)?;
                continue;
            }
            Err(error) => {
                eprintln!("organizational append-log message rejected: {error}");
                message.double_ack().await.map_err(consumer_io)?;
                continue;
            }
        };
        match runtime.project_committed(event).await {
            Ok(response) => {
                message.double_ack().await.map_err(consumer_io)?;
                if response.authority == ProjectionAuthority::Rust {
                    println!(
                        "organizational append-log projection committed subject={} revision={} entities={} assertions={}",
                        subject,
                        response.graph_revision.unwrap_or_default(),
                        response.entities_upserted,
                        response.assertions_upserted
                    );
                }
            }
            Err(error) => match failure_disposition(error.is_retryable()) {
                FailureDisposition::Retry => {
                    eprintln!(
                        "organizational append-log projection retry subject={subject} error={error}"
                    );
                    message
                        .ack_with(AckKind::Nak(Some(RETRY_DELAY)))
                        .await
                        .map_err(consumer_io)?;
                }
                FailureDisposition::Reject => {
                    eprintln!(
                        "organizational append-log projection rejected subject={subject} error={error}"
                    );
                    message.double_ack().await.map_err(consumer_io)?;
                }
            },
        }
    }
    Err("organizational append-log consumer stopped receiving messages".into())
}

fn decode_event(
    payload: &[u8],
    subject_source: &str,
    subject: &str,
    subject_prefix: &str,
    catalog_source_known: bool,
) -> Result<Option<CommittedSourceEvent>, String> {
    match CommittedSourceEvent::decode(payload) {
        Ok(Some(event))
            if event.is_portable_security_lifecycle()
                && subject == format!("{subject_prefix}.{}", event.event_kind()) =>
        {
            Ok(Some(event))
        }
        Ok(Some(event)) if event.is_portable_security_lifecycle() => Err(format!(
            "append-log lifecycle event {} must use subject {subject_prefix}.{}",
            event.event_kind(),
            event.event_kind()
        )),
        Ok(Some(_)) if !catalog_source_known => Ok(None),
        Ok(Some(event)) if event.source_id() == subject_source => Ok(Some(event)),
        Ok(Some(event)) => Err(format!(
            "append-log subject source {subject_source} does not match envelope source {}",
            event.source_id()
        )),
        Ok(None) => Err(format!(
            "append-log subject {subject} is catalog-owned but has no source envelope"
        )),
        Err(error) => Err(format!(
            "append-log subject {subject} failed the committed source boundary: {error}"
        )),
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

fn source_from_subject<'a>(subject: &'a str, prefix: &str) -> Option<&'a str> {
    let remainder = subject.strip_prefix(prefix)?.strip_prefix('.')?;
    let (source, family) = remainder.split_once('.')?;
    if source.is_empty() || family.is_empty() {
        None
    } else {
        Some(source)
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
        EventWire {
            id: "event-1".to_owned(),
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
            source_from_subject("events.box.content_assets", "events"),
            Some("box")
        );
        assert_eq!(
            source_from_subject("events.google_workspace.users", "events"),
            Some("google_workspace")
        );
        assert_eq!(source_from_subject("events.box", "events"), None);
        assert_eq!(source_from_subject("sec.findings.v1", "events"), None);
        assert_eq!(source_from_subject("events..users", "events"), None);
    }

    #[test]
    fn existing_consumer_must_match_the_hard_delivery_contract() {
        let expected = ConsumerConfig {
            nats_url: "nats://localhost:4222".to_owned(),
            stream: DEFAULT_STREAM.to_owned(),
            subject_prefix: DEFAULT_SUBJECT_PREFIX.to_owned(),
            durable_name: DEFAULT_CONSUMER.to_owned(),
            deliver_policy: DeliverPolicy::New,
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
    fn replay_policies_preserve_an_explicit_start_boundary() {
        let all = ConsumerConfig {
            nats_url: "nats://localhost:4222".to_owned(),
            stream: DEFAULT_STREAM.to_owned(),
            subject_prefix: DEFAULT_SUBJECT_PREFIX.to_owned(),
            durable_name: "organizational-graph-bootstrap".to_owned(),
            deliver_policy: DeliverPolicy::All,
        }
        .pull_config();
        assert_eq!(all.deliver_policy, DeliverPolicy::All);

        let from_sequence = ConsumerConfig {
            nats_url: "nats://localhost:4222".to_owned(),
            stream: DEFAULT_STREAM.to_owned(),
            subject_prefix: DEFAULT_SUBJECT_PREFIX.to_owned(),
            durable_name: "organizational-graph-replay-42".to_owned(),
            deliver_policy: DeliverPolicy::ByStartSequence { start_sequence: 42 },
        }
        .pull_config();
        assert_eq!(
            from_sequence.deliver_policy,
            DeliverPolicy::ByStartSequence { start_sequence: 42 }
        );
        assert!(validate_delivery_identity(DeliverPolicy::All, DEFAULT_CONSUMER).is_err());
        assert!(
            validate_delivery_identity(
                DeliverPolicy::ByStartSequence { start_sequence: 42 },
                "organizational-graph-replay-42",
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
}
