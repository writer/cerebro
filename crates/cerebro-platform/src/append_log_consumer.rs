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

#[derive(Clone, Debug, Eq, PartialEq)]
struct ConsumerConfig {
    nats_url: String,
    stream: String,
    subject_prefix: String,
    durable_name: String,
}

impl ConsumerConfig {
    fn from_env() -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            nats_url: required("CEREBRO_JETSTREAM_URL")?,
            stream: optional("CEREBRO_JETSTREAM_STREAM_NAME", DEFAULT_STREAM),
            subject_prefix: optional("CEREBRO_JETSTREAM_SUBJECT_PREFIX", DEFAULT_SUBJECT_PREFIX),
            durable_name: optional("CEREBRO_ORGANIZATIONAL_CONSUMER_NAME", DEFAULT_CONSUMER),
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
            deliver_policy: DeliverPolicy::New,
            ack_policy: AckPolicy::Explicit,
            ack_wait: ACK_WAIT,
            max_deliver: -1,
            filter_subject: self.filter_subject(),
            max_ack_pending: 1,
            ..Default::default()
        }
    }
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
        if runtime.catalog.get(subject_source).is_none() {
            message.double_ack().await.map_err(consumer_io)?;
            continue;
        }
        let event = match CommittedSourceEvent::decode(&message.message.payload) {
            Ok(Some(event)) if event.source_id() == subject_source => event,
            Ok(Some(event)) => {
                message
                    .ack_with(AckKind::Nak(Some(RETRY_DELAY)))
                    .await
                    .map_err(consumer_io)?;
                return Err(format!(
                    "append-log subject source {subject_source} does not match envelope source {}",
                    event.source_id()
                )
                .into());
            }
            Ok(None) => {
                message
                    .ack_with(AckKind::Nak(Some(RETRY_DELAY)))
                    .await
                    .map_err(consumer_io)?;
                return Err(format!(
                    "append-log subject {subject} is catalog-owned but has no source envelope"
                )
                .into());
            }
            Err(error) => {
                message
                    .ack_with(AckKind::Nak(Some(RETRY_DELAY)))
                    .await
                    .map_err(consumer_io)?;
                return Err(format!(
                    "append-log subject {subject} failed the committed source boundary: {error}"
                )
                .into());
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
            Err(error) if error.is_retryable() => {
                eprintln!(
                    "organizational append-log projection retry subject={subject} error={error}"
                );
                message
                    .ack_with(AckKind::Nak(Some(RETRY_DELAY)))
                    .await
                    .map_err(consumer_io)?;
            }
            Err(error) => {
                message
                    .ack_with(AckKind::Nak(Some(RETRY_DELAY)))
                    .await
                    .map_err(consumer_io)?;
                return Err(format!(
                    "append-log subject {subject} violates the compiled projection contract: {error}"
                )
                .into());
            }
        }
    }
    Err("organizational append-log consumer stopped receiving messages".into())
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

fn consumer_io(error: impl std::fmt::Display) -> io::Error {
    io::Error::other(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consumer_starts_at_new_events_and_never_exhausts_delivery() {
        let config = ConsumerConfig {
            nats_url: "nats://localhost:4222".to_owned(),
            stream: DEFAULT_STREAM.to_owned(),
            subject_prefix: DEFAULT_SUBJECT_PREFIX.to_owned(),
            durable_name: DEFAULT_CONSUMER.to_owned(),
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
}
