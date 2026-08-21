use std::{error::Error, fmt};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum WorkerError {
    Protobuf,
    InvalidPlan,
    UnsupportedStatus,
    ResponseTooLarge,
    MissingExecutionIdentity,
    InvalidProviderResponse,
}

impl fmt::Display for WorkerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Protobuf => "source_worker.protobuf: input or output protobuf is invalid",
            Self::InvalidPlan => "source_worker.invalid_plan: compiled plan is invalid",
            Self::UnsupportedStatus => "source_worker.unsupported_status: provider response status is not allowed",
            Self::ResponseTooLarge => "source_worker.response_too_large: provider response exceeds the compiled bound",
            Self::MissingExecutionIdentity => "source_worker.missing_execution_identity: execution identity or safe receipt is missing",
            Self::InvalidProviderResponse => "source_worker.invalid_provider_response: provider response is invalid",
        })
    }
}

impl Error for WorkerError {}
