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
            Self::Protobuf => "source worker protobuf is invalid",
            Self::InvalidPlan => "source worker plan is invalid",
            Self::UnsupportedStatus => "source worker response status is not allowed",
            Self::ResponseTooLarge => "source worker response exceeds the compiled bound",
            Self::MissingExecutionIdentity => "source worker execution identity is missing",
            Self::InvalidProviderResponse => "source worker provider response is invalid",
        })
    }
}

impl Error for WorkerError {}
