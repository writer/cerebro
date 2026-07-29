use std::{error::Error, fmt};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SdkError {
    Empty(&'static str),
    Invalid(&'static str),
    TooLong(&'static str),
    OutOfRange(&'static str),
    Conflict(String),
    NotFound(String),
    CapabilityUnavailable(String),
    Backend(String),
}

impl fmt::Display for SdkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty(field) => write!(formatter, "{field} is required"),
            Self::Invalid(field) => write!(formatter, "{field} is invalid"),
            Self::TooLong(field) => write!(formatter, "{field} exceeds its size limit"),
            Self::OutOfRange(field) => write!(formatter, "{field} is outside its allowed range"),
            Self::Conflict(message) => write!(formatter, "platform conflict: {message}"),
            Self::NotFound(message) => write!(formatter, "platform value not found: {message}"),
            Self::CapabilityUnavailable(message) => {
                write!(formatter, "platform capability unavailable: {message}")
            }
            Self::Backend(message) => write!(formatter, "platform backend failed: {message}"),
        }
    }
}

impl Error for SdkError {}
