use std::fmt;

/// Errors returned by the ip-api.io client.
///
/// The client never retries; [`Error::RateLimit`]'s `reset` field is the unix
/// timestamp when the quota renews.
#[derive(Debug)]
pub enum Error {
    /// HTTP 401/403 — missing or invalid API key.
    Authentication {
        status: u16,
        message: String,
        body: String,
    },
    /// HTTP 429 — quota exhausted, with the x-ratelimit-* header values.
    RateLimit {
        status: u16,
        message: String,
        body: String,
        limit: Option<i64>,
        remaining: Option<i64>,
        reset: Option<i64>,
    },
    /// HTTP 400/404/422 — malformed input or unknown resource.
    InvalidRequest {
        status: u16,
        message: String,
        body: String,
    },
    /// HTTP 5xx — ip-api.io server-side failure.
    Server {
        status: u16,
        message: String,
        body: String,
    },
    /// Any other non-2xx response.
    Api {
        status: u16,
        message: String,
        body: String,
    },
    /// Transport-level failure (DNS, connect, timeout, TLS, JSON decoding).
    Transport(reqwest::Error),
    /// Invalid argument detected before any network call (e.g. oversized batch).
    InvalidArgument(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Authentication { status, message, .. }
            | Error::InvalidRequest { status, message, .. }
            | Error::Server { status, message, .. }
            | Error::Api { status, message, .. } => {
                write!(f, "ip-api.io: {message} (HTTP {status})")
            }
            Error::RateLimit {
                status,
                message,
                limit,
                remaining,
                reset,
                ..
            } => write!(
                f,
                "ip-api.io: {message} (HTTP {status}, limit={limit:?}, remaining={remaining:?}, reset={reset:?})"
            ),
            Error::Transport(inner) => write!(f, "ip-api.io: transport error: {inner}"),
            Error::InvalidArgument(message) => write!(f, "ip-api.io: {message}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Transport(inner) => Some(inner),
            _ => None,
        }
    }
}

impl From<reqwest::Error> for Error {
    fn from(inner: reqwest::Error) -> Self {
        Error::Transport(inner)
    }
}

pub(crate) fn classify(status: u16, message: String, body: String) -> Error {
    match status {
        401 | 403 => Error::Authentication {
            status,
            message,
            body,
        },
        400 | 404 | 422 => Error::InvalidRequest {
            status,
            message,
            body,
        },
        500..=599 => Error::Server {
            status,
            message,
            body,
        },
        _ => Error::Api {
            status,
            message,
            body,
        },
    }
}

pub(crate) fn extract_message(status: u16, body: &str) -> String {
    let message = match serde_json::from_str::<serde_json::Value>(body) {
        Ok(serde_json::Value::Object(map)) => map
            .get("message")
            .or_else(|| map.get("error"))
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .to_string(),
        Ok(_) => String::new(),
        Err(_) => body.trim().chars().take(200).collect(),
    };
    if message.is_empty() {
        format!("HTTP {status} from ip-api.io")
    } else {
        message
    }
}
