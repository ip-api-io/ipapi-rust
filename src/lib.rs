//! Official Rust client for the [ip-api.io](https://ip-api.io) IP intelligence
//! and email validation API: IP geolocation, email validation, fraud detection
//! and risk scoring, VPN/proxy/Tor detection, ASN lookup, WHOIS, DNS and
//! domain age.
//!
//! Get a free API key at <https://ip-api.io>.
//!
//! ```no_run
//! # async fn run() -> Result<(), ip_api_io::Error> {
//! let client = ip_api_io::Client::with_api_key("YOUR_API_KEY");
//!
//! let info = client.lookup_ip("8.8.8.8").await?;
//! println!("{:?} vpn={}", info.location.country, info.suspicious_factors.is_vpn);
//!
//! let risk = client.risk_score_ip("8.8.8.8").await?;
//! println!("{} {}", risk.score, risk.risk_level);
//! # Ok(())
//! # }
//! ```
//!
//! A synchronous client is available behind the `blocking` feature as
//! [`blocking::Client`].

#[cfg(feature = "blocking")]
pub mod blocking;
mod client;
mod error;
pub mod models;

pub use client::{Client, ClientBuilder};
pub use error::Error;
pub use models::*;

/// Client library version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub(crate) const DEFAULT_BASE_URL: &str = "https://ip-api.io";
pub(crate) const USER_AGENT: &str = concat!("ip-api-io-rust/", env!("CARGO_PKG_VERSION"));

/// Documented per-request limit for batch endpoints.
pub const MAX_BATCH_SIZE: usize = 100;

pub(crate) fn check_batch(items: &[&str], name: &str) -> Result<(), Error> {
    if items.is_empty() {
        return Err(Error::InvalidArgument(format!("{name} must not be empty")));
    }
    if items.len() > MAX_BATCH_SIZE {
        return Err(Error::InvalidArgument(format!(
            "{name} must contain at most {MAX_BATCH_SIZE} items"
        )));
    }
    Ok(())
}

/// RFC 3986 percent-encoding for a single path segment (zero-dependency).
pub(crate) fn encode_segment(segment: &str) -> String {
    let mut encoded = String::with_capacity(segment.len());
    for byte in segment.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(byte as char)
            }
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}
