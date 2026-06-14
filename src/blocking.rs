//! Blocking (synchronous) client, enabled with the `blocking` cargo feature.

use std::time::Duration;

use serde::de::DeserializeOwned;
use serde_json::json;

use crate::error::{classify, extract_message, Error};
use crate::models::*;
use crate::{check_batch, encode_segment, DEFAULT_BASE_URL, USER_AGENT};

/// Blocking client for the ip-api.io API.
///
/// ```no_run
/// # fn run() -> Result<(), ip_api_io::Error> {
/// let client = ip_api_io::blocking::Client::with_api_key("YOUR_API_KEY");
/// let info = client.lookup_ip("8.8.8.8")?;
/// println!("{:?}", info.location.country);
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct Client {
    api_key: Option<String>,
    base_url: String,
    http: reqwest::blocking::Client,
}

/// Builder for the blocking [`Client`].
#[derive(Debug, Default)]
pub struct ClientBuilder {
    api_key: Option<String>,
    base_url: Option<String>,
    timeout: Option<Duration>,
}

impl ClientBuilder {
    pub fn api_key(mut self, key: impl Into<String>) -> Self {
        self.api_key = Some(key.into());
        self
    }

    pub fn base_url(mut self, base: impl Into<String>) -> Self {
        self.base_url = Some(base.into());
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn build(self) -> Client {
        let http = reqwest::blocking::Client::builder()
            .timeout(self.timeout.unwrap_or(Duration::from_secs(10)))
            .build()
            .expect("failed to build reqwest client");
        Client {
            api_key: self.api_key,
            base_url: self
                .base_url
                .unwrap_or_else(|| DEFAULT_BASE_URL.to_string())
                .trim_end_matches('/')
                .to_string(),
            http,
        }
    }
}

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}

impl Client {
    pub fn new() -> Self {
        Self::builder().build()
    }

    pub fn with_api_key(key: impl Into<String>) -> Self {
        Self::builder().api_key(key).build()
    }

    pub fn builder() -> ClientBuilder {
        ClientBuilder::default()
    }

    pub fn lookup(&self) -> Result<IpInfo, Error> {
        self.get("/api/v1/ip".into())
    }

    pub fn lookup_ip(&self, ip: &str) -> Result<IpInfo, Error> {
        self.get(format!("/api/v1/ip/{}", encode_segment(ip)))
    }

    pub fn lookup_batch(&self, ips: &[&str]) -> Result<BatchIpLookupResponse, Error> {
        check_batch(ips, "ips")?;
        self.post("/api/v1/ip/batch".into(), json!({ "ips": ips }))
    }

    pub fn ip_reputation(&self, ip: &str) -> Result<serde_json::Value, Error> {
        self.get(format!("/api/v1/ip-reputation/{}", encode_segment(ip)))
    }

    pub fn tor_check(&self, ip: &str) -> Result<TorDetection, Error> {
        self.get(format!("/api/v1/tor/{}", encode_segment(ip)))
    }

    pub fn asn(&self, ip: &str) -> Result<AsnLookup, Error> {
        self.get(format!("/api/v1/asn/{}", encode_segment(ip)))
    }

    pub fn email_info(&self, email: &str) -> Result<EmailInfo, Error> {
        self.get(format!("/api/v1/email/{}", encode_segment(email)))
    }

    pub fn validate_email(&self, email: &str) -> Result<AdvancedEmailValidation, Error> {
        self.get(format!("/api/v1/email/advanced/{}", encode_segment(email)))
    }

    pub fn validate_email_batch(
        &self,
        emails: &[&str],
    ) -> Result<BatchEmailValidationResponse, Error> {
        check_batch(emails, "emails")?;
        self.post("/api/v1/email/advanced/batch".into(), json!({ "emails": emails }))
    }

    pub fn risk_score(&self) -> Result<RiskScore, Error> {
        self.get("/api/v1/risk-score".into())
    }

    pub fn risk_score_ip(&self, ip: &str) -> Result<RiskScore, Error> {
        self.get(format!("/api/v1/risk-score/{}", encode_segment(ip)))
    }

    pub fn email_risk_score(&self, email: &str) -> Result<RiskScore, Error> {
        self.get(format!("/api/v1/risk-score/email/{}", encode_segment(email)))
    }

    pub fn whois(&self, domain: &str) -> Result<Whois, Error> {
        self.get(format!("/api/v1/dns/whois/{}", encode_segment(domain)))
    }

    pub fn reverse_dns(&self, ip: &str) -> Result<ReverseDns, Error> {
        self.get(format!("/api/v1/dns/reverse/{}", encode_segment(ip)))
    }

    pub fn forward_dns(&self, hostname: &str) -> Result<ForwardDns, Error> {
        self.get(format!("/api/v1/dns/forward/{}", encode_segment(hostname)))
    }

    pub fn mx_records(&self, domain: &str) -> Result<MxLookup, Error> {
        self.get(format!("/api/v1/dns/mx/{}", encode_segment(domain)))
    }

    pub fn domain_age(&self, domain: &str) -> Result<DomainAge, Error> {
        self.get(format!("/api/v1/domain/age/{}", encode_segment(domain)))
    }

    pub fn domain_age_batch(&self, domains: &[&str]) -> Result<BatchDomainAgeResponse, Error> {
        if domains.is_empty() {
            return Err(Error::InvalidArgument("domains must not be empty".into()));
        }
        self.post("/api/v1/domain/age/batch".into(), json!({ "domains": domains }))
    }

    pub fn rate_limit(&self) -> Result<RateLimitInfo, Error> {
        self.get("/api/v1/ratelimit".into())
    }

    pub fn usage_summary(&self) -> Result<UsageSummary, Error> {
        self.get("/api/v1/usage/summary".into())
    }

    fn get<T: DeserializeOwned>(&self, path: String) -> Result<T, Error> {
        self.request(reqwest::Method::GET, path, None)
    }

    fn post<T: DeserializeOwned>(
        &self,
        path: String,
        body: serde_json::Value,
    ) -> Result<T, Error> {
        self.request(reqwest::Method::POST, path, Some(body))
    }

    fn request<T: DeserializeOwned>(
        &self,
        method: reqwest::Method,
        path: String,
        body: Option<serde_json::Value>,
    ) -> Result<T, Error> {
        let mut request = self
            .http
            .request(method, format!("{}{}", self.base_url, path))
            .header(reqwest::header::USER_AGENT, USER_AGENT)
            .header(reqwest::header::ACCEPT, "application/json");
        if let Some(key) = &self.api_key {
            request = request.query(&[("api_key", key)]);
        }
        if let Some(body) = body {
            request = request.json(&body);
        }

        let response = request.send()?;
        let status = response.status().as_u16();
        if !response.status().is_success() {
            let limit = header_i64(&response, "x-ratelimit-limit");
            let remaining = header_i64(&response, "x-ratelimit-remaining");
            let reset = header_i64(&response, "x-ratelimit-reset");
            let body = response.text().unwrap_or_default();
            let message = extract_message(status, &body);
            if status == 429 {
                return Err(Error::RateLimit {
                    status,
                    message,
                    body,
                    limit,
                    remaining,
                    reset,
                });
            }
            return Err(classify(status, message, body));
        }
        Ok(response.json::<T>()?)
    }
}

fn header_i64(response: &reqwest::blocking::Response, name: &str) -> Option<i64> {
    response
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse().ok())
}
