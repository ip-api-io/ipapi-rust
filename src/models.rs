//! Response models mirroring the schemas in <https://ip-api.io/openapi.json>.
//! Unknown fields are tolerated for forward compatibility.

use std::collections::HashMap;

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct SuspiciousFactors {
    pub is_proxy: bool,
    pub is_tor_node: bool,
    pub is_spam: bool,
    pub is_crawler: bool,
    pub is_datacenter: bool,
    pub is_vpn: bool,
    pub is_threat: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Location {
    pub country: Option<String>,
    pub country_code: Option<String>,
    pub city: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub zip: Option<String>,
    pub timezone: Option<String>,
    pub local_time: Option<String>,
    pub local_time_unix: Option<i64>,
    pub is_daylight_savings: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IpInfo {
    pub ip: String,
    pub isp: Option<String>,
    pub asn: Option<String>,
    pub suspicious_factors: SuspiciousFactors,
    pub location: Location,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BatchIpLookupResponse {
    pub results: HashMap<String, IpInfo>,
    #[serde(default)]
    pub total_processed: i32,
    #[serde(default)]
    pub successful_lookups: i32,
    #[serde(default)]
    pub failed_lookups: i32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MxRecord {
    pub priority: i32,
    pub hostname: String,
    pub ttl: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EmailSyntax {
    pub domain: Option<String>,
    pub username: Option<String>,
    pub is_valid: bool,
    #[serde(default)]
    pub error_reasons: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EmailInfo {
    pub email: String,
    pub is_disposable: bool,
    pub has_mx_records: bool,
    #[serde(default)]
    pub mx_records: Vec<MxRecord>,
    pub syntax: EmailSyntax,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AdvancedSyntax {
    pub username: String,
    pub domain: String,
    pub valid: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AdvancedSmtp {
    pub host_exists: bool,
    pub full_inbox: bool,
    pub catch_all: bool,
    pub deliverable: bool,
    pub disabled: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AdvancedGravatar {
    pub has_gravatar: bool,
    pub gravatar_url: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AdvancedEmailValidation {
    pub email: String,
    pub reachable: String,
    pub syntax: AdvancedSyntax,
    pub smtp: Option<AdvancedSmtp>,
    pub gravatar: Option<AdvancedGravatar>,
    #[serde(default)]
    pub suggestion: String,
    pub disposable: bool,
    pub role_account: bool,
    pub free: bool,
    pub has_mx_records: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BatchEmailValidationResponse {
    pub results: HashMap<String, AdvancedEmailValidation>,
    #[serde(rename = "totalProcessed", default)]
    pub total_processed: i32,
    #[serde(rename = "successfulValidations", default)]
    pub successful_validations: i32,
    #[serde(rename = "failedValidations", default)]
    pub failed_validations: i32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IpFactors {
    pub is_proxy: bool,
    pub is_tor_node: bool,
    pub is_spam: bool,
    pub is_vpn: bool,
    pub is_datacenter: bool,
    pub risk_contribution: f64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EmailFactors {
    pub is_disposable: bool,
    pub is_valid_syntax: bool,
    pub risk_contribution: f64,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct RiskScoreFactors {
    pub ip_factors: Option<IpFactors>,
    pub email_factors: Option<EmailFactors>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RiskScore {
    pub score: f64,
    pub risk_level: String,
    pub ip: Option<String>,
    pub email: Option<String>,
    #[serde(default)]
    pub factors: RiskScoreFactors,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TorDetection {
    pub ip: String,
    pub is_tor: bool,
    #[serde(default)]
    pub tor_node_count: i32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AsnLookup {
    pub ip: String,
    pub asn: Option<i64>,
    pub organization: Option<String>,
    pub network: Option<String>,
    #[serde(default)]
    pub is_datacenter: bool,
    pub country: Option<String>,
    pub country_code: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DomainAge {
    pub domain: String,
    pub is_valid: bool,
    pub registration_date: Option<String>,
    pub age_in_years: Option<i32>,
    pub age_in_days: Option<i64>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BatchDomainAgeResponse {
    pub results: HashMap<String, DomainAge>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WhoisRegistrar {
    pub name: Option<String>,
    pub url: Option<String>,
    pub iana_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WhoisStatus {
    pub code: String,
    pub humanized: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Whois {
    pub domain: String,
    pub registrar: Option<WhoisRegistrar>,
    pub registered_on: Option<String>,
    pub expires_on: Option<String>,
    pub updated_on: Option<String>,
    #[serde(default)]
    pub name_servers: Vec<String>,
    #[serde(default)]
    pub status: Vec<WhoisStatus>,
    #[serde(default)]
    pub raw: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ReverseDns {
    pub ip: String,
    pub hostname: Option<String>,
    pub ptr_record: Option<String>,
    pub ttl: Option<i64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ForwardLookupRecord {
    pub r#type: String,
    pub address: String,
    pub ttl: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ForwardDns {
    pub hostname: String,
    #[serde(default)]
    pub addresses: Vec<ForwardLookupRecord>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MxLookup {
    pub domain: String,
    #[serde(default)]
    pub mx_records: Vec<MxRecord>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ApiLimitInfo {
    pub limit: i64,
    pub remaining: i64,
    pub used: i64,
    pub usage_percent: f64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RateLimitInfo {
    pub plan_id: String,
    pub plan_name: Option<String>,
    pub ip_api: ApiLimitInfo,
    pub email_api: ApiLimitInfo,
    pub interval_seconds: i64,
    pub next_renewal_date: Option<String>,
    pub status: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UsageSummary {
    #[serde(rename = "apiKey")]
    pub api_key: String,
    #[serde(rename = "apiType")]
    pub api_type: String,
    #[serde(rename = "periodStart")]
    pub period_start: String,
    #[serde(rename = "periodEnd")]
    pub period_end: String,
    #[serde(rename = "totalRequests")]
    pub total_requests: i64,
    #[serde(rename = "successfulRequests")]
    pub successful_requests: i64,
    #[serde(rename = "rateLimitedRequests")]
    pub rate_limited_requests: i64,
    #[serde(rename = "quotaConsumed")]
    pub quota_consumed: i64,
    #[serde(rename = "batchOperations")]
    pub batch_operations: i64,
    #[serde(rename = "avgRequestDurationMs")]
    pub avg_request_duration_ms: Option<f64>,
}
