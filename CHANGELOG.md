# Changelog

All notable changes to this project will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.0.0] - 2026-06-12

### Added
- Initial release: full client for the ip-api.io v1 API — IP geolocation and
  threat intelligence (single + batch), email validation (basic, advanced,
  batch), risk scoring, IP reputation, Tor detection, ASN lookup, WHOIS,
  reverse/forward DNS, MX records, domain age (single + batch), rate limit
  and usage info.
- Async client (`reqwest` + `rustls`) with fully typed `serde` models;
  optional `blocking` feature for synchronous use.
- Typed `Error` enum (`Authentication`, `RateLimit` with x-ratelimit header
  values, `InvalidRequest`, `Server`, `Transport`).
