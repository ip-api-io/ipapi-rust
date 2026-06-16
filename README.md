# ip-api-io — Official Rust client for [ip-api.io](https://ip-api.io)

[![crates.io](https://img.shields.io/crates/v/ip-api-io)](https://crates.io/crates/ip-api-io)
[![docs.rs](https://img.shields.io/docsrs/ip-api-io)](https://docs.rs/ip-api-io)
[![test](https://github.com/ip-api-io/ipapi-rust/actions/workflows/test.yml/badge.svg)](https://github.com/ip-api-io/ipapi-rust/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

The official Rust client for the [ip-api.io](https://ip-api.io) IP intelligence
platform. One client covers [IP geolocation](https://ip-api.io/what-is-my-ip),
[email validation](https://ip-api.io/email-validation) and [verification](https://ip-api.io/email-verification-api)
(syntax, MX, SMTP deliverability), [fraud detection](https://ip-api.io/fraud-detection-api)
and [risk scoring](https://ip-api.io/risk-score),
[VPN](https://ip-api.io/vpn-detection-api)/[proxy](https://ip-api.io/proxy-detection-api)/[Tor detection](https://ip-api.io/tor-detection),
[disposable email detection](https://ip-api.io/disposable-email-checker), [ASN lookup](https://ip-api.io/asn-lookup),
[WHOIS](https://ip-api.io/whois-lookup), [reverse DNS](https://ip-api.io/reverse-dns-lookup),
[MX records](https://ip-api.io/mx-record-lookup) and [domain age](https://ip-api.io/domain-age-checker).

Async by default (`reqwest` + `rustls`), fully typed responses, optional `blocking` feature.

## Install

```bash
cargo add ip-api-io
```

## Quickstart

```rust
use ip_api_io::Client;

#[tokio::main]
async fn main() -> Result<(), ip_api_io::Error> {
    let client = Client::with_api_key("YOUR_API_KEY"); // free key at https://ip-api.io

    let info = client.lookup_ip("8.8.8.8").await?;
    println!("{:?}", info.location.country);          // Some("United States")
    println!("{}", info.suspicious_factors.is_vpn);   // false

    let risk = client.risk_score_ip("8.8.8.8").await?;
    println!("{} {}", risk.score, risk.risk_level);   // 0 low

    Ok(())
}
```

Synchronous usage with the `blocking` feature
(`cargo add ip-api-io --features blocking`):

```rust
let client = ip_api_io::blocking::Client::with_api_key("YOUR_API_KEY");
let info = client.lookup_ip("8.8.8.8")?;
```

An API key is required — the API rejects keyless requests with `401`. Sign up at
[ip-api.io](https://ip-api.io) for a free key.

## Documentation

Each guide documents the methods for one capability, with runnable examples and a link
to the matching ip-api.io product page:

- **[IP geolocation & bulk lookup](docs/ip-geolocation.md)** — `lookup`, `lookup_ip`, `lookup_batch`
- **[Email validation & verification](docs/email-validation.md)** — `email_info`, `validate_email`, `validate_email_batch`
- **[Fraud detection & risk scoring](docs/fraud-risk-scoring.md)** — `risk_score`, `risk_score_ip`, `email_risk_score`, `ip_reputation`
- **[VPN, proxy & Tor detection](docs/vpn-proxy-tor.md)** — `tor_check`, `suspicious_factors`
- **[ASN & DNS lookups](docs/asn-and-dns.md)** — `asn`, `whois`, `reverse_dns`, `forward_dns`, `mx_records`
- **[Domain age checker](docs/domain-age.md)** — `domain_age`, `domain_age_batch`
- **[Errors, rate limits & usage](docs/error-handling.md)** — the `Error` enum, `rate_limit`, `usage_summary`

## Methods

Every method maps to one ip-api.io endpoint and its product page:

| Method | Endpoint | Product page |
|---|---|---|
| `lookup()` / `lookup_ip(ip)` | `GET /api/v1/ip[/{ip}]` | [IP geolocation](https://ip-api.io/what-is-my-ip) |
| `lookup_batch(ips)` | `POST /api/v1/ip/batch` (≤100 IPs) | [Bulk IP lookup](https://ip-api.io/bulk-ip-lookup) |
| `email_info(email)` | `GET /api/v1/email/{email}` | [Email validation](https://ip-api.io/email-validation) |
| `validate_email(email)` | `GET /api/v1/email/advanced/{email}` | [Advanced email validation](https://ip-api.io/advanced-email-validation) |
| `validate_email_batch(emails)` | `POST /api/v1/email/advanced/batch` (≤100) | [Email list cleaning](https://ip-api.io/email-list-cleaning) |
| `risk_score()` / `risk_score_ip(ip)` | `GET /api/v1/risk-score[/{ip}]` | [Risk score](https://ip-api.io/risk-score) |
| `email_risk_score(email)` | `GET /api/v1/risk-score/email/{email}` | [Fraud detection](https://ip-api.io/fraud-detection-api) |
| `ip_reputation(ip)` | `GET /api/v1/ip-reputation/{ip}` | [IP reputation](https://ip-api.io/ip-reputation) |
| `tor_check(ip)` | `GET /api/v1/tor/{ip}` | [Tor detection](https://ip-api.io/tor-detection) |
| `asn(ip)` | `GET /api/v1/asn/{ip}` | [ASN lookup](https://ip-api.io/asn-lookup) |
| `whois(domain)` | `GET /api/v1/dns/whois/{domain}` | [WHOIS lookup](https://ip-api.io/whois-lookup) |
| `reverse_dns(ip)` | `GET /api/v1/dns/reverse/{ip}` | [Reverse DNS](https://ip-api.io/reverse-dns-lookup) |
| `forward_dns(hostname)` | `GET /api/v1/dns/forward/{hostname}` | — |
| `mx_records(domain)` | `GET /api/v1/dns/mx/{domain}` | [MX record lookup](https://ip-api.io/mx-record-lookup) |
| `domain_age(domain)` | `GET /api/v1/domain/age/{domain}` | [Domain age checker](https://ip-api.io/domain-age-checker) |
| `domain_age_batch(domains)` | `POST /api/v1/domain/age/batch` | [Domain age checker](https://ip-api.io/domain-age-checker) |
| `rate_limit()` | `GET /api/v1/ratelimit` | — |
| `usage_summary()` | `GET /api/v1/usage/summary` | — |

Every method has the same signature on `blocking::Client`, minus `.await`.

## Error handling

The client returns a typed `Error` enum and **never retries** —
`Error::RateLimit`'s `reset` field tells you when your quota renews:

```rust
match client.lookup_ip("8.8.8.8").await {
    Ok(info) => println!("{info:?}"),
    Err(ip_api_io::Error::RateLimit { limit, remaining, reset, .. }) => {
        println!("limit={limit:?} remaining={remaining:?} resets_at={reset:?}");
    }
    Err(ip_api_io::Error::Authentication { .. }) => println!("invalid API key"),
    Err(other) => println!("{other}"),
}
```

See [docs/error-handling.md](docs/error-handling.md) for the full `Error` taxonomy.

## Links

- Full tutorial: https://ip-api.io/docs/sdk/rust
- Website: https://ip-api.io
- API reference: https://ip-api.io/api-docs.html
- OpenAPI spec: https://ip-api.io/openapi.json
- Get a free API key: https://ip-api.io

---

`ip-api-io` is the official client for [ip-api.io](https://ip-api.io).
It is not affiliated with ip-api.com or ipapi.com.
