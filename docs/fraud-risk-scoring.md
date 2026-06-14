# Fraud detection & risk scoring

Collapse every signal — geolocation, proxy/VPN/Tor flags, datacenter hosting,
disposable email, syntax — into a single 0–100 risk score you can act on at sign-up,
checkout or login. Or pull the raw [IP reputation](https://ip-api.io/ip-reputation)
record when you want to build your own rules.

Powers the [fraud detection API](https://ip-api.io/fraud-detection-api),
[risk score](https://ip-api.io/risk-score) and
[IP reputation](https://ip-api.io/ip-reputation) products.

## `risk_score_ip(ip)` / `risk_score()` — score an IP

Returns a `score` (0–100) and a human `risk_level`, plus the `factors` that drove it.
`risk_score` scores the caller's own IP.

```rust
use ip_api_io::Client;

# async fn run() -> Result<(), ip_api_io::Error> {
let client = Client::with_api_key("YOUR_API_KEY");

let risk = client.risk_score_ip("185.220.101.1").await?;

println!("{}", risk.score);        // 88.0
println!("{}", risk.risk_level);   // "high"
if let Some(ip) = &risk.factors.ip_factors {
    println!("{} {}", ip.is_tor_node, ip.is_datacenter);
}

if risk.score >= 75.0 {
    // block, or send to manual review / step-up auth
}
# Ok(())
# }
```

### Response (`RiskScore`)

| Field | Type | Description |
|---|---|---|
| `score` | `f64` | Risk score, 0 (safe) – 100 (high risk) |
| `risk_level` | `String` | Bucketed level, e.g. `"low"`, `"medium"`, `"high"` |
| `ip` | `Option<String>` | Scored IP (when applicable) |
| `email` | `Option<String>` | Scored email (when applicable) |
| `factors` | `RiskScoreFactors` | `ip_factors` and/or `email_factors` (both `Option`) |

`IpFactors`: `is_proxy`, `is_vpn`, `is_tor_node`, `is_spam`, `is_datacenter`,
`risk_contribution`.
`EmailFactors`: `is_disposable`, `is_valid_syntax`, `risk_contribution`.

## `email_risk_score(email)` — score an email

Same 0–100 scale, driven by email signals (disposable provider, invalid syntax).
Use it to grade leads or gate sign-ups by address quality.

```rust
# async fn run(client: ip_api_io::Client) -> Result<(), ip_api_io::Error> {
let risk = client.email_risk_score("user@mailinator.com").await?;

println!("{} {}", risk.score, risk.risk_level);   // 90 high
if let Some(email) = &risk.factors.email_factors {
    println!("{}", email.is_disposable);          // true
}
# Ok(())
# }
```

## `ip_reputation(ip)` — raw reputation record

Returns the underlying reputation data for an IP as a `serde_json::Value` — use it when
you want the source signals rather than a computed score.

```rust
# async fn run(client: ip_api_io::Client) -> Result<(), ip_api_io::Error> {
let reputation = client.ip_reputation("185.220.101.1").await?;
println!("{reputation}");
# Ok(())
# }
```

## See also

- [IP geolocation & bulk lookup](ip-geolocation.md) — `suspicious_factors` per IP
- [VPN, proxy & Tor detection](vpn-proxy-tor.md) — the individual checks behind the score
- [Email validation & verification](email-validation.md) — deliverability before scoring
- Product pages: [Fraud detection](https://ip-api.io/fraud-detection-api) · [Risk score](https://ip-api.io/risk-score) · [IP reputation](https://ip-api.io/ip-reputation)
