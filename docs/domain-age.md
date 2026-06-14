# Domain age checker

Newly registered domains are a strong fraud and spam signal. `domain_age` returns how
long ago a domain was registered, derived from WHOIS data, so you can flag or block
domains created days ago.

Powers the [domain age checker](https://ip-api.io/domain-age-checker).

## `domain_age(domain)` — age of one domain

```rust
use ip_api_io::Client;

# async fn run() -> Result<(), ip_api_io::Error> {
let client = Client::with_api_key("YOUR_API_KEY");

let age = client.domain_age("example.com").await?;

println!("{}", age.is_valid);             // true
println!("{:?}", age.registration_date);  // Some("1995-08-14")
println!("{:?}", age.age_in_years);       // Some(30)
println!("{:?}", age.age_in_days);        // Some(11000+)

if age.age_in_days.unwrap_or(i64::MAX) < 30 {
    // treat brand-new domains as higher risk
}
# Ok(())
# }
```

### Response (`DomainAge`)

| Field | Type | Description |
|---|---|---|
| `domain` | `String` | The domain checked |
| `is_valid` | `bool` | Whether age could be determined |
| `registration_date` | `Option<String>` | First registration date |
| `age_in_years` | `Option<i32>` | Age in whole years |
| `age_in_days` | `Option<i64>` | Age in days |
| `error` | `Option<String>` | Reason when `is_valid` is false |

## `domain_age_batch(domains)` — many domains at once

Check a slice of domains in one request (non-empty; returns `Error::InvalidArgument`
if empty).

```rust
# async fn run(client: ip_api_io::Client) -> Result<(), ip_api_io::Error> {
let batch = client
    .domain_age_batch(&["example.com", "brand-new-domain.xyz"])
    .await?;

for (domain, age) in &batch.results {
    println!("{domain} {:?}", age.age_in_days);
}
# Ok(())
# }
```

### Response (`BatchDomainAgeResponse`)
`results` — a `HashMap<String, DomainAge>` mapping each domain to its age.

## See also

- [ASN & DNS lookups](asn-and-dns.md) — `whois` for the full registration record
- [Fraud detection & risk scoring](fraud-risk-scoring.md) — combine age with other signals
- Product page: [Domain age checker](https://ip-api.io/domain-age-checker)
