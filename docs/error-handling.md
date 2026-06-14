# Errors, rate limits & usage

Every method returns `Result<T, ip_api_io::Error>`. The client **never retries** — you
stay in control of back-off. It also exposes your current quota so you can throttle
before you hit a limit.

## The `Error` enum

| Variant | Trigger | Fields |
|---|---|---|
| `Error::Authentication` | HTTP 401, 403 | `status`, `message`, `body` |
| `Error::RateLimit` | HTTP 429 | `status`, `message`, `body`, `limit`, `remaining`, `reset` |
| `Error::InvalidRequest` | HTTP 400, 404, 422 | `status`, `message`, `body` |
| `Error::Server` | HTTP 5xx | `status`, `message`, `body` |
| `Error::Api` | any other non-2xx | `status`, `message`, `body` |
| `Error::Transport` | DNS, connect, timeout, TLS, JSON decode | wraps `reqwest::Error` |
| `Error::InvalidArgument` | client-side check (e.g. oversized batch) | `String` |

```rust
use ip_api_io::{Client, Error};

# async fn run() -> Result<(), Error> {
let client = Client::with_api_key("YOUR_API_KEY");

match client.lookup_ip("8.8.8.8").await {
    Ok(info) => println!("{:?}", info.location.country),
    Err(Error::RateLimit { reset, .. }) => println!("quota hit — resets at {reset:?}"),
    Err(Error::Authentication { .. }) => println!("check your API key"),
    Err(Error::InvalidRequest { message, .. }) => println!("bad request: {message}"),
    Err(Error::Server { .. }) => println!("ip-api.io is having trouble, try later"),
    Err(other) => println!("{other}"),
}
# Ok(())
# }
```

`Error` implements `std::error::Error` and `Display`, so it works with `?` and
`anyhow`/`thiserror` out of the box.

## Rate limits

On HTTP 429 you get `Error::RateLimit`, carrying the `x-ratelimit-*` header values.
Because the client never retries, **`reset` tells you when to**:

```rust
# async fn run(client: ip_api_io::Client) -> Result<(), ip_api_io::Error> {
if let Err(ip_api_io::Error::RateLimit { limit, remaining, reset, .. }) =
    client.lookup_ip("8.8.8.8").await
{
    println!("{limit:?} {remaining:?} {reset:?}");
    // `reset` is the unix timestamp when the quota renews — schedule a retry then
}
# Ok(())
# }
```

## `rate_limit()` — check quota proactively

Read your current limits without triggering a 429, so you can throttle in advance.

```rust
# async fn run(client: ip_api_io::Client) -> Result<(), ip_api_io::Error> {
let rl = client.rate_limit().await?;

println!("{:?}", rl.plan_name);
println!("{} / {}", rl.ip_api.remaining, rl.ip_api.limit);
println!("{} % used", rl.email_api.usage_percent);
println!("{:?}", rl.next_renewal_date);
# Ok(())
# }
```

`RateLimitInfo`: `plan_id`, `plan_name`, `ip_api` and `email_api`
(`ApiLimitInfo`: `limit`, `remaining`, `used`, `usage_percent`), `interval_seconds`,
`next_renewal_date`, `status`.

## `usage_summary()` — account usage

Aggregate usage for the current period — handy for dashboards and internal alerts.

```rust
# async fn run(client: ip_api_io::Client) -> Result<(), ip_api_io::Error> {
let usage = client.usage_summary().await?;

println!("{} {}", usage.total_requests, usage.successful_requests);
println!("{} {}", usage.rate_limited_requests, usage.quota_consumed);
println!("{} -> {}", usage.period_start, usage.period_end);
# Ok(())
# }
```

`UsageSummary`: `api_key`, `api_type`, `period_start`, `period_end`, `total_requests`,
`successful_requests`, `rate_limited_requests`, `quota_consumed`, `batch_operations`,
`avg_request_duration_ms`.

## See also

- [IP geolocation & bulk lookup](ip-geolocation.md) — the most common call
- API reference: https://ip-api.io/api-docs.html
- Get a free API key: https://ip-api.io
