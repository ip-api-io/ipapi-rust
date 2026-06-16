# IP geolocation & bulk lookup

Turn any IP address into geolocation, network and threat intelligence. A single
`lookup_ip` returns the country, city, coordinates, timezone, ISP and ASN of an IP,
plus the `suspicious_factors` flags used for fraud screening (proxy, VPN, Tor,
datacenter, spam, crawler, threat).

Powers the [IP geolocation API](https://ip-api.io/what-is-my-ip) and the
[bulk IP lookup](https://ip-api.io/bulk-ip-lookup) product.

## `lookup_ip(ip)` / `lookup()` — geolocate one IP

`lookup_ip` geolocates a specific address; `lookup` geolocates the caller's own IP.

```rust
use ip_api_io::Client;

# async fn run() -> Result<(), ip_api_io::Error> {
let client = Client::with_api_key("YOUR_API_KEY");

let info = client.lookup_ip("8.8.8.8").await?;

println!("{}", info.ip);                         // "8.8.8.8"
println!("{:?}", info.isp);                       // Some("Google LLC")
println!("{:?}", info.location.country);          // Some("United States")
println!("{:?}", info.location.city);             // Some("Mountain View")
println!("{:?} {:?}", info.location.latitude, info.location.longitude);
println!("{:?}", info.location.timezone);         // Some("America/Los_Angeles")
println!("{}", info.suspicious_factors.is_datacenter); // true

// Geolocate the machine making the request
let me = client.lookup().await?;
println!("{} {:?}", me.ip, me.location.country);
# Ok(())
# }
```

### Response (`IpInfo`)

| Field | Type | Description |
|---|---|---|
| `ip` | `String` | The looked-up address |
| `isp` | `Option<String>` | Internet service provider |
| `asn` | `Option<String>` | Autonomous system the IP belongs to |
| `location` | `Location` | `country`, `country_code`, `city`, `latitude`, `longitude`, `zip`, `timezone`, `local_time`, `local_time_unix`, `is_daylight_savings` (all `Option`) |
| `suspicious_factors` | `SuspiciousFactors` | `is_proxy`, `is_vpn`, `is_tor_node`, `is_datacenter`, `is_spam`, `is_crawler`, `is_threat` |

> The `suspicious_factors` block is the fastest way to flag risky traffic in one call.
> For a single 0–100 score, see [Fraud detection & risk scoring](fraud-risk-scoring.md);
> for the individual checks, see [VPN, proxy & Tor detection](vpn-proxy-tor.md).

## `lookup_batch(ips)` — geolocate up to 100 IPs

Look up to 100 addresses in one request — ideal for enriching logs, sign-up events or
historical data without a round trip per IP. Returns `Error::InvalidArgument` if the
slice is empty or longer than 100.

```rust
# async fn run(client: ip_api_io::Client) -> Result<(), ip_api_io::Error> {
let batch = client.lookup_batch(&["8.8.8.8", "1.1.1.1", "9.9.9.9"]).await?;

println!("{}", batch.total_processed);     // 3
println!("{}", batch.successful_lookups);  // 3
println!("{}", batch.failed_lookups);      // 0

for (ip, info) in &batch.results {
    println!("{ip} {:?} {}", info.location.country, info.suspicious_factors.is_vpn);
}
# Ok(())
# }
```

### Response (`BatchIpLookupResponse`)

| Field | Type | Description |
|---|---|---|
| `results` | `HashMap<String, IpInfo>` | Map of IP → info |
| `total_processed` | `i32` | IPs received |
| `successful_lookups` | `i32` | IPs resolved |
| `failed_lookups` | `i32` | IPs that could not be resolved |

## See also

- [Fraud detection & risk scoring](fraud-risk-scoring.md) — turn the flags into a score
- [VPN, proxy & Tor detection](vpn-proxy-tor.md) — the individual threat checks
- [ASN & DNS lookups](asn-and-dns.md) — network ownership for an IP
- Product pages: [IP geolocation](https://ip-api.io/what-is-my-ip) · [Bulk IP lookup](https://ip-api.io/bulk-ip-lookup)
- [Full tutorial on ip-api.io](https://ip-api.io/docs/sdk/rust/ip-geolocation)
