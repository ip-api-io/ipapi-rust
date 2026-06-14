# VPN, proxy & Tor detection

Catch traffic that hides behind anonymizers. Every `lookup_ip` already returns the
`suspicious_factors` flags for proxy, VPN, Tor, datacenter, spam and crawler; the
dedicated `tor_check` adds live Tor exit-node confirmation.

Powers [VPN detection](https://ip-api.io/vpn-detection-api),
[proxy detection](https://ip-api.io/proxy-detection-api) and
[Tor detection](https://ip-api.io/tor-detection).

## `suspicious_factors` — flags on every lookup

No extra call needed: read the flags from a normal [`lookup_ip`](ip-geolocation.md).

```rust
use ip_api_io::Client;

# async fn run() -> Result<(), ip_api_io::Error> {
let client = Client::with_api_key("YOUR_API_KEY");

let info = client.lookup_ip("185.220.101.1").await?;
let f = &info.suspicious_factors;

println!("{}", f.is_vpn);         // VPN service
println!("{}", f.is_proxy);       // open / anonymizing proxy
println!("{}", f.is_tor_node);    // Tor node
println!("{}", f.is_datacenter);  // hosting / datacenter IP (often a bot)
println!("{}", f.is_spam);        // known spam source
println!("{}", f.is_crawler);     // known crawler / bot
println!("{}", f.is_threat);      // listed on a threat feed

if f.is_vpn || f.is_proxy || f.is_tor_node {
    // require step-up verification
}
# Ok(())
# }
```

### `SuspiciousFactors`

| Field | Type | Meaning |
|---|---|---|
| `is_proxy` | `bool` | Open or anonymizing proxy |
| `is_vpn` | `bool` | Commercial VPN endpoint |
| `is_tor_node` | `bool` | Part of the Tor network |
| `is_datacenter` | `bool` | Hosting / datacenter range |
| `is_spam` | `bool` | Known spam source |
| `is_crawler` | `bool` | Known crawler / bot |
| `is_threat` | `bool` | Listed on a threat feed |

## `tor_check(ip)` — confirm a Tor exit node

A dedicated check against the live Tor node list, with a count of matching nodes.

```rust
# async fn run(client: ip_api_io::Client) -> Result<(), ip_api_io::Error> {
let tor = client.tor_check("185.220.101.1").await?;

println!("{}", tor.is_tor);          // true
println!("{}", tor.tor_node_count);  // number of matching Tor nodes
# Ok(())
# }
```

### Response (`TorDetection`)

| Field | Type | Description |
|---|---|---|
| `ip` | `String` | The checked IP |
| `is_tor` | `bool` | Whether the IP is a Tor node |
| `tor_node_count` | `i32` | Matching nodes for the IP |

> Want one number instead of individual flags? See
> [Fraud detection & risk scoring](fraud-risk-scoring.md) — `risk_score_ip` folds all of
> these signals into a 0–100 score.

## See also

- [IP geolocation & bulk lookup](ip-geolocation.md) — where `suspicious_factors` comes from
- [Fraud detection & risk scoring](fraud-risk-scoring.md) — combine the flags into a score
- Product pages: [VPN detection](https://ip-api.io/vpn-detection-api) · [Proxy detection](https://ip-api.io/proxy-detection-api) · [Tor detection](https://ip-api.io/tor-detection)
