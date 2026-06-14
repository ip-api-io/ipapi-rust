# ASN & DNS lookups

Resolve the network and DNS layer behind an IP or domain: which autonomous system
owns an address, who registered a domain, what a host's PTR record is, and which mail
servers a domain uses.

Powers [ASN lookup](https://ip-api.io/asn-lookup),
[WHOIS lookup](https://ip-api.io/whois-lookup),
[reverse DNS](https://ip-api.io/reverse-dns-lookup) and
[MX record lookup](https://ip-api.io/mx-record-lookup).

## `asn(ip)` — autonomous system for an IP

Returns the ASN, owning organization, network range and country for an IP — and
whether it belongs to a datacenter.

```rust
use ip_api_io::Client;

# async fn run() -> Result<(), ip_api_io::Error> {
let client = Client::with_api_key("YOUR_API_KEY");

let asn = client.asn("8.8.8.8").await?;

println!("{:?}", asn.asn);            // Some(15169)
println!("{:?}", asn.organization);   // Some("Google LLC")
println!("{:?}", asn.network);        // Some("8.8.8.0/24")
println!("{}", asn.is_datacenter);    // true
println!("{:?}", asn.country_code);   // Some("US")
# Ok(())
# }
```

### Response (`AsnLookup`)
`ip`, `asn`, `organization`, `network`, `is_datacenter`, `country`, `country_code`.

## `whois(domain)` — domain registration

WHOIS record for a domain: registrar, registration/expiry/update dates, name servers,
status codes and the raw WHOIS text.

```rust
# async fn run(client: ip_api_io::Client) -> Result<(), ip_api_io::Error> {
let whois = client.whois("example.com").await?;

if let Some(registrar) = &whois.registrar {
    println!("{:?}", registrar.name);
}
println!("{:?}", whois.registered_on);  // Some("1995-08-14")
println!("{:?}", whois.expires_on);
println!("{:?}", whois.name_servers);
# Ok(())
# }
```

### Response (`Whois`)
`domain`, `registrar` (`name`, `url`, `iana_id`), `registered_on`, `expires_on`,
`updated_on`, `name_servers`, `status` (`code`, `humanized`), `raw`, `error`.

## `reverse_dns(ip)` — PTR record for an IP

```rust
# async fn run(client: ip_api_io::Client) -> Result<(), ip_api_io::Error> {
let rdns = client.reverse_dns("8.8.8.8").await?;

println!("{:?}", rdns.hostname);    // Some("dns.google")
println!("{:?}", rdns.ptr_record);
println!("{:?}", rdns.ttl);
# Ok(())
# }
```

### Response (`ReverseDns`)
`ip`, `hostname`, `ptr_record`, `ttl`.

## `forward_dns(hostname)` — resolve a hostname to addresses

```rust
# async fn run(client: ip_api_io::Client) -> Result<(), ip_api_io::Error> {
let fdns = client.forward_dns("dns.google").await?;

for record in &fdns.addresses {
    println!("{} {} {}", record.r#type, record.address, record.ttl); // "A" "8.8.8.8" 300
}
# Ok(())
# }
```

### Response (`ForwardDns`)
`hostname`, `addresses` (each `r#type`, `address`, `ttl`).

## `mx_records(domain)` — mail servers for a domain

```rust
# async fn run(client: ip_api_io::Client) -> Result<(), ip_api_io::Error> {
let mx = client.mx_records("example.com").await?;

for record in &mx.mx_records {
    println!("{} {} {}", record.priority, record.hostname, record.ttl);
}
# Ok(())
# }
```

### Response (`MxLookup`)
`domain`, `mx_records` (each `priority`, `hostname`, `ttl`).

## See also

- [IP geolocation & bulk lookup](ip-geolocation.md) — geolocation for the same IP
- [Email validation & verification](email-validation.md) — MX records feed deliverability
- [Domain age checker](domain-age.md) — registration age from WHOIS data
- Product pages: [ASN lookup](https://ip-api.io/asn-lookup) · [WHOIS lookup](https://ip-api.io/whois-lookup) · [Reverse DNS](https://ip-api.io/reverse-dns-lookup) · [MX record lookup](https://ip-api.io/mx-record-lookup)
