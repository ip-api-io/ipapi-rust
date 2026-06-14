# Email validation & verification

Check whether an email address is real, deliverable and safe to accept — before it
ever enters your database. The SDK exposes three levels: a fast syntax/MX/disposable
check, full SMTP verification, and a batch endpoint for cleaning whole lists.

Powers [email validation](https://ip-api.io/email-validation),
[advanced email validation](https://ip-api.io/advanced-email-validation),
[email verification](https://ip-api.io/email-verification-api),
[disposable email detection](https://ip-api.io/disposable-email-checker) and
[email list cleaning](https://ip-api.io/email-list-cleaning).

## `email_info(email)` — fast syntax, MX & disposable check

A lightweight check (no SMTP probe): validates syntax, confirms the domain has MX
records, and flags disposable/throwaway providers. Use it inline on sign-up forms.

```rust
use ip_api_io::Client;

# async fn run() -> Result<(), ip_api_io::Error> {
let client = Client::with_api_key("YOUR_API_KEY");

let info = client.email_info("user@example.com").await?;

println!("{}", info.syntax.is_valid);   // true
println!("{}", info.is_disposable);     // false
println!("{}", info.has_mx_records);    // true
if let Some(mx) = info.mx_records.first() {
    println!("{}", mx.hostname);
}
# Ok(())
# }
```

### Response (`EmailInfo`)

| Field | Type | Description |
|---|---|---|
| `email` | `String` | The address checked |
| `is_disposable` | `bool` | Throwaway / temporary provider |
| `has_mx_records` | `bool` | Domain can receive mail |
| `mx_records` | `Vec<MxRecord>` | Each: `priority`, `hostname`, `ttl` |
| `syntax` | `EmailSyntax` | `is_valid`, `domain`, `username`, `error_reasons` |

## `validate_email(email)` — full SMTP deliverability

Advanced verification that connects to the mail server to confirm the mailbox is
deliverable, and adds role-account, free-provider, catch-all and Gravatar signals.
Use it before sending important mail or accepting a paying customer.

```rust
# async fn run(client: ip_api_io::Client) -> Result<(), ip_api_io::Error> {
let result = client.validate_email("user@example.com").await?;

println!("{}", result.reachable);     // "yes" | "no" | "unknown"
if let Some(smtp) = &result.smtp {
    println!("{} {}", smtp.deliverable, smtp.catch_all);
}
println!("{}", result.disposable);    // false
println!("{}", result.role_account);  // false  (e.g. info@, support@)
println!("{}", result.free);          // false  (e.g. gmail.com)
println!("{}", result.suggestion);    // typo fix, e.g. "user@gmail.com"
# Ok(())
# }
```

### Response (`AdvancedEmailValidation`)

| Field | Type | Description |
|---|---|---|
| `email` | `String` | The address checked |
| `reachable` | `String` | `"yes"`, `"no"` or `"unknown"` |
| `syntax` | `AdvancedSyntax` | `username`, `domain`, `valid` |
| `smtp` | `Option<AdvancedSmtp>` | `host_exists`, `deliverable`, `full_inbox`, `catch_all`, `disabled` |
| `gravatar` | `Option<AdvancedGravatar>` | `has_gravatar`, `gravatar_url` |
| `suggestion` | `String` | Suggested correction for a likely typo |
| `disposable` | `bool` | Throwaway provider |
| `role_account` | `bool` | Role address (info@, sales@, …) |
| `free` | `bool` | Free webmail provider |
| `has_mx_records` | `bool` | Domain can receive mail |

## `validate_email_batch(emails)` — clean a list (≤100)

Advanced-validate up to 100 addresses in one request — the building block for
[email list cleaning](https://ip-api.io/email-list-cleaning). Returns
`Error::InvalidArgument` if the slice is empty or longer than 100.

```rust
# async fn run(client: ip_api_io::Client) -> Result<(), ip_api_io::Error> {
let batch = client
    .validate_email_batch(&["user@example.com", "fake@mailinator.com"])
    .await?;

println!("{}", batch.total_processed);        // 2
println!("{}", batch.successful_validations); // 2

for (email, result) in &batch.results {
    println!("{email} {} {}", result.reachable, result.disposable);
}
# Ok(())
# }
```

### Response (`BatchEmailValidationResponse`)

| Field | Type | Description |
|---|---|---|
| `results` | `HashMap<String, AdvancedEmailValidation>` | Map of email → result |
| `total_processed` | `i32` | Emails received |
| `successful_validations` | `i32` | Emails validated |
| `failed_validations` | `i32` | Emails that errored |

## See also

- [Fraud detection & risk scoring](fraud-risk-scoring.md) — `email_risk_score` for a 0–100 score
- [ASN & DNS lookups](asn-and-dns.md) — `mx_records` to inspect a domain's mail servers
- Product pages: [Email validation](https://ip-api.io/email-validation) · [Advanced validation](https://ip-api.io/advanced-email-validation) · [Email verification API](https://ip-api.io/email-verification-api) · [Disposable email checker](https://ip-api.io/disposable-email-checker) · [Email list cleaning](https://ip-api.io/email-list-cleaning)
