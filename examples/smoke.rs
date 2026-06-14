//! Live smoke test against https://ip-api.io.
//! Usage: IPAPI_API_KEY=... cargo run --example smoke
//! The API requires a key; without IPAPI_API_KEY this program skips.

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let Ok(api_key) = std::env::var("IPAPI_API_KEY") else {
        println!("SKIPPED: set IPAPI_API_KEY to run the live smoke test");
        return Ok(());
    };

    let client = ip_api_io::Client::with_api_key(api_key);

    let info = client.lookup_ip("8.8.8.8").await?;
    assert_eq!(info.ip, "8.8.8.8");
    println!(
        "lookup(8.8.8.8): {:?} / {:?}",
        info.location.country, info.asn
    );

    let rate_limit = client.rate_limit().await?;
    println!(
        "rate_limit: plan={} ip_api remaining={}",
        rate_limit.plan_id, rate_limit.ip_api.remaining
    );

    println!("smoke OK");
    Ok(())
}
