use httpmock::prelude::*;
use ip_api_io::{Client, Error};

// IpInfoV1Dto example from https://ip-api.io/openapi.json
const IP_INFO_FIXTURE: &str = r#"{
  "ip": "203.0.113.195",
  "isp": "Comcast Cable Communications",
  "asn": "AS7922",
  "suspicious_factors": {
    "is_proxy": false, "is_tor_node": false, "is_spam": false,
    "is_crawler": false, "is_datacenter": true, "is_vpn": false, "is_threat": false
  },
  "location": {
    "country": "United States", "country_code": "US", "city": "San Francisco",
    "latitude": 37.7749, "longitude": -122.4194, "zip": "94105",
    "timezone": "America/Los_Angeles", "local_time": "2023-06-21T14:30:00-07:00",
    "local_time_unix": 1687385400, "is_daylight_savings": true
  }
}"#;

fn client(server: &MockServer) -> Client {
    Client::builder().base_url(server.base_url()).build()
}

#[tokio::test]
async fn lookup_parses_response_and_sends_user_agent() {
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/ip/203.0.113.195")
            .header("user-agent", concat!("ip-api-io-rust/", env!("CARGO_PKG_VERSION")));
        then.status(200)
            .header("content-type", "application/json")
            .body(IP_INFO_FIXTURE);
    });

    let info = client(&server).lookup_ip("203.0.113.195").await.unwrap();
    mock.assert();
    assert_eq!(info.ip, "203.0.113.195");
    assert_eq!(info.location.country.as_deref(), Some("United States"));
    assert!(info.suspicious_factors.is_datacenter);
    assert_eq!(info.asn.as_deref(), Some("AS7922"));
}

#[tokio::test]
async fn api_key_sent_as_query_param() {
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/ip")
            .query_param("api_key", "secret123");
        then.status(200).body(IP_INFO_FIXTURE);
    });

    let client = Client::builder()
        .base_url(server.base_url())
        .api_key("secret123")
        .build();
    client.lookup().await.unwrap();
    mock.assert();
}

#[tokio::test]
async fn email_path_is_url_encoded() {
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/email/advanced/user%2Btag%40example.com");
        then.status(200).body(
            r#"{"email":"user+tag@example.com","reachable":"yes",
                "syntax":{"username":"user+tag","domain":"example.com","valid":true},
                "disposable":false,"role_account":false,"free":false,"has_mx_records":true}"#,
        );
    });

    client(&server).validate_email("user+tag@example.com").await.unwrap();
    mock.assert();
}

#[tokio::test]
async fn batch_post_sends_json_body() {
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(POST)
            .path("/api/v1/ip/batch")
            .header("content-type", "application/json")
            .json_body(serde_json::json!({ "ips": ["8.8.8.8", "1.1.1.1"] }));
        then.status(200).body(r#"{"results": {}}"#);
    });

    client(&server).lookup_batch(&["8.8.8.8", "1.1.1.1"]).await.unwrap();
    mock.assert();
}

#[tokio::test]
async fn batch_size_validation() {
    let client = Client::new();
    assert!(matches!(
        client.lookup_batch(&[]).await,
        Err(Error::InvalidArgument(_))
    ));
    let big: Vec<&str> = vec!["1.1.1.1"; 101];
    assert!(matches!(
        client.lookup_batch(&big).await,
        Err(Error::InvalidArgument(_))
    ));
    assert!(matches!(
        client.validate_email_batch(&[]).await,
        Err(Error::InvalidArgument(_))
    ));
}

#[tokio::test]
async fn rate_limit_error_exposes_headers() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(GET).path("/api/v1/ip/8.8.8.8");
        then.status(429)
            .header("x-ratelimit-limit", "1000")
            .header("x-ratelimit-remaining", "0")
            .header("x-ratelimit-reset", "1718200000")
            .body(r#"{"message": "Rate limit exceeded"}"#);
    });

    let error = client(&server).lookup_ip("8.8.8.8").await.unwrap_err();
    match error {
        Error::RateLimit {
            status,
            message,
            limit,
            remaining,
            reset,
            ..
        } => {
            assert_eq!(status, 429);
            assert_eq!(message, "Rate limit exceeded");
            assert_eq!(limit, Some(1000));
            assert_eq!(remaining, Some(0));
            assert_eq!(reset, Some(1718200000));
        }
        other => panic!("expected RateLimit, got {other:?}"),
    }
}

#[tokio::test]
async fn authentication_error_on_401() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(GET).path("/api/v1/ip");
        then.status(401).body(r#"{"error": "Invalid API key"}"#);
    });

    let error = client(&server).lookup().await.unwrap_err();
    assert!(matches!(error, Error::Authentication { status: 401, .. }));
}

#[tokio::test]
async fn invalid_request_error_on_400() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(GET).path("/api/v1/ip/not-an-ip");
        then.status(400).body(r#"{"message": "Invalid IP address"}"#);
    });

    let error = client(&server).lookup_ip("not-an-ip").await.unwrap_err();
    assert!(matches!(error, Error::InvalidRequest { status: 400, .. }));
}

#[tokio::test]
async fn server_error_on_500() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(GET).path("/api/v1/ip");
        then.status(500).body("{}");
    });

    let error = client(&server).lookup().await.unwrap_err();
    assert!(matches!(error, Error::Server { status: 500, .. }));
}
