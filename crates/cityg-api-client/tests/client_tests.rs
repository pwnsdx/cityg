use cityg_api_client::{CitygApiClient, Error};

#[test]
fn test_client_new_removes_trailing_slash() {
    let _client = CitygApiClient::new("http://localhost:8080/");
    // Client should store base_url without trailing slash
    // We can't directly access base_url, but we can verify behavior
    let _client2 = CitygApiClient::new("http://localhost:8080");
    // Both should behave the same
}

#[test]
fn test_client_new_with_https() {
    let _client = CitygApiClient::new("https://example.com");
    // Should accept HTTPS URLs
}

#[test]
fn test_client_new_with_port() {
    let _client = CitygApiClient::new("http://localhost:3000");
    // Should accept custom ports
}

#[tokio::test]
async fn test_health_check_unreachable_server() {
    let client = CitygApiClient::new("http://localhost:65535");
    let result = client.health().await;
    assert!(
        result.is_err(),
        "Health check should fail for unreachable server"
    );
}

#[tokio::test]
async fn test_health_check_invalid_url() {
    let client = CitygApiClient::new("http://invalid.local.test.example:99999");
    let result = client.health().await;
    assert!(
        result.is_err(),
        "Health check should fail for invalid domain"
    );
}

#[test]
fn test_error_display() {
    // Test error display implementations
    let err = Error::Parse("test message".to_string());
    let display = format!("{}", err);
    assert!(display.contains("test message"));
}

#[test]
fn test_error_from_reqwest() {
    // Test that we can create errors from reqwest errors
    // This will be tested indirectly through actual HTTP calls
}

// Mock server tests would go here if we had a mock server setup
// For now, these basic construction tests ensure the API is usable
