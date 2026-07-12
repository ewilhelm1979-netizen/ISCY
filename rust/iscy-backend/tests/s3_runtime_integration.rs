use iscy_backend::evidence_s3_runtime::{
    canonical_object_key, S3RuntimeClient, S3RuntimeConfig, S3RuntimeError, SecretResolver,
};
use sha2::Digest;

#[tokio::test]
#[ignore = "requires the isolated MinIO integration environment"]
async fn minio_put_head_get_drill_and_controlled_delete_lifecycle() {
    let endpoint = std::env::var("ISCY_TEST_S3_ENDPOINT").expect("test endpoint");
    let bucket = std::env::var("ISCY_TEST_S3_BUCKET").expect("test bucket");
    let client = S3RuntimeClient::new(
        S3RuntimeConfig {
            endpoint,
            region: "us-east-1".to_string(),
            bucket,
            key_prefix: "integration".to_string(),
            access_key_secret_ref: "env:ISCY_TEST_S3_ACCESS_KEY".to_string(),
            secret_key_secret_ref: "env:ISCY_TEST_S3_SECRET_KEY".to_string(),
            session_token_secret_ref: String::new(),
            allow_path_style: true,
            allow_local_test_endpoint: true,
            production: false,
            max_object_bytes: 1024 * 1024,
        },
        SecretResolver::from_environment(),
    );
    let object_id = "0123456789abcdef0123456789abcdef";
    let key = canonical_object_key("integration", 42, 7001, object_id).unwrap();
    let content = b"ISCY MinIO runtime integration evidence";
    let expected_sha256 = format!("{:x}", sha2::Sha256::digest(content));

    let put = client.put(&key, content, "text/plain").await.unwrap();
    assert!(put.completed);
    assert_eq!(put.sha256, expected_sha256);

    let head = client.head(&key).await.unwrap();
    assert!(head.present);
    assert_eq!(head.size_bytes, Some(content.len() as u64));

    let read = client.get(&key).await.unwrap();
    assert_eq!(read.bytes, content);
    assert_eq!(read.sha256, expected_sha256);

    let valid = client.drill(&key, &expected_sha256).await.unwrap();
    assert_eq!(valid.status, "valid");
    assert!(valid.hash_matches);

    let mismatch = client.drill(&key, &"0".repeat(64)).await.unwrap();
    assert_eq!(mismatch.status, "mismatch");
    assert_eq!(mismatch.safe_error_class, "hash_mismatch");

    let missing_key =
        canonical_object_key("integration", 42, 7001, "ffffffffffffffffffffffffffffffff").unwrap();
    assert_eq!(
        client.head(&missing_key).await.unwrap_err(),
        S3RuntimeError::ObjectMissing
    );

    std::env::set_var("ISCY_TEST_S3_WRONG_SECRET", "wrong-test-secret");
    let denied = S3RuntimeClient::new(
        S3RuntimeConfig {
            endpoint: std::env::var("ISCY_TEST_S3_ENDPOINT").unwrap(),
            region: "us-east-1".to_string(),
            bucket: std::env::var("ISCY_TEST_S3_BUCKET").unwrap(),
            key_prefix: "integration".to_string(),
            access_key_secret_ref: "env:ISCY_TEST_S3_ACCESS_KEY".to_string(),
            secret_key_secret_ref: "env:ISCY_TEST_S3_WRONG_SECRET".to_string(),
            session_token_secret_ref: String::new(),
            allow_path_style: true,
            allow_local_test_endpoint: true,
            production: false,
            max_object_bytes: 1024 * 1024,
        },
        SecretResolver::from_environment(),
    )
    .head(&key)
    .await
    .unwrap_err();
    assert_eq!(denied, S3RuntimeError::AccessDenied);

    let deleted = client.delete(&key).await.unwrap();
    assert!(deleted.completed);
    assert!(deleted.object_present_before);
    assert_eq!(
        client.head(&key).await.unwrap_err(),
        S3RuntimeError::ObjectMissing
    );
    let repeated = client.delete(&key).await.unwrap();
    assert!(repeated.completed);
    assert_eq!(repeated.safe_error_class, "object_already_missing");
}
