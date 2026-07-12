use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

pub const BACKEND_LOCAL_FILESYSTEM: &str = "local_filesystem";
pub const BACKEND_S3_COMPATIBLE: &str = "s3_compatible";
pub const BACKEND_DISABLED: &str = "disabled";
pub const STATUS_NOT_CONFIGURED: &str = "not_configured";
pub const STATUS_CONFIGURED_METADATA_ONLY: &str = "configured_metadata_only";
pub const STATUS_VALIDATION_REQUIRED: &str = "validation_required";
pub const STATUS_READY_FOR_TEST: &str = "ready_for_test";
pub const STATUS_READY: &str = "ready";
pub const STATUS_DISABLED: &str = "disabled";
pub const STATUS_ERROR: &str = "error";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceStorageBackendConfigRequest {
    pub backend_id: Option<String>,
    pub backend_type: String,
    pub display_name: String,
    pub status: Option<String>,
    pub endpoint_reference: Option<String>,
    pub region: Option<String>,
    pub bucket_name: Option<String>,
    pub key_prefix: Option<String>,
    pub access_key_secret_ref: Option<String>,
    pub secret_key_secret_ref: Option<String>,
    pub session_token_secret_ref: Option<String>,
    pub tls_required: Option<bool>,
    pub allow_path_style: Option<bool>,
    pub allowed_endpoint_policy: Option<String>,
    pub known_limitations: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EvidenceStorageBackendConfig {
    pub id: i64,
    pub tenant_id: i64,
    pub backend_id: String,
    pub backend_type: String,
    pub display_name: String,
    pub status: String,
    pub endpoint_reference: String,
    pub region: String,
    pub bucket_name: String,
    pub key_prefix: String,
    pub access_key_secret_ref: String,
    pub secret_key_secret_ref: String,
    pub session_token_secret_ref: String,
    pub tls_required: bool,
    pub allow_path_style: bool,
    pub allowed_endpoint_policy: String,
    pub last_validation_at: Option<String>,
    pub last_validation_status: String,
    pub last_validation_error_class: String,
    pub created_at: String,
    pub updated_at: String,
    pub known_limitations: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct EvidenceStorageSecretReferenceStatus {
    pub id: i64,
    pub tenant_id: i64,
    pub backend_id: String,
    pub secret_reference: String,
    pub secret_ref_type: String,
    pub presence_status: String,
    pub last_checked_at: Option<String>,
    pub last_check_error_class: String,
    pub redacted_display_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceObjectReferenceAttachRequest {
    pub backend_id: String,
    pub object_key: String,
    pub expected_sha256: Option<String>,
    pub contract_status: Option<String>,
    pub contract_sha256: Option<String>,
    pub contract_size_bytes: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EvidenceObjectReference {
    pub id: i64,
    pub tenant_id: i64,
    pub evidence_id: i64,
    pub backend_id: String,
    pub backend_type: String,
    pub object_key_redacted: String,
    pub object_key_sha256: String,
    pub object_reference_status: String,
    pub expected_sha256: String,
    pub contract_status: String,
    pub contract_sha256: String,
    pub contract_size_bytes: Option<i64>,
    pub last_drill_at: Option<String>,
    pub last_drill_status: String,
    pub last_drill_error_class: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct EvidenceObjectDrillResult {
    pub backend_id: String,
    pub backend_type: String,
    pub evidence_id: i64,
    pub object_reference_present: bool,
    pub object_present: bool,
    pub readable: bool,
    pub expected_sha256_present: bool,
    pub calculated_sha256: String,
    pub hash_matches: bool,
    pub status: String,
    pub safe_error_class: String,
    pub size_bytes: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EvidenceStorageBackendEvent {
    pub id: i64,
    pub tenant_id: i64,
    pub backend_id: String,
    pub evidence_id: Option<i64>,
    pub event_type: String,
    pub actor_id: Option<i64>,
    pub status: String,
    pub error_class: String,
    pub summary: String,
    pub detail: serde_json::Value,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct EndpointValidationResult {
    pub valid: bool,
    pub safe_error_class: String,
    pub scheme: String,
    pub host_class: String,
    pub dns_resolution_checked: bool,
    pub runtime_dns_recheck_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedObjectKey {
    pub redacted: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectStorageValidationError {
    InvalidBackendType,
    InvalidBackendStatus,
    InvalidEndpoint,
    EndpointContainsCredentials,
    InsecureScheme,
    BlockedLoopback,
    BlockedLinkLocal,
    BlockedPrivateNetwork,
    BlockedMetadataService,
    DnsResolutionFailed,
    EndpointPolicyViolation,
    InvalidSecretReference,
    InvalidBucketName,
    InvalidObjectKey,
    ObjectKeyTraversal,
    ObjectKeyOutsidePrefix,
    ObjectReferenceTenantMismatch,
}

impl ObjectStorageValidationError {
    pub fn safe_error_class(&self) -> &'static str {
        match self {
            Self::InvalidBackendType => "invalid_backend_type",
            Self::InvalidBackendStatus => "invalid_backend_status",
            Self::InvalidEndpoint => "invalid_endpoint",
            Self::EndpointContainsCredentials => "endpoint_contains_credentials",
            Self::InsecureScheme => "insecure_scheme",
            Self::BlockedLoopback => "blocked_loopback",
            Self::BlockedLinkLocal => "blocked_link_local",
            Self::BlockedPrivateNetwork => "blocked_private_network",
            Self::BlockedMetadataService => "blocked_metadata_service",
            Self::DnsResolutionFailed => "dns_resolution_failed",
            Self::EndpointPolicyViolation => "endpoint_policy_violation",
            Self::InvalidSecretReference => "invalid_reference",
            Self::InvalidBucketName => "invalid_bucket_name",
            Self::InvalidObjectKey => "invalid_object_key",
            Self::ObjectKeyTraversal => "object_key_traversal",
            Self::ObjectKeyOutsidePrefix => "object_key_outside_prefix",
            Self::ObjectReferenceTenantMismatch => "object_reference_tenant_mismatch",
        }
    }
}

impl fmt::Display for ObjectStorageValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "object_storage_validation:{}",
            self.safe_error_class()
        )
    }
}

impl std::error::Error for ObjectStorageValidationError {}

pub fn normalize_backend_type(value: &str) -> Option<&'static str> {
    match value.trim().to_ascii_lowercase().as_str() {
        BACKEND_LOCAL_FILESYSTEM => Some(BACKEND_LOCAL_FILESYSTEM),
        BACKEND_S3_COMPATIBLE | "object_storage_s3_compatible" => Some(BACKEND_S3_COMPATIBLE),
        BACKEND_DISABLED | "not_configured" => Some(BACKEND_DISABLED),
        _ => None,
    }
}

pub fn normalize_backend_status(value: Option<&str>, backend_type: &str) -> Option<&'static str> {
    let value = value.unwrap_or("").trim().to_ascii_lowercase();
    if value.is_empty() {
        return Some(if backend_type == BACKEND_DISABLED {
            STATUS_NOT_CONFIGURED
        } else {
            STATUS_VALIDATION_REQUIRED
        });
    }
    match value.as_str() {
        STATUS_NOT_CONFIGURED => Some(STATUS_NOT_CONFIGURED),
        STATUS_CONFIGURED_METADATA_ONLY => Some(STATUS_CONFIGURED_METADATA_ONLY),
        STATUS_VALIDATION_REQUIRED => Some(STATUS_VALIDATION_REQUIRED),
        STATUS_READY_FOR_TEST => Some(STATUS_READY_FOR_TEST),
        STATUS_READY => Some(STATUS_READY),
        STATUS_DISABLED => Some(STATUS_DISABLED),
        STATUS_ERROR => Some(STATUS_ERROR),
        _ => None,
    }
}

pub fn normalize_endpoint_policy(value: Option<&str>) -> String {
    match value.unwrap_or("").trim().to_ascii_lowercase().as_str() {
        "local_dev_only" => "local_dev_only".to_string(),
        "metadata_only" => "metadata_only".to_string(),
        _ => "production_https_public".to_string(),
    }
}

pub fn normalize_key_prefix(value: Option<&str>) -> Result<String, ObjectStorageValidationError> {
    let value = value.unwrap_or("").trim().trim_matches('/');
    if value.is_empty() {
        return Ok(String::new());
    }
    validate_key_components(value)?;
    Ok(value.to_string())
}

pub fn validate_bucket_name(bucket: &str) -> Result<String, ObjectStorageValidationError> {
    let bucket = bucket.trim().to_ascii_lowercase();
    let valid = !bucket.is_empty()
        && bucket.len() <= 63
        && bucket.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'.'
        })
        && !bucket.starts_with('-')
        && !bucket.ends_with('-')
        && !bucket.contains("..")
        && !bucket.starts_with('.')
        && !bucket.ends_with('.');
    if valid {
        Ok(bucket)
    } else {
        Err(ObjectStorageValidationError::InvalidBucketName)
    }
}

pub fn validate_endpoint_reference(
    endpoint: &str,
    tls_required: bool,
    allowed_endpoint_policy: &str,
) -> Result<EndpointValidationResult, ObjectStorageValidationError> {
    let endpoint = endpoint.trim();
    if endpoint.is_empty() {
        return Err(ObjectStorageValidationError::InvalidEndpoint);
    }
    let url =
        reqwest::Url::parse(endpoint).map_err(|_| ObjectStorageValidationError::InvalidEndpoint)?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err(ObjectStorageValidationError::EndpointContainsCredentials);
    }
    let scheme = url.scheme().to_ascii_lowercase();
    let local_dev_policy = allowed_endpoint_policy == "local_dev_only";
    if scheme != "https" && (scheme != "http" || tls_required || !local_dev_policy) {
        return Err(ObjectStorageValidationError::InsecureScheme);
    }
    let Some(host) = url.host_str() else {
        return Err(ObjectStorageValidationError::InvalidEndpoint);
    };
    let host_lower = host.trim_matches(['[', ']']).to_ascii_lowercase();
    if is_metadata_host(&host_lower) {
        return Err(ObjectStorageValidationError::BlockedMetadataService);
    }
    if let Ok(ip) = host_lower.parse::<IpAddr>() {
        return classify_ip_endpoint(ip, local_dev_policy).map(|host_class| {
            EndpointValidationResult {
                valid: true,
                safe_error_class: String::new(),
                scheme,
                host_class,
                dns_resolution_checked: true,
                runtime_dns_recheck_required: false,
            }
        });
    }
    if host_lower == "localhost" || host_lower.ends_with(".localhost") {
        if local_dev_policy {
            return Ok(EndpointValidationResult {
                valid: true,
                safe_error_class: String::new(),
                scheme,
                host_class: "local_dev_hostname".to_string(),
                dns_resolution_checked: false,
                runtime_dns_recheck_required: true,
            });
        }
        return Err(ObjectStorageValidationError::BlockedLoopback);
    }
    if host_lower.ends_with(".local") && !local_dev_policy {
        return Err(ObjectStorageValidationError::EndpointPolicyViolation);
    }
    Ok(EndpointValidationResult {
        valid: true,
        safe_error_class: String::new(),
        scheme,
        host_class: "public_hostname_unresolved".to_string(),
        dns_resolution_checked: false,
        runtime_dns_recheck_required: true,
    })
}

pub fn validate_secret_reference(reference: &str) -> Result<String, ObjectStorageValidationError> {
    let reference = reference.trim();
    if reference.is_empty() {
        return Ok(String::new());
    }
    let has_allowed_prefix = ["env:", "file:", "vault:", "secret:", "external:"]
        .iter()
        .any(|prefix| reference.starts_with(prefix));
    let looks_like_value = reference.contains('\n')
        || reference.contains('\r')
        || reference.contains('=')
        || reference.contains("://")
        || reference.to_ascii_uppercase().contains("BEGIN ")
        || reference.to_ascii_uppercase().starts_with("AKIA")
        || reference.len() > 160;
    if !has_allowed_prefix || looks_like_value {
        return Err(ObjectStorageValidationError::InvalidSecretReference);
    }
    Ok(reference.to_string())
}

pub fn secret_presence_status(reference: &str) -> &'static str {
    if reference.trim().is_empty() {
        "not_configured"
    } else {
        "reference_present"
    }
}

pub fn redacted_secret_display(reference: &str) -> String {
    let reference = reference.trim();
    if reference.is_empty() {
        return "nicht konfiguriert".to_string();
    }
    let prefix = reference.split(':').next().unwrap_or("ref");
    let digest = short_sha256(reference);
    format!("{prefix}:...{digest}")
}

pub fn validate_object_key(
    tenant_id: i64,
    evidence_id: i64,
    key_prefix: &str,
    object_key: &str,
) -> Result<ValidatedObjectKey, ObjectStorageValidationError> {
    let object_key = object_key.trim();
    validate_key_components(object_key)?;
    let prefix = normalize_key_prefix(Some(key_prefix))?;
    if !prefix.is_empty() && object_key != prefix && !object_key.starts_with(&format!("{prefix}/"))
    {
        return Err(ObjectStorageValidationError::ObjectKeyOutsidePrefix);
    }
    let required_fragment = format!("tenants/{tenant_id}/evidence/{evidence_id}/");
    if !object_key.contains(&required_fragment) {
        return Err(ObjectStorageValidationError::ObjectReferenceTenantMismatch);
    }
    Ok(ValidatedObjectKey {
        redacted: redacted_object_key(object_key),
        sha256: full_sha256(object_key),
    })
}

pub fn redacted_object_key(object_key: &str) -> String {
    let digest = short_sha256(object_key);
    let tail = object_key
        .rsplit('/')
        .next()
        .unwrap_or("object")
        .chars()
        .take(16)
        .collect::<String>();
    format!("object:{tail}...{digest}")
}

pub fn full_sha256(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}

pub fn short_sha256(value: &str) -> String {
    full_sha256(value).chars().take(12).collect::<String>()
}

fn validate_key_components(value: &str) -> Result<(), ObjectStorageValidationError> {
    if value.is_empty()
        || value.contains('\0')
        || value.contains('\\')
        || value.starts_with('/')
        || value.starts_with('~')
        || has_windows_drive_prefix(value)
    {
        return Err(ObjectStorageValidationError::InvalidObjectKey);
    }
    for component in value.split('/') {
        if component.is_empty() || component == "." || component == ".." {
            return Err(ObjectStorageValidationError::ObjectKeyTraversal);
        }
    }
    Ok(())
}

fn has_windows_drive_prefix(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() > 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

fn is_metadata_host(host: &str) -> bool {
    matches!(host, "169.254.169.254" | "169.254.170.2")
        || host == "metadata.google.internal"
        || host == "metadata"
        || host.contains("metadata.service")
}

fn classify_ip_endpoint(
    ip: IpAddr,
    local_dev_policy: bool,
) -> Result<String, ObjectStorageValidationError> {
    match ip {
        IpAddr::V4(ip) => classify_ipv4_endpoint(ip, local_dev_policy),
        IpAddr::V6(ip) => classify_ipv6_endpoint(ip, local_dev_policy),
    }
}

pub fn validate_resolved_ip(
    ip: IpAddr,
    allow_local_test_endpoint: bool,
) -> Result<String, ObjectStorageValidationError> {
    classify_ip_endpoint(ip, allow_local_test_endpoint)
}

fn classify_ipv4_endpoint(
    ip: Ipv4Addr,
    local_dev_policy: bool,
) -> Result<String, ObjectStorageValidationError> {
    if ip == Ipv4Addr::new(169, 254, 169, 254) || ip == Ipv4Addr::new(169, 254, 170, 2) {
        return Err(ObjectStorageValidationError::BlockedMetadataService);
    }
    if ip.is_loopback() {
        return if local_dev_policy {
            Ok("local_dev_loopback".to_string())
        } else {
            Err(ObjectStorageValidationError::BlockedLoopback)
        };
    }
    if ip.is_link_local() {
        return Err(ObjectStorageValidationError::BlockedLinkLocal);
    }
    if is_shared_carrier_grade_nat(ip) {
        return Err(ObjectStorageValidationError::BlockedPrivateNetwork);
    }
    if ip.is_private() {
        return if local_dev_policy {
            Ok("local_dev_private".to_string())
        } else {
            Err(ObjectStorageValidationError::BlockedPrivateNetwork)
        };
    }
    Ok("public_ip".to_string())
}

fn classify_ipv6_endpoint(
    ip: Ipv6Addr,
    local_dev_policy: bool,
) -> Result<String, ObjectStorageValidationError> {
    if ip.is_loopback() {
        return if local_dev_policy {
            Ok("local_dev_loopback".to_string())
        } else {
            Err(ObjectStorageValidationError::BlockedLoopback)
        };
    }
    if ip.is_unspecified() || is_ipv6_link_local(ip) {
        return Err(ObjectStorageValidationError::BlockedLinkLocal);
    }
    if is_ipv6_unique_local(ip) {
        return if local_dev_policy {
            Ok("local_dev_private".to_string())
        } else {
            Err(ObjectStorageValidationError::BlockedPrivateNetwork)
        };
    }
    Ok("public_ip".to_string())
}

fn is_shared_carrier_grade_nat(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 100 && (octets[1] & 0b1100_0000) == 0b0100_0000
}

fn is_ipv6_link_local(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
}

fn is_ipv6_unique_local(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xfe00) == 0xfc00
}

#[derive(Debug, Clone)]
pub struct MockObjectStorageObject {
    pub sha256: String,
    pub size_bytes: i64,
    pub readable: bool,
}

#[derive(Debug, Clone, Default)]
pub struct MockObjectStorageClient {
    objects: BTreeMap<String, MockObjectStorageObject>,
}

impl MockObjectStorageClient {
    pub fn with_object(mut self, object_key: &str, sha256: &str, size_bytes: i64) -> Self {
        self.objects.insert(
            object_key.to_string(),
            MockObjectStorageObject {
                sha256: sha256.to_string(),
                size_bytes,
                readable: true,
            },
        );
        self
    }

    pub fn with_unreadable_object(mut self, object_key: &str, size_bytes: i64) -> Self {
        self.objects.insert(
            object_key.to_string(),
            MockObjectStorageObject {
                sha256: String::new(),
                size_bytes,
                readable: false,
            },
        );
        self
    }

    pub fn drill(
        &self,
        object_key: &str,
        expected_sha256: Option<&str>,
    ) -> EvidenceObjectDrillResult {
        let Some(object) = self.objects.get(object_key) else {
            return EvidenceObjectDrillResult {
                backend_id: "mock".to_string(),
                backend_type: BACKEND_S3_COMPATIBLE.to_string(),
                evidence_id: 0,
                object_reference_present: true,
                object_present: false,
                readable: false,
                expected_sha256_present: expected_sha256.is_some_and(|value| !value.is_empty()),
                calculated_sha256: String::new(),
                hash_matches: false,
                status: "missing_artifact".to_string(),
                safe_error_class: "object_missing".to_string(),
                size_bytes: None,
            };
        };
        if !object.readable {
            return EvidenceObjectDrillResult {
                backend_id: "mock".to_string(),
                backend_type: BACKEND_S3_COMPATIBLE.to_string(),
                evidence_id: 0,
                object_reference_present: true,
                object_present: true,
                readable: false,
                expected_sha256_present: expected_sha256.is_some_and(|value| !value.is_empty()),
                calculated_sha256: String::new(),
                hash_matches: false,
                status: "check_failed".to_string(),
                safe_error_class: "object_unreadable".to_string(),
                size_bytes: Some(object.size_bytes),
            };
        }
        let expected = expected_sha256.unwrap_or("").trim();
        let expected_present = !expected.is_empty();
        let hash_matches = expected_present && expected.eq_ignore_ascii_case(&object.sha256);
        EvidenceObjectDrillResult {
            backend_id: "mock".to_string(),
            backend_type: BACKEND_S3_COMPATIBLE.to_string(),
            evidence_id: 0,
            object_reference_present: true,
            object_present: true,
            readable: true,
            expected_sha256_present: expected_present,
            calculated_sha256: object.sha256.clone(),
            hash_matches,
            status: if !expected_present || hash_matches {
                "valid".to_string()
            } else {
                "mismatch".to_string()
            },
            safe_error_class: if !expected_present || hash_matches {
                String::new()
            } else {
                "hash_mismatch".to_string()
            },
            size_bytes: Some(object.size_bytes),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_validation_blocks_ssrf_and_credentials() {
        assert_eq!(
            validate_endpoint_reference(
                "https://access:secret@example.com",
                true,
                "production_https_public"
            )
            .unwrap_err()
            .safe_error_class(),
            "endpoint_contains_credentials"
        );
        assert_eq!(
            validate_endpoint_reference(
                "http://objects.example.test",
                true,
                "production_https_public"
            )
            .unwrap_err()
            .safe_error_class(),
            "insecure_scheme"
        );
        assert_eq!(
            validate_endpoint_reference("https://169.254.169.254", true, "production_https_public")
                .unwrap_err()
                .safe_error_class(),
            "blocked_metadata_service"
        );
        assert_eq!(
            validate_endpoint_reference("https://127.0.0.1:9000", true, "production_https_public")
                .unwrap_err()
                .safe_error_class(),
            "blocked_loopback"
        );
        assert_eq!(
            validate_endpoint_reference("https://10.0.0.1", true, "production_https_public")
                .unwrap_err()
                .safe_error_class(),
            "blocked_private_network"
        );
        let valid = validate_endpoint_reference(
            "https://objects.example.test",
            true,
            "production_https_public",
        )
        .unwrap();
        assert!(valid.valid);
        assert!(valid.runtime_dns_recheck_required);
    }

    #[test]
    fn object_key_validation_enforces_prefix_tenant_and_traversal_rules() {
        let key = validate_object_key(
            7,
            42,
            "iscy",
            "iscy/tenants/7/evidence/42/artifacts/report.pdf",
        )
        .unwrap();
        assert!(key.redacted.starts_with("object:report.pdf"));
        assert_eq!(key.sha256.len(), 64);

        assert_eq!(
            validate_object_key(7, 42, "iscy", "iscy/tenants/7/evidence/43/report.pdf")
                .unwrap_err()
                .safe_error_class(),
            "object_reference_tenant_mismatch"
        );
        assert_eq!(
            validate_object_key(7, 42, "iscy", "other/tenants/7/evidence/42/report.pdf")
                .unwrap_err()
                .safe_error_class(),
            "object_key_outside_prefix"
        );
        assert_eq!(
            validate_object_key(7, 42, "iscy", "iscy/../tenants/7/evidence/42/report.pdf")
                .unwrap_err()
                .safe_error_class(),
            "object_key_traversal"
        );
        assert_eq!(
            validate_object_key(7, 42, "iscy", "/iscy/tenants/7/evidence/42/report.pdf")
                .unwrap_err()
                .safe_error_class(),
            "invalid_object_key"
        );
    }

    #[test]
    fn secret_refs_are_references_only() {
        assert_eq!(
            validate_secret_reference("AKIAIOSFODNN7EXAMPLE")
                .unwrap_err()
                .safe_error_class(),
            "invalid_reference"
        );
        let reference = validate_secret_reference("env:ISCY_OBJECT_ACCESS_KEY_FILE").unwrap();
        assert_eq!(reference, "env:ISCY_OBJECT_ACCESS_KEY_FILE");
        assert!(redacted_secret_display(&reference).starts_with("env:..."));
    }

    #[test]
    fn mock_client_contract_covers_found_missing_unreadable_and_mismatch() {
        let client = MockObjectStorageClient::default()
            .with_object("key/valid", "aaaaaaaa", 8)
            .with_object("key/mismatch", "bbbbbbbb", 8)
            .with_unreadable_object("key/unreadable", 8);
        assert_eq!(client.drill("key/valid", Some("aaaaaaaa")).status, "valid");
        assert_eq!(
            client.drill("key/mismatch", Some("aaaaaaaa")).status,
            "mismatch"
        );
        assert_eq!(
            client
                .drill("key/missing", Some("aaaaaaaa"))
                .safe_error_class,
            "object_missing"
        );
        assert_eq!(
            client
                .drill("key/unreadable", Some("aaaaaaaa"))
                .safe_error_class,
            "object_unreadable"
        );
    }
}
