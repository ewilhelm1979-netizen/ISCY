use crate::evidence_object_storage::{
    full_sha256, normalize_key_prefix, validate_bucket_name, validate_endpoint_reference,
    validate_resolved_ip, validate_secret_reference, EvidenceStorageBackendConfig,
    ObjectStorageValidationError, BACKEND_S3_COMPATIBLE,
};
use chrono::Utc;
use hmac::{Hmac, Mac};
use reqwest::{header, Method, StatusCode, Url};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fmt, fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::{net::lookup_host, time::timeout};

type HmacSha256 = Hmac<Sha256>;

pub const MAX_SECRET_BYTES: u64 = 16 * 1024;
pub const DEFAULT_MAX_OBJECT_BYTES: usize = 25 * 1024 * 1024;
const DNS_TIMEOUT: Duration = Duration::from_secs(3);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const OPERATION_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone)]
pub struct SecretValue(Vec<u8>);

impl SecretValue {
    fn as_str(&self) -> Result<&str, S3RuntimeError> {
        std::str::from_utf8(&self.0).map_err(|_| S3RuntimeError::SecretResolutionFailed)
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretValue([redacted])")
    }
}

impl Drop for SecretValue {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum S3RuntimeError {
    InvalidEndpoint,
    EndpointContainsCredentials,
    InsecureScheme,
    BlockedLoopback,
    BlockedPrivateNetwork,
    BlockedLinkLocal,
    BlockedMetadataService,
    BlockedRedirect,
    DnsResolutionFailed,
    DnsRevalidationFailed,
    EndpointPolicyViolation,
    ConnectionTimeout,
    SecretReferenceMissing,
    SecretReferenceInvalid,
    SecretReferenceUnsupported,
    SecretFileOutsideAllowedRoot,
    SecretFileSymlinkEscape,
    SecretFilePermissionsInsecure,
    SecretResolutionFailed,
    BackendNotReady,
    InvalidObjectKey,
    ObjectTooLarge,
    ObjectMissing,
    AccessDenied,
    BackendUnavailable,
    HashMismatch,
    ObjectDeleteFailed,
}

impl S3RuntimeError {
    pub fn safe_error_class(&self) -> &'static str {
        match self {
            Self::InvalidEndpoint => "invalid_endpoint",
            Self::EndpointContainsCredentials => "endpoint_contains_credentials",
            Self::InsecureScheme => "insecure_scheme",
            Self::BlockedLoopback => "blocked_loopback",
            Self::BlockedPrivateNetwork => "blocked_private_network",
            Self::BlockedLinkLocal => "blocked_link_local",
            Self::BlockedMetadataService => "blocked_metadata_service",
            Self::BlockedRedirect => "blocked_redirect",
            Self::DnsResolutionFailed => "dns_resolution_failed",
            Self::DnsRevalidationFailed => "dns_revalidation_failed",
            Self::EndpointPolicyViolation => "endpoint_policy_violation",
            Self::ConnectionTimeout => "connection_timeout",
            Self::SecretReferenceMissing => "secret_reference_missing",
            Self::SecretReferenceInvalid => "secret_reference_invalid",
            Self::SecretReferenceUnsupported => "secret_reference_unsupported",
            Self::SecretFileOutsideAllowedRoot => "secret_file_outside_allowed_root",
            Self::SecretFileSymlinkEscape => "secret_file_symlink_escape",
            Self::SecretFilePermissionsInsecure => "secret_file_permissions_insecure",
            Self::SecretResolutionFailed => "secret_resolution_failed",
            Self::BackendNotReady => "backend_not_ready",
            Self::InvalidObjectKey => "invalid_object_key",
            Self::ObjectTooLarge => "object_too_large",
            Self::ObjectMissing => "object_missing",
            Self::AccessDenied => "access_denied",
            Self::BackendUnavailable => "backend_unavailable",
            Self::HashMismatch => "hash_mismatch",
            Self::ObjectDeleteFailed => "object_delete_failed",
        }
    }
}

impl fmt::Display for S3RuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "s3_runtime:{}", self.safe_error_class())
    }
}

impl std::error::Error for S3RuntimeError {}

impl From<ObjectStorageValidationError> for S3RuntimeError {
    fn from(value: ObjectStorageValidationError) -> Self {
        match value {
            ObjectStorageValidationError::InvalidEndpoint => Self::InvalidEndpoint,
            ObjectStorageValidationError::EndpointContainsCredentials => {
                Self::EndpointContainsCredentials
            }
            ObjectStorageValidationError::InsecureScheme => Self::InsecureScheme,
            ObjectStorageValidationError::BlockedLoopback => Self::BlockedLoopback,
            ObjectStorageValidationError::BlockedLinkLocal => Self::BlockedLinkLocal,
            ObjectStorageValidationError::BlockedPrivateNetwork => Self::BlockedPrivateNetwork,
            ObjectStorageValidationError::BlockedMetadataService => Self::BlockedMetadataService,
            ObjectStorageValidationError::DnsResolutionFailed => Self::DnsResolutionFailed,
            ObjectStorageValidationError::EndpointPolicyViolation => Self::EndpointPolicyViolation,
            ObjectStorageValidationError::InvalidSecretReference => Self::SecretReferenceInvalid,
            _ => Self::InvalidObjectKey,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SecretResolver {
    allowed_file_roots: Vec<PathBuf>,
}

impl SecretResolver {
    pub fn from_environment() -> Self {
        let mut roots = vec![PathBuf::from("/run/secrets")];
        roots.extend(
            std::env::var_os("ISCY_EVIDENCE_SECRET_ROOTS")
                .map(|value| {
                    std::env::split_paths(&value)
                        .filter(|path| path.is_absolute())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default(),
        );
        Self {
            allowed_file_roots: roots,
        }
    }

    pub fn with_allowed_file_roots(roots: Vec<PathBuf>) -> Self {
        Self {
            allowed_file_roots: roots,
        }
    }

    pub fn resolve(&self, reference: &str) -> Result<SecretValue, S3RuntimeError> {
        let reference = reference.trim();
        if reference.is_empty() {
            return Err(S3RuntimeError::SecretReferenceMissing);
        }
        if let Some(name) = reference.strip_prefix("env:") {
            return self.resolve_env_reference(name);
        }
        if let Some(path) = reference.strip_prefix("file:") {
            return self.resolve_file_secret(Path::new(path));
        }
        if ["vault:", "external:", "secret:"]
            .iter()
            .any(|prefix| reference.starts_with(prefix))
        {
            return Err(S3RuntimeError::SecretReferenceUnsupported);
        }
        Err(S3RuntimeError::SecretReferenceInvalid)
    }

    fn resolve_env_reference(&self, name: &str) -> Result<SecretValue, S3RuntimeError> {
        if !valid_env_name(name) {
            return Err(S3RuntimeError::SecretReferenceInvalid);
        }
        if let Some(base_name) = name.strip_suffix("_FILE") {
            if !valid_env_name(base_name) {
                return Err(S3RuntimeError::SecretReferenceInvalid);
            }
            if std::env::var_os(base_name).is_some() && std::env::var_os(name).is_some() {
                return Err(S3RuntimeError::SecretReferenceInvalid);
            }
            let path = std::env::var_os(name).ok_or(S3RuntimeError::SecretReferenceMissing)?;
            return self.resolve_file_secret(&PathBuf::from(path));
        }

        let file_name = format!("{name}_FILE");
        let direct = std::env::var_os(name);
        let file = std::env::var_os(&file_name);
        if direct.is_some() && file.is_some() {
            return Err(S3RuntimeError::SecretReferenceInvalid);
        }
        if let Some(path) = file {
            return self.resolve_file_secret(&PathBuf::from(path));
        }
        resolve_env_secret(name)
    }

    fn resolve_file_secret(&self, path: &Path) -> Result<SecretValue, S3RuntimeError> {
        if !path.is_absolute() || self.allowed_file_roots.is_empty() {
            return Err(S3RuntimeError::SecretFileOutsideAllowedRoot);
        }
        let initial_metadata =
            fs::symlink_metadata(path).map_err(|_| S3RuntimeError::SecretResolutionFailed)?;
        if initial_metadata.file_type().is_symlink() {
            return Err(S3RuntimeError::SecretFileSymlinkEscape);
        }
        let canonical_path = path
            .canonicalize()
            .map_err(|_| S3RuntimeError::SecretResolutionFailed)?;
        let mut within_root = false;
        for root in &self.allowed_file_roots {
            let root_metadata = match fs::symlink_metadata(root) {
                Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => metadata,
                _ => continue,
            };
            let _ = root_metadata;
            let canonical_root = root
                .canonicalize()
                .map_err(|_| S3RuntimeError::SecretResolutionFailed)?;
            if canonical_path.starts_with(&canonical_root) {
                within_root = true;
                break;
            }
        }
        if !within_root {
            return Err(S3RuntimeError::SecretFileSymlinkEscape);
        }
        let metadata =
            fs::metadata(&canonical_path).map_err(|_| S3RuntimeError::SecretResolutionFailed)?;
        if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_SECRET_BYTES {
            return Err(S3RuntimeError::SecretResolutionFailed);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(S3RuntimeError::SecretFilePermissionsInsecure);
            }
        }
        let mut value =
            fs::read(&canonical_path).map_err(|_| S3RuntimeError::SecretResolutionFailed)?;
        while matches!(value.last(), Some(b'\n' | b'\r')) {
            value.pop();
        }
        validate_secret_bytes(value)
    }
}

fn resolve_env_secret(name: &str) -> Result<SecretValue, S3RuntimeError> {
    if !valid_env_name(name) {
        return Err(S3RuntimeError::SecretReferenceInvalid);
    }
    let value = std::env::var_os(name).ok_or(S3RuntimeError::SecretReferenceMissing)?;
    let value = value
        .into_string()
        .map_err(|_| S3RuntimeError::SecretResolutionFailed)?
        .into_bytes();
    validate_secret_bytes(value)
}

fn valid_env_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    (first.is_ascii_uppercase() || first == b'_')
        && name.len() <= 128
        && bytes.all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

fn validate_secret_bytes(value: Vec<u8>) -> Result<SecretValue, S3RuntimeError> {
    if value.is_empty() || value.len() as u64 > MAX_SECRET_BYTES || value.contains(&0) {
        return Err(S3RuntimeError::SecretResolutionFailed);
    }
    std::str::from_utf8(&value).map_err(|_| S3RuntimeError::SecretResolutionFailed)?;
    Ok(SecretValue(value))
}

#[derive(Debug, Clone)]
pub struct S3RuntimeConfig {
    pub endpoint: String,
    pub region: String,
    pub bucket: String,
    pub key_prefix: String,
    pub access_key_secret_ref: String,
    pub secret_key_secret_ref: String,
    pub session_token_secret_ref: String,
    pub allow_path_style: bool,
    pub allow_local_test_endpoint: bool,
    pub production: bool,
    pub max_object_bytes: usize,
}

impl S3RuntimeConfig {
    pub fn from_backend(
        backend: &EvidenceStorageBackendConfig,
        production: bool,
        allow_local_test_endpoint: bool,
    ) -> Result<Self, S3RuntimeError> {
        if backend.backend_type != BACKEND_S3_COMPATIBLE
            || backend.endpoint_reference.trim().is_empty()
            || backend.region.trim().is_empty()
            || backend.bucket_name.trim().is_empty()
        {
            return Err(S3RuntimeError::BackendNotReady);
        }
        if production
            && (allow_local_test_endpoint || backend.allowed_endpoint_policy == "local_dev_only")
        {
            return Err(S3RuntimeError::EndpointPolicyViolation);
        }
        validate_bucket_name(&backend.bucket_name)?;
        let endpoint =
            Url::parse(&backend.endpoint_reference).map_err(|_| S3RuntimeError::InvalidEndpoint)?;
        if endpoint.query().is_some() || endpoint.fragment().is_some() {
            return Err(S3RuntimeError::InvalidEndpoint);
        }
        let key_prefix = normalize_key_prefix(Some(&backend.key_prefix))?;
        validate_endpoint_reference(
            &backend.endpoint_reference,
            backend.tls_required,
            if allow_local_test_endpoint && !production {
                "local_dev_only"
            } else {
                "production_https_public"
            },
        )?;
        // Revalidate persisted values at the outbound boundary. This protects
        // installations containing legacy or directly inserted backend rows.
        validate_secret_reference(
            &backend.access_key_secret_ref,
            "ISCY_EVIDENCE_OBJECT_STORAGE_ACCESS_KEY",
        )?;
        validate_secret_reference(
            &backend.secret_key_secret_ref,
            "ISCY_EVIDENCE_OBJECT_STORAGE_SECRET_KEY",
        )?;
        validate_secret_reference(
            &backend.session_token_secret_ref,
            "ISCY_EVIDENCE_OBJECT_STORAGE_SESSION_TOKEN",
        )?;
        Ok(Self {
            endpoint: backend.endpoint_reference.clone(),
            region: backend.region.clone(),
            bucket: backend.bucket_name.clone(),
            key_prefix,
            access_key_secret_ref: backend.access_key_secret_ref.clone(),
            secret_key_secret_ref: backend.secret_key_secret_ref.clone(),
            session_token_secret_ref: backend.session_token_secret_ref.clone(),
            allow_path_style: backend.allow_path_style,
            allow_local_test_endpoint: allow_local_test_endpoint && !production,
            production,
            max_object_bytes: DEFAULT_MAX_OBJECT_BYTES,
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct S3ObjectMetadata {
    pub present: bool,
    pub size_bytes: Option<u64>,
    pub etag_present: bool,
    pub safe_error_class: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct S3ObjectRead {
    #[serde(skip_serializing)]
    pub bytes: Vec<u8>,
    pub size_bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct S3OperationResult {
    pub completed: bool,
    pub object_present_before: bool,
    pub size_bytes: Option<u64>,
    pub sha256: String,
    pub safe_error_class: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct S3RuntimeDrill {
    pub object_present: bool,
    pub readable: bool,
    pub size_bytes: Option<u64>,
    pub calculated_sha256: String,
    pub hash_matches: bool,
    pub status: String,
    pub safe_error_class: String,
}

pub fn canonical_object_key(
    key_prefix: &str,
    tenant_id: i64,
    evidence_id: i64,
    object_id: &str,
) -> Result<String, S3RuntimeError> {
    if tenant_id < 1 || evidence_id < 1 || !valid_object_id(object_id) {
        return Err(S3RuntimeError::InvalidObjectKey);
    }
    let prefix = normalize_key_prefix(Some(key_prefix))?;
    let suffix = format!("tenants/{tenant_id}/evidence/{evidence_id}/objects/{object_id}");
    Ok(if prefix.is_empty() {
        suffix
    } else {
        format!("{prefix}/{suffix}")
    })
}

pub fn generate_object_id() -> Result<String, S3RuntimeError> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| S3RuntimeError::BackendUnavailable)?;
    Ok(hex_lower(&bytes))
}

fn valid_object_id(value: &str) -> bool {
    value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[derive(Debug)]
struct ResolvedEndpoint {
    url: Url,
    host: String,
    socket: SocketAddr,
}

pub struct S3RuntimeClient {
    config: S3RuntimeConfig,
    resolver: SecretResolver,
}

impl S3RuntimeClient {
    pub fn new(config: S3RuntimeConfig, resolver: SecretResolver) -> Self {
        Self { config, resolver }
    }

    pub async fn validate_live(&self) -> Result<S3ObjectMetadata, S3RuntimeError> {
        let probe_key = canonical_object_key(&self.config.key_prefix, 1, 1, &"0".repeat(32))?;
        match self.head(&probe_key).await {
            Ok(metadata) => Ok(metadata),
            Err(S3RuntimeError::ObjectMissing) => Ok(S3ObjectMetadata {
                present: false,
                size_bytes: None,
                etag_present: false,
                safe_error_class: "probe_object_missing".to_string(),
            }),
            Err(error) => Err(error),
        }
    }

    pub async fn put(
        &self,
        object_key: &str,
        bytes: &[u8],
        content_type: &str,
    ) -> Result<S3OperationResult, S3RuntimeError> {
        if bytes.len() > self.config.max_object_bytes {
            return Err(S3RuntimeError::ObjectTooLarge);
        }
        let payload_hash = full_sha256_bytes(bytes);
        let response = self
            .request(
                Method::PUT,
                object_key,
                &payload_hash,
                Some(bytes),
                Some(content_type),
            )
            .await?;
        ensure_success(response.status())?;
        Ok(S3OperationResult {
            completed: true,
            object_present_before: false,
            size_bytes: Some(bytes.len() as u64),
            sha256: payload_hash,
            safe_error_class: String::new(),
        })
    }

    pub async fn head(&self, object_key: &str) -> Result<S3ObjectMetadata, S3RuntimeError> {
        let response = self
            .request(
                Method::HEAD,
                object_key,
                &full_sha256_bytes(b""),
                None,
                None,
            )
            .await?;
        if response.status() == StatusCode::NOT_FOUND {
            return Err(S3RuntimeError::ObjectMissing);
        }
        ensure_success(response.status())?;
        let size_bytes = response_content_length(response.headers())?;
        if size_bytes.is_some_and(|size| size > self.config.max_object_bytes as u64) {
            return Err(S3RuntimeError::ObjectTooLarge);
        }
        Ok(S3ObjectMetadata {
            present: true,
            size_bytes,
            etag_present: response.headers().contains_key(header::ETAG),
            safe_error_class: String::new(),
        })
    }

    pub async fn get(&self, object_key: &str) -> Result<S3ObjectRead, S3RuntimeError> {
        let mut response = self
            .request(Method::GET, object_key, &full_sha256_bytes(b""), None, None)
            .await?;
        if response.status() == StatusCode::NOT_FOUND {
            return Err(S3RuntimeError::ObjectMissing);
        }
        ensure_success(response.status())?;
        if response
            .content_length()
            .is_some_and(|size| size > self.config.max_object_bytes as u64)
        {
            return Err(S3RuntimeError::ObjectTooLarge);
        }
        let mut bytes = Vec::with_capacity(response.content_length().unwrap_or(0) as usize);
        let mut hasher = Sha256::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| S3RuntimeError::BackendUnavailable)?
        {
            if bytes.len().saturating_add(chunk.len()) > self.config.max_object_bytes {
                return Err(S3RuntimeError::ObjectTooLarge);
            }
            hasher.update(&chunk);
            bytes.extend_from_slice(&chunk);
        }
        Ok(S3ObjectRead {
            size_bytes: bytes.len() as u64,
            sha256: format!("{:x}", hasher.finalize()),
            bytes,
        })
    }

    pub async fn drill(
        &self,
        object_key: &str,
        expected_sha256: &str,
    ) -> Result<S3RuntimeDrill, S3RuntimeError> {
        self.head(object_key).await?;
        let object = self.get(object_key).await?;
        let expected = expected_sha256.trim().to_ascii_lowercase();
        let matches = !expected.is_empty() && object.sha256 == expected;
        Ok(S3RuntimeDrill {
            object_present: true,
            readable: true,
            size_bytes: Some(object.size_bytes),
            calculated_sha256: object.sha256,
            hash_matches: matches,
            status: if matches { "valid" } else { "mismatch" }.to_string(),
            safe_error_class: if matches {
                String::new()
            } else {
                S3RuntimeError::HashMismatch.safe_error_class().to_string()
            },
        })
    }

    pub async fn delete(&self, object_key: &str) -> Result<S3OperationResult, S3RuntimeError> {
        let present_before = match self.head(object_key).await {
            Ok(_) => true,
            Err(S3RuntimeError::ObjectMissing) => false,
            Err(error) => return Err(error),
        };
        if !present_before {
            return Ok(S3OperationResult {
                completed: true,
                object_present_before: false,
                size_bytes: None,
                sha256: String::new(),
                safe_error_class: "object_already_missing".to_string(),
            });
        }
        let response = self
            .request(
                Method::DELETE,
                object_key,
                &full_sha256_bytes(b""),
                None,
                None,
            )
            .await?;
        ensure_success(response.status()).map_err(|_| S3RuntimeError::ObjectDeleteFailed)?;
        let absent = matches!(
            self.head(object_key).await,
            Err(S3RuntimeError::ObjectMissing)
        );
        if !absent {
            return Err(S3RuntimeError::ObjectDeleteFailed);
        }
        Ok(S3OperationResult {
            completed: true,
            object_present_before: true,
            size_bytes: None,
            sha256: String::new(),
            safe_error_class: String::new(),
        })
    }

    async fn request(
        &self,
        method: Method,
        object_key: &str,
        payload_hash: &str,
        body: Option<&[u8]>,
        content_type: Option<&str>,
    ) -> Result<reqwest::Response, S3RuntimeError> {
        let access_key = self.resolver.resolve(&self.config.access_key_secret_ref)?;
        let secret_key = self.resolver.resolve(&self.config.secret_key_secret_ref)?;
        let session_token = if self.config.session_token_secret_ref.trim().is_empty() {
            None
        } else {
            Some(
                self.resolver
                    .resolve(&self.config.session_token_secret_ref)?,
            )
        };
        let endpoint = self.resolve_endpoint(object_key).await?;
        let mut builder = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(OPERATION_TIMEOUT)
            .resolve(&endpoint.host, endpoint.socket);
        builder = builder.user_agent("ISCY-Evidence-Storage/1");
        let client = builder
            .build()
            .map_err(|_| S3RuntimeError::BackendUnavailable)?;
        let now = Utc::now();
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
        let date = now.format("%Y%m%d").to_string();
        let host_header = host_header(&endpoint.url)?;
        let canonical_uri = endpoint.url.path();
        let token = session_token
            .as_ref()
            .map(SecretValue::as_str)
            .transpose()?;
        let signed = sign_request(SignRequest {
            method: method.as_str(),
            canonical_uri,
            host: &host_header,
            amz_date: &amz_date,
            date: &date,
            region: &self.config.region,
            access_key: access_key.as_str()?,
            secret_key: secret_key.as_str()?,
            session_token: token,
            payload_hash,
        })?;
        let mut request = client
            .request(method, endpoint.url)
            .header(header::HOST, host_header)
            .header("x-amz-content-sha256", payload_hash)
            .header("x-amz-date", amz_date)
            .header(header::AUTHORIZATION, signed.authorization);
        if let Some(token) = token {
            request = request.header("x-amz-security-token", token);
        }
        if let Some(content_type) = content_type {
            request = request.header(header::CONTENT_TYPE, safe_content_type(content_type));
        }
        if let Some(body) = body {
            request = request.body(body.to_vec());
        }
        match request.send().await {
            Ok(response) if response.status().is_redirection() => {
                Err(S3RuntimeError::BlockedRedirect)
            }
            Ok(response) => Ok(response),
            Err(error) if error.is_timeout() => Err(S3RuntimeError::ConnectionTimeout),
            Err(_) => Err(S3RuntimeError::BackendUnavailable),
        }
    }

    async fn resolve_endpoint(&self, object_key: &str) -> Result<ResolvedEndpoint, S3RuntimeError> {
        if canonical_object_key_parts_valid(object_key).is_err() {
            return Err(S3RuntimeError::InvalidObjectKey);
        }
        let endpoint =
            Url::parse(&self.config.endpoint).map_err(|_| S3RuntimeError::InvalidEndpoint)?;
        let scheme = endpoint.scheme();
        let endpoint_host = endpoint.host_str().ok_or(S3RuntimeError::InvalidEndpoint)?;
        let host = if self.config.allow_path_style {
            endpoint_host.to_string()
        } else {
            format!("{}.{}", self.config.bucket, endpoint_host)
        };
        let port = endpoint
            .port_or_known_default()
            .ok_or(S3RuntimeError::InvalidEndpoint)?;
        let base_path = endpoint.path().trim_end_matches('/');
        let object_path = aws_uri_path(object_key);
        let path = if self.config.allow_path_style {
            format!(
                "{base_path}/{}/{object_path}",
                aws_encode(&self.config.bucket)
            )
        } else {
            format!("{base_path}/{object_path}")
        };
        let authority_host = if host.parse::<std::net::Ipv6Addr>().is_ok() {
            format!("[{host}]")
        } else {
            host.clone()
        };
        let authority = if (scheme == "https" && port == 443) || (scheme == "http" && port == 80) {
            authority_host
        } else {
            format!("{authority_host}:{port}")
        };
        let url = Url::parse(&format!("{scheme}://{authority}{path}"))
            .map_err(|_| S3RuntimeError::InvalidEndpoint)?;
        validate_endpoint_reference(
            url.as_str(),
            self.config.production || scheme == "https",
            if self.config.allow_local_test_endpoint {
                "local_dev_only"
            } else {
                "production_https_public"
            },
        )?;
        let resolved = timeout(DNS_TIMEOUT, lookup_host((host.as_str(), port)))
            .await
            .map_err(|_| S3RuntimeError::DnsResolutionFailed)?
            .map_err(|_| S3RuntimeError::DnsResolutionFailed)?
            .collect::<Vec<_>>();
        if resolved.is_empty() {
            return Err(S3RuntimeError::DnsResolutionFailed);
        }
        for address in &resolved {
            validate_resolved_ip(address.ip(), self.config.allow_local_test_endpoint)
                .map_err(|_| S3RuntimeError::DnsRevalidationFailed)?;
        }
        Ok(ResolvedEndpoint {
            url,
            host,
            socket: resolved[0],
        })
    }
}

fn canonical_object_key_parts_valid(value: &str) -> Result<(), ()> {
    if value.is_empty()
        || value.starts_with('/')
        || value.contains(['\0', '\\'])
        || value
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        Err(())
    } else {
        Ok(())
    }
}

fn safe_content_type(value: &str) -> &'static str {
    match value.trim().to_ascii_lowercase().as_str() {
        "application/pdf" => "application/pdf",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document" => {
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        }
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" => {
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        }
        "image/png" => "image/png",
        "image/jpeg" => "image/jpeg",
        "text/csv" => "text/csv",
        "text/plain" => "text/plain",
        _ => "application/octet-stream",
    }
}

fn ensure_success(status: StatusCode) -> Result<(), S3RuntimeError> {
    if status.is_success() {
        Ok(())
    } else if status == StatusCode::NOT_FOUND {
        Err(S3RuntimeError::ObjectMissing)
    } else if status == StatusCode::FORBIDDEN || status == StatusCode::UNAUTHORIZED {
        Err(S3RuntimeError::AccessDenied)
    } else {
        Err(S3RuntimeError::BackendUnavailable)
    }
}

struct SignRequest<'a> {
    method: &'a str,
    canonical_uri: &'a str,
    host: &'a str,
    amz_date: &'a str,
    date: &'a str,
    region: &'a str,
    access_key: &'a str,
    secret_key: &'a str,
    session_token: Option<&'a str>,
    payload_hash: &'a str,
}

struct SignedRequest {
    authorization: String,
}

fn sign_request(request: SignRequest<'_>) -> Result<SignedRequest, S3RuntimeError> {
    let (canonical_headers, signed_headers) = if let Some(token) = request.session_token {
        (
            format!(
                "host:{}\nx-amz-content-sha256:{}\nx-amz-date:{}\nx-amz-security-token:{}\n",
                request.host, request.payload_hash, request.amz_date, token
            ),
            "host;x-amz-content-sha256;x-amz-date;x-amz-security-token",
        )
    } else {
        (
            format!(
                "host:{}\nx-amz-content-sha256:{}\nx-amz-date:{}\n",
                request.host, request.payload_hash, request.amz_date
            ),
            "host;x-amz-content-sha256;x-amz-date",
        )
    };
    let canonical_request = format!(
        "{}\n{}\n\n{}\n{}\n{}",
        request.method,
        request.canonical_uri,
        canonical_headers,
        signed_headers,
        request.payload_hash
    );
    let scope = format!("{}/{}/s3/aws4_request", request.date, request.region);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        request.amz_date,
        scope,
        full_sha256(&canonical_request)
    );
    let date_key = hmac_bytes(
        format!("AWS4{}", request.secret_key).as_bytes(),
        request.date.as_bytes(),
    )?;
    let region_key = hmac_bytes(&date_key, request.region.as_bytes())?;
    let service_key = hmac_bytes(&region_key, b"s3")?;
    let signing_key = hmac_bytes(&service_key, b"aws4_request")?;
    let signature = hex_lower(&hmac_bytes(&signing_key, string_to_sign.as_bytes())?);
    Ok(SignedRequest {
        authorization: format!(
            "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
            request.access_key, scope, signed_headers, signature
        ),
    })
}

fn hmac_bytes(key: &[u8], value: &[u8]) -> Result<Vec<u8>, S3RuntimeError> {
    let mut mac =
        HmacSha256::new_from_slice(key).map_err(|_| S3RuntimeError::SecretResolutionFailed)?;
    mac.update(value);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn aws_uri_path(key: &str) -> String {
    key.split('/').map(aws_encode).collect::<Vec<_>>().join("/")
}

fn aws_encode(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(byte as char);
        } else {
            encoded.push('%');
            encoded.push_str(&format!("{byte:02X}"));
        }
    }
    encoded
}

fn host_header(url: &Url) -> Result<String, S3RuntimeError> {
    let host = url.host_str().ok_or(S3RuntimeError::InvalidEndpoint)?;
    let host = if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    let port = url
        .port_or_known_default()
        .ok_or(S3RuntimeError::InvalidEndpoint)?;
    Ok(
        if (url.scheme() == "https" && port == 443) || (url.scheme() == "http" && port == 80) {
            host
        } else {
            format!("{host}:{port}")
        },
    )
}

fn full_sha256_bytes(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}

fn response_content_length(headers: &header::HeaderMap) -> Result<Option<u64>, S3RuntimeError> {
    headers
        .get(header::CONTENT_LENGTH)
        .map(|value| {
            value
                .to_str()
                .map_err(|_| S3RuntimeError::BackendUnavailable)?
                .parse::<u64>()
                .map_err(|_| S3RuntimeError::BackendUnavailable)
        })
        .transpose()
}

fn hex_lower(value: &[u8]) -> String {
    let mut result = String::with_capacity(value.len() * 2);
    for byte in value {
        result.push_str(&format!("{byte:02x}"));
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::Mutex,
        time::{SystemTime, UNIX_EPOCH},
    };

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn temp_root(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("iscy-s3-secret-{name}-{nanos}"));
        fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn canonical_keys_are_server_generated_and_tenant_bound() {
        let key = canonical_object_key("governance", 7, 11, &"a".repeat(32)).unwrap();
        assert_eq!(
            key,
            format!(
                "governance/tenants/7/evidence/11/objects/{}",
                "a".repeat(32)
            )
        );
        assert!(canonical_object_key("../escape", 7, 11, &"a".repeat(32)).is_err());
        assert!(canonical_object_key("", 0, 11, &"a".repeat(32)).is_err());
        assert!(canonical_object_key("", 7, 11, "client/key").is_err());
    }

    #[test]
    fn head_object_size_uses_content_length_header() {
        let mut headers = header::HeaderMap::new();
        headers.insert(
            header::CONTENT_LENGTH,
            header::HeaderValue::from_static("39"),
        );

        assert_eq!(response_content_length(&headers).unwrap(), Some(39));
    }

    #[test]
    fn env_secret_resolution_is_explicit_and_redacted() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("ISCY_TEST_S3_SECRET", "dummy-test-secret");
        let resolver = SecretResolver::with_allowed_file_roots(Vec::new());
        let value = resolver.resolve("env:ISCY_TEST_S3_SECRET").unwrap();
        assert_eq!(value.as_str().unwrap(), "dummy-test-secret");
        assert_eq!(format!("{value:?}"), "SecretValue([redacted])");
        assert_eq!(
            resolver.resolve("env:bad-name").unwrap_err(),
            S3RuntimeError::SecretReferenceInvalid
        );
        assert_eq!(
            resolver.resolve("env:ISCY_TEST_S3_MISSING").unwrap_err(),
            S3RuntimeError::SecretReferenceMissing
        );
        assert_eq!(
            resolver.resolve("vault:path").unwrap_err(),
            S3RuntimeError::SecretReferenceUnsupported
        );
        std::env::remove_var("ISCY_TEST_S3_SECRET");
    }

    #[test]
    fn env_file_secret_resolution_rejects_direct_file_conflicts() {
        let _guard = ENV_LOCK.lock().unwrap();
        let root = temp_root("env-file");
        let path = root.join("access-key");
        fs::write(&path, b"TestOnly-file-backed-value\r\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let resolver = SecretResolver::with_allowed_file_roots(vec![root.clone()]);
        std::env::set_var("ISCY_TEST_S3_ACCESS_KEY_FILE", &path);

        let resolved = resolver.resolve("env:ISCY_TEST_S3_ACCESS_KEY").unwrap();
        assert_eq!(resolved.as_str().unwrap().len(), 26);
        assert!(resolver.resolve("env:ISCY_TEST_S3_ACCESS_KEY_FILE").is_ok());

        std::env::set_var("ISCY_TEST_S3_ACCESS_KEY", "TestOnly-direct-value");
        assert_eq!(
            resolver.resolve("env:ISCY_TEST_S3_ACCESS_KEY").unwrap_err(),
            S3RuntimeError::SecretReferenceInvalid
        );
        std::env::remove_var("ISCY_TEST_S3_ACCESS_KEY");
        std::env::remove_var("ISCY_TEST_S3_ACCESS_KEY_FILE");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn file_secret_resolution_enforces_root_symlink_and_permissions() {
        let root = temp_root("allowed");
        let outside = temp_root("outside");
        let secret = root.join("access-key");
        fs::write(&secret, b"dummy-access\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&secret, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let resolver = SecretResolver::with_allowed_file_roots(vec![root.clone()]);
        assert_eq!(
            resolver
                .resolve(&format!("file:{}", secret.display()))
                .unwrap()
                .as_str()
                .unwrap(),
            "dummy-access"
        );
        let outside_secret = outside.join("outside");
        fs::write(&outside_secret, b"outside").unwrap();
        assert_eq!(
            resolver
                .resolve(&format!("file:{}", outside_secret.display()))
                .unwrap_err(),
            S3RuntimeError::SecretFileSymlinkEscape
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::{symlink, PermissionsExt};
            let link = root.join("link");
            symlink(&outside_secret, &link).unwrap();
            assert_eq!(
                resolver
                    .resolve(&format!("file:{}", link.display()))
                    .unwrap_err(),
                S3RuntimeError::SecretFileSymlinkEscape
            );
            fs::set_permissions(&secret, fs::Permissions::from_mode(0o666)).unwrap();
            assert_eq!(
                resolver
                    .resolve(&format!("file:{}", secret.display()))
                    .unwrap_err(),
                S3RuntimeError::SecretFilePermissionsInsecure
            );
        }
        let _ = fs::remove_dir_all(root);
        let _ = fs::remove_dir_all(outside);
    }

    #[test]
    fn sigv4_matches_aws_documentation_vector() {
        let signed = sign_request(SignRequest {
            method: "GET",
            canonical_uri: "/test.txt",
            host: "examplebucket.s3.amazonaws.com",
            amz_date: "20130524T000000Z",
            date: "20130524",
            region: "us-east-1",
            access_key: "AKIAIOSFODNN7EXAMPLE", // gitleaks:allow
            secret_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", // gitleaks:allow
            session_token: None,
            payload_hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        })
        .unwrap();
        assert!(signed.authorization.starts_with(
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request"
        ));
        assert!(signed
            .authorization
            .contains("SignedHeaders=host;x-amz-content-sha256;x-amz-date"));
    }

    #[test]
    fn production_endpoint_policy_blocks_local_and_metadata_targets() {
        for endpoint in [
            "http://127.0.0.1:9000",
            "https://10.0.0.1",
            "https://169.254.169.254",
            "https://service.local",
        ] {
            let error =
                validate_endpoint_reference(endpoint, true, "production_https_public").unwrap_err();
            assert!(matches!(
                error,
                ObjectStorageValidationError::InsecureScheme
                    | ObjectStorageValidationError::BlockedLoopback
                    | ObjectStorageValidationError::BlockedPrivateNetwork
                    | ObjectStorageValidationError::BlockedMetadataService
                    | ObjectStorageValidationError::EndpointPolicyViolation
            ));
        }
        assert!(
            validate_endpoint_reference("http://127.0.0.1:9000", false, "local_dev_only").is_ok()
        );
    }
}
