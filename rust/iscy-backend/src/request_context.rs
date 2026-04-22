use axum::http::{HeaderMap, StatusCode};
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RequestContext {
    pub authenticated: bool,
    pub tenant_id: Option<i64>,
    pub user_id: Option<i64>,
    pub user_email: Option<String>,
    pub roles: Vec<String>,
    pub is_staff: bool,
    pub is_superuser: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuthenticatedTenantContext {
    pub tenant_id: i64,
    pub user_id: i64,
    pub user_email: Option<String>,
    pub roles: Vec<String>,
    pub is_staff: bool,
    pub is_superuser: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestContextError {
    InvalidTenantId,
    InvalidUserId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequiredTenantContextError {
    InvalidHeaders(RequestContextError),
    InvalidSession,
    MissingUser,
    MissingTenant,
}

impl RequestContext {
    pub fn from_headers(headers: &HeaderMap) -> Result<Self, RequestContextError> {
        let tenant_id = optional_i64_header(headers, "x-iscy-tenant-id")
            .map_err(|_| RequestContextError::InvalidTenantId)?;
        let user_id = optional_i64_header(headers, "x-iscy-user-id")
            .map_err(|_| RequestContextError::InvalidUserId)?;
        let user_email = optional_string_header(headers, "x-iscy-user-email");
        let mut roles = optional_roles_header(headers, "x-iscy-roles");
        if user_id.is_some() && roles.is_empty() {
            roles.push("CONTRIBUTOR".to_string());
        }
        let is_staff = optional_bool_header(headers, "x-iscy-is-staff").unwrap_or(false);
        let is_superuser = optional_bool_header(headers, "x-iscy-is-superuser").unwrap_or(false);

        Ok(Self {
            authenticated: user_id.is_some(),
            tenant_id,
            user_id,
            user_email,
            roles,
            is_staff,
            is_superuser,
        })
    }

    pub fn authenticated_tenant_from_headers(
        headers: &HeaderMap,
    ) -> Result<AuthenticatedTenantContext, RequiredTenantContextError> {
        Self::from_headers(headers)
            .map_err(RequiredTenantContextError::InvalidHeaders)?
            .require_authenticated_tenant()
    }

    pub fn require_authenticated_tenant(
        self,
    ) -> Result<AuthenticatedTenantContext, RequiredTenantContextError> {
        let user_id = self
            .user_id
            .ok_or(RequiredTenantContextError::MissingUser)?;
        let tenant_id = self
            .tenant_id
            .ok_or(RequiredTenantContextError::MissingTenant)?;
        Ok(AuthenticatedTenantContext {
            tenant_id,
            user_id,
            user_email: self.user_email,
            roles: self.roles,
            is_staff: self.is_staff,
            is_superuser: self.is_superuser,
        })
    }
}

impl AuthenticatedTenantContext {
    pub fn has_role(&self, role: &str) -> bool {
        let role = role.trim().to_ascii_uppercase();
        self.roles
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(&role))
    }

    pub fn can_write(&self) -> bool {
        self.is_superuser
            || self.is_staff
            || [
                "ADMIN",
                "MANAGEMENT",
                "CISO",
                "ISMS_MANAGER",
                "COMPLIANCE_MANAGER",
                "PROCESS_OWNER",
                "RISK_OWNER",
                "CONTRIBUTOR",
            ]
            .iter()
            .any(|role| self.has_role(role))
    }
}

impl RequestContextError {
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::InvalidTenantId => "invalid_tenant_id",
            Self::InvalidUserId => "invalid_user_id",
        }
    }

    pub fn message(&self) -> &'static str {
        match self {
            Self::InvalidTenantId => "X-ISCY-Tenant-ID muss eine positive Ganzzahl sein.",
            Self::InvalidUserId => "X-ISCY-User-ID muss eine positive Ganzzahl sein.",
        }
    }
}

impl RequiredTenantContextError {
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::InvalidHeaders(_) => StatusCode::BAD_REQUEST,
            Self::InvalidSession => StatusCode::UNAUTHORIZED,
            Self::MissingUser => StatusCode::UNAUTHORIZED,
            Self::MissingTenant => StatusCode::FORBIDDEN,
        }
    }

    pub fn error_code(&self) -> &'static str {
        match self {
            Self::InvalidHeaders(err) => err.error_code(),
            Self::InvalidSession => "invalid_session",
            Self::MissingUser => "missing_user_context",
            Self::MissingTenant => "missing_tenant_context",
        }
    }

    pub fn message(&self) -> &'static str {
        match self {
            Self::InvalidHeaders(err) => err.message(),
            Self::InvalidSession => "Rust-Session ist ungueltig oder abgelaufen.",
            Self::MissingUser => "Authentifizierte Rust-App-Routen benoetigen X-ISCY-User-ID.",
            Self::MissingTenant => "Tenant-gebundene Rust-App-Routen benoetigen X-ISCY-Tenant-ID.",
        }
    }
}

fn optional_i64_header(headers: &HeaderMap, name: &'static str) -> Result<Option<i64>, ()> {
    let Some(raw) = headers.get(name) else {
        return Ok(None);
    };
    let value = raw.to_str().map_err(|_| ())?.trim();
    if value.is_empty() {
        return Ok(None);
    }
    let parsed = value.parse::<i64>().map_err(|_| ())?;
    if parsed <= 0 {
        return Err(());
    }
    Ok(Some(parsed))
}

fn optional_string_header(headers: &HeaderMap, name: &'static str) -> Option<String> {
    headers
        .get(name)
        .and_then(|raw| raw.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn optional_roles_header(headers: &HeaderMap, name: &'static str) -> Vec<String> {
    headers
        .get(name)
        .and_then(|raw| raw.to_str().ok())
        .map(|raw| {
            raw.split(',')
                .map(str::trim)
                .filter(|role| !role.is_empty())
                .map(|role| role.to_ascii_uppercase())
                .fold(Vec::<String>::new(), |mut roles, role| {
                    if !roles.iter().any(|existing| existing == &role) {
                        roles.push(role);
                    }
                    roles
                })
        })
        .unwrap_or_default()
}

fn optional_bool_header(headers: &HeaderMap, name: &'static str) -> Option<bool> {
    headers
        .get(name)
        .and_then(|raw| raw.to_str().ok())
        .map(str::trim)
        .map(|value| matches!(value.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderValue};

    use super::{RequestContext, RequestContextError, RequiredTenantContextError};

    #[test]
    fn parses_empty_context_as_anonymous() {
        let context = RequestContext::from_headers(&HeaderMap::new()).unwrap();

        assert!(!context.authenticated);
        assert_eq!(context.tenant_id, None);
        assert_eq!(context.user_id, None);
        assert!(context.roles.is_empty());
    }

    #[test]
    fn parses_tenant_and_user_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("x-iscy-tenant-id", HeaderValue::from_static("42"));
        headers.insert("x-iscy-user-id", HeaderValue::from_static("7"));
        headers.insert(
            "x-iscy-user-email",
            HeaderValue::from_static("security@example.test"),
        );
        headers.insert("x-iscy-roles", HeaderValue::from_static("auditor, ciso"));

        let context = RequestContext::from_headers(&headers).unwrap();

        assert!(context.authenticated);
        assert_eq!(context.tenant_id, Some(42));
        assert_eq!(context.user_id, Some(7));
        assert_eq!(context.user_email.as_deref(), Some("security@example.test"));
        assert_eq!(context.roles, vec!["AUDITOR", "CISO"]);
    }

    #[test]
    fn rejects_invalid_tenant_header() {
        let mut headers = HeaderMap::new();
        headers.insert("x-iscy-tenant-id", HeaderValue::from_static("tenant-a"));

        assert_eq!(
            RequestContext::from_headers(&headers).unwrap_err(),
            RequestContextError::InvalidTenantId
        );
    }

    #[test]
    fn requires_authenticated_user_for_tenant_context() {
        let mut headers = HeaderMap::new();
        headers.insert("x-iscy-tenant-id", HeaderValue::from_static("42"));

        assert_eq!(
            RequestContext::authenticated_tenant_from_headers(&headers).unwrap_err(),
            RequiredTenantContextError::MissingUser
        );
    }

    #[test]
    fn requires_tenant_for_authenticated_tenant_context() {
        let mut headers = HeaderMap::new();
        headers.insert("x-iscy-user-id", HeaderValue::from_static("7"));

        assert_eq!(
            RequestContext::authenticated_tenant_from_headers(&headers).unwrap_err(),
            RequiredTenantContextError::MissingTenant
        );
    }

    #[test]
    fn builds_authenticated_tenant_context() {
        let mut headers = HeaderMap::new();
        headers.insert("x-iscy-tenant-id", HeaderValue::from_static("42"));
        headers.insert("x-iscy-user-id", HeaderValue::from_static("7"));

        let context = RequestContext::authenticated_tenant_from_headers(&headers).unwrap();

        assert_eq!(context.tenant_id, 42);
        assert_eq!(context.user_id, 7);
        assert_eq!(context.roles, vec!["CONTRIBUTOR"]);
        assert!(context.can_write());
    }

    #[test]
    fn auditor_role_is_read_only() {
        let mut headers = HeaderMap::new();
        headers.insert("x-iscy-tenant-id", HeaderValue::from_static("42"));
        headers.insert("x-iscy-user-id", HeaderValue::from_static("7"));
        headers.insert("x-iscy-roles", HeaderValue::from_static("AUDITOR"));

        let context = RequestContext::authenticated_tenant_from_headers(&headers).unwrap();

        assert!(context.has_role("AUDITOR"));
        assert!(!context.can_write());
    }
}
