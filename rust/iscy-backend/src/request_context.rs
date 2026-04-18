use axum::http::HeaderMap;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RequestContext {
    pub authenticated: bool,
    pub tenant_id: Option<i64>,
    pub user_id: Option<i64>,
    pub user_email: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestContextError {
    InvalidTenantId,
    InvalidUserId,
}

impl RequestContext {
    pub fn from_headers(headers: &HeaderMap) -> Result<Self, RequestContextError> {
        let tenant_id = optional_i64_header(headers, "x-iscy-tenant-id")
            .map_err(|_| RequestContextError::InvalidTenantId)?;
        let user_id = optional_i64_header(headers, "x-iscy-user-id")
            .map_err(|_| RequestContextError::InvalidUserId)?;
        let user_email = optional_string_header(headers, "x-iscy-user-email");

        Ok(Self {
            authenticated: user_id.is_some(),
            tenant_id,
            user_id,
            user_email,
        })
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

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderValue};

    use super::{RequestContext, RequestContextError};

    #[test]
    fn parses_empty_context_as_anonymous() {
        let context = RequestContext::from_headers(&HeaderMap::new()).unwrap();

        assert!(!context.authenticated);
        assert_eq!(context.tenant_id, None);
        assert_eq!(context.user_id, None);
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

        let context = RequestContext::from_headers(&headers).unwrap();

        assert!(context.authenticated);
        assert_eq!(context.tenant_id, Some(42));
        assert_eq!(context.user_id, Some(7));
        assert_eq!(context.user_email.as_deref(), Some("security@example.test"));
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
}
