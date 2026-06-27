use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode, Uri},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use iscy_backend::hardening::{AppMode, CommunitySecurityConfig};

const LEGACY_IDENTITY_QUERY_KEYS: &[&str] = &["tenant_id", "user_id", "user_email"];

/// Removes legacy URL identity context before production requests reach any
/// route handler. A valid session or bearer token remains available through
/// headers/cookies, while unauthenticated query-only context becomes empty.
pub async fn sanitize_legacy_identity_query(
    State(config): State<CommunitySecurityConfig>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    if config.app_mode == AppMode::Production {
        match sanitized_uri(request.uri()) {
            Ok(Some(uri)) => *request.uri_mut() = uri,
            Ok(None) => {}
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "accepted": false,
                        "api_version": "v1",
                        "error_code": "invalid_request_uri",
                        "message": "Die Request-URL konnte nicht sicher verarbeitet werden."
                    })),
                )
                    .into_response();
            }
        }
    }

    next.run(request).await
}

fn sanitized_uri(uri: &Uri) -> Result<Option<Uri>, axum::http::uri::InvalidUri> {
    let Some(query) = uri.query() else {
        return Ok(None);
    };

    let pairs = form_urlencoded::parse(query.as_bytes()).collect::<Vec<_>>();
    let contains_legacy_identity = pairs.iter().any(|(key, _)| {
        LEGACY_IDENTITY_QUERY_KEYS
            .iter()
            .any(|blocked| key.as_ref() == *blocked)
    });
    if !contains_legacy_identity {
        return Ok(None);
    }

    let mut serializer = form_urlencoded::Serializer::new(String::new());
    for (key, value) in pairs {
        if LEGACY_IDENTITY_QUERY_KEYS
            .iter()
            .any(|blocked| key.as_ref() == *blocked)
        {
            continue;
        }
        serializer.append_pair(&key, &value);
    }
    let sanitized_query = serializer.finish();

    let mut rebuilt = uri.path().to_string();
    if !sanitized_query.is_empty() {
        rebuilt.push('?');
        rebuilt.push_str(&sanitized_query);
    }

    rebuilt.parse::<Uri>().map(Some)
}

#[cfg(test)]
mod tests {
    use axum::http::Uri;

    use super::sanitized_uri;

    #[test]
    fn strips_identity_query_and_preserves_filters() {
        let uri: Uri = "/incidents/1?tenant_id=4&user_id=7&timeline=all&alert_filter=open"
            .parse()
            .unwrap();

        let sanitized = sanitized_uri(&uri).unwrap().unwrap();

        assert_eq!(
            sanitized.to_string(),
            "/incidents/1?timeline=all&alert_filter=open"
        );
    }

    #[test]
    fn strips_percent_encoded_identity_key() {
        let uri: Uri = "/risks/?tenant%5Fid=4&review_filter=open"
            .parse()
            .unwrap();

        let sanitized = sanitized_uri(&uri).unwrap().unwrap();

        assert_eq!(sanitized.to_string(), "/risks/?review_filter=open");
    }

    #[test]
    fn leaves_non_identity_query_unchanged() {
        let uri: Uri = "/product-security/?review_filter=open".parse().unwrap();

        assert!(sanitized_uri(&uri).unwrap().is_none());
    }
}
