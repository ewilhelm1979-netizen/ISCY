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

/// Removes legacy URL identity context before non-development requests reach
/// any route handler. A valid session or bearer token remains available through
/// headers/cookies, while unauthenticated query-only context becomes empty.
pub async fn sanitize_legacy_identity_query(
    State(config): State<CommunitySecurityConfig>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    if config.app_mode != AppMode::Development {
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

    let segments = query.split('&').collect::<Vec<_>>();
    let contains_legacy_identity = segments
        .iter()
        .any(|segment| is_legacy_identity_segment(segment));
    if !contains_legacy_identity {
        return Ok(None);
    }

    let sanitized_query = segments
        .into_iter()
        .filter(|segment| !is_legacy_identity_segment(segment))
        .collect::<Vec<_>>()
        .join("&");

    let mut rebuilt = uri.path().to_string();
    if !sanitized_query.is_empty() {
        rebuilt.push('?');
        rebuilt.push_str(&sanitized_query);
    }

    rebuilt.parse::<Uri>().map(Some)
}

fn is_legacy_identity_segment(segment: &str) -> bool {
    let raw_key = segment
        .split_once('=')
        .map(|(key, _)| key)
        .unwrap_or(segment);
    let Some(decoded_key) = percent_decode_query_key(raw_key.as_bytes()) else {
        return false;
    };

    LEGACY_IDENTITY_QUERY_KEYS
        .iter()
        .any(|blocked| decoded_key == *blocked)
}

fn percent_decode_query_key(input: &[u8]) -> Option<String> {
    let mut decoded = Vec::with_capacity(input.len());
    let mut index = 0;
    while index < input.len() {
        match input[index] {
            b'%' => {
                if index + 2 >= input.len() {
                    return None;
                }
                let high = hex_value(input[index + 1])?;
                let low = hex_value(input[index + 2])?;
                decoded.push((high << 4) | low);
                index += 3;
            }
            b'+' => {
                decoded.push(b' ');
                index += 1;
            }
            value => {
                decoded.push(value);
                index += 1;
            }
        }
    }
    String::from_utf8(decoded).ok()
}

fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
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
        let uri: Uri = "/risks/?tenant%5Fid=4&review_filter=open".parse().unwrap();

        let sanitized = sanitized_uri(&uri).unwrap().unwrap();

        assert_eq!(sanitized.to_string(), "/risks/?review_filter=open");
    }

    #[test]
    fn preserves_original_encoding_for_other_parameters() {
        let uri: Uri = "/evidence/?tenant_id=4&return_to=%2Fincidents%2F1%3Ftimeline%3Dall"
            .parse()
            .unwrap();

        let sanitized = sanitized_uri(&uri).unwrap().unwrap();

        assert_eq!(
            sanitized.to_string(),
            "/evidence/?return_to=%2Fincidents%2F1%3Ftimeline%3Dall"
        );
    }

    #[test]
    fn leaves_non_identity_query_unchanged() {
        let uri: Uri = "/product-security/?review_filter=open".parse().unwrap();

        assert!(sanitized_uri(&uri).unwrap().is_none());
    }
}
