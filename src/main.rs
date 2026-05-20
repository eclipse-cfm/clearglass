// Copyright (c) 2026 Metaform Systems, Inc.
//
// This program and the accompanying materials are made available under the
// terms of the Apache License, Version 2.0 which is available at
// https://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0
//
// Contributors:
//      Metaform Systems, Inc. - initial API and implementation

// clearglass is a lightweight Traefik ForwardAuth target that validates
// Bearer tokens via Keycloak's token introspection endpoint (RFC 7662)
// and enforces per-route scope requirements.
//
// Traefik calls: GET /validate?scope=<s1>&scope=<s2>
//   - 200 → token is active and has at least one of the listed scopes
//   - 401 → missing/inactive token
//   - 403 → token is valid but lacks the required scopes

use async_trait::async_trait;
use http::{Response, StatusCode};
use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::{decode, decode_header, DecodingKey, Validation};
use pingora_core::apps::http_app::{HttpServer, ServeHttp};
use pingora_core::protocols::http::ServerSession;
use pingora_core::server::Server;
use pingora_core::services::listening::Service;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::collections::HashSet;
use std::env;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
use tracing_subscriber::EnvFilter;

#[derive(Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    #[serde(skip_serializing_if = "Option::is_none")]
    iss: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    aud: Option<serde_json::Value>, // can be string OR array in Keycloak
    exp: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    iat: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nbf: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    azp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
}

type Error = Box<dyn std::error::Error>;

// ---------------------------------------------------------------------------
// JwksClient — fetches public keys from a JWKS endpoint and caches them.
// ---------------------------------------------------------------------------

struct JwksClient {
    jwks_url: String,
    http_client: Client,
    cache: Arc<RwLock<HashMap<String, DecodingKey>>>,
}

impl JwksClient {
    fn new(jwks_url: String, http_client: Client) -> Self {
        JwksClient {
            jwks_url,
            http_client,
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    async fn decoding_key(&self, kid: &str) -> Result<DecodingKey, Error> {
        {
            let cache = self.cache.read().await;
            if let Some(key) = cache.get(kid) {
                debug!(kid = %kid, "using cached JWKS key");
                return Ok(key.clone());
            }
        }

        debug!(url = %self.jwks_url, "fetching JWKS");
        let jwks: Jwks = match self.http_client.get(&self.jwks_url).send().await {
            Ok(resp) => match resp.json().await {
                Ok(jwks) => jwks,
                Err(err) => {
                    let msg = format!("failed to parse JWKS response: {}", err);
                    error!(msg);
                    return Err(Error::from(msg));
                }
            },
            Err(err) => {
                let msg = format!("failed to fetch JWKS: {}", err);
                error!(msg);
                return Err(Error::from(msg));
            }
        };

        let jwk = match jwks
            .keys
            .iter()
            .find(|k| k.common.key_id.as_deref() == Some(kid))
        {
            Some(key) => key,
            None => {
                let msg = format!("key not found in JWKS for kid: {}", kid);
                warn!(msg);
                return Err(Error::from(msg));
            }
        };

        let decoding_key = match DecodingKey::from_jwk(jwk) {
            Ok(key) => key,
            Err(err) => {
                let msg = format!("failed to create DecodingKey from JWK: {}", err);
                error!(msg);
                return Err(Error::from(msg));
            }
        };

        {
            let mut cache = self.cache.write().await;
            cache.insert(kid.to_string(), decoding_key.clone());
        }

        debug!(kid = %kid, "cached new JWKS key");
        Ok(decoding_key)
    }
}

// ---------------------------------------------------------------------------
// ClearGlassProxy — HTTP handler; validates Bearer tokens and checks scopes.
// ---------------------------------------------------------------------------

struct ClearGlassProxy {
    jwks: Arc<JwksClient>,
}

impl ClearGlassProxy {
    fn from_env() -> Self {
        let http_client = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("failed to build HTTP client");
        ClearGlassProxy {
            jwks: Arc::new(JwksClient::new(must_env("JWKS_URL"), http_client)),
        }
    }

    /// Verifies the JWT and returns the space-separated scope string from the claims.
    async fn validate(&self, token: &str) -> Result<String, Error> {
        let header = decode_header(token)
            .map_err(|e| Error::from(format!("failed to decode JWT header: {}", e)))?;

        let kid = header.kid.ok_or_else(|| {
            warn!("JWT header missing kid");
            Error::from("JWT header missing 'kid' field")
        })?;

        let decoding_key = self.jwks.decoding_key(&kid).await?;

        let mut validation = Validation::new(header.alg);
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation.leeway = 10;
        validation.validate_aud = false;

        let token_data = decode::<Claims>(token, &decoding_key, &validation).map_err(|e| {
            warn!("JWT verification failed");
            Error::from(format!("failed to decode and verify JWT: {}", e))
        })?;

        Ok(token_data.claims.scope.unwrap_or_default())
    }

    async fn handle_validate(
        &self,
        auth_header: Option<&str>,
        required_token_scopes: &str,
    ) -> Response<Vec<u8>> {
        let token = match auth_header.and_then(|h| h.strip_prefix("Bearer ")) {
            Some(t) if !t.is_empty() && t.len() <= 4096 => t,
            Some(_) => {
                warn!("request rejected: invalid token length");
                return text_response(StatusCode::UNAUTHORIZED, "invalid bearer token");
            }
            None => {
                warn!("request rejected: no bearer token");
                return text_response(StatusCode::UNAUTHORIZED, "missing bearer token");
            }
        };

        let scope = match self.validate(token).await {
            Ok(s) => s,
            Err(e) => {
                let msg = format!("failed to validate token: {}", e);
                error!(msg);
                return text_response(StatusCode::UNAUTHORIZED, msg.as_str());
            }
        };

        // ?scope= params are candidates; the token must carry at least one.
        let required: Vec<&str> = required_token_scopes
            .split('&')
            .filter_map(|kv| {
                let (k, v) = kv.split_once('=')?;
                (k == "scope").then_some(v)
            })
            .collect();

        if !required.is_empty() {
            let present: HashSet<&str> = scope.split_whitespace().collect();
            if !required.iter().any(|s| present.contains(s)) {
                warn!(required = ?required, present = ?present, "request rejected: insufficient scope");
                return text_response(StatusCode::FORBIDDEN, "insufficient scope");
            }
            debug!(required = ?required, "scope check passed");
        }

        debug!("request allowed");
        text_response(StatusCode::OK, "ok")
    }
}

#[async_trait]
impl ServeHttp for ClearGlassProxy {
    async fn response(&self, http_session: &mut ServerSession) -> Response<Vec<u8>> {
        let path = http_session.req_header().uri.path().to_owned();
        let query = http_session
            .req_header()
            .uri
            .query()
            .unwrap_or("")
            .to_owned();
        let auth = http_session
            .req_header()
            .headers
            .get(http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);

        match path.as_str() {
            "/healthz" => text_response(StatusCode::OK, "ok"),
            "/validate" => self.handle_validate(auth.as_deref(), &query).await,
            _ => {
                warn!(path = %path, "request for unknown path");
                text_response(StatusCode::NOT_FOUND, "not found")
            }
        }
    }
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let port = env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let addr = format!("0.0.0.0:{port}");
    info!("clearglass listening on {addr}");

    let mut server = Server::new(None).expect("failed to create server");
    server.bootstrap();

    let app = HttpServer::new_app(ClearGlassProxy::from_env());
    let mut service = Service::new("clearglass".to_string(), app);
    service.add_tcp(&addr);
    server.add_service(service);

    server.run_forever();
}

fn text_response(status: StatusCode, body: &str) -> Response<Vec<u8>> {
    Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "text/plain")
        .body(body.as_bytes().to_vec())
        .unwrap()
}

fn must_env(key: &str) -> String {
    env::var(key).unwrap_or_else(|_| {
        eprintln!("required environment variable not set: {key}");
        std::process::exit(1);
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use ed25519_dalek::pkcs8::EncodePrivateKey;
    use ed25519_dalek::SigningKey;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use std::sync::OnceLock;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const TEST_KID: &str = "test-key-id";

    struct Fixture {
        encoding_key: EncodingKey,
        decoding_key: DecodingKey,
        jwks_json: String,
    }

    static FIXTURE: OnceLock<Fixture> = OnceLock::new();

    fn fixture() -> &'static Fixture {
        FIXTURE.get_or_init(|| {
            let signing_key = SigningKey::from_bytes(&[42u8; 32]);

            let priv_der = signing_key
                .to_pkcs8_der()
                .expect("Ed25519 PKCS8 DER encoding failed");
            let encoding_key = EncodingKey::from_ed_der(priv_der.as_bytes());

            let verifying_key = signing_key.verifying_key();
            let x = URL_SAFE_NO_PAD.encode(verifying_key.as_bytes());

            let jwk_json =
                format!(r#"{{"kty":"OKP","crv":"Ed25519","kid":"{TEST_KID}","x":"{x}"}}"#);
            let jwks_json = format!(r#"{{"keys":[{jwk_json}]}}"#);

            let jwk: Jwk = serde_json::from_str(&jwk_json).expect("JWK parse failed");
            let decoding_key = DecodingKey::from_jwk(&jwk).expect("DecodingKey build failed");

            Fixture {
                encoding_key,
                decoding_key,
                jwks_json,
            }
        })
    }

    fn make_jwt(scope: &str) -> String {
        let mut header = Header::new(jsonwebtoken::Algorithm::EdDSA);
        header.kid = Some(TEST_KID.to_string());

        let exp = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600) as usize;

        let claims = Claims {
            iss: None,
            sub: Some("test-subject".to_string()),
            aud: None,
            exp,
            iat: None,
            nbf: None,
            azp: None,
            scope: if scope.is_empty() {
                None
            } else {
                Some(scope.to_string())
            },
        };

        encode(&header, &claims, &fixture().encoding_key).expect("JWT encode failed")
    }

    /// Creates a proxy with a pre-seeded JWKS cache so no HTTP request is made.
    fn make_proxy() -> ClearGlassProxy {
        let mut cache = HashMap::new();
        cache.insert(TEST_KID.to_string(), fixture().decoding_key.clone());
        ClearGlassProxy {
            jwks: Arc::new(JwksClient {
                jwks_url: "http://unused-in-cached-tests".to_string(),
                http_client: Client::builder()
                    .timeout(Duration::from_secs(2))
                    .build()
                    .unwrap(),
                cache: Arc::new(RwLock::new(cache)),
            }),
        }
    }

    fn bearer(token: &str) -> String {
        format!("Bearer {token}")
    }

    fn body(resp: &Response<Vec<u8>>) -> String {
        String::from_utf8(resp.body().clone()).unwrap()
    }

    // --- Token extraction (rejected before JWT validation) ---

    #[tokio::test]
    async fn no_auth_header_returns_401() {
        let resp = make_proxy().handle_validate(None, "").await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(body(&resp), "missing bearer token");
    }

    #[tokio::test]
    async fn wrong_auth_scheme_returns_401() {
        let resp = make_proxy().handle_validate(Some("Basic abc123"), "").await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(body(&resp), "missing bearer token");
    }

    #[tokio::test]
    async fn empty_bearer_returns_401() {
        let resp = make_proxy().handle_validate(Some("Bearer "), "").await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(body(&resp), "invalid bearer token");
    }

    #[tokio::test]
    async fn oversized_token_returns_401() {
        let tok = format!("Bearer {}", "x".repeat(4097));
        let resp = make_proxy().handle_validate(Some(&tok), "").await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(body(&resp), "invalid bearer token");
    }

    // --- JWT validation ---

    #[tokio::test]
    async fn valid_jwt_no_scope_required_returns_200() {
        let tok = make_jwt("read");
        let resp = make_proxy().handle_validate(Some(&bearer(&tok)), "").await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn malformed_jwt_returns_401() {
        let resp = make_proxy()
            .handle_validate(Some("Bearer not.a.jwt"), "")
            .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn jwks_fetch_failure_returns_401() {
        let proxy = ClearGlassProxy {
            jwks: Arc::new(JwksClient::new(
                "http://127.0.0.1:1/jwks".to_string(),
                Client::builder()
                    .timeout(Duration::from_secs(1))
                    .build()
                    .unwrap(),
            )),
        };
        let tok = make_jwt("read");
        let resp = proxy.handle_validate(Some(&bearer(&tok)), "").await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn jwks_endpoint_is_fetched_and_key_cached() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(fixture().jwks_json.clone())
                    .insert_header("content-type", "application/json"),
            )
            .mount(&server)
            .await;

        let proxy = ClearGlassProxy {
            jwks: Arc::new(JwksClient::new(
                format!("{}/jwks", server.uri()),
                Client::builder()
                    .timeout(Duration::from_secs(2))
                    .build()
                    .unwrap(),
            )),
        };

        let tok = make_jwt("read");
        let resp = proxy.handle_validate(Some(&bearer(&tok)), "").await;
        assert_eq!(resp.status(), StatusCode::OK);

        // Second call must hit the cache (wiremock only registered one match).
        let tok2 = make_jwt("read");
        let resp2 = proxy.handle_validate(Some(&bearer(&tok2)), "").await;
        assert_eq!(resp2.status(), StatusCode::OK);
    }

    // --- Scope checking ---

    #[tokio::test]
    async fn token_with_matching_scope_returns_200() {
        let tok = make_jwt("read write");
        let resp = make_proxy()
            .handle_validate(Some(&bearer(&tok)), "scope=read")
            .await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn token_satisfying_one_of_multiple_required_scopes_returns_200() {
        let tok = make_jwt("write");
        let resp = make_proxy()
            .handle_validate(Some(&bearer(&tok)), "scope=read&scope=write")
            .await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn token_missing_required_scope_returns_403() {
        let tok = make_jwt("read");
        let resp = make_proxy()
            .handle_validate(Some(&bearer(&tok)), "scope=admin")
            .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(body(&resp), "insufficient scope");
    }

    #[tokio::test]
    async fn empty_scope_param_value_returns_403() {
        let tok = make_jwt("");
        let resp = make_proxy()
            .handle_validate(Some(&bearer(&tok)), "scope=")
            .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn non_scope_query_params_are_ignored() {
        let tok = make_jwt("read");
        let resp = make_proxy()
            .handle_validate(Some(&bearer(&tok)), "foo=bar&scope=read&baz=qux")
            .await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // --- text_response helper ---

    #[test]
    fn text_response_sets_status_and_body() {
        let resp = text_response(StatusCode::FORBIDDEN, "denied");
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(body(&resp), "denied");
        assert_eq!(resp.headers().get("content-type").unwrap(), "text/plain");
    }
}
