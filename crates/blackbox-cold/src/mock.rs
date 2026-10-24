//! Local S3-compatible mock server — a test/dev fixture with the wire
//! surface that matters for the cold tier:
//!
//! - `PUT /{bucket}/{key}` — stores the object, **verifies
//!   `x-amz-content-sha256` against the actual body** (real payload
//!   integrity, the same check MinIO/AWS perform), requires a well-formed
//!   SigV4 `Authorization` header for the expected access key (403
//!   otherwise),
//! - `GET /{bucket}/{key}` / `HEAD` — serves bytes or a 404 XML error,
//! - `GET /{bucket}?list-type=2&prefix=…` — ListObjectsV2 XML.
//!
//! Signature values are NOT re-verified server-side (that would just
//! re-run our own canonicalizer); spec-correctness is pinned by the
//! AWS-documentation vector test in [`crate::sigv4`]. Counters for
//! puts/gets/lists are exposed so the gates can PROVE a fetch actually
//! hit the cold tier.

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// Live counters + object store for one mock instance.
#[derive(Debug, Default)]
pub struct MockS3State {
    pub objects: Mutex<BTreeMap<String, Vec<u8>>>,
    pub puts: AtomicU64,
    pub gets: AtomicU64,
    pub lists: AtomicU64,
    pub rejected: AtomicU64,
}

impl MockS3State {
    pub fn put_count(&self) -> u64 {
        self.puts.load(Ordering::Relaxed)
    }
    pub fn get_count(&self) -> u64 {
        self.gets.load(Ordering::Relaxed)
    }
    pub fn list_count(&self) -> u64 {
        self.lists.load(Ordering::Relaxed)
    }
    pub fn rejected_count(&self) -> u64 {
        self.rejected.load(Ordering::Relaxed)
    }
}

/// Spawn the mock on `addr` (use port 0 for ephemeral). Returns
/// `(bound_addr, state)`.
pub async fn spawn_mock_s3(
    addr: &str,
    bucket: &str,
    access_key: &str,
    secret_key: &str,
) -> anyhow::Result<(std::net::SocketAddr, Arc<MockS3State>)> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let local = listener.local_addr()?;
    let state = Arc::new(MockS3State::default());
    let ctx = Arc::new(MockCtx {
        bucket: bucket.to_string(),
        access_key: access_key.to_string(),
        // The secret is part of the fixture (the mock doesn't verify the
        // HMAC chain); kept so tests can construct real clients against it.
        _secret_key: secret_key.to_string(),
        state: Arc::clone(&state),
    });
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else { return };
            let _ = tcp.set_nodelay(true);
            let ctx = Arc::clone(&ctx);
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(move |req: hyper::Request<Incoming>| {
                    let ctx = Arc::clone(&ctx);
                    async move { Ok::<_, std::convert::Infallible>(route(req, ctx).await) }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tcp), svc)
                    .await;
            });
        }
    });
    Ok((local, state))
}

struct MockCtx {
    bucket: String,
    access_key: String,
    _secret_key: String,
    state: Arc<MockS3State>,
}

fn xml(status: u16, code: &str, message: &str) -> hyper::Response<Full<Bytes>> {
    hyper::Response::builder()
        .status(status)
        .header("content-type", "application/xml")
        .body(Full::new(Bytes::from(format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>{code}</Code><Message>{message}</Message></Error>"
        ))))
        .expect("xml error builds")
}

fn ok(body: Vec<u8>, extra: Vec<(&str, String)>) -> hyper::Response<Full<Bytes>> {
    let mut b = hyper::Response::builder()
        .status(200)
        .header("content-length", body.len().to_string());
    for (k, v) in extra {
        b = b.header(k, v);
    }
    b.body(Full::new(Bytes::from(body))).expect("mock response builds")
}

/// Split `/{bucket}/{key…}` or `/{bucket}?query`.
fn split_target(uri: &hyper::Uri) -> (String, String, HashMap<String, String>) {
    let path = uri.path().to_string();
    let mut query = HashMap::new();
    if let Some(q) = uri.query() {
        for pair in q.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                query.insert(k.to_string(), v.to_string());
            } else {
                query.insert(pair.to_string(), String::new());
            }
        }
    }
    let trimmed = path.trim_start_matches('/');
    let (bucket, key) = match trimmed.split_once('/') {
        Some((b, k)) => (b.to_string(), k.to_string()),
        None => (trimmed.to_string(), String::new()),
    };
    (bucket, key, query)
}

async fn route(req: hyper::Request<Incoming>, ctx: Arc<MockCtx>) -> hyper::Response<Full<Bytes>> {
    let method = req.method().clone();
    let (bucket, raw_key, query) = split_target(req.uri());

    // Auth: require a well-formed SigV4 Authorization header for the
    // expected access key + the x-amz-date stamp (payload integrity is
    // verified separately below).
    let auth = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let amz_date_ok = req.headers().contains_key("x-amz-date");
    let cred_ok = auth.starts_with("AWS4-HMAC-SHA256 ")
        && auth.contains(&format!("Credential={}/", ctx.access_key));
    if !cred_ok || !amz_date_ok {
        ctx.state.rejected.fetch_add(1, Ordering::Relaxed);
        return xml(403, "AccessDenied", "invalid or missing SigV4 authorization");
    }

    if bucket != ctx.bucket {
        return xml(404, "NoSuchBucket", "bucket does not exist");
    }

    // Keys arrive percent-encoded on the wire (our client encodes); decode.
    let key = percent_decode(&raw_key);

    match method {
        hyper::Method::PUT => {
            // Read the claimed payload hash BEFORE consuming the body.
            let claimed = req
                .headers()
                .get("x-amz-content-sha256")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            let body = match http_body_util::BodyExt::collect(req.into_body()).await {
                Ok(b) => b.to_bytes().to_vec(),
                Err(_) => return xml(400, "IncompleteBody", "could not read body"),
            };
            // Real payload-integrity check (mirrors AWS/MinIO behavior).
            let actual = hex_enc(&Sha256::digest(&body));
            if claimed != actual {
                ctx.state.rejected.fetch_add(1, Ordering::Relaxed);
                return xml(400, "XAmzContentSHA256Mismatch", "payload hash does not match body");
            }
            let etag = format!("\"{}\"", &actual[..32.min(actual.len())]);
            ctx.state.objects.lock().unwrap().insert(key, body);
            ctx.state.puts.fetch_add(1, Ordering::Relaxed);
            ok(Vec::new(), vec![("etag", etag)])
        }
        hyper::Method::GET => {
            if raw_key.is_empty() {
                // ListObjectsV2.
                ctx.state.lists.fetch_add(1, Ordering::Relaxed);
                let prefix = percent_decode(query.get("prefix").map(|s| s.as_str()).unwrap_or(""));
                let objects = ctx.state.objects.lock().unwrap();
                let mut body = String::from(
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<ListBucketResult>",
                );
                body.push_str(&format!("<Name>{}</Name>", ctx.bucket));
                body.push_str(&format!("<Prefix>{}</Prefix>", xml_escape(&prefix)));
                body.push_str("<IsTruncated>false</IsTruncated>");
                for (k, v) in objects.iter() {
                    if k.starts_with(&prefix) {
                        body.push_str("<Contents>");
                        body.push_str(&format!("<Key>{}</Key>", xml_escape(k)));
                        body.push_str(&format!("<Size>{}</Size>", v.len()));
                        body.push_str("</Contents>");
                    }
                }
                body.push_str("</ListBucketResult>");
                ok(body.into_bytes(), vec![])
            } else {
                ctx.state.gets.fetch_add(1, Ordering::Relaxed);
                let objects = ctx.state.objects.lock().unwrap();
                match objects.get(&key) {
                    Some(bytes) => ok(
                        bytes.clone(),
                        vec![("etag", format!("\"{}\"", &hex_enc(&Sha256::digest(bytes))[..32]))],
                    ),
                    None => xml(404, "NoSuchKey", "the specified key does not exist"),
                }
            }
        }
        hyper::Method::HEAD => {
            let objects = ctx.state.objects.lock().unwrap();
            match objects.get(&key) {
                Some(bytes) => {
                    let len = bytes.len();
                    let mut resp = hyper::Response::builder().status(200);
                    resp = resp.header("content-length", len.to_string());
                    resp.body(Full::new(Bytes::new())).expect("head builds")
                }
                None => hyper::Response::builder()
                    .status(404)
                    .body(Full::new(Bytes::new()))
                    .expect("head 404 builds"),
            }
        }
        _ => xml(405, "MethodNotAllowed", "unsupported method"),
    }
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            let hi = (b.get(i + 1)).and_then(|c| (*c as char).to_digit(16));
            let lo = (b.get(i + 2)).and_then(|c| (*c as char).to_digit(16));
            if let (Some(h), Some(l)) = (hi, lo) {
                out.push(((h << 4) | l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn hex_enc(d: &[u8]) -> String {
    d.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_decode_roundtrip() {
        assert_eq!(percent_decode("segments%2Fsegment_000001.log.zst"), "segments/segment_000001.log.zst");
        assert_eq!(percent_decode("plain-key"), "plain-key");
        assert_eq!(percent_decode("a%20b"), "a b");
        assert_eq!(percent_decode("bad%zz"), "bad%zz");
    }
}
