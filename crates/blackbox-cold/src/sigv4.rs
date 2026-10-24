//! Hand-rolled AWS Signature V4 (AWS4-HMAC-SHA256) — the "zero-bloat"
//! cold-tier signer.
//!
//! We deliberately do NOT pull in `aws-sdk-s3` (tens of MB of binary).
//! Everything a segment sync needs — PUT / GET / HEAD / ListObjectsV2 — is
//! signed right here on top of the existing `sha2` + `hmac` stack, fully
//! compatible with AWS S3, Cloudflare R2 (`region = "auto"`), MinIO and
//! any SigV4-conformant object store.
//!
//! Canonicalization follows the SigV4 spec exactly:
//! - canonical URI: each path segment URI-encoded (unreserved = `A-Za-z0-9-._~`),
//!   `/` separators preserved (S3 path-style rule — no double encoding),
//! - canonical query: params sorted by (name, value), both fully encoded,
//! - canonical headers: lowercase names, trimmed values, sorted,
//! - payload hash: lowercase hex SHA-256 of the body (`UNSIGNED-PAYLOAD` is
//!   never used — every request body is fully materialized here anyway).
//!
//! The unit test pins the whole chain to the AWS documentation's "GET
//! Object" worked example, so any canonicalization drift fails CI, not a
//! customer's MinIO.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// SigV4 credentials.
#[derive(Debug, Clone)]
pub struct Credentials {
    pub access_key: String,
    pub secret_key: String,
}

/// A signed request ready to be sent: the canonical-signed header set plus
/// the exact query string that must appear in the request URI.
#[derive(Debug, Clone)]
pub struct SignedRequest {
    /// Value for the `Authorization` header.
    pub authorization: String,
    /// Value for `x-amz-date`.
    pub amz_date: String,
    /// Value for `x-amz-content-sha256`.
    pub payload_hash: String,
    /// The canonical (sorted, fully encoded) query string — send EXACTLY
    /// these bytes in the request URI so wire and signature always match.
    pub canonical_query: String,
}

/// RFC 3986 unreserved set — everything else gets %XY (uppercase hex).
fn uri_encode(s: &str, encode_slash: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b'/' if !encode_slash => out.push('/'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Lowercase hex SHA-256.
pub fn sha256_hex(data: &[u8]) -> String {
    let d = Sha256::digest(data);
    crate::hex::enc(&d)
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// Compute the SigV4 signature for one request.
///
/// * `method` — "PUT" / "GET" / "HEAD" / "DELETE".
/// * `path` — the raw (unencoded) object path INCLUDING the leading `/`
///   (path-style: `/{bucket}/{key}`); each segment is encoded for signing.
/// * `query` — already-encoded `(name, value)` pairs; re-encoded canonically
///   (values must be the RAW values; encoding happens here). An empty value
///   is legal and signs as `name=`.
/// * `host` — the `Host` header value that will actually be sent (includes
///   a non-default port when present).
/// * `extra_signed_headers` — additional headers to sign, e.g. `range`;
///   names are lowercased, values trimmed, duplicates must be pre-merged.
/// * `payload` — the exact request body (empty for GET/HEAD).
/// * `amz_date_override` — frozen `YYYYMMDDThhmmssZ` stamp for tests.
pub fn sign_request(
    method: &str,
    path: &str,
    query: &[(String, String)],
    host: &str,
    extra_signed_headers: &[(String, String)],
    payload: &[u8],
    creds: &Credentials,
    region: &str,
    service: &str,
    amz_date_override: Option<&str>,
) -> SignedRequest {
    let payload_hash = sha256_hex(payload);
    let (amz_date, date_stamp) = match amz_date_override {
        Some(stamp) => (stamp.to_string(), stamp[..8].to_string()),
        None => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            // UTC calendar date without pulling chrono in.
            let days = now / 86_400;
            let secs = now % 86_400;
            let (y, m, d) = civil_from_days(days as i64);
            (
                format!("{y:04}{m:02}{d:02}T{:02}{:02}{:02}Z", secs / 3600, (secs / 60) % 60, secs % 60),
                format!("{y:04}{m:02}{d:02}"),
            )
        }
    };

    // Canonical URI — S3 path-style: encode each segment, keep `/`.
    let canonical_uri = uri_encode(path, false);
    // Canonical query — sorted by (name, value), both fully encoded.
    let mut pairs: Vec<(String, String)> = query.to_vec();
    pairs.sort();
    let canonical_query = pairs
        .iter()
        .map(|(k, v)| format!("{}={}", uri_encode(k, true), uri_encode(v, true)))
        .collect::<Vec<_>>()
        .join("&");
    let canonical_query_out = canonical_query.clone();

    // Canonical headers: host + extras + the two x-amz-* we always sign.
    let mut headers: Vec<(String, String)> = vec![
        ("host".into(), host.to_ascii_lowercase()),
        ("x-amz-content-sha256".into(), payload_hash.clone()),
        ("x-amz-date".into(), amz_date.clone()),
    ];
    for (k, v) in extra_signed_headers {
        headers.push((k.to_ascii_lowercase(), v.trim().to_string()));
    }
    headers.sort_by(|a, b| a.0.cmp(&b.0));
    let canonical_headers = headers
        .iter()
        .map(|(k, v)| format!("{k}:{v}\n"))
        .collect::<String>();
    let signed_headers = headers
        .iter()
        .map(|(k, _)| k.as_str())
        .collect::<Vec<_>>()
        .join(";");

    let canonical_request = format!(
        "{method}\n{canonical_uri}\n{canonical_query}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    );

    let scope = format!("{date_stamp}/{region}/{service}/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        sha256_hex(canonical_request.as_bytes())
    );

    // Signing key chain: kSecret → kDate → kRegion → kService → kSigning.
    let k_date = hmac_sha256(format!("AWS4{}", creds.secret_key).as_bytes(), date_stamp.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    let k_signing = hmac_sha256(&k_service, b"aws4_request");
    let signature = crate::hex::enc(&hmac_sha256(&k_signing, string_to_sign.as_bytes()));

    SignedRequest {
        authorization: format!(
            "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
            creds.access_key, scope, signed_headers, signature
        ),
        amz_date,
        payload_hash,
        canonical_query: canonical_query_out,
    }
}

/// Days-since-epoch → (year, month, day) — Howard Hinnant's civil algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The AWS documentation's "GET Object" worked example, frozen.
    /// (docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html)
    /// Any drift in canonicalization, header folding or the HMAC chain
    /// breaks this test against the spec — not against ourselves.
    #[test]
    fn aws_documentation_get_object_vector() {
        let creds = Credentials {
            access_key: "AKIAIOSFODNN7EXAMPLE".into(),
            secret_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
        };
        let signed = sign_request(
            "GET",
            "/test.txt",
            &[],
            "examplebucket.s3.amazonaws.com",
            &[("range".into(), "bytes=0-9".into())],
            b"",
            &creds,
            "us-east-1",
            "s3",
            Some("20130524T000000Z"),
        );
        assert_eq!(
            signed.payload_hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            signed.authorization,
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, \
             SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, \
             Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );
    }

    #[test]
    fn uri_encoding_rules() {
        // Unreserved set passes through; `/` is path-legal but query-encoded.
        assert_eq!(uri_encode("segment_000001.log.zst", false), "segment_000001.log.zst");
        assert_eq!(uri_encode("a/b c+d", false), "a/b%20c%2Bd");
        assert_eq!(uri_encode("a/b c+d", true), "a%2Fb%20c%2Bd");
        assert_eq!(uri_encode("~._-", false), "~._-");
    }

    #[test]
    fn civil_date_known_values() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(19_000), (2022, 1, 8));
    }
}
