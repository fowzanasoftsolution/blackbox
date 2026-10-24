//! OTLP/HTTP ingestion parsing (`POST /v1/traces`, `POST /v1/logs`).
//!
//! Both the JSON (`application/json`) and protobuf
//! (`application/x-protobuf`) encodings of
//! `ExportTraceServiceRequest` / `ExportLogsServiceRequest` are decoded.
//!
//! Storage mapping (Phase 1 disk schema is frozen): each OTLP **span** or
//! **log record** becomes a [`TelemetryLog`] record correlated by the
//! span/log `trace_id`:
//!
//! - `level` — log `severity_number` → 1..5; spans map `status.code == ERROR`
//!   to level 5, everything else 3.
//! - `service` — the enclosing `resource.attributes["service.name"]`.
//! - `message` — log `body` (string form) or the span `name`.
//! - `attributes` — span/log attributes + `span_id` / timing metadata.

use crate::pb;
use blackbox_core::schema::{parse_trace_hex, TraceId};
use serde_json::Value as Json;

/// One decoded OTLP span or log record, ready to frame as a TelemetryLog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtlpRecord {
    pub trace_id: Option<TraceId>,
    pub span_id: Option<String>,
    /// blackbox level: 1=TRACE 2=DEBUG 3=INFO 4=WARN 5=ERROR.
    pub level: u8,
    pub service: String,
    pub message: String,
    pub attributes: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OtlpError {
    #[error("unsupported OTLP Content-Type {0:?}")]
    UnsupportedContentType(String),
    #[error("OTLP body is not valid JSON: {0}")]
    BadJson(String),
    #[error("OTLP protobuf body is malformed: {0}")]
    BadProtobuf(String),
}

/// Which OTLP signal the endpoint serves (the router knows the path).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtlpKind {
    Traces,
    Logs,
}

/// Decode an OTLP export request from either wire encoding.
pub fn decode(kind: OtlpKind, content_type: &str, body: &[u8]) -> Result<Vec<OtlpRecord>, OtlpError> {
    let ct = content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    match ct.as_str() {
        "application/json" => {
            let root: Json =
                serde_json::from_slice(body).map_err(|e| OtlpError::BadJson(e.to_string()))?;
            match kind {
                OtlpKind::Traces => traces_from_json(&root),
                OtlpKind::Logs => logs_from_json(&root),
            }
        }
        "application/x-protobuf" | "application/grpc+proto" | "application/octet-stream" => {
            match kind {
                OtlpKind::Traces => traces_from_protobuf(body),
                OtlpKind::Logs => logs_from_protobuf(body),
            }
        }
        other => Err(OtlpError::UnsupportedContentType(other.to_string())),
    }
}

// ---------------------------------------------------------------- JSON ----

/// `ExportTraceServiceRequest` (JSON).
pub fn traces_from_json(root: &Json) -> Result<Vec<OtlpRecord>, OtlpError> {
    let mut out = Vec::new();
    for rs in arr(root, "resourceSpans") {
        let service = service_name(rs.get("resource"));
        for ss in arr(rs, "scopeSpans") {
            for span in arr(ss, "spans") {
                out.push(span_to_record(span, &service));
            }
        }
    }
    Ok(out)
}

/// `ExportLogsServiceRequest` (JSON).
pub fn logs_from_json(root: &Json) -> Result<Vec<OtlpRecord>, OtlpError> {
    let mut out = Vec::new();
    for rl in arr(root, "resourceLogs") {
        let service = service_name(rl.get("resource"));
        for sl in arr(rl, "scopeLogs") {
            for log in arr(sl, "logRecords") {
                out.push(log_to_record(log, &service));
            }
        }
    }
    Ok(out)
}

fn span_to_record(span: &Json, service: &str) -> OtlpRecord {
    let status_code = span
        .pointer("/status/code")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let level = if status_code == 2 { 5 } else { 3 }; // ERROR vs INFO
    let message = span
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let mut attrs: Vec<(String, String)> = attrs_json(span.get("attributes"));
    if let Some(sid) = span.get("spanId").and_then(|v| v.as_str()) {
        attrs.push(("span_id".into(), sid.to_string()));
    }
    if let (Some(s), Some(e)) = (
        span.get("startTimeUnixNano").and_then(|v| as_u64(v)),
        span.get("endTimeUnixNano").and_then(|v| as_u64(v)),
    ) {
        attrs.push(("duration_ns".into(), (e.saturating_sub(s)).to_string()));
    }
    let kind = span.get("kind").and_then(|v| as_u64(v));
    if let Some(k) = kind {
        attrs.push(("span_kind".into(), k.to_string()));
    }

    OtlpRecord {
        trace_id: span
            .get("traceId")
            .and_then(|v| v.as_str())
            .and_then(parse_trace_hex),
        span_id: span.get("spanId").and_then(|v| v.as_str()).map(String::from),
        level,
        service: service.to_string(),
        message,
        attributes: attrs,
    }
}

fn log_to_record(log: &Json, service: &str) -> OtlpRecord {
    let sev = log.get("severityNumber").and_then(|v| as_u64(v)).unwrap_or(9) as u8;
    let level = map_severity(sev);
    let message = log
        .get("body")
        .map(any_value_to_string)
        .unwrap_or_else(|| {
            log.get("severityText")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string()
        });
    let mut attrs = attrs_json(log.get("attributes"));
    if let Some(sid) = log.get("spanId").and_then(|v| v.as_str()) {
        attrs.push(("span_id".into(), sid.to_string()));
    }
    OtlpRecord {
        trace_id: log
            .get("traceId")
            .and_then(|v| v.as_str())
            .and_then(parse_trace_hex),
        span_id: log.get("spanId").and_then(|v| v.as_str()).map(String::from),
        level,
        service: service.to_string(),
        message,
        attributes: attrs,
    }
}

/// OTLP severity_number (1–24) → blackbox level 1–5.
fn map_severity(sev: u8) -> u8 {
    match sev {
        0 => 3,
        1..=4 => 2,    // TRACE/DEBUG band
        5..=8 => 3,    // INFO
        9..=12 => 4,   // WARN
        _ => 5,        // ERROR..=FATAL
    }
}

fn service_name(resource: Option<&Json>) -> String {
    resource
        .and_then(|r| r.get("attributes"))
        .and_then(|attrs| attrs.as_array())
        .and_then(|attrs| {
            attrs.iter().find_map(|kv| {
                if kv.get("key").and_then(|k| k.as_str()) == Some("service.name") {
                    kv.pointer("/value/stringValue").and_then(|v| v.as_str()).map(String::from)
                } else {
                    None
                }
            })
        })
        .unwrap_or_else(|| "unknown".into())
}

fn attrs_json(v: Option<&Json>) -> Vec<(String, String)> {
    let mut out = Vec::new();
    if let Some(arr) = v.and_then(|a| a.as_array()) {
        for kv in arr {
            let key = kv.get("key").and_then(|k| k.as_str()).unwrap_or("");
            let val = kv.get("value").map(any_value_to_string).unwrap_or_default();
            out.push((key.to_string(), val));
        }
    }
    out
}

/// OTLP `AnyValue` → string form (JSON).
fn any_value_to_string(v: &Json) -> String {
    if let Some(s) = v.get("stringValue").and_then(|s| s.as_str()) {
        s.to_string()
    } else if let Some(b) = v.get("boolValue").and_then(|s| s.as_bool()) {
        b.to_string()
    } else if let Some(i) = v.get("intValue").and_then(|s| as_u64(s)) {
        i.to_string()
    } else if let Some(d) = v.get("doubleValue").and_then(|s| s.as_f64()) {
        d.to_string()
    } else if v.get("kvlistValue").is_some() || v.get("arrayValue").is_some() {
        v.to_string()
    } else {
        String::new()
    }
}

fn as_u64(v: &Json) -> Option<u64> {
    v.as_u64()
        .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
}

fn arr<'a>(v: &'a Json, key: &str) -> &'a [Json] {
    v.get(key).and_then(|x| x.as_array()).map(|a| a.as_slice()).unwrap_or(&[])
}

// ----------------------------------------------------------- protobuf ----

/// `ExportTraceServiceRequest` (protobuf).
pub fn traces_from_protobuf(body: &[u8]) -> Result<Vec<OtlpRecord>, OtlpError> {
    let mut out = Vec::new();
    let root = pb::fields(body).map_err(|e| OtlpError::BadProtobuf(e.to_string()))?;
    for rs_bytes in pb::sub(&root, 1) {
        let rs = pb::fields(rs_bytes).map_err(|e| OtlpError::BadProtobuf(e.to_string()))?;
        let service = pb_service_name(&rs); // resource = field 1
        for ss_bytes in pb::sub(&rs, 2) {
            let ss = pb::fields(ss_bytes).map_err(|e| OtlpError::BadProtobuf(e.to_string()))?;
            for span_bytes in pb::sub(&ss, 2) {
                out.push(span_from_pb(span_bytes, &service)?);
            }
        }
    }
    Ok(out)
}

/// `ExportLogsServiceRequest` (protobuf).
pub fn logs_from_protobuf(body: &[u8]) -> Result<Vec<OtlpRecord>, OtlpError> {
    let mut out = Vec::new();
    let root = pb::fields(body).map_err(|e| OtlpError::BadProtobuf(e.to_string()))?;
    for rl_bytes in pb::sub(&root, 1) {
        let rl = pb::fields(rl_bytes).map_err(|e| OtlpError::BadProtobuf(e.to_string()))?;
        let service = pb_service_name(&rl);
        for sl_bytes in pb::sub(&rl, 2) {
            let sl = pb::fields(sl_bytes).map_err(|e| OtlpError::BadProtobuf(e.to_string()))?;
            for log_bytes in pb::sub(&sl, 2) {
                out.push(log_from_pb(log_bytes, &service)?);
            }
        }
    }
    Ok(out)
}

fn pb_service_name(resource_spans: &[pb::PbField<'_>]) -> String {
    let subs = pb::sub(resource_spans, 1);
    let Some(res) = subs.first() else {
        return "unknown".into();
    };
    let Ok(res_fs) = pb::fields(res) else {
        return "unknown".into();
    };
    let kv_subs = pb::sub(&res_fs, 1);
    for kv_bytes in kv_subs.iter() {
        let Ok(kv) = pb::fields(kv_bytes) else { continue };
        if pb::string(&kv, 1) == Some("service.name") {
            let avs = pb::sub(&kv, 2);
            if let Some(av) = avs.first() {
                if let Ok(av_fs) = pb::fields(av) {
                    if let Some(s) = pb::string(&av_fs, 1) {
                        return s.to_string();
                    }
                }
            }
        }
    }
    "unknown".into()
}

fn pb_attrs(fs: &[pb::PbField<'_>], field: u32) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for kv_bytes in pb::sub(fs, field) {
        let Ok(kv) = pb::fields(kv_bytes) else { continue };
        let key = pb::string(&kv, 1).unwrap_or("").to_string();
        let val = pb::sub(&kv, 2)
            .first()
            .and_then(|av| pb::fields(av).ok())
            .map(|av| pb_any_value(&av))
            .unwrap_or_default();
        out.push((key, val));
    }
    out
}

fn pb_any_value(fs: &[pb::PbField<'_>]) -> String {
    if let Some(s) = pb::string(fs, 1) {
        return s.to_string();
    }
    if let Some(b) = pb::var(fs, 2) {
        return (b != 0).to_string();
    }
    if let Some(i) = pb::var(fs, 3) {
        return i.to_string();
    }
    String::new()
}

fn span_from_pb(buf: &[u8], service: &str) -> Result<OtlpRecord, OtlpError> {
    let fs = pb::fields(buf).map_err(|e| OtlpError::BadProtobuf(e.to_string()))?;
    let status_code = pb::sub(&fs, 15)
        .first()
        .and_then(|s| pb::fields(s).ok())
        .and_then(|s| pb::var(&s, 3))
        .unwrap_or(0);
    let level = if status_code == 2 { 5 } else { 3 };
    let mut attrs = pb_attrs(&fs, 9);
    if let Some(sid) = pb::bytes(&fs, 2) {
        attrs.push(("span_id".into(), blackbox_core::schema::trace_id_to_hex(&pad8(sid))));
    }
    Ok(OtlpRecord {
        trace_id: pb::bytes(&fs, 1).and_then(|b| TryInto::<TraceId>::try_into(b.to_vec()).ok()),
        span_id: pb::bytes(&fs, 2).map(|b| blackbox_core::schema::trace_id_to_hex(&pad8(b))),
        level,
        service: service.to_string(),
        message: pb::string(&fs, 5).unwrap_or("").to_string(),
        attributes: attrs,
    })
}

fn log_from_pb(buf: &[u8], service: &str) -> Result<OtlpRecord, OtlpError> {
    let fs = pb::fields(buf).map_err(|e| OtlpError::BadProtobuf(e.to_string()))?;
    let sev = pb::var(&fs, 2).unwrap_or(9) as u8;
    let message = pb::sub(&fs, 5)
        .first()
        .and_then(|av| pb::fields(av).ok())
        .map(|av| pb_any_value(&av))
        .unwrap_or_else(|| pb::string(&fs, 3).unwrap_or("").to_string());
    Ok(OtlpRecord {
        trace_id: pb::bytes(&fs, 9).and_then(|b| TryInto::<TraceId>::try_into(b.to_vec()).ok()),
        span_id: pb::bytes(&fs, 10).map(|b| blackbox_core::schema::trace_id_to_hex(&pad8(b))),
        level: map_severity(sev),
        service: service.to_string(),
        message,
        attributes: pb_attrs(&fs, 6),
    })
}

fn pad8(b: &[u8]) -> [u8; 16] {
    let mut o16 = [0u8; 16];
    for (i, v) in b.iter().take(8).enumerate() {
        o16[i] = *v;
    }
    o16
}

#[cfg(test)]
mod tests {
    use super::*;

    const TID: &str = "5b8efff798038103d269b633813fc60c";
    const SID: &str = "eee19b7ec3c1b174";

    fn traces_json() -> String {
        format!(
            r#"{{"resourceSpans":[{{
                "resource":{{"attributes":[{{"key":"service.name","value":{{"stringValue":"cart-api"}}}}]}},
                "scopeSpans":[{{"spans":[
                    {{"traceId":"{TID}","spanId":"{SID}","name":"POST /checkout","kind":2,
                      "startTimeUnixNano":"1000","endTimeUnixNano":"1500",
                      "attributes":[{{"key":"http.method","value":{{"stringValue":"POST"}}}}],
                      "status":{{"code":2}}}},
                    {{"traceId":"{TID}","spanId":"aaaabbbbccccdddd","name":"db.query","kind":3}}
                ]}}]}}]}}"#
        )
    }

    #[test]
    fn json_traces_parse_with_status_and_service() {
        let recs = traces_from_json(&serde_json::from_str(&traces_json()).unwrap()).unwrap();
        assert_eq!(recs.len(), 2);
        let first = &recs[0];
        assert_eq!(first.trace_id, parse_trace_hex(TID));
        assert_eq!(first.level, 5, "status.code=2 → ERROR");
        assert_eq!(first.service, "cart-api");
        assert_eq!(first.message, "POST /checkout");
        assert!(first.attributes.contains(&("span_id".into(), SID.into())));
        assert!(first.attributes.contains(&("duration_ns".into(), "500".into())));
        assert!(first.attributes.contains(&("http.method".into(), "POST".into())));
        // Second span has no status → INFO.
        assert_eq!(recs[1].level, 3);
    }

    #[test]
    fn json_logs_parse_severity_mapping() {
        let body = format!(
            r#"{{"resourceLogs":[{{
                "resource":{{"attributes":[{{"key":"service.name","value":{{"stringValue":"payments"}}}}]}},
                "scopeLogs":[{{"logRecords":[
                    {{"timeUnixNano":"1","severityNumber":13,"severityText":"ERROR",
                      "body":{{"stringValue":"card declined"}},"traceId":"{TID}",
                      "attributes":[{{"key":"user.id","value":{{"intValue":"42"}}}}]}},
                    {{"severityNumber":9,"body":{{"stringValue":"slow query"}}}},
                    {{"severityNumber":5,"body":{{"stringValue":"started"}}}}
                ]}}]}}]}}"#
        );
        let recs = logs_from_json(&serde_json::from_str(&body).unwrap()).unwrap();
        assert_eq!(recs.len(), 3);
        assert_eq!(recs[0].level, 5);
        assert_eq!(recs[0].message, "card declined");
        assert_eq!(recs[0].service, "payments");
        assert_eq!(recs[0].trace_id, parse_trace_hex(TID));
        assert_eq!(recs[1].level, 4, "sev 9 → WARN");
        assert_eq!(recs[2].level, 3, "sev 5 → INFO");
    }

    #[test]
    fn protobuf_traces_match_json_semantics() {
        // Hand-encode ExportTraceServiceRequest{ resourceSpans(1) } →
        // ResourceSpans{ resource(1), scopeSpans(2) } → ScopeSpans{ spans(2) } →
        // Span{ trace_id(1), span_id(2), name(5), attributes(9), status(15) }.
        let tid = parse_trace_hex(TID).unwrap();
        let sid = parse_trace_hex(&format!("{SID}0000000000000000")).unwrap()[..8].to_vec();
        let attr = kv_pb("http.method", "GET");
        let status = [(3u8 << 3) | pb::WIRE_VARINT, 2].to_vec();
        let mut span = Vec::new();
        len_field(&mut span, 1, &tid);
        len_field(&mut span, 2, &sid);
        len_field(&mut span, 5, b"GET /items");
        len_field(&mut span, 9, &attr);
        len_field(&mut span, 15, &status);
        let mut scope_spans = Vec::new();
        len_field(&mut scope_spans, 2, &span);
        let res_attr = kv_pb("service.name", "cart-api");
        let mut resource = Vec::new();
        len_field(&mut resource, 1, &res_attr);
        let mut resource_spans = Vec::new();
        len_field(&mut resource_spans, 1, &resource);
        len_field(&mut resource_spans, 2, &scope_spans);
        let mut root = Vec::new();
        len_field(&mut root, 1, &resource_spans);

        let recs = traces_from_protobuf(&root).unwrap();
        assert_eq!(recs.len(), 1);
        let r = &recs[0];
        assert_eq!(r.trace_id, Some(tid));
        let expect_sid = blackbox_core::schema::trace_id_to_hex(&try_arr8(&sid));
        assert_eq!(r.span_id.as_deref(), Some(expect_sid.as_str()));
        assert_eq!(r.level, 5);
        assert_eq!(r.service, "cart-api");
        assert_eq!(r.message, "GET /items");
        assert!(r.attributes.contains(&("http.method".into(), "GET".into())));
    }

    fn try_arr8(v: &[u8]) -> [u8; 16] {
        let mut o = [0u8; 16];
        o[..v.len().min(16)].copy_from_slice(&v[..v.len().min(16)]);
        o
    }

    fn len_field(out: &mut Vec<u8>, no: u32, payload: &[u8]) {
        out.push((((no << 3) | pb::WIRE_LEN as u32) & 0xFF) as u8);
        let mut len = payload.len();
        while len >= 0x80 {
            out.push((len & 0x7F) as u8 | 0x80);
            len >>= 7;
        }
        out.push(len as u8);
        out.extend_from_slice(payload);
    }

    fn kv_pb(key: &str, val: &str) -> Vec<u8> {
        let mut av = Vec::new();
        len_field(&mut av, 1, val.as_bytes()); // AnyValue.stringValue
        let mut kv = Vec::new();
        len_field(&mut kv, 1, key.as_bytes());
        len_field(&mut kv, 2, &av);
        kv
    }

    #[test]
    fn unsupported_content_type_rejected() {
        assert!(matches!(
            decode(OtlpKind::Traces, "text/csv", b"x"),
            Err(OtlpError::UnsupportedContentType(_))
        ));
    }

    #[test]
    fn json_empty_export_is_ok() {
        let root: Json = serde_json::from_slice(b"{}").unwrap();
        assert_eq!(traces_from_json(&root).unwrap(), Vec::new());
        assert_eq!(logs_from_json(&root).unwrap(), Vec::new());
    }

    #[test]
    fn json_decode_routes_by_kind() {
        let traces = traces_json();
        let logs_body = format!(
            r#"{{"resourceLogs":[{{"scopeLogs":[{{"logRecords":[{{"severityNumber":13,"body":{{"stringValue":"x"}}}}]}}]}}]}}"#
        );
        assert_eq!(
            decode(OtlpKind::Traces, "application/json", traces.as_bytes())
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            decode(OtlpKind::Logs, "application/json", logs_body.as_bytes())
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn protobuf_decode_routes_by_kind() {
        let body = format!(
            r#"{{"resourceLogs":[{{"scopeLogs":[{{"logRecords":[{{"severityNumber":13,"body":{{"stringValue":"pb-route"}}}}]}}]}}]}}"#
        );
        // JSON body with protobuf kind must fail cleanly (bad protobuf), not
        // silently produce records — decoding is kind-dispatched.
        assert!(decode(OtlpKind::Logs, "application/x-protobuf", body.as_bytes()).is_err());
    }
}
