//! The `send` action's request/response shapes and disclosure surface (SPEC §6).
//!
//! This module holds the pure, HTTP-adjacent logic of `POST /email/send`: the JSON
//! request schema (including the string-or-array recipient fields), validation into
//! the SMTP module's typed [`OutgoingMessage`], and
//! the **disclosure** a gating caller sees. The route handler ([`crate::routes`])
//! threads the parsed mailbox credential through the SMTP module; this module never
//! touches the network.
//!
//! ## Disclosure & redaction (SPEC §6)
//!
//! `send` is the one **write**-class action, so callers that gate writes need a
//! preview to approve. That disclosure is deliberately narrow — **To / From /
//! Subject and a clamped Body preview**, and nothing else:
//!
//! - The mailbox password lives in [`crate::auth::Secret`] and is never part of a
//!   request field, so it cannot reach a disclosure.
//! - The `X-Mailbox-Auth: Basic …` header is an HTTP header, never a body field;
//!   the disclosure is built only from body fields, so the `Basic` value cannot
//!   appear in the response, an audit log, or an error (SPEC §6).
//! - `Cc`/`Bcc` are intentionally omitted from the disclosure — the approval
//!   surface is the sender-facing summary, and `Bcc` is blind by definition.
//! - Attachments are disclosed by **filename and decoded size only** — never their
//!   contents, and no validation error ever echoes a byte of `content_base64`.
//!
//! ## Attachments
//!
//! overfwd stays stateless: a caller (e.g. the Overslash gateway, which stages the
//! uploads itself) inlines each file as `{ filename, content_type, content_base64 }`.
//! [`SendRequest::into_message`] validates them against [`AttachmentLimits`] before
//! anything is decoded — see `decode_attachments`.

use base64::Engine;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::config::DEFAULT_MAX_ATTACHMENT_BYTES;
use crate::error::GatewayError;
use crate::smtp::{OutgoingAttachment, OutgoingBody, OutgoingMessage};

/// Maximum number of characters retained in the disclosed body preview (SPEC §6
/// "clamped Body"). Counted in `char`s, so the clamp never splits a UTF-8 boundary.
pub const BODY_PREVIEW_LIMIT: usize = 256;

/// Maximum number of attachments on one message.
pub const MAX_ATTACHMENTS: usize = 20;

/// Maximum length of a sanitized attachment filename, in `char`s.
pub const MAX_FILENAME_CHARS: usize = 255;

/// The filename used when sanitizing leaves nothing usable.
const FALLBACK_FILENAME: &str = "attachment";

/// The bounds [`SendRequest::into_message`] enforces on attachments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttachmentLimits {
    /// Maximum number of attachments ([`MAX_ATTACHMENTS`]).
    pub max_count: usize,
    /// Maximum total **decoded** size across all attachments, in bytes
    /// (`OVERFWD_MAX_ATTACHMENT_BYTES`).
    pub max_total_bytes: usize,
}

impl AttachmentLimits {
    /// The limits for a deployment whose total-size cap is `max_total_bytes`.
    pub fn with_max_total_bytes(max_total_bytes: usize) -> Self {
        AttachmentLimits {
            max_count: MAX_ATTACHMENTS,
            max_total_bytes,
        }
    }
}

impl Default for AttachmentLimits {
    fn default() -> Self {
        Self::with_max_total_bytes(DEFAULT_MAX_ATTACHMENT_BYTES)
    }
}

/// The `POST /email/send` JSON request body (SPEC §6).
///
/// `cc`/`bcc` default to empty and `text`/`html` are optional, but at least one of
/// `text`/`html` must be present and `to` must be non-empty — enforced by
/// [`SendRequest::into_message`], not by serde.
///
/// Each recipient field accepts either a JSON array of addresses or a single string,
/// which is split on commas the way a mail client treats a `To:` line — see
/// [`de_recipients`].
#[derive(Debug, Deserialize, ToSchema)]
pub struct SendRequest {
    /// Envelope + header `From`.
    #[schema(example = "sender@example.com")]
    pub from: String,
    /// Primary recipients (`To`). Must be non-empty.
    #[serde(deserialize_with = "de_recipients")]
    #[schema(schema_with = recipients_schema)]
    pub to: Vec<String>,
    /// Carbon-copy recipients (`Cc`).
    #[serde(default, deserialize_with = "de_recipients")]
    #[schema(schema_with = recipients_schema)]
    pub cc: Vec<String>,
    /// Blind-carbon-copy recipients (`Bcc`) — delivered but never written to a header.
    #[serde(default, deserialize_with = "de_recipients")]
    #[schema(schema_with = recipients_schema)]
    pub bcc: Vec<String>,
    /// The `Subject` header.
    #[schema(example = "Hello from overfwd")]
    pub subject: String,
    /// A `text/plain` body.
    #[serde(default)]
    pub text: Option<String>,
    /// A `text/html` body.
    #[serde(default)]
    pub html: Option<String>,
    /// Files to attach, inlined as base64. At most 20, and at most
    /// `OVERFWD_MAX_ATTACHMENT_BYTES` (default 10 MiB) decoded in total. With any
    /// attachment the message is sent as `multipart/mixed`.
    // Inlined rather than referenced so the MCP tool's `inputSchema`, which is this
    // schema standing alone, stays self-contained.
    #[serde(default)]
    #[schema(inline)]
    pub attachments: Vec<Attachment>,
}

/// One file attached to a `send`, inlined as base64.
#[derive(Deserialize, ToSchema)]
pub struct Attachment {
    /// The file name shown to the recipient. Control characters and path separators
    /// are stripped, it is clamped to 255 characters, and an empty result becomes
    /// `attachment`.
    #[schema(example = "invoice.pdf")]
    pub filename: String,
    /// The MIME type, as `type/subtype`. Any `;` parameters are ignored.
    #[schema(example = "application/pdf")]
    pub content_type: String,
    /// The file's bytes, standard base64 (RFC 4648 §4, padded). Whitespace and line
    /// breaks are tolerated.
    #[schema(example = "JVBERi0xLjcK")]
    pub content_base64: String,
}

/// Hand-written so a `{:?}` of a request can never dump attachment contents.
impl std::fmt::Debug for Attachment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Attachment")
            .field("filename", &self.filename)
            .field("content_type", &self.content_type)
            .field(
                "content_base64",
                &format_args!("<{} base64 chars>", self.content_base64.len()),
            )
            .finish()
    }
}

/// Deserialize a recipient field from either an array of addresses or a single string.
///
/// A bare string is split on commas and trimmed (`"a@x , b@y"` → two recipients), so
/// callers that hand-roll JSON — or an MCP client whose model emits a plain string —
/// get the same behaviour as a mail client's `To:` line. Array elements are taken
/// verbatim: the array form is already explicit about where one address ends.
///
/// A string that yields nothing (`""`, `" , "`) deserializes to an empty `Vec` rather
/// than a serde error, so the "at least one recipient" failure stays a
/// [`GatewayError::BadRequest`] raised by [`SendRequest::into_message`].
fn de_recipients<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(String),
        Many(Vec<String>),
    }

    Ok(match OneOrMany::deserialize(deserializer)? {
        OneOrMany::Many(addresses) => addresses,
        OneOrMany::One(line) => line
            .split(',')
            .map(str::trim)
            .filter(|address| !address.is_empty())
            .map(str::to_string)
            .collect(),
    })
}

/// The OpenAPI schema for a recipient field: `oneOf` a comma-separated string or an
/// array of addresses. Mirrors [`de_recipients`] so the generated document — and the
/// MCP tool `inputSchema` derived from it ([`crate::mcp`]) — advertise both forms.
fn recipients_schema() -> utoipa::openapi::schema::Schema {
    use utoipa::openapi::schema::{ArrayBuilder, ObjectBuilder, OneOfBuilder, Schema, Type};

    Schema::OneOf(
        OneOfBuilder::new()
            .item(Schema::Object(
                ObjectBuilder::new()
                    .schema_type(Type::String)
                    .description(Some("A single address, or several separated by commas."))
                    .examples(["dest@example.com, other@example.com"])
                    .build(),
            ))
            .item(Schema::Array(
                ArrayBuilder::new()
                    .items(ObjectBuilder::new().schema_type(Type::String))
                    .build(),
            ))
            .build(),
    )
}

impl SendRequest {
    /// Validate the request and turn it into the SMTP module's [`OutgoingMessage`].
    ///
    /// Fails with [`GatewayError::BadRequest`] when `to` is empty, when neither
    /// `text` nor `html` is supplied (the body enum makes "no body" unrepresentable
    /// downstream, so the check lives here), or when an attachment breaks one of the
    /// rules in `decode_attachments`.
    pub fn into_message(self, limits: &AttachmentLimits) -> Result<OutgoingMessage, GatewayError> {
        if self.to.is_empty() {
            return Err(GatewayError::BadRequest(
                "`to` must contain at least one recipient".to_string(),
            ));
        }

        let body = match (self.text, self.html) {
            (Some(text), Some(html)) => OutgoingBody::Both { text, html },
            (Some(text), None) => OutgoingBody::Text(text),
            (None, Some(html)) => OutgoingBody::Html(html),
            (None, None) => {
                return Err(GatewayError::BadRequest(
                    "a message body is required: provide `text`, `html`, or both".to_string(),
                ))
            }
        };

        let attachments = decode_attachments(self.attachments, limits)?;

        Ok(OutgoingMessage {
            from: self.from,
            to: self.to,
            cc: self.cc,
            bcc: self.bcc,
            subject: self.subject,
            body,
            attachments,
        })
    }
}

/// Validate and decode a request's attachments.
///
/// Every check that can run on the encoded form runs first, across *all*
/// attachments, so an oversized request is refused before a single byte is decoded:
///
/// 1. at most `limits.max_count` attachments;
/// 2. each `content_type` is a bare `type/subtype` (the header-injection check);
/// 3. each `content_base64` has a well-formed length, and the decoded size — computed
///    exactly from that length — summed over all attachments fits
///    `limits.max_total_bytes`;
/// 4. only then is each one decoded, strictly (standard alphabet, canonical padding;
///    ASCII whitespace is the one thing tolerated).
///
/// Errors name the attachment by index, never by its content, and the `base64`
/// crate's own error is not forwarded because it quotes the offending byte.
fn decode_attachments(
    attachments: Vec<Attachment>,
    limits: &AttachmentLimits,
) -> Result<Vec<OutgoingAttachment>, GatewayError> {
    if attachments.len() > limits.max_count {
        return Err(GatewayError::BadRequest(format!(
            "too many attachments: {} given, at most {} allowed",
            attachments.len(),
            limits.max_count
        )));
    }

    let mut content_types = Vec::with_capacity(attachments.len());
    let mut total: usize = 0;
    for (index, attachment) in attachments.iter().enumerate() {
        content_types.push(
            content_type_essence(&attachment.content_type).ok_or_else(|| {
                GatewayError::BadRequest(format!(
                    "invalid `attachments[{index}].content_type`: expected a MIME type like \
                 \"application/pdf\""
                ))
            })?,
        );
        let size = decoded_len(&attachment.content_base64).ok_or_else(|| invalid_base64(index))?;
        total = total.saturating_add(size);
    }
    if total > limits.max_total_bytes {
        return Err(GatewayError::BadRequest(format!(
            "attachments too large: {total} bytes decoded in total, at most {} allowed",
            limits.max_total_bytes
        )));
    }

    attachments
        .into_iter()
        .zip(content_types)
        .enumerate()
        .map(|(index, (attachment, content_type))| {
            Ok(OutgoingAttachment {
                bytes: decode_base64(&attachment.content_base64)
                    .ok_or_else(|| invalid_base64(index))?,
                filename: sanitize_filename(&attachment.filename),
                content_type,
            })
        })
        .collect()
}

fn invalid_base64(index: usize) -> GatewayError {
    GatewayError::BadRequest(format!(
        "invalid `attachments[{index}].content_base64`: not valid standard base64"
    ))
}

/// The exact decoded length of a base64 string, from its length alone — no
/// allocation, no decoding. `None` when the length cannot be that of padded
/// standard base64 (the full decode would reject it anyway).
fn decoded_len(encoded: &str) -> Option<usize> {
    let mut chars = 0usize;
    let mut padding = 0usize;
    for byte in encoded.bytes().filter(|b| !b.is_ascii_whitespace()) {
        chars += 1;
        // Only trailing `=` count as padding; any other byte after one is invalid,
        // which the full decode catches. Here it just resets the tally.
        padding = if byte == b'=' { padding + 1 } else { 0 };
    }
    if !chars.is_multiple_of(4) || padding > 2 {
        return None;
    }
    Some(chars / 4 * 3 - padding)
}

/// Strict standard-alphabet base64 decode that tolerates ASCII whitespace (the line
/// breaks of a MIME-style wrapped encoding). The whitespace-free fast path decodes
/// in place without a filtered copy.
fn decode_base64(encoded: &str) -> Option<Vec<u8>> {
    let engine = base64::engine::general_purpose::STANDARD;
    if encoded.bytes().any(|b| b.is_ascii_whitespace()) {
        let compact: Vec<u8> = encoded
            .bytes()
            .filter(|b| !b.is_ascii_whitespace())
            .collect();
        engine.decode(compact).ok()
    } else {
        engine.decode(encoded).ok()
    }
}

/// Reduce a caller's `content_type` to a lowercase `type/subtype`, or `None` if it
/// isn't one.
///
/// This value lands verbatim in a MIME `Content-Type` header, so it is held to the
/// RFC 2045 `token` grammar: no whitespace, no control characters (so no CR/LF
/// header injection), no tspecials. `;` parameters are accepted but dropped — the
/// bytes go out base64-encoded, so a `charset` changes nothing about what arrives.
/// `multipart/*` is refused: a multipart part needs a boundary this gateway never
/// writes, and would render as a corrupt message.
fn content_type_essence(raw: &str) -> Option<String> {
    if raw.chars().any(char::is_control) {
        return None;
    }
    let essence = raw.split(';').next().unwrap_or_default().trim();
    let (kind, subtype) = essence.split_once('/')?;
    let is_token = |part: &str| {
        !part.is_empty()
            && part
                .bytes()
                .all(|b| b.is_ascii_graphic() && !b"()<>@,;:\\\"/[]?=".contains(&b))
    };
    if !is_token(kind) || !is_token(subtype) || kind.eq_ignore_ascii_case("multipart") {
        return None;
    }
    Some(format!(
        "{}/{}",
        kind.to_ascii_lowercase(),
        subtype.to_ascii_lowercase()
    ))
}

/// Make a caller's filename safe to send and to save.
///
/// Strips control characters (CR/LF included — mail-builder quotes the value, but
/// no header value of ours should ever carry one), Unicode bidi overrides (the
/// `invoice\u{202E}fdp.exe` → "invoiceexe.pdf" spoof), and path separators, so a
/// recipient's client can't be steered into a directory. Clamped to
/// [`MAX_FILENAME_CHARS`] by `char` — never a byte slice, so UTF-8 stays intact — and
/// replaced with [`FALLBACK_FILENAME`] if nothing meaningful is left.
fn sanitize_filename(raw: &str) -> String {
    let is_bidi_control = |c: char| {
        matches!(
            c,
            '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
        )
    };
    let cleaned: String = raw
        .chars()
        .filter(|&c| !c.is_control() && !is_bidi_control(c) && c != '/' && c != '\\')
        .collect();
    let clamped: String = cleaned.trim().chars().take(MAX_FILENAME_CHARS).collect();
    let name = clamped.trim_end();
    if name.is_empty() || name.chars().all(|c| c == '.') {
        FALLBACK_FILENAME.to_string()
    } else {
        name.to_string()
    }
}

/// The narrow, approval-facing disclosure of a send (SPEC §6): To / From / Subject,
/// a clamped Body preview, and each attachment's filename and size. Built from the
/// message, so it can only ever contain non-secret fields — never the `Basic` auth
/// header, the password, or an attachment's contents.
#[derive(Debug, Serialize, ToSchema)]
pub struct SendDisclosure {
    pub from: String,
    pub to: Vec<String>,
    pub subject: String,
    /// The body clamped to [`BODY_PREVIEW_LIMIT`] chars (with an ellipsis when
    /// truncated). Prefers the `text` part, falling back to `html`.
    pub body_preview: String,
    /// One entry per attachment: its (sanitized) filename and decoded size. Never
    /// the contents. Empty when nothing is attached.
    pub attachments: Vec<AttachmentDisclosure>,
}

/// What a disclosure reveals about one attachment: its name and size, nothing more.
#[derive(Debug, Serialize, ToSchema)]
pub struct AttachmentDisclosure {
    /// The sanitized filename, as the recipient will see it.
    #[schema(example = "invoice.pdf")]
    pub filename: String,
    /// The decoded size in bytes.
    #[schema(example = 48213)]
    pub size_bytes: usize,
}

impl SendDisclosure {
    /// Derive the disclosure from the outgoing message. The preview prefers the
    /// `text` part (falling back to `html`) and is clamped to [`BODY_PREVIEW_LIMIT`];
    /// attachments contribute only their filename and decoded size.
    pub fn for_message(message: &OutgoingMessage) -> Self {
        SendDisclosure {
            from: message.from.clone(),
            to: message.to.clone(),
            subject: message.subject.clone(),
            body_preview: clamp_preview(preview_source(&message.body)),
            attachments: message
                .attachments
                .iter()
                .map(|a| AttachmentDisclosure {
                    filename: a.filename.clone(),
                    size_bytes: a.bytes.len(),
                })
                .collect(),
        }
    }
}

/// The `POST /email/send` success response: an acknowledgement plus the disclosure.
#[derive(Debug, Serialize, ToSchema)]
pub struct SendResponse {
    /// Always `true` on this path — the provider accepted the message (SMTP `250`).
    #[schema(example = true)]
    pub sent: bool,
    /// The To/From/Subject/body-preview disclosure (SPEC §6).
    pub disclosure: SendDisclosure,
}

impl SendResponse {
    /// Wrap a disclosure in an accepted (`sent: true`) response.
    pub fn accepted(disclosure: SendDisclosure) -> Self {
        SendResponse {
            sent: true,
            disclosure,
        }
    }
}

/// The body part shown in the disclosure preview: the `text` part when present,
/// otherwise the `html` part.
fn preview_source(body: &OutgoingBody) -> &str {
    match body {
        OutgoingBody::Text(text) => text,
        OutgoingBody::Html(html) => html,
        OutgoingBody::Both { text, .. } => text,
    }
}

/// Clamp a body to [`BODY_PREVIEW_LIMIT`] characters, appending an ellipsis when it
/// was truncated. Counts `char`s (not bytes) so multi-byte characters stay intact.
fn clamp_preview(body: &str) -> String {
    let mut preview: String = body.chars().take(BODY_PREVIEW_LIMIT).collect();
    if body.chars().nth(BODY_PREVIEW_LIMIT).is_some() {
        preview.push('…');
    }
    preview
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> SendRequest {
        SendRequest {
            from: "sender@localhost".to_string(),
            to: vec!["alice@localhost".to_string()],
            cc: vec![],
            bcc: vec![],
            subject: "Hi".to_string(),
            text: Some("plain body".to_string()),
            html: None,
            attachments: vec![],
        }
    }

    #[test]
    fn into_message_maps_body_variants() {
        let mut r = request();
        r.text = Some("t".to_string());
        r.html = None;
        assert!(matches!(
            r.into_message(&AttachmentLimits::default()).unwrap().body,
            OutgoingBody::Text(_)
        ));

        let mut r = request();
        r.text = None;
        r.html = Some("<p>h</p>".to_string());
        assert!(matches!(
            r.into_message(&AttachmentLimits::default()).unwrap().body,
            OutgoingBody::Html(_)
        ));

        let mut r = request();
        r.text = Some("t".to_string());
        r.html = Some("<p>h</p>".to_string());
        assert!(matches!(
            r.into_message(&AttachmentLimits::default()).unwrap().body,
            OutgoingBody::Both { .. }
        ));
    }

    #[test]
    fn into_message_requires_a_body() {
        let mut r = request();
        r.text = None;
        r.html = None;
        assert_eq!(
            r.into_message(&AttachmentLimits::default())
                .unwrap_err()
                .code(),
            "bad_request"
        );
    }

    #[test]
    fn into_message_requires_a_recipient() {
        let mut r = request();
        r.to = vec![];
        assert_eq!(
            r.into_message(&AttachmentLimits::default())
                .unwrap_err()
                .code(),
            "bad_request"
        );
    }

    fn parse(json: &str) -> SendRequest {
        serde_json::from_str(json).expect("request parses")
    }

    #[test]
    fn recipients_accept_a_bare_string() {
        let r = parse(r#"{"from":"a@x","to":"b@y","subject":"s","text":"t"}"#);
        assert_eq!(r.to, vec!["b@y"]);
    }

    #[test]
    fn a_recipient_string_splits_on_commas_and_trims() {
        let r = parse(r#"{"from":"a@x","to":"b@y , c@z","subject":"s","text":"t"}"#);
        assert_eq!(r.to, vec!["b@y", "c@z"]);
    }

    #[test]
    fn recipients_still_accept_an_array_verbatim() {
        let r = parse(r#"{"from":"a@x","to":["b@y","c@z"],"subject":"s","text":"t"}"#);
        assert_eq!(r.to, vec!["b@y", "c@z"]);
    }

    #[test]
    fn an_empty_recipient_string_is_a_bad_request_not_a_parse_error() {
        let r = parse(r#"{"from":"a@x","to":" , ","subject":"s","text":"t"}"#);
        assert!(r.to.is_empty());
        assert_eq!(
            r.into_message(&AttachmentLimits::default())
                .unwrap_err()
                .code(),
            "bad_request"
        );
    }

    #[test]
    fn cc_and_bcc_take_strings_and_still_default_to_empty() {
        let r = parse(r#"{"from":"a@x","to":"b@y","subject":"s","text":"t"}"#);
        assert!(r.cc.is_empty() && r.bcc.is_empty());

        let r = parse(
            r#"{"from":"a@x","to":"b@y","cc":"c@z, d@z","bcc":"blind@z","subject":"s","text":"t"}"#,
        );
        assert_eq!(r.cc, vec!["c@z", "d@z"]);
        assert_eq!(r.bcc, vec!["blind@z"]);
    }

    #[test]
    fn into_message_carries_bcc_through() {
        let mut r = request();
        r.bcc = vec!["blind@localhost".to_string()];
        assert_eq!(
            r.into_message(&AttachmentLimits::default()).unwrap().bcc,
            vec!["blind@localhost"]
        );
    }

    fn b64(bytes: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    fn attachment(filename: &str, content_type: &str, content_base64: &str) -> Attachment {
        Attachment {
            filename: filename.to_string(),
            content_type: content_type.to_string(),
            content_base64: content_base64.to_string(),
        }
    }

    fn with_attachments(attachments: Vec<Attachment>) -> SendRequest {
        SendRequest {
            attachments,
            ..request()
        }
    }

    /// The `bad_request` message a request's attachments are rejected with.
    fn rejection(request: SendRequest, limits: &AttachmentLimits) -> String {
        let err = request
            .into_message(limits)
            .expect_err("attachments should be rejected");
        assert_eq!(err.code(), "bad_request", "{err}");
        err.message().to_string()
    }

    #[test]
    fn no_attachments_leaves_the_message_unchanged() {
        let r = parse(r#"{"from":"a@x","to":"b@y","subject":"s","text":"t"}"#);
        assert!(r.attachments.is_empty(), "attachments default to empty");
        let message = r.into_message(&AttachmentLimits::default()).unwrap();
        assert!(message.attachments.is_empty());
        assert!(SendDisclosure::for_message(&message).attachments.is_empty());
    }

    #[test]
    fn attachments_parse_from_the_wire_shape_and_decode() {
        let r = parse(
            r#"{"from":"a@x","to":"b@y","subject":"s","text":"t","attachments":[
                {"filename":"hello.txt","content_type":"text/plain","content_base64":"aGVsbG8="}
            ]}"#,
        );
        let message = r.into_message(&AttachmentLimits::default()).unwrap();
        let [a] = &message.attachments[..] else {
            panic!("one attachment expected: {:?}", message.attachments)
        };
        assert_eq!(a.filename, "hello.txt");
        assert_eq!(a.content_type, "text/plain");
        assert_eq!(a.bytes, b"hello");
    }

    #[test]
    fn base64_tolerates_whitespace_and_line_breaks() {
        let bytes: Vec<u8> = (0..=255u8).collect();
        let wrapped = b64(&bytes)
            .as_bytes()
            .chunks(76)
            .map(|line| std::str::from_utf8(line).unwrap())
            .collect::<Vec<_>>()
            .join("\r\n");
        let r = with_attachments(vec![attachment(
            "a.bin",
            "application/octet-stream",
            &format!(" {wrapped}\n"),
        )]);
        let message = r.into_message(&AttachmentLimits::default()).unwrap();
        assert_eq!(message.attachments[0].bytes, bytes);
    }

    #[test]
    fn bad_base64_is_rejected_without_echoing_content() {
        for bad in [
            "aGVsbG8",      // missing padding
            "aGVs*G8=",     // not in the alphabet
            "aGVsbG8-",     // URL-safe alphabet
            "aGVsbG8=aGVs", // data after padding
            "aGVsbG9=",     // non-canonical trailing bits
            "a===",
        ] {
            let message = rejection(
                with_attachments(vec![attachment("a.txt", "text/plain", bad)]),
                &AttachmentLimits::default(),
            );
            assert!(
                message.contains("attachments[0].content_base64"),
                "{message}"
            );
            assert!(!message.contains(bad), "content echoed: {message}");
        }
    }

    #[test]
    fn more_than_the_count_cap_is_rejected() {
        let many = (0..=MAX_ATTACHMENTS)
            .map(|i| attachment(&format!("{i}.txt"), "text/plain", "aGk="))
            .collect();
        let message = rejection(with_attachments(many), &AttachmentLimits::default());
        assert!(message.contains("too many attachments"), "{message}");

        let at_cap = (0..MAX_ATTACHMENTS)
            .map(|i| attachment(&format!("{i}.txt"), "text/plain", "aGk="))
            .collect();
        assert!(with_attachments(at_cap)
            .into_message(&AttachmentLimits::default())
            .is_ok());
    }

    #[test]
    fn over_the_byte_cap_is_rejected_from_the_encoded_length() {
        let limits = AttachmentLimits::with_max_total_bytes(10);
        // 6 + 6 = 12 decoded bytes > 10, split over two attachments so the cap is
        // checked on the total, not per file.
        let message = rejection(
            with_attachments(vec![
                attachment("a", "text/plain", &b64(b"abcdef")),
                attachment("b", "text/plain", &b64(b"ghijkl")),
            ]),
            &limits,
        );
        assert!(message.contains("attachments too large"), "{message}");
        assert!(message.contains("12 bytes"), "{message}");

        // Exactly at the cap is fine.
        assert!(
            with_attachments(vec![attachment("a", "text/plain", &b64(b"abcdefghij"))])
                .into_message(&limits)
                .is_ok()
        );
    }

    #[test]
    fn the_byte_cap_is_enforced_before_any_decoding() {
        // The oversized payload is invalid base64 *and* comes after a second, invalid
        // one. If anything were decoded first we'd see a base64 error; the size check
        // must win, proving it ran on the encoded length alone.
        let limits = AttachmentLimits::with_max_total_bytes(3);
        let message = rejection(
            with_attachments(vec![
                attachment("a", "text/plain", "!!!!"),
                attachment("b", "text/plain", "!!!!!!!!"),
            ]),
            &limits,
        );
        assert!(message.contains("attachments too large"), "{message}");
    }

    #[test]
    fn decoded_len_matches_the_real_decode() {
        for n in 0..40 {
            let bytes = vec![0xA5u8; n];
            let encoded = b64(&bytes);
            assert_eq!(decoded_len(&encoded), Some(n), "{encoded}");
            assert_eq!(decoded_len(&format!("{encoded}\r\n ")), Some(n));
        }
        assert_eq!(decoded_len("abc"), None, "length not a multiple of 4");
        assert_eq!(decoded_len("a==="), None, "three padding chars");
    }

    #[test]
    fn crlf_injection_in_a_filename_is_sanitized() {
        let r = with_attachments(vec![attachment(
            "evil.txt\r\nBcc: victim@example.com\r\n",
            "text/plain",
            "aGk=",
        )]);
        let message = r.into_message(&AttachmentLimits::default()).unwrap();
        let name = &message.attachments[0].filename;
        assert!(!name.contains('\r') && !name.contains('\n'), "{name:?}");
        assert_eq!(name, "evil.txtBcc: victim@example.com");
    }

    #[test]
    fn filenames_lose_paths_controls_and_bidi_and_are_clamped() {
        assert_eq!(sanitize_filename("../../etc/passwd"), "....etcpasswd");
        assert_eq!(sanitize_filename("C:\\Users\\x.doc"), "C:Usersx.doc");
        assert_eq!(sanitize_filename("a\u{0}b\tc"), "abc");
        assert_eq!(
            sanitize_filename("invoice\u{202E}fdp.exe"),
            "invoicefdp.exe"
        );
        assert_eq!(sanitize_filename("  report.pdf  "), "report.pdf");

        for empty in ["", "   ", "\r\n", "/", "..", "./"] {
            assert_eq!(sanitize_filename(empty), "attachment", "{empty:?}");
        }

        // Clamped by chars, so a multi-byte name is never cut mid-character.
        let long = "é".repeat(MAX_FILENAME_CHARS + 20);
        let clamped = sanitize_filename(&long);
        assert_eq!(clamped.chars().count(), MAX_FILENAME_CHARS);
        assert!(clamped.chars().all(|c| c == 'é'));
    }

    #[test]
    fn content_type_must_be_a_bare_type_subtype() {
        assert_eq!(
            content_type_essence("application/pdf").as_deref(),
            Some("application/pdf")
        );
        assert_eq!(
            content_type_essence(" Text/Plain ").as_deref(),
            Some("text/plain")
        );
        assert_eq!(
            content_type_essence("text/plain; charset=utf-8").as_deref(),
            Some("text/plain"),
            "parameters are dropped"
        );
        assert_eq!(
            content_type_essence(
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            )
            .as_deref(),
            Some("application/vnd.openxmlformats-officedocument.wordprocessingml.document")
        );

        for bad in [
            "",
            "pdf",
            "application/",
            "/pdf",
            "text/plain\r\nBcc: victim@example.com",
            "text/plain\nX-Evil: 1",
            "text/pl ain",
            "text/plain/extra",
            "text/\"plain\"",
            "multipart/mixed",
        ] {
            assert_eq!(content_type_essence(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn a_bad_content_type_is_a_bad_request() {
        let message = rejection(
            with_attachments(vec![attachment("a.txt", "text/plain\r\nBcc: x@y", "aGk=")]),
            &AttachmentLimits::default(),
        );
        assert!(message.contains("attachments[0].content_type"), "{message}");
        assert!(!message.contains("Bcc"), "content type echoed: {message}");
    }

    #[test]
    fn disclosure_lists_attachment_names_and_sizes_but_never_contents() {
        let message = with_attachments(vec![
            attachment("a/b.txt", "text/plain", &b64(b"SECRET-PAYLOAD")),
            attachment("c.bin", "application/octet-stream", &b64(&[0u8; 1000])),
        ])
        .into_message(&AttachmentLimits::default())
        .unwrap();

        let disclosure = SendDisclosure::for_message(&message);
        let summary: Vec<(&str, usize)> = disclosure
            .attachments
            .iter()
            .map(|a| (a.filename.as_str(), a.size_bytes))
            .collect();
        assert_eq!(summary, vec![("ab.txt", 14), ("c.bin", 1000)]);

        let json = serde_json::to_string(&disclosure).unwrap();
        assert!(!json.contains("SECRET-PAYLOAD"), "{json}");
        assert!(!json.contains(&b64(b"SECRET-PAYLOAD")), "{json}");
    }

    #[test]
    fn attachment_debug_never_prints_contents() {
        let rendered = format!("{:?}", attachment("a.txt", "text/plain", "U0VDUkVU"));
        assert!(!rendered.contains("U0VDUkVU"), "{rendered}");
    }

    #[test]
    fn disclosure_prefers_text_and_exposes_only_to_from_subject() {
        let message = SendRequest {
            from: "sender@localhost".to_string(),
            to: vec!["alice@localhost".to_string()],
            cc: vec!["carol@localhost".to_string()],
            bcc: vec!["blind@localhost".to_string()],
            subject: "Subject line".to_string(),
            text: Some("the text part".to_string()),
            html: Some("the html part".to_string()),
            attachments: vec![],
        }
        .into_message(&AttachmentLimits::default())
        .unwrap();

        let disclosure = SendDisclosure::for_message(&message);
        assert_eq!(disclosure.from, "sender@localhost");
        assert_eq!(disclosure.to, vec!["alice@localhost"]);
        assert_eq!(disclosure.subject, "Subject line");
        assert_eq!(disclosure.body_preview, "the text part");

        // Cc/Bcc must not leak into the approval surface.
        let json = serde_json::to_string(&disclosure).unwrap();
        assert!(!json.contains("carol@localhost"), "cc leaked: {json}");
        assert!(!json.contains("blind@localhost"), "bcc leaked: {json}");
    }

    #[test]
    fn disclosure_falls_back_to_html_when_no_text() {
        let message = SendRequest {
            html: Some("<p>only html</p>".to_string()),
            text: None,
            ..request()
        }
        .into_message(&AttachmentLimits::default())
        .unwrap();
        assert_eq!(
            SendDisclosure::for_message(&message).body_preview,
            "<p>only html</p>"
        );
    }

    #[test]
    fn preview_is_clamped_with_ellipsis_when_over_limit() {
        let long = "a".repeat(BODY_PREVIEW_LIMIT + 50);
        let preview = clamp_preview(&long);
        assert_eq!(preview.chars().count(), BODY_PREVIEW_LIMIT + 1, "clamp + …");
        assert!(preview.ends_with('…'));
    }

    #[test]
    fn preview_at_limit_is_not_marked_truncated() {
        let exact = "b".repeat(BODY_PREVIEW_LIMIT);
        let preview = clamp_preview(&exact);
        assert_eq!(preview, exact);
        assert!(!preview.ends_with('…'));
    }

    #[test]
    fn preview_clamp_respects_char_boundaries() {
        // Multi-byte characters must never be split by the clamp.
        let body = "é".repeat(BODY_PREVIEW_LIMIT + 10);
        let preview = clamp_preview(&body);
        assert_eq!(preview.chars().count(), BODY_PREVIEW_LIMIT + 1);
        assert!(preview.starts_with('é'));
    }
}
