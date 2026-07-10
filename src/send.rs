//! The `send` action's request/response shapes and disclosure surface (SPEC §6).
//!
//! This module holds the pure, HTTP-adjacent logic of `POST /email/send`: the JSON
//! request schema, validation into the SMTP module's typed [`OutgoingMessage`], and
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

use serde::{Deserialize, Serialize};

use crate::error::GatewayError;
use crate::smtp::{OutgoingBody, OutgoingMessage};

/// Maximum number of characters retained in the disclosed body preview (SPEC §6
/// "clamped Body"). Counted in `char`s, so the clamp never splits a UTF-8 boundary.
pub const BODY_PREVIEW_LIMIT: usize = 256;

/// The `POST /email/send` JSON request body (SPEC §6).
///
/// `cc`/`bcc` default to empty and `text`/`html` are optional, but at least one of
/// `text`/`html` must be present and `to` must be non-empty — enforced by
/// [`SendRequest::into_message`], not by serde.
#[derive(Debug, Deserialize)]
pub struct SendRequest {
    /// Envelope + header `From`.
    pub from: String,
    /// Primary recipients (`To`). Must be non-empty.
    pub to: Vec<String>,
    /// Carbon-copy recipients (`Cc`).
    #[serde(default)]
    pub cc: Vec<String>,
    /// Blind-carbon-copy recipients (`Bcc`) — delivered but never written to a header.
    #[serde(default)]
    pub bcc: Vec<String>,
    /// The `Subject` header.
    pub subject: String,
    /// A `text/plain` body.
    #[serde(default)]
    pub text: Option<String>,
    /// A `text/html` body.
    #[serde(default)]
    pub html: Option<String>,
}

impl SendRequest {
    /// Validate the request and turn it into the SMTP module's [`OutgoingMessage`].
    ///
    /// Fails with [`GatewayError::BadRequest`] when `to` is empty or when neither
    /// `text` nor `html` is supplied (the body enum makes "no body" unrepresentable
    /// downstream, so the check lives here).
    pub fn into_message(self) -> Result<OutgoingMessage, GatewayError> {
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

        Ok(OutgoingMessage {
            from: self.from,
            to: self.to,
            cc: self.cc,
            bcc: self.bcc,
            subject: self.subject,
            body,
        })
    }
}

/// The narrow, approval-facing disclosure of a send (SPEC §6): To / From / Subject
/// and a clamped Body preview. Built from the message, so it can only ever contain
/// non-secret fields — never the `Basic` auth header or the password.
#[derive(Debug, Serialize)]
pub struct SendDisclosure {
    pub from: String,
    pub to: Vec<String>,
    pub subject: String,
    pub body_preview: String,
}

impl SendDisclosure {
    /// Derive the disclosure from the outgoing message. The preview prefers the
    /// `text` part (falling back to `html`) and is clamped to [`BODY_PREVIEW_LIMIT`].
    pub fn for_message(message: &OutgoingMessage) -> Self {
        SendDisclosure {
            from: message.from.clone(),
            to: message.to.clone(),
            subject: message.subject.clone(),
            body_preview: clamp_preview(preview_source(&message.body)),
        }
    }
}

/// The `POST /email/send` success response: an acknowledgement plus the disclosure.
#[derive(Debug, Serialize)]
pub struct SendResponse {
    /// Always `true` on this path — the provider accepted the message (SMTP `250`).
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
        }
    }

    #[test]
    fn into_message_maps_body_variants() {
        let mut r = request();
        r.text = Some("t".to_string());
        r.html = None;
        assert!(matches!(
            r.into_message().unwrap().body,
            OutgoingBody::Text(_)
        ));

        let mut r = request();
        r.text = None;
        r.html = Some("<p>h</p>".to_string());
        assert!(matches!(
            r.into_message().unwrap().body,
            OutgoingBody::Html(_)
        ));

        let mut r = request();
        r.text = Some("t".to_string());
        r.html = Some("<p>h</p>".to_string());
        assert!(matches!(
            r.into_message().unwrap().body,
            OutgoingBody::Both { .. }
        ));
    }

    #[test]
    fn into_message_requires_a_body() {
        let mut r = request();
        r.text = None;
        r.html = None;
        assert_eq!(r.into_message().unwrap_err().code(), "bad_request");
    }

    #[test]
    fn into_message_requires_a_recipient() {
        let mut r = request();
        r.to = vec![];
        assert_eq!(r.into_message().unwrap_err().code(), "bad_request");
    }

    #[test]
    fn into_message_carries_bcc_through() {
        let mut r = request();
        r.bcc = vec!["blind@localhost".to_string()];
        assert_eq!(r.into_message().unwrap().bcc, vec!["blind@localhost"]);
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
        }
        .into_message()
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
        .into_message()
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
