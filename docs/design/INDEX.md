# overfwd Design Documents

Design documents for **overfwd**, the open-source Mailbox Gateway (`overspiral/overfwd`).
Migrated from the Overslash design workspace, where the gateway was scoped as an Overslash
integration effort before being split into this standalone MIT-licensed project.

> The live product spec is at [SPEC.md](../../SPEC.md). These design docs capture the
> original planning, the decisions taken, and the alternatives considered.

---

| Document | Status | Summary |
|----------|--------|---------|
| [email-integration.md](email-integration.md) | Draft — design settled | The originating design: email **send** + on-demand **read/search** across the standard-IMAP long tail via overfwd, a MIT OSS Mailbox Gateway presenting a REST facade over IMAP/SMTP. Zero-persistence Inline mode (credential-free, bring-your-own-secrets), optional Portfolio/Session modes, ephemeral in-memory connection pooling. Explicitly not Gmail/Outlook (those stay on native REST). Own-inbox and real-time inbound deferred. Captures the settled decisions, the Overslash-side integration requirements, and the disruptor thesis vs EmailEngine / Nylas / Unipile. |
