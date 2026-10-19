# ADR-0036: Preserve recorded HTTP exchange values

Date: 2026-10-18
Status: Accepted for local implementation; not deployed

## Context

The user explicitly requested removal of HTTP exchange redaction and complete payload visibility. ADR-0030's value allowlist erased ordinary diagnostic headers, hid every URL query value, and withheld most useful HTML bodies. Additional ingestion and presentation filters discarded data again. A display-only change could not recover values already removed by the worker.

## Decision

1. Supersede ADR-0030 decision 4 for HTTP exchange activity. Record the observed header values, duplicate headers, URL query values, and consumed request/response bytes without credential, unknown-header, JSON-key, MIME-parameter or body-format redaction. Preserve the actual text rather than reformatting or substituting it. URL fragments are omitted because HTTP never sends them.
2. Retain full consumed bodies up to 1 MiB, matching the bounded HTTP transport's maximum response size. Do not issue additional requests, follow redirects, or drain a body the check did not consume. A HEAD/204/304 response may have an empty body; unconsumed, canceled, lost and over-limit captures remain explicit.
3. Send bodies larger than the inline sample as 8-KiB byte chunks in the existing authenticated activity channel. Each chunk carries the original exchange identity, a byte offset, and Base64-encoded bytes. `request_payload` is an additive stage; `request_payload_offset` and `response_payload_offset` are additive fields. Existing 32-KiB signed batches, 24-KiB normalized events and 256 ordinals per lease remain bounded. Input shape, original lease/tenant/worker identity, immutable replay and cancellation checks remain enforced. Dropped ordinals and chunk gaps never imply complete capture.
4. Reassemble only matching original job/lease/exchange chunks, in byte-offset order. Duplicate identical chunks are harmless; contradictory duplicates are capture conflicts. Decode complete valid UTF-8 only after reassembly, so a multibyte character crossing a chunk boundary survives. Binary content remains visible/copyable as Base64. Missing chunks or missing completion keep the body partial.
5. Render headers and bodies as React text, never HTML, scripts, links, frames or replay commands. Display and clipboard use the same complete recorded representation, with no second masking or 4-KiB display cutoff.
6. Preserve existing tenant access, event retention, audit, signed result provenance and readiness rules. HTTP activity remains observational telemetry, not verdict proof. No database migration is needed: chunks use the existing activity JSON/event storage. Other secret handling (worker credentials, account configuration, errors and unrelated evidence) is outside this change.
7. Historical redacted records remain unchanged. Their discarded values cannot be reconstructed; a new explicitly started check records new data. Deploy the accepting server before the emitting worker and portal.

## Verification

Owned loopback HTTP verifies an exact 64-KiB request and 1-MiB response through worker-size batches, normalization, stored-event projection, reassembly and clipboard formatting. Regression tests cover all header values/duplicates, query values, structured HTML/XML/multipart, binary data, UTF-8 chunk boundaries, missing/conflicting chunks and existing protocol identities. Browser checks cover literal HTML, copy, long payloads, responsive layouts and the connected signed-worker path. Current outcomes are recorded in PROGRESS.md.
