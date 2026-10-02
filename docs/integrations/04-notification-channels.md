# Notification channels: Slack, Microsoft Teams, Email, Webhook

Notification channels send readiness alerts out of AstraNull. A channel only receives redacted event summaries. It never gets access to customer infrastructure, and connecting one does not require any cloud credentials.

- UI: `NotificationChannelsPanel` (`apps/web/react/src/components/integrations/notification-channels.tsx`)
- Pure helpers: `apps/web/react/src/lib/notification-channels.mjs`
- API client: `apps/web/react/src/lib/notification-channels-api.ts`
- Backend: `src/lib/notifications.mjs` (rules) and `src/lib/notificationDelivery.mjs` (delivery adapters)

## Who can do what

| Action | Permission | Roles |
|---|---|---|
| View channels and the delivery ledger | `notification:read` | owner, admin, engineer, soc, auditor |
| Connect a channel | `notification:write` | owner, admin |
| Turn a channel on or off, edit its events or replace its destination | `notification:write` | owner, admin |
| Remove a channel | `notification:write` | owner, admin |

Read-only roles see the channel cards with the Connect buttons disabled, and the per-row Turn on/off, Edit, and Remove actions are disabled for them too.

### Managing a connected channel

- **Turn off / Turn on** sends `PATCH /v1/notifications/:id` with `{ enabled }`. A disabled rule emits nothing.
- **Edit** changes the events and, optionally, the destination. The current destination is a secret and is never shown back, so leaving the field blank keeps it. A new destination goes through the same validation as a new connection: https only, no `user:password@`, one email address.
- **Remove** asks for confirmation, then sends `DELETE /v1/notifications/:id`. Removal is a soft delete. The rule disappears from the panel, the stored destination is cleared, and the rule never emits, retries, or redrives again. Its delivery history stays in the ledger.

Errors from any action appear in an alert banner above the table. Only the redacted `destination_preview` is ever returned. Roles that don't have `notification:read` see a role-restricted notice instead of the panel.

## Events

| Trigger | Fires when | Default |
|---|---|---|
| `finding.high_severity` | A new high or critical finding is recorded | on |
| `high_scale.state_change` | A SOC-governed high-scale request changes state | on |
| `safe_test.completed` | A safe validation run reaches a verdict | off |
| `report.ready` | A readiness report is generated | off |

Emitters: `finding.high_severity` fires from finding creation (dev store) and from the Postgres run-terminal hook for newly created high/critical findings. `safe_test.completed` fires from the run-terminal hook on `verdicted` runs. `report.ready` fires after `POST /v1/reports`. The dev finding-creation emitter, the run-terminal hook, and `report.ready` record an event only for tenants with an enabled rule on that trigger. Two dev-store emitters still record without that check: WAF drift `finding.high_severity` (`src/services/wafPosture.mjs`) and `high_scale.state_change` (`src/services/highScale.mjs`); such events carry zero delivery attempts and send nothing.

In Postgres the run-terminal hook and `report.ready` use a durable outbox (migration `0060_notification_event_outbox.sql`): the event and its pending attempts commit once per trigger identity (`safe_test.completed:run:<id>`, `finding.high_severity:finding:<id>:verdict:<verdict_id>`, `report.ready:report:<id>`) before any provider send, so a replay, a second API instance, or a crash cannot drop or duplicate the event. Provider delivery runs off the run/report critical path in a bounded in-process worker, which gets the first 5 minutes to send. After that the retry scheduler picks up anything unfinished. Every sender claims the attempt with a Postgres lease first, so the same attempt is never sent by two workers at once. Each recovery tick also re-enqueues notifications whose initial enqueue failed after the report or run committed ([ADR-0010](../adr/0010-notification-delivery-leases-and-outbox-reconciliation.md)). A turned-off rule's pending work is held until it is turned back on; a removed rule's pending work is cancelled.

## Setup per channel

### Slack (incoming webhook)

1. Open api.slack.com/apps and choose Create New App, then From scratch. Pick your workspace.
2. Under Features, open Incoming Webhooks and turn on Activate Incoming Webhooks.
3. Select Add New Webhook to Workspace, pick the alert channel, and select Authorize.
4. Copy the URL (`https://hooks.slack.com/services/T…/B…/…`) and paste it into Connect Slack.

The URL is a secret. Slack revokes webhook URLs it finds published online. The UI warns, but still accepts, URLs that are not on `hooks.slack.com` or `hooks.slack-gov.com` under `/services/`.

Reference: https://docs.slack.dev/messaging/sending-messages-using-incoming-webhooks/

### Microsoft Teams (Workflows webhook)

Microsoft is retiring Microsoft 365 (Office 365) connectors, so use the Workflows app.

1. In Teams, open the target channel, select More options (…), then Workflows.
2. Choose the template Send webhook alerts to a channel.
3. Confirm the team and channel, then select Save.
4. Copy the webhook URL shown after the workflow is created, and paste it into Connect Microsoft Teams.

Notes:

- A workflow is owned by the user who created it. Add a co-owner so alerts keep flowing if that person leaves.
- Teams limits messages to 28 KB and throttles senders above 4 requests per second.
- Posting to private channels through Workflows has limited support.
- The UI warns on legacy connector URLs (`*.webhook.office.com`, `outlook.office.com`).

References:

- https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook
- https://support.microsoft.com/en-us/office/send-messages-in-teams-using-incoming-webhooks-323660ec-12ca-40b1-a1d3-a3df47e808c4

### Email (SMTP)

1. Choose a shared mailbox or distribution list your on-call team reads.
2. Enter one address per channel.
3. Have your mail admin allowlist the sender (`ASTRANULL_SMTP_FROM`) so alerts are not filtered as spam.

### Webhook (HTTPS POST)

1. Expose an HTTPS endpoint that accepts `POST` with `Content-Type: application/json`.
2. Return any `2xx` within 10 seconds. Redirects are not followed and count as failures.
3. Requests are not signed yet. Use a long, unguessable path segment, restrict the endpoint by network policy where you can, and de-duplicate on `event_id`.

## Validation

The UI mirrors the backend and is slightly stricter, so it never saves a rule that delivery would later reject.

| Check | UI | Backend |
|---|---|---|
| Destination required | yes | `missing_destination` (400) |
| `https://` only (http allowed for `localhost`, `127.0.0.1`, `*.invalid`) | webhook, Slack, Teams | rule creation (`invalid_webhook_destination`) and delivery precheck |
| No `user:password@` in URLs | yes | rule creation and delivery precheck (`webhook_url_credentials_not_allowed`) |
| No whitespace or control characters, max 2048 chars | yes | `invalid_destination` (400) |
| Single email address | yes | `invalid_email_destination` (400) |
| Slack/Teams: `https://`, no `user:password@` | yes | `invalid_webhook_destination` / `webhook_url_credentials_not_allowed` (400) |

As defense in depth, the SMTP adapter also refuses any envelope field containing CR/LF (`smtp_envelope_invalid`) and folds line breaks out of the subject.
| At least one known trigger | yes | `invalid_trigger` (400) |

## Payloads

Every payload is built from the redacted event: `trigger`, `subject`, `metadata`, `created_at`. Example payloads for each channel appear under "Example payload" in the Connect dialog.

Webhook body (max 32 KB):

```json
{
  "event_id": "nevt_example",
  "rule_id": "nrule_example",
  "trigger": "finding.high_severity",
  "subject": "High-severity finding on api.example.com",
  "metadata": { "target": "api.example.com", "severity": "high" },
  "created_at": "<ISO-8601 timestamp>"
}
```

- Slack: Block Kit message with a section for trigger and subject, a context block with the time, and a metadata section.
- Teams: `type: message` with one Adaptive Card 1.4 attachment. A View in AstraNull `Action.OpenUrl` is added only when `ASTRANULL_PORTAL_URL` (or `ASTRANULL_PUBLIC_BASE_URL`) is an https URL.
- Email: HTML table with Trigger, Subject, Metadata, and Timestamp rows. Subject is `[AstraNull] <subject>`.

Slack payloads are capped at 64 KB. Teams payloads are capped at 28 KB, matching the Teams message limit; larger cards go straight to the dead-letter queue with `provider_payload_too_large`.

## Delivery modes

Outbound delivery is opt-in on the server. By default, every external channel records `queued_provider_not_configured` in the delivery ledger and nothing is sent.

| Variable | Purpose |
|---|---|
| `ASTRANULL_NOTIFICATION_DELIVERY_MODE` | `metadata_only` (default), `webhook`, `email`, `slack`, `teams`, `all`, or a comma-separated list such as `slack,teams` |
| `ASTRANULL_SMTP_HOST` | SMTP relay. If unset, email stays `queued_provider_not_configured`. |
| `ASTRANULL_SMTP_PORT` | Default `587` |
| `ASTRANULL_SMTP_STARTTLS` | Default on; set `false` only for a trusted local relay |
| `ASTRANULL_SMTP_USERNAME` / `ASTRANULL_SMTP_PASSWORD` | Relay credentials (operator-side only) |
| `ASTRANULL_SMTP_FROM` | Sender address |
| `ASTRANULL_PORTAL_URL` | Optional https portal base URL used for the Teams card link |

Each send has a 10 second timeout and up to 3 attempts, with retries scheduled 60 seconds apart. After the last failed attempt, the event goes to the dead-letter queue.

## Delivery status in the UI

| Ledger status | UI label |
|---|---|
| `delivered_provider` | Delivered |
| `delivered_in_app` | In-app feed |
| `queued_provider_not_configured` | Recorded, not sent |
| `provider_retry_scheduled` | Retry scheduled |
| `provider_failed_dlq` | Failed |
| server reports no attempt for the rule | No deliveries yet |
| server did not report a latest delivery (older API), and none in the loaded events | None in recent history |

Last delivery comes from `latest_deliveries` in `GET /v1/notifications`. The server computes it over the full delivery history for each rule, so a rule that has been quiet while other rules were busy still shows its real last delivery. The events feed holds only the 100 most recent events (`events_window`). When the server does not provide `latest_deliveries`, the panel says the attempt is missing from the loaded events and does not claim nothing has ever fired.

Refresh is disabled and shows a spinner while a reload is in flight. Overlapping loads resolve latest-request-wins: an older response, or a response fetched for a previous session, is discarded rather than overwriting newer channel state.

The backend has no "send test" endpoint, so the panel does not offer one. To check a channel end to end, enable its delivery mode on a staging server and trigger a real event.

## Security and privacy

- Destinations are stored server-side. Reads return only `destination_preview` (for example `webhook://hooks.example.com…`, `email:a…@example.com`, `slack://hooks.slack.com…`, `teams://<host>…`). The UI never renders a full URL or address after submission.
- Event payloads are redacted before they are stored and before they are sent.
- No HMAC signing for webhooks yet (see open items).
- Rule creation, update (`notification.rule_updated`), and removal (`notification.rule_deleted`) are audit-logged under `notification:write`. Update metadata lists the changed fields and whether the destination changed, never the destination itself.
- Each new rule returns a `delivery_note` derived from the server's current delivery mode, so the UI never claims a channel is silent when delivery is enabled (or the reverse).

## API

See [`docs/api.md`](../api.md#notifications): `GET /v1/notifications`, `POST /v1/notifications`, `PATCH /v1/notifications/:id`, `DELETE /v1/notifications/:id`, `POST /v1/notifications/provider-credentials`, `POST /v1/notifications/retries/process`, `POST /v1/notifications/dlq/redrive`.

## Brand marks

- Slack mark: Slack brand guidelines, used only to identify the Slack integration.
- Microsoft Teams icon: the Microsoft Fluent UI brand icon (`teams_48x1.svg` from the Office CDN), used under the Microsoft Fabric Assets License, section 1(b), to show that AstraNull integrates with Microsoft Teams. Colors are reproduced as OKLCH tokens scoped to `.channel-logo`.
- Email and Webhook use the lucide `Mail` and `Webhook` glyphs (ISC license).

## Open items

- No test-send endpoint for rules.
- No webhook request signing.
- Brand mark attributions live in `THIRD_PARTY_NOTICES/provider-logos-NOTICE.txt`.
