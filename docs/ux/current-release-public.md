# Current-release public pages

Status: **Candidate**, implemented locally on 2026-10-04. No human design approval or user research has happened yet (G1 approval and G3 study: not run). Scope comes from [current-release scope](../feedback/24-current-release-scope.md) and the page reviews for [landing](../feedback/landing.md), [login](../feedback/login.md), [signup](../feedback/signup.md), [signup-status](../feedback/signup-status.md), [set-password](../feedback/set-password.md) and [not-found](../feedback/not-found.md).

Source: `apps/web/react/src/pages/public-pages.tsx`, `apps/web/react/src/pages/public-landing.css`.
Tests: `tests/unit/current-release-public-ui.test.mjs`, `tests/e2e/journeys/current-release-public.spec.mjs`.

## Design read

The landing is a calm persuasion page for security and platform buyers. The access pages are tasks for people who want to get in quickly. Both use the existing AstraNull system: pure-black option A canvas, Space Grotesk, Inter and JetBrains Mono, orange as the only accent, hairline depth and the shared primitives. No tokens, fonts or shared components changed.

Dials: landing 5/4/4 (variance/motion/density), access tasks 3/3/5.

## Page decisions

### Landing (`/`)

- **Hero:** the value line, then a two-sentence lead. The first sentence states the product rules: "AstraNull checks customer-declared targets from outside your network, with no required cloud credentials and no automatic IP inventory discovery." The second covers the workflow. Then Request access and How a check works. On the right is an illustrative walkthrough (declare a target, prove ownership, run one bounded check, read the evidence), labeled **Example data** with the caption "Illustrative example with invented data. It is not a customer result." The host is `checkout.shop.example`, which uses a reserved domain.
- **Walkthrough:** advances only when you press it. It announces "Step n of 4" through a polite live region and adds no time-based motion. All content is visible before any interaction, so reduced motion loses nothing.
- **Verdict record:** the field names (`target_id`, `confidence`, `verdict`, `evidence_ids`, `reason_codes`) moved into a collapsed "Fields in every verdict record" disclosure. The hero no longer leads with the schema.
- **Removed:** the high-scale section, the SOC flow step, high-scale footer links and the high-scale comparison row. These belong to a deferred release.
- **Evidence limits:** the Boundaries section states them: "A passed check covers that check on that target. It does not certify protection or measure volumetric capacity."
- **Demo button:** renamed "Open demo workspace (sample data)". It only appears in `dev-headers` mode.
- **Intake closed:** when `signup_enabled` is false, Log in becomes the primary action and a note explains that intake is closed.

### Sign-in (`/login`) and recovery subflows

- **Layout:** one column with "Log in to AstraNull", one sentence specific to the auth mode, the form, then recovery links. On mobile the heading and form arrive first. The old marketing aside is gone.
- **Auth modes:**
  - Developer mode shows a warning that no password is checked.
  - The password lane has no role picker.
  - The staging bypass stays behind its disclosure.
  - OIDC redirect shows a manual "Continue to your identity provider" fallback.
  - SSO with no configured link explains itself and shows no form.
  - An `unknown` auth mode ("We could not confirm how this deployment signs people in.") offers Try again and shows no form.
- **Errors:**
  - Field errors are inline, linked with `aria-describedby`, and focus moves to the first field that needs attention.
  - Server errors go to a focused alert. Messages differ for invalid credentials (password cleared, email kept, reset link offered), lockout, rate limit, disabled account, invitation setup required, and network failure.
- **Return to intent (PUB-R01 fixed):** `?next=` and `?reason=` are read through `sanitizeReturnHash` and `resolveSafeReturnPath`. Only real non-staff route ids survive, and each route keeps only the parameters its page reads:

  | Route | Kept parameters |
  | --- | --- |
  | Every detail route | `id` (or `entity_id`, normalized to `id`); safe id `^[A-Za-z0-9_.:-]{1,128}$` |
  | `target-detail` | `tab` (lowercase slug), `check` (safe id) |
  | `check-detail` | `policy`, `target` (safe ids) |
  | `checks` | `target` (safe id) |
  | `finding-group-detail` | `key`, validated by `parseFindingGroupReturnKey` |
  | Any route | Evidence-inspector state, only via the shared `parseInspectorRef`/`buildEvidenceInspectorHref` schema |

  `parseFindingGroupReturnKey` accepts exactly the canonical `findingGroupKey` shape: two URI-encoded parts joined by `|`. Each part must decode and re-encode to itself. Parts are capped at 240 decoded characters and the whole key at 640, with no control characters. The check part must be a safe id. The issue part keeps the `v:`/`t:`/`f:`/`none` form and is refused if it looks like a credential (`pwi_`/`pwr_`, `bearer `, JWT-like).

  Everything else is dropped: free text, list filters, tokens, raw payloads, external URLs, `#admin` and unknown routes. Reasons `session_expired` and `signed_out` show a notice, plus "After you log in, you return to {label}" when a destination survives. After sign-in the portal's own route guard decides access, and a denied destination falls back through the existing notice.
- **Recovery request:** stays enumeration-safe. The existing copy "This response confirms neither condition." is kept.
- **Recovery reset:**
  - The token is read once and stripped from the URL.
  - When it came from a link, no token field is shown. A manual code field is masked (`type="password"`) and opted out of password managers.
  - `invalid_reset_token` and `reset_token_expired` end the flow with "Request a new link".
  - If the network fails mid-submit, the page says the outcome is uncertain.

### Set password (`/set-password`)

- **Token handling:** an invitation link fills the code and strips it from the address bar. The page shows "Invitation link detected." with no visible token. A manual code is a masked fallback that is only shown without a link.
- **Requirements:** live and checked against the server policy: at least 12 characters, and three of lowercase, uppercase, number and symbol. The email-name and common-password rules are stated as "Checked when you submit." Each item carries a screen-reader "Met" or "Not met yet" prefix, and the list is tied to the field with `aria-describedby`.
- **Password entry:** paste and password managers work (`autocomplete="new-password"`, no paste blocking). One Show/Hide control covers both fields.
- **Confirm field:** shows "Passwords do not match." on blur and on submit, linked to the field.
- **Outcomes:**
  - `weak_password` lists the server failures under the field.
  - `invite_expired` and `invalid_invite` end the flow and say no account was activated.
  - Success says "Your account is active." with the returned email, then offers Log in. No session is created.

### Request access (`/signup`)

- **Copy:** "Request access" throughout. The heading is "Request access to AstraNull." Two assurances: no credentials, agents or discovery, and submitting does not create an account or grant a plan.
- **Form:**
  - The high-scale interest checkbox is removed, which is deferred intake. The backend defaults it to false.
  - The plan carries "A request, not an entitlement" help, and the region carries data-location help.
  - Inline validation follows the backend's `validateSignupRequestInput` rules, and a unit test checks they agree.
  - Server `fields[]` are mapped back onto the matching fields. Answers are kept on every failure.
  - `duplicate_request` never shows the other request's `existing_id`.
- **Confirmation:**
  - Shows "Request received." with "No account exists yet."
  - The request ID has a Copy button with local, announced feedback, including a manual-copy fallback if the clipboard fails.
  - The ID stays in the address bar so the page can be bookmarked.
  - The lifecycle shows "Received" as the current step.
  - Check status opens the status page with the ID prefilled.
- **Failed reload:** a reload with an unknown `?id=` explains the failure and links to status. It no longer silently shows an empty form.

### Request status (`/signup-status`)

- **Lookup:** the query ID is trimmed and looked up automatically. Each successful lookup also writes the ID into the URL.
- **Errors:** three distinct cases. Not found is a field error ("IDs are case-sensitive"). Rate-limited and service-unavailable use an alert, keep the ID and offer Try again.
- **Lifecycle:** maps the backend states `submitted → under_review → approved → provisioned → customer_invited` to Received, Under review, Approved, Workspace created and Invitation issued. A final "Password set" step is shown but marked **Not tracked here**.
- **Next step:** every state answers whether you can sign in. Only `customer_invited` offers Log in. `rejected` shows the reviewer's `customer_notice` as "Message from AstraNull" with no timeline. Unknown states show "Recorded as {state}".
- **Dates and timing:** only `created_at` and `updated_at` are shown. There is no ETA or progress percentage.
- **Lost ID:** the help line shows `support_email`, `support_contact_email`, `contact_email`, `support_url` or `contact_url` from site config when one is published. Otherwise it truthfully says none is published.

### Unavailable routes (`PortalUnavailablePage`)

Exported for the foundation owner to wire into `router.tsx` and `App.tsx`:

| Kind | Title | Notes |
| --- | --- | --- |
| `not-found` | This page is unavailable. | No redirect; requested route shown without its query string. |
| `access-denied` | You do not have access to this page. | Names the page label and role; "Nothing from it was loaded." |
| `record-missing` | This record is not available. | Optional parent action; "No placeholder values are shown." |

Actions are a primary home or parent link, plus Go back when history exists. Identifiers are never echoed: `displayRequestedRoute` keeps only the route part of the hash.

## Integration requests (outside this ownership)

1. **`router.tsx`:** render `<PortalUnavailablePage kind="not-found" />` for `route === 'not-found'`. Missing-entity detail views can use `kind="record-missing"` with their parent list.
2. **`App.tsx` (access denial):** currently it swaps to the fallback route with an 8-second notice. A persistent `kind="access-denied"` page, with `requestedLabel` and `role`, would keep 403 distinct from a healthy dashboard.
3. **`App.tsx` (sign-in redirects):** in `goToLogin`, the boot redirect and the expiry redirect, build the destination with `buildLoginReturnUrl(loginUrl, { hash: window.location.hash, reason: 'session_expired' })`. Until then the login page's return-to-intent support is dormant but safe.
4. **`App.tsx` (status page):** pass `config` to `<SignupStatusPage config={config} />`. Without it the page fetches `/v1/public/site-config` itself.
5. **Backend (optional):** add a published support contact field to `getPublicSiteConfig` (for example `support_email` or `support_url`) if the deployment wants lost-ID recovery to name a channel.
6. **Build:** `apps/web/react-app.js` and `react-app.css` are tracked build output and were not rebuilt. The in-process Playwright server serves that bundle, so run `npm run web:build` before running the journey spec without `ASTRANULL_PUBLIC_UI_BASE_URL`.

## Verification

- **Unit tests:** `node --test tests/unit/current-release-public-ui.test.mjs` loads the real module through Vite SSR. It checks:
  - the route-scoped return-to-intent schema, including real `findingGroupKey`/`findingGroupHref` fixtures round-tripped through the sign-in URL, rejected non-canonical, oversized, control-character and credential-shaped keys, and inspector state only via the shared schema
  - lifecycle mapping for every backend state
  - password-requirement agreement with `assessPassword`
  - signup-validation agreement with `validateSignupRequestInput`
  - the support-contact allowlist
  - the three unavailable kinds
  - source safety: no storage, console or paste blocking; token stripping; no em dash; reduced motion
- **Journey spec:** `ASTRANULL_PUBLIC_UI_BASE_URL=<vite dev URL> npx playwright test tests/e2e/journeys/current-release-public.spec.mjs` has 16 journeys. Real API calls go to an isolated `ASTRANULL_DEV_DATA_DIR` with `ASTRANULL_NO_PERSIST=1`. Lanes the local server does not enable are fixtured with documented response codes. All credentials and tokens are synthetic, and no invitation is sent or consumed.
- **Evidence:** screenshots are outside the repo, in `/tmp/astranull-current-release-orchestration/public-evidence/`:
  - `before/` and `after/`: 6 pages × 2 themes × 375/768/1024/1440
  - `before-states/` and `after-states/`: error, loading, busy, lifecycle, keyboard, 200% reflow and motion states
  - `*-harness.png`: the unavailable kinds rendered inside the shell

## Open gates

- **G1:** visual approval of these candidates by the design owner and the user. Not done.
- **G3:** representative-user task study. Not run.
- **Surface option B:** not evaluated. Option A stays.
