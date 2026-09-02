# Vector Library Page

## Purpose

The `#checks` route is AstraNull's customer-facing **vector library**. It accounts for all 721 canonical vectors and explains what exposure each vector is intended to evaluate, what a failed check means, which control should have prevented it, and what evidence tier can support a conclusion. It is not cloud infrastructure provisioning and does not request customer cloud credentials.

## Truth model

Every vector detail keeps these concepts separate:

| Field | Meaning |
|---|---|
| Intended detection goal | Catalog intent only; never an observed result. |
| Evidence capability | E1 declaration-only, E2 transport-only, E3 semantic-safe, E4 SOC-governed, or E5 monitor-only. |
| Selected-target disposition | Whether mapped checks support the exact selected target, need more customer input, are SOC-gated, or are monitor-only. |
| Failure means | The bounded interpretation of failed/missing evidence; E1/E2 never become semantic exposure proof. |
| Expected controls | Controls such as rate limiting, queue bounds, origin shielding, WAF canonicalization, or protocol-specific safeguards. |
| Mapped checks | Check-level execution choices; a shared check result is not synthesized into a per-vector verdict. |

E4 vectors remain SOC-gated even when declaration metadata exists. E5 vectors provide telemetry/integration guidance and cannot launch active outside-in checks.

## Target and launch workflow

1. The operator explicitly selects a declared target group.
2. The portal loads that group's active targets; it does not select the first target.
3. The operator explicitly selects the exact target.
4. Each vector recomputes target compatibility from its mapped customer-safe checks and each check's `supported_targets` contract.
5. Owners, admins, and engineers may open an eligible vector and explicitly select one mapped bounded check. Viewer, auditor, and customer-SOC roles remain read-only.
6. A confirmation dialog repeats the vector intent, exact group, target ID/value, check ID, and evidence limit before `POST /v1/test-runs`.
7. The backend revalidates ownership, eligibility, target compatibility, run concurrency, rate/cooldown policy, and kill-switch state. The UI cannot bypass these controls.

SOC/high-scale vectors link to the governed request workflow. Monitor-only vectors link to telemetry integrations. Additional-input rows explain that a customer-supplied URL, route, or declaration is required rather than fabricating one.

## Browse and accessibility behavior

- The authenticated `/v1/vectors` API is read in eight bounded pages of at most 100 rows and cached across React StrictMode effect replay.
- Only 25 rows render per UI page.
- Search covers canonical ID/name, protocol, exposure goal, failure meaning, and expected controls.
- Filters cover catalog section, evidence capability, execution boundary, and exact-target disposition.
- Loading, API failure/retry, no-results, empty-target, and read-only-role states are explicit.
- The data table uses one interactive Review button per row; rows are not nested interactive controls.
- Custom selects support pointer and keyboard operation; dialogs use native focus trapping and Escape handling.
- Layout collapses at tablet/mobile breakpoints and table overflow remains keyboard-scrollable.

## Completion evidence

- `tests/unit/vector-library-ui.test.mjs` protects E1/E2/E4/E5 wording, target compatibility, additional-input classification, and semantic-check preference.
- `tests/e2e/journeys/portal-vector-library.spec.mjs` verifies 721-row retrieval, 25-row rendering, exact target/check selection, confirmation payload, SOC/E5 refusal, viewer RBAC, and serious/critical axe findings.
- The runs page no longer launches the first group/target/check; its customer-safe action opens this vector library.

## Completion criteria

Complete when all 721 vectors are browseable through bounded pages; exposure, failure, control, evidence, and target disposition remain distinct; no implicit scope selection exists; only eligible bounded checks can launch after confirmation; and SOC/high-scale and monitor-only vectors remain non-customer-runnable.
