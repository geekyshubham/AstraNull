import { validateBreakGlassActivation } from '../contracts/breakGlass.mjs';
import { getStore, persistStore } from '../store.mjs';

/**
 * Break-glass is REPORTING-ONLY by design.
 *
 * An activation records that a human declared an emergency and produces an audit trail.
 * It does NOT itself grant, widen, or bypass any authorization: no code path consults
 * `getActiveBreakGlassActivation()` to make an access decision, and none should start
 * doing so without a designed elevated-access mode (scoped permission set, expiry
 * enforcement, and revocation) behind it. Treating "active" as "elevated" on a guess would
 * silently change who can do what. The status payload therefore reports
 * `enforcement: 'reporting_only'` so callers cannot mistake declaration for entitlement.
 */
export const BREAK_GLASS_ENFORCEMENT = 'reporting_only';

/**
 * Activations live in the shared dev store (not module-level state) so they survive a
 * process restart in dev mode, exactly like the other stateful in-memory services. Sharing
 * across workers/instances comes from the Postgres persistence port (`options.store`), which
 * the server supplies in postgres mode.
 */
function memoryActivations() {
  const store = getStore();
  if (!Array.isArray(store.breakGlassActivations)) store.breakGlassActivations = [];
  return store.breakGlassActivations;
}

/** Persistence port backed by the dev store. */
const memoryPort = {
  listBreakGlassActivations() {
    return memoryActivations().map((entry) => ({ ...entry }));
  },
  saveBreakGlassActivation(activation) {
    // Supersede-then-insert must be one step for every backend so two activations can
    // never both be 'active'; the Postgres port does the same in a transaction.
    const activations = memoryActivations();
    for (const entry of activations) {
      if (entry.status === 'active') entry.status = 'superseded';
    }
    activations.push({ ...activation });
    persistStore();
    return { ...activation };
  },
};

export function resetBreakGlassStore() {
  memoryActivations().length = 0;
}

function resolvePort(options = {}) {
  const store = options.store;
  if (
    store
    && typeof store.listBreakGlassActivations === 'function'
    && typeof store.saveBreakGlassActivation === 'function'
  ) {
    return store;
  }
  return memoryPort;
}

/** Picks the newest still-valid activation from a set of records. */
export function selectActiveActivation(activations, now = new Date()) {
  const nowMs = now.getTime();
  const active = (activations ?? []).filter((entry) => {
    const expiresMs = Date.parse(entry.expires_at);
    return entry.status === 'active' && Number.isFinite(expiresMs) && expiresMs > nowMs;
  });
  active.sort((a, b) => String(b.activated_at).localeCompare(String(a.activated_at)));
  return active[0] ?? null;
}

export async function listBreakGlassActivations(options = {}) {
  return resolvePort(options).listBreakGlassActivations();
}

export async function getActiveBreakGlassActivation(now = new Date(), options = {}) {
  return selectActiveActivation(await resolvePort(options).listBreakGlassActivations(), now);
}

/**
 * @param {object} ctx staff context
 * @param {object} body activation request
 * @param {{
 *   audit: (event: object) => unknown|Promise<unknown>,
 *   store?: object,
 *   now?: () => Date,
 * }} options
 */
export async function activateBreakGlass(ctx, body, options = {}) {
  // Audit integrity: emergency access must never be recorded as activated without an audit
  // entry, so a missing writer fails loudly here instead of silently no-opping. This used to
  // be an optional call (`audit?.()`) with no implementation behind it in either persistence
  // mode, which dropped every `break_glass.activated` event on the floor.
  if (typeof options.audit !== 'function') {
    throw new Error('activateBreakGlass requires an audit writer: refusing to activate unaudited.');
  }

  const validation = validateBreakGlassActivation(body);
  if (!validation.ok) {
    return {
      error: 'validation_failed',
      status: 400,
      missing_fields: validation.missing_fields,
      forbidden_fields: validation.forbidden_fields,
    };
  }

  const port = resolvePort(options);
  const now = options.now?.() ?? new Date();
  const expiresAt = new Date(now.getTime() + validation.duration_minutes * 60_000);
  const activation = {
    id: `bg_${now.getTime().toString(36)}`,
    status: 'active',
    reason: validation.reason,
    ticket_reference: validation.ticket_reference,
    activated_by: ctx?.staffId ?? ctx?.userId ?? 'unknown',
    activated_role: ctx?.staffRole ?? ctx?.role ?? 'unknown',
    activated_at: now.toISOString(),
    expires_at: expiresAt.toISOString(),
    duration_minutes: validation.duration_minutes,
  };

  const saved = (await port.saveBreakGlassActivation(activation)) ?? activation;

  // Awaited, and allowed to reject: if the audit write fails the caller gets an error rather
  // than a 200 for an unrecorded emergency activation.
  await options.audit({
    action: 'break_glass.activated',
    actor_user_id: saved.activated_by,
    actor_role: saved.activated_role,
    resource_type: 'break_glass_activation',
    resource_id: saved.id,
    reason: saved.reason,
    metadata: {
      ticket_reference: saved.ticket_reference,
      duration_minutes: saved.duration_minutes,
      expires_at: saved.expires_at,
      enforcement: BREAK_GLASS_ENFORCEMENT,
    },
  });

  return { activation: saved };
}

export async function breakGlassStatus(now = new Date(), options = {}) {
  const active = selectActiveActivation(
    await resolvePort(options).listBreakGlassActivations(),
    now,
  );
  return {
    active: Boolean(active),
    activation: active
      ? {
          id: active.id,
          activated_at: active.activated_at,
          expires_at: active.expires_at,
          ticket_reference: active.ticket_reference,
          activated_by: active.activated_by,
        }
      : null,
    // Declaration, not entitlement — see BREAK_GLASS_ENFORCEMENT above.
    enforcement: BREAK_GLASS_ENFORCEMENT,
    procedure_reference: 'runbook://security/break-glass',
  };
}
