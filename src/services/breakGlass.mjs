import { validateBreakGlassActivation } from '../contracts/breakGlass.mjs';

const store = {
  activations: [],
};

export function resetBreakGlassStore() {
  store.activations.length = 0;
}

export function listBreakGlassActivations() {
  return store.activations.map((entry) => ({ ...entry }));
}

export function getActiveBreakGlassActivation(now = new Date()) {
  const nowMs = now.getTime();
  return store.activations.find((entry) => {
    const expiresMs = Date.parse(entry.expires_at);
    return entry.status === 'active' && Number.isFinite(expiresMs) && expiresMs > nowMs;
  }) ?? null;
}

/**
 * @param {object} ctx staff context
 * @param {object} body activation request
 * @param {{ audit?: (event: object) => void, now?: () => Date }} [options]
 */
export function activateBreakGlass(ctx, body, options = {}) {
  const validation = validateBreakGlassActivation(body);
  if (!validation.ok) {
    return {
      error: 'validation_failed',
      status: 400,
      missing_fields: validation.missing_fields,
      forbidden_fields: validation.forbidden_fields,
    };
  }

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

  for (const entry of store.activations) {
    if (entry.status === 'active') entry.status = 'superseded';
  }
  store.activations.push(activation);

  options.audit?.({
    action: 'break_glass.activated',
    actor_user_id: activation.activated_by,
    actor_role: activation.activated_role,
    resource_type: 'break_glass_activation',
    resource_id: activation.id,
    metadata: {
      ticket_reference: activation.ticket_reference,
      duration_minutes: activation.duration_minutes,
      expires_at: activation.expires_at,
    },
  });

  return { activation };
}

export function breakGlassStatus(now = new Date()) {
  const active = getActiveBreakGlassActivation(now);
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
    procedure_reference: 'runbook://security/break-glass',
  };
}