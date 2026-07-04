const MAX_REASON_LENGTH = 500;
const MAX_TICKET_REFERENCE_LENGTH = 120;

export function validateBreakGlassActivation(body = {}) {
  const missing_fields = [];
  const forbidden_fields = [];
  if (!body?.reason || String(body.reason).trim() === '') missing_fields.push('reason');
  if (!body?.ticket_reference || String(body.ticket_reference).trim() === '') {
    missing_fields.push('ticket_reference');
  }
  const durationMinutes = Number(body?.duration_minutes ?? 60);
  if (!Number.isFinite(durationMinutes) || durationMinutes < 5 || durationMinutes > 240) {
    missing_fields.push('duration_minutes');
  }
  for (const key of ['password', 'token', 'secret', 'credential', 'headers', 'body']) {
    if (body?.[key] != null) forbidden_fields.push(key);
  }
  if (body?.reason && String(body.reason).length > MAX_REASON_LENGTH) {
    forbidden_fields.push('reason');
  }
  if (body?.ticket_reference && String(body.ticket_reference).length > MAX_TICKET_REFERENCE_LENGTH) {
    forbidden_fields.push('ticket_reference');
  }
  return {
    ok: missing_fields.length === 0 && forbidden_fields.length === 0,
    missing_fields,
    forbidden_fields,
    duration_minutes: durationMinutes,
    reason: body?.reason ? String(body.reason).trim() : null,
    ticket_reference: body?.ticket_reference ? String(body.ticket_reference).trim() : null,
  };
}