const ID = /^[A-Za-z0-9_.:-]{1,128}$/;
const SEVERITIES = new Set(['critical', 'high', 'medium', 'low', 'info', 'unknown']);
const record = (value) => value && typeof value === 'object' && !Array.isArray(value) ? value : null;
const copy = (value, max) => typeof value === 'string' && value.trim() && value.length <= max && !/[\u0000-\u0008\u000b-\u001f]/.test(value) ? value : null;
const id = (value) => typeof value === 'string' && ID.test(value) ? value : null;

export function sanitizeWidgetConfig(value) {
  const body = record(value);
  if (!body) return null;
  const name = copy(body.name, 80);
  const question = copy(body.question, 500);
  if (!name || !question || !['summary', 'finding_list'].includes(body.template)) return null;
  if (body.target_id !== undefined && !id(body.target_id)) return null;
  if (body.severity !== undefined && !SEVERITIES.has(body.severity)) return null;
  return { name, question, template: body.template, ...(body.target_id ? { target_id: body.target_id } : {}), ...(body.severity ? { severity: body.severity } : {}) };
}

export function sanitizeWidget(value) {
  const body = record(value);
  const config = sanitizeWidgetConfig(body?.config);
  if (!body || !id(body.id) || !config || !Number.isSafeInteger(body.version) || body.version < 1 || !Number.isFinite(Date.parse(body.updated_at)) || !Number.isFinite(Date.parse(body.created_at))) return null;
  return { id: body.id, config, version: body.version, created_at: body.created_at, updated_at: body.updated_at };
}

export function sanitizeWidgetDefinition(value) {
  const body = record(value);
  if (body?.unavailable === true) {
    if (typeof body.id !== 'string' || !/^aw_[a-f0-9]{24}$/.test(body.id) || !Number.isSafeInteger(body.version) || body.version < 1) return null;
    return { id: body.id, version: body.version, unavailable: true };
  }
  return sanitizeWidget(value);
}

export function sanitizeWidgetData(value) {
  const body = record(value);
  const scope = record(body?.scope);
  if (!body || !scope || !copy(body.title, 160) || !Number.isSafeInteger(body.count) || body.count < 0 || typeof body.count_is_total !== 'boolean' || !Number.isFinite(Date.parse(body.observed_at))) return null;
  if (!Array.isArray(body.rows) || body.rows.length > 6 || !Array.isArray(body.citations) || body.citations.length > 200 || body.citations.some((entry) => !id(entry)) || new Set(body.citations).size !== body.citations.length) return null;
  const rows = [];
  for (const value of body.rows) {
    const row = record(value);
    if (!row || !id(row.id) || !copy(row.title, 500) || !SEVERITIES.has(row.severity) || !copy(row.status, 40) || !body.citations.includes(row.id)) return null;
    rows.push({ id: row.id, title: row.title, severity: row.severity, status: row.status, ...(id(row.target_id) ? { target_id: row.target_id } : {}) });
  }
  if (new Set(rows.map((row) => row.id)).size !== rows.length || body.count < rows.length || body.count > 200) return null;
  if (typeof scope.complete !== 'boolean' || typeof scope.findings_complete !== 'boolean' || (body.count_is_total && !scope.findings_complete) || (scope.complete && !scope.findings_complete)) return null;
  return { title: body.title, count: body.count, rows, citations: [...body.citations], observed_at: body.observed_at, count_is_total: body.count_is_total, scope: { complete: scope.complete, findings_complete: scope.findings_complete } };
}

export function sanitizeWidgetCommentary(value, data) {
  const body = record(value);
  if (!body || !data || !copy(body.text, 1800) || !Array.isArray(body.citations) || body.citations.length > 12 || (data.citations.length > 0 && body.citations.length === 0) || new Set(body.citations).size !== body.citations.length || body.citations.some((entry) => !data.citations.includes(entry))) return null;
  return { text: body.text, citations: [...body.citations] };
}
