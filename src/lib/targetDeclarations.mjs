/**
 * Typed target and target-group declarations.
 * Stored fields are customer-authored. Inheritance is applied only when the
 * target field was never set, and only from the target group's declaration.
 * Tags, finding assignees, and metadata are not inputs.
 */

export const SERVICE_ROLES = Object.freeze(['website', 'api', 'login', 'dns', 'network']);
export const CRITICALITIES = Object.freeze(['critical', 'high', 'medium', 'low']);
export const MAX_PURPOSE_LENGTH = 200;
export const MAX_OWNER_LABEL_LENGTH = 80;

const SERVICE_ROLE_SET = new Set(SERVICE_ROLES);
const CRITICALITY_SET = new Set(CRITICALITIES);
const DECLARATION_KEYS = new Set(['purpose', 'service_roles', 'owner', 'owner_label', 'criticality']);

export class DeclarationValidationError extends Error {
  constructor(field, message) {
    super(message);
    this.name = 'DeclarationValidationError';
    this.code = 'invalid_declaration';
    this.status = 400;
    this.field = field;
  }

  toResponse() {
    return { error: this.code, status: this.status, field: this.field, message: this.message };
  }
}

function asObject(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : null;
}

function boundedText(value, field, maxLength) {
  if (value == null || value === '') return null;
  if (typeof value !== 'string') {
    throw new DeclarationValidationError(field, `${field} must be a string.`);
  }
  const trimmed = value.trim();
  if (!trimmed) return null;
  if (trimmed.length > maxLength) {
    throw new DeclarationValidationError(field, `${field} must be at most ${maxLength} characters.`);
  }
  return trimmed;
}

/**
 * Partial stored patch. Only keys the caller sent are present.
 * `null` / `[]` are explicit clears and block group inheritance.
 *
 * @param {unknown} input
 */
export function normalizeDeclarationInput(input) {
  const source = asObject(input);
  if (!source) {
    throw new DeclarationValidationError('declaration', 'Declaration must be an object.');
  }
  for (const key of Object.keys(source)) {
    if (!DECLARATION_KEYS.has(key)) {
      throw new DeclarationValidationError(key, `Unknown declaration field "${key}".`);
    }
  }

  const patch = {};
  if (Object.hasOwn(source, 'purpose')) {
    patch.purpose = boundedText(source.purpose, 'purpose', MAX_PURPOSE_LENGTH);
  }
  if (Object.hasOwn(source, 'service_roles')) {
    patch.service_roles = normalizeServiceRoles(source.service_roles);
  }
  if (Object.hasOwn(source, 'owner') || Object.hasOwn(source, 'owner_label')) {
    patch.owner_label = normalizeOwner(Object.hasOwn(source, 'owner') ? source.owner : source.owner_label);
  }
  if (Object.hasOwn(source, 'criticality')) {
    patch.criticality = normalizeCriticality(source.criticality);
  }
  return patch;
}

function normalizeServiceRoles(value) {
  if (value == null) return [];
  if (!Array.isArray(value)) {
    throw new DeclarationValidationError('service_roles', 'service_roles must be an array.');
  }
  const seen = new Set();
  for (const entry of value) {
    if (typeof entry !== 'string') {
      throw new DeclarationValidationError('service_roles', 'Each service role must be a string.');
    }
    const role = entry.trim().toLowerCase();
    if (!role) continue;
    if (!SERVICE_ROLE_SET.has(role)) {
      throw new DeclarationValidationError(
        'service_roles',
        `Unsupported service role "${role}". Expected one of ${SERVICE_ROLES.join(', ')}.`,
      );
    }
    seen.add(role);
  }
  return SERVICE_ROLES.filter((role) => seen.has(role));
}

function normalizeOwner(value) {
  if (value == null || value === '') return null;
  if (typeof value === 'string') return boundedText(value, 'owner', MAX_OWNER_LABEL_LENGTH);
  const record = asObject(value);
  if (!record) {
    throw new DeclarationValidationError('owner', 'Owner must be a label string.');
  }
  for (const key of Object.keys(record)) {
    if (key !== 'label') {
      throw new DeclarationValidationError('owner', 'Owner accepts a label only. Status and source are server-derived.');
    }
  }
  return boundedText(record.label, 'owner', MAX_OWNER_LABEL_LENGTH);
}

function normalizeCriticality(value) {
  if (value == null || value === '') return null;
  if (typeof value !== 'string') {
    throw new DeclarationValidationError('criticality', 'Criticality must be a string.');
  }
  const criticality = value.trim().toLowerCase();
  if (!criticality) return null;
  if (!CRITICALITY_SET.has(criticality)) {
    throw new DeclarationValidationError(
      'criticality',
      `Unsupported criticality "${criticality}". Expected one of ${CRITICALITIES.join(', ')}.`,
    );
  }
  return criticality;
}

/** Persisted object. Absent keys were never set and may inherit. Present null/[] do not inherit. */
export function storedDeclarationFromRow(value) {
  let raw = value;
  if (typeof raw === 'string') {
    try {
      raw = JSON.parse(raw);
    } catch {
      raw = null;
    }
  }
  const record = asObject(raw) ?? {};
  const stored = {};
  if (Object.hasOwn(record, 'purpose')) stored.purpose = record.purpose ?? null;
  if (Object.hasOwn(record, 'service_roles')) {
    stored.service_roles = Array.isArray(record.service_roles) ? record.service_roles : [];
  }
  if (Object.hasOwn(record, 'owner_label')) stored.owner_label = record.owner_label ?? null;
  if (Object.hasOwn(record, 'criticality')) stored.criticality = record.criticality ?? null;
  return stored;
}

export function mergeStoredDeclaration(current, patch) {
  return { ...storedDeclarationFromRow(current), ...patch };
}

function emptyText(value) {
  return value == null || value === '';
}

function ownSource(subject) {
  return subject === 'target_group' ? 'target_group' : 'target';
}

function resolveText(targetStored, groupStored, key, subject) {
  if (Object.hasOwn(targetStored, key)) {
    const value = emptyText(targetStored[key]) ? null : targetStored[key];
    return {
      value,
      status: value ? 'declared' : 'unassigned',
      source: ownSource(subject),
    };
  }
  if (Object.hasOwn(groupStored, key) && !emptyText(groupStored[key])) {
    return { value: groupStored[key], status: 'inherited', source: 'target_group' };
  }
  return { value: null, status: 'unassigned', source: null };
}

function resolveRoles(targetStored, groupStored, subject) {
  if (Object.hasOwn(targetStored, 'service_roles')) {
    const values = Array.isArray(targetStored.service_roles) ? targetStored.service_roles : [];
    return {
      values,
      status: values.length ? 'declared' : 'unassigned',
      source: ownSource(subject),
    };
  }
  if (Object.hasOwn(groupStored, 'service_roles') && groupStored.service_roles?.length) {
    return { values: [...groupStored.service_roles], status: 'inherited', source: 'target_group' };
  }
  return { values: [], status: 'unassigned', source: null };
}

/**
 * Public declaration. The same shape is returned for inventory items and detail targets.
 *
 * @param {unknown} targetStored
 * @param {unknown} [groupStored]
 * @param {{ subject?: 'target' | 'target_group' }} [options]
 */
export function presentTargetDeclaration(targetStored, groupStored = null, { subject = 'target' } = {}) {
  const target = storedDeclarationFromRow(targetStored);
  const group = subject === 'target_group' ? {} : storedDeclarationFromRow(groupStored);
  const purpose = resolveText(target, group, 'purpose', subject);
  const roles = resolveRoles(target, group, subject);
  const owner = resolveText(target, group, 'owner_label', subject);
  const criticality = resolveText(target, group, 'criticality', subject);
  return {
    purpose: purpose.value,
    purpose_status: purpose.status,
    purpose_source: purpose.source,
    service_roles: roles.values,
    service_roles_status: roles.status,
    service_roles_source: roles.source,
    owner: {
      status: owner.status,
      label: owner.value,
      source: owner.source,
    },
    criticality: {
      status: criticality.status,
      value: criticality.value,
      source: criticality.source,
    },
  };
}

export function presentGroupDeclaration(stored) {
  return presentTargetDeclaration(stored, null, { subject: 'target_group' });
}
