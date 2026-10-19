export const REDACTED = '[REDACTED]';
export const UNTRUSTED_MAX_CHARS = 30000;

const PATTERNS = [
  /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|$)/g,
  /-----BEGIN [A-Z0-9 ]*CERTIFICATE-----[\s\S]*?(?:-----END [A-Z0-9 ]*CERTIFICATE-----|$)/g,
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
  /\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[A-Z0-9]{16}\b/g,
  /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b/g,
  /\bgithub_pat_[A-Za-z0-9_]{20,}\b/g,
  /\bxox[abposr]-[A-Za-z0-9-]{10,}\b/g,
  /\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{10,}\b/g,
  /\bsk-(?:ant-)?[A-Za-z0-9_-]{16,}\b/g,
  /\bAIza[0-9A-Za-z_-]{30,}\b/g,
];

const HEADER_VALUE = /\b((?:proxy-)?authorization|cookie|set-cookie|x-api-key|api-key)(\s*[:=]\s*)("?)[^\r\n"]+\3/gi;
const URL_USERINFO = /\b([a-z][a-z0-9+.-]*:\/\/)[^\s/@:]+(?::[^\s/@]*)?@/gi;
const KEY_VALUE = /\b([A-Za-z0-9_.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret)[A-Za-z0-9_.-]*)(\s*["']?\s*[:=]\s*["']?)([^\s"'&,;}]+)/gi;
const HIGH_ENTROPY = /[A-Za-z0-9+/_=-]{40,}/g;

function entropy(value) {
  const counts = new Map();
  for (const char of value) counts.set(char, (counts.get(char) ?? 0) + 1);
  let bits = 0;
  for (const count of counts.values()) {
    const p = count / value.length;
    bits -= p * Math.log2(p);
  }
  return bits;
}

function looksSecret(value) {
  if (/^https?:/i.test(value) || /^[a-f0-9]+$/i.test(value)) return false;
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/].filter((pattern) => pattern.test(value)).length;
  return classes >= 2 && entropy(value) >= 4;
}

/** Replaces credentials and other secrets in free text with a fixed marker. */
export function redactSecrets(text) {
  let out = String(text ?? '');
  for (const pattern of PATTERNS) out = out.replace(pattern, REDACTED);
  out = out.replace(HEADER_VALUE, (_match, name, sep) => `${name}${sep}${REDACTED}`);
  out = out.replace(URL_USERINFO, (_match, scheme) => `${scheme}${REDACTED}@`);
  out = out.replace(KEY_VALUE, (match, name, sep, value) => (value === REDACTED ? match : `${name}${sep}${REDACTED}`));
  out = out.replace(HIGH_ENTROPY, (match, offset, whole) => (looksSecret(match) && !insideUrl(whole, offset) ? REDACTED : match));
  return out;
}

function insideUrl(text, offset) {
  const tokenStart = Math.max(...[' ', '\n', '\t', '(', '<', '"', "'"].map((char) => text.lastIndexOf(char, offset - 1))) + 1;
  return /^[a-z][a-z0-9+.-]*:\/\//i.test(text.slice(tokenStart, offset + 1)) || text.slice(tokenStart, offset).includes('://');
}

function cleanLabel(label) {
  return String(label ?? 'data').replace(/[^A-Za-z0-9 _.:-]/g, '').slice(0, 60) || 'data';
}

/** Redacts, defangs embedded markers, truncates and fences text so the model reads it as data. */
export function wrapUntrusted(label, text) {
  let body = redactSecrets(text).replace(/<{2,}\s*\/?\s*UNTRUSTED_DATA[^>]*>{0,3}/gi, '[marker removed]');
  if (body.length > UNTRUSTED_MAX_CHARS) body = `${body.slice(0, UNTRUSTED_MAX_CHARS)}\n[truncated]`;
  const name = cleanLabel(label);
  return `<<<UNTRUSTED_DATA_BEGIN ${name}>>>\n${body}\n<<<UNTRUSTED_DATA_END>>>`;
}
