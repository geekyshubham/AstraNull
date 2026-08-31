import { createHash, createHmac } from 'node:crypto';

function sha256Hex(value) {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

function hmac(key, value, encoding) {
  const digest = createHmac('sha256', key).update(value, 'utf8');
  return encoding ? digest.digest(encoding) : digest.digest();
}

function toAmzDate(date) {
  return date.toISOString().replace(/[:-]|\.\d{3}/g, '');
}

export function deriveAwsV4SigningKey(secretAccessKey, dateStamp, region, service) {
  const kDate = hmac(`AWS4${secretAccessKey}`, dateStamp);
  const kRegion = hmac(kDate, region);
  const kService = hmac(kRegion, service);
  return hmac(kService, 'aws4_request');
}

/**
 * Minimal AWS SigV4 signer for JSON 1.1 service calls via fetch.
 */
export function signAwsJsonRequest({
  method = 'POST',
  host,
  path = '/',
  region,
  service,
  body,
  credentials,
  amzTarget,
  now = new Date(),
}) {
  const amzDate = toAmzDate(now);
  const dateStamp = amzDate.slice(0, 8);
  const payloadHash = sha256Hex(body ?? '');
  const canonicalHeaderEntries = [
    ['content-type', 'application/x-amz-json-1.1'],
    ['host', host],
    ['x-amz-date', amzDate],
    ...(credentials.session_token ? [['x-amz-security-token', credentials.session_token]] : []),
    ['x-amz-target', amzTarget],
  ].sort(([left], [right]) => left.localeCompare(right));
  const canonicalHeaders = canonicalHeaderEntries
    .map(([name, value]) => `${name}:${String(value).trim().replace(/\s+/g, ' ')}`)
    .join('\n');
  const signedHeaders = canonicalHeaderEntries.map(([name]) => name).join(';');
  const canonicalRequest = [
    method,
    path,
    '',
    `${canonicalHeaders}\n`,
    signedHeaders,
    payloadHash,
  ].join('\n');
  const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;
  const stringToSign = [
    'AWS4-HMAC-SHA256',
    amzDate,
    credentialScope,
    sha256Hex(canonicalRequest),
  ].join('\n');
  const signingKey = deriveAwsV4SigningKey(
    credentials.secret_access_key,
    dateStamp,
    region,
    service,
  );
  const signature = hmac(signingKey, stringToSign, 'hex');
  const authorization = [
    'AWS4-HMAC-SHA256',
    `Credential=${credentials.access_key_id}/${credentialScope},`,
    `SignedHeaders=${signedHeaders},`,
    `Signature=${signature}`,
  ].join(' ');

  return {
    'content-type': 'application/x-amz-json-1.1',
    host,
    'x-amz-date': amzDate,
    'x-amz-target': amzTarget,
    authorization,
    ...(credentials.session_token ? { 'x-amz-security-token': credentials.session_token } : {}),
  };
}