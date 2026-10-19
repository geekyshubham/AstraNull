export const ASSISTANT_DOC_DOMAINS = Object.freeze([
  'developers.cloudflare.com', 'cloudflare.com',
  'docs.aws.amazon.com', 'aws.amazon.com', 'repost.aws',
  'cloud.google.com', 'learn.microsoft.com', 'azure.microsoft.com',
  'techdocs.akamai.com', 'akamai.com',
  'docs.fastly.com', 'fastly.com', 'developer.fastly.com',
  'docs.fortinet.com', 'community.fortinet.com',
  'clouddocs.f5.com', 'my.f5.com', 'f5.com', 'docs.nginx.com', 'nginx.org',
  'docs.imperva.com', 'docs.paloaltonetworks.com', 'docs.netscaler.com',
  'owasp.org', 'cheatsheetseries.owasp.org', 'coreruleset.org',
  'cisa.gov', 'nist.gov', 'csrc.nist.gov', 'rfc-editor.org', 'datatracker.ietf.org',
  'developer.mozilla.org', 'httpd.apache.org', 'kubernetes.io', 'docs.oracle.com',
]);

const PRIVATE_HOST = /^(localhost|.*\.local|.*\.internal|.*\.localhost|metadata\.google\.internal)$/i;
const IP_LITERAL = /^(\d{1,3}(\.\d{1,3}){3}|\[[0-9a-f:.]+\])$/i;

/** True only for a public https URL on an allow-listed vendor or standards documentation domain. */
export function isAllowedDocUrl(value) {
  let url;
  try {
    url = new URL(String(value ?? ''));
  } catch {
    return false;
  }
  if (url.protocol !== 'https:' || url.username || url.password || (url.port && url.port !== '443')) return false;
  const host = url.hostname.toLowerCase().replace(/\.$/, '');
  if (!host || IP_LITERAL.test(host) || PRIVATE_HOST.test(host)) return false;
  return ASSISTANT_DOC_DOMAINS.some((domain) => host === domain || host.endsWith(`.${domain}`));
}
