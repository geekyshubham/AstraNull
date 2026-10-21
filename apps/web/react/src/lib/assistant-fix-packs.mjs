const PROVIDERS = new Set(['gcp', 'aws', 'azure', 'cloudflare', 'akamai', 'fastly', 'generic']);
const HOSTS = new Set(['cloud.google.com', 'docs.aws.amazon.com', 'aws.amazon.com', 'learn.microsoft.com', 'developers.cloudflare.com', 'techdocs.akamai.com', 'www.fastly.com', 'cheatsheetseries.owasp.org', 'owasp.org', 'www.cisa.gov', 'www.rfc-editor.org', 'csrc.nist.gov']);
const LISTS = ['prerequisites', 'steps', 'verification', 'rollback', 'limitations'];
const KEYS = ['title', 'provider', 'finding_id', ...LISTS, 'sources', 'citations'];
const plain = (value, max) => typeof value === 'string' && value.trim() && value.length <= max && !/(?:https?:|javascript:|data:|www\.)/i.test(value);

export function sanitizeFixPack(value, scope) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || !scope || Object.keys(value).length !== KEYS.length || KEYS.some((key) => !Object.hasOwn(value, key))) return null;
  if (!PROVIDERS.has(value.provider) || value.provider !== scope.provider || value.finding_id !== scope.findingId || !plain(value.title, 240)) return null;
  for (const key of LISTS) if (!Array.isArray(value[key]) || !value[key].length || value[key].length > 16 || value[key].some((item) => !plain(item, 1200))) return null;
  if (!Array.isArray(value.sources) || value.sources.length > 12 || !Array.isArray(value.citations)) return null;
  const sources = [];
  for (const source of value.sources) {
    if (!source || typeof source !== 'object' || Object.keys(source).sort().join(',') !== 'id,title,url' || typeof source.title !== 'string' || !source.title || source.title.length > 240 || typeof source.url !== 'string') return null;
    let url;
    try { url = new URL(source.url); } catch { return null; }
    if (url.protocol !== 'https:' || !HOSTS.has(url.hostname) || url.username || url.password || url.port || url.search || url.hash || !scope.docs.includes(source.url)) return null;
    if (source.id !== `remediation:${scope.controlFamily}:${scope.provider}:${scope.docs.indexOf(source.url) + 1}` || sources.some((item) => item.id === source.id)) return null;
    sources.push({ id: source.id, title: source.title, url: source.url });
  }
  if (JSON.stringify(value.citations) !== JSON.stringify([scope.findingId, ...sources.map((source) => source.id)])) return null;
  return { title: value.title, provider: value.provider, finding_id: value.finding_id, ...Object.fromEntries(LISTS.map((key) => [key, [...value[key]]])), sources, citations: [...value.citations] };
}

export function fixPackCopyText(pack) {
  return [pack.title, ...LISTS.flatMap((key) => ['', key[0].toUpperCase() + key.slice(1), ...pack[key].map((line, index) => `${index + 1}. ${line}`)]), '', 'Sources', ...pack.sources.map((source) => `${source.id}: ${source.url}`), '', `Citations: ${pack.citations.join(', ')}`].join('\n');
}
