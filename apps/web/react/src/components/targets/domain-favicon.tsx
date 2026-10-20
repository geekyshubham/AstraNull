import { useState } from 'react';
import { Globe2, Server } from 'lucide-react';

/** Only a hostname goes to the icon service; paths, queries and credentials stay local. */
export function DomainFavicon({ value, kind, className }: { value: string; kind: string; className: string }) {
  let host = '';
  try {
    const url = new URL(value.includes('://') ? value : `https://${value}`);
    const hostname = url.hostname.toLowerCase().replace(/\.$/, '');
    const validHostname = hostname.length <= 253 && /\.[a-z]{2,}$/.test(hostname)
      && hostname.split('.').every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label));
    // Special-use and conventional private suffixes must never leave the browser.
    const privateHostname = /\.(local|internal|localhost|test|invalid|example|arpa|onion|alt|home|lan|corp|intranet|private)$/.test(hostname)
      || /(^|\.)example\.(com|net|org)$/.test(hostname);
    if (['https:', 'http:'].includes(url.protocol) && validHostname && !privateHostname) host = hostname;
  } catch { /* Non-domain targets keep their type icon. */ }
  const src = host && !['ip', 'cidr'].includes(kind) ? `https://icons.duckduckgo.com/ip3/${encodeURIComponent(host)}.ico` : '';
  const [failedSrc, setFailedSrc] = useState('');
  return (
    <span className={className} aria-hidden="true">
      {src && src !== failedSrc
        ? <img src={src} alt="" width={16} height={16} loading="lazy" decoding="async" referrerPolicy="no-referrer" onError={() => setFailedSrc(src)} />
        : kind === 'ip' || kind === 'tcp' ? <Server size={16} /> : <Globe2 size={16} />}
    </span>
  );
}
