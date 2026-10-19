import { useState } from 'react';
import { Globe2, Server } from 'lucide-react';

/** Only a hostname goes to the icon service; paths, queries and credentials stay local. */
export function DomainFavicon({ value, kind, className }: { value: string; kind: string; className: string }) {
  let host = '';
  try {
    const url = new URL(value.includes('://') ? value : `https://${value}`);
    if (['https:', 'http:'].includes(url.protocol) && /\.[a-z]{2,}$/i.test(url.hostname)
      && !/\.(local|internal|localhost|test|invalid|example)$/i.test(url.hostname)) host = url.hostname;
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
