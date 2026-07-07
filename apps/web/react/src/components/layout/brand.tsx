import { useId } from 'react';

export function BrandMark() {
  const clipId = useId();
  return (
    <svg className="brand-mark" viewBox="0 0 32 32" aria-hidden="true" focusable="false">
      <defs>
        <clipPath id={clipId}>
          <circle cx="16" cy="16" r="13.4" />
        </clipPath>
      </defs>
      <circle className="ring" cx="16" cy="16" r="14.5" />
      <path className="core" clipPath={`url(#${clipId})`} d="M16 -5 L34.6 27 L-2.6 27 Z" />
    </svg>
  );
}

export function Brand() {
  return (
    <a href="/app" className="brand" aria-label="AstraNull home">
      <BrandMark />
      <span>AstraNull</span>
    </a>
  );
}