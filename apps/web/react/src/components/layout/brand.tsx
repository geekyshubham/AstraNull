export function BrandMark() {
  return (
    <svg className="brand-mark" viewBox="0 0 32 32" aria-hidden="true">
      <defs>
        <clipPath id="bm-clip">
          <circle cx="16" cy="16" r="13.4" />
        </clipPath>
      </defs>
      <circle className="ring" cx="16" cy="16" r="14.5" />
      <path className="core" clipPath="url(#bm-clip)" d="M16 -5 L34.6 27 L-2.6 27 Z" />
    </svg>
  );
}

export function Brand() {
  return (
    <a href="/app" className="brand">
      <BrandMark />
      <span>AstraNull</span>
    </a>
  );
}