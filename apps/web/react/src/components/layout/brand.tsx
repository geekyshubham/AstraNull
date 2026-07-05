export function BrandMark() {
  return (
    <svg className="brand-mark" viewBox="0 0 32 32" fill="none" aria-hidden="true">
      <circle cx="16" cy="16" r="14" stroke="currentColor" strokeWidth="2" />
      <path d="M16 4 L25 22 H7 Z" fill="currentColor" />
      <circle cx="16" cy="18" r="3" fill="var(--bg)" />
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
