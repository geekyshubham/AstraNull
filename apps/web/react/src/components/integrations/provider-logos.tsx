import { useSyncExternalStore } from 'react';
import type { CSSProperties } from 'react';
import akamaiLogo from './logos/akamai.png';
import azureLogo from './logos/azure.png';
import cloudflareLogo from './logos/cloudflare.png';
import gcpLogo from './logos/gcp.png';
import godaddyLogo from './logos/godaddy.png';
import hetznerLogo from './logos/hetzner.png';
import hetznerDarkLogo from './logos/hetzner-dark.png';
import namecheapLogo from './logos/namecheap.png';
import ns1Logo from './logos/ns1.png';
import ns1DarkLogo from './logos/ns1-dark.png';
import route53Logo from './logos/route53.png';
import route53DarkLogo from './logos/route53-dark.png';

/**
 * Full-color provider marks for the Integrations directory and domain
 * protection panels.
 *
 * The 128x128 PNGs come from the DNS Migrator provider logo set
 * (apps/web/public/providers in that project). They are trademarks of their
 * respective owners and are used only to identify the service a connector
 * reads from (nominative use). See THIRD_PARTY_NOTICES/provider-logos-NOTICE.txt.
 *
 * Vite library mode inlines imported assets as data: URIs, so the marks ship
 * inside react-app.js and satisfy the portal CSP (img-src 'self' data:).
 * Marks that would vanish on a dark well ship a `-dark` variant, selected from
 * the active `html[data-theme]` value (dark is the default theme).
 */

export type ProviderLogoId =
  | 'cloudflare'
  | 'akamai'
  | 'route53'
  | 'godaddy'
  | 'namecheap'
  | 'hetzner'
  | 'google_cloud'
  | 'azure'
  | 'ibm_ns1'
  | 'generic';

type LogoAsset = { light: string; dark?: string };

const PROVIDER_LOGO_ASSETS: Record<Exclude<ProviderLogoId, 'generic'>, LogoAsset> = {
  cloudflare: { light: cloudflareLogo },
  akamai: { light: akamaiLogo },
  route53: { light: route53Logo, dark: route53DarkLogo },
  godaddy: { light: godaddyLogo },
  namecheap: { light: namecheapLogo },
  hetzner: { light: hetznerLogo, dark: hetznerDarkLogo },
  google_cloud: { light: gcpLogo },
  azure: { light: azureLogo },
  ibm_ns1: { light: ns1Logo, dark: ns1DarkLogo },
};

// --- Theme tracking: one shared observer on <html data-theme>. ---
const themeListeners = new Set<() => void>();
let themeObserver: MutationObserver | null = null;

function subscribeTheme(listener: () => void) {
  themeListeners.add(listener);
  if (!themeObserver && typeof MutationObserver !== 'undefined' && typeof document !== 'undefined') {
    themeObserver = new MutationObserver(() => themeListeners.forEach((notify) => notify()));
    themeObserver.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
  }
  return () => {
    themeListeners.delete(listener);
    if (themeListeners.size === 0 && themeObserver) {
      themeObserver.disconnect();
      themeObserver = null;
    }
  };
}

function readIsDarkTheme() {
  if (typeof document === 'undefined') return true;
  return document.documentElement.getAttribute('data-theme') !== 'light';
}

function useIsDarkTheme() {
  return useSyncExternalStore(subscribeTheme, readIsDarkTheme, () => true);
}

export type ProviderLogoProps = {
  provider: ProviderLogoId;
  /** px size for width/height, defaults to 22. */
  size?: number;
  className?: string;
  style?: CSSProperties;
  /** Accessible label. When omitted the mark is decorative (alt=""), because adjacent text names the provider. */
  title?: string;
};

/** Render a full-color provider mark, or a neutral outline glyph for unknown providers. */
export function ProviderLogo({ provider, size = 22, className, style, title }: ProviderLogoProps) {
  const isDark = useIsDarkTheme();
  const asset = provider === 'generic' ? null : PROVIDER_LOGO_ASSETS[provider];
  const classes = className ? `provider-logo ${className}` : 'provider-logo';
  const decorative = !title;

  if (!asset) {
    // Generic and manual-only providers have no brand mark; render a neutral
    // outline glyph so the row still reads as a provider tile.
    return (
      <svg
        className={classes}
        data-provider={provider}
        width={size}
        height={size}
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth={1.7}
        strokeLinecap="round"
        strokeLinejoin="round"
        style={style}
        role={decorative ? undefined : 'img'}
        aria-hidden={decorative ? true : undefined}
        aria-label={decorative ? undefined : title}
      >
        {decorative ? null : <title>{title}</title>}
        <rect x="3" y="4" width="18" height="16" rx="2.5" />
        <path d="M3 9h18" />
        <path d="M8 14h5" />
      </svg>
    );
  }

  const src = isDark && asset.dark ? asset.dark : asset.light;
  return (
    <img
      className={classes}
      data-provider={provider}
      src={src}
      width={size}
      height={size}
      alt={decorative ? '' : title}
      decoding="async"
      draggable={false}
      style={{ objectFit: 'contain', ...style }}
    />
  );
}
