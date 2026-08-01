/**
 * Types for portal-auth-policy.mjs. The implementation is plain ESM so `node --test` can import
 * the real shipped logic instead of a copy; this declaration lets `api.ts` import it too.
 */
import type { PortalConfig, Session } from './types';

export declare const AUTH_MODE_UNKNOWN: 'unknown';

export declare function resolveAuthMode(
  ready: Record<string, unknown> | null | undefined,
  siteConfig: Record<string, unknown> | null | undefined,
): string;

export declare function isAuthFailure(status: number, payload: unknown): boolean;

export declare function isOidcJwtMode(config: Pick<PortalConfig, 'authMode'>): boolean;

export declare function isExternalAuthUrl(url: string): boolean;

export declare function portalSurface(pathname: string): 'customer' | 'staff';

export declare function resolveOidcLoginRedirect(
  config: PortalConfig,
  surface?: 'customer' | 'staff',
): string | null;

export declare function resolveLoginDestination(
  candidate: string | null | undefined,
  pathname: string,
): string;

export declare function sessionFromLoginResponse(
  loginResponse: Record<string, unknown>,
  now?: number,
): Session;

export declare function isSessionExpired(
  session: Session | null | undefined,
  now?: number,
): boolean;

export declare const STAFF_SOC_ROLES: Set<string>;

export declare function isStaffSocRole(session: Session): boolean;

export declare function buildApiHeaders(
  config: PortalConfig,
  session: Session,
  now?: number,
): Record<string, string>;

export declare function buildSocCustomerHeaders(
  config: PortalConfig,
  session: Session,
  tenantId?: string,
  now?: number,
): Record<string, string>;
