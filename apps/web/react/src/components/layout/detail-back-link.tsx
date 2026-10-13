import { ArrowLeft } from 'lucide-react';
import type { RouteId } from '../../lib/types';
import { AnchorButton } from '../ui/button';

export type DetailListLink = { label: string; href: string };

export const DETAIL_LIST_LINKS: Partial<Record<RouteId, DetailListLink>> = {
  'run-detail': { label: 'targets', href: '#targets' },
  'scan-detail': { label: 'targets', href: '#targets' },
  'target-detail': { label: 'targets', href: '#targets' },
  'report-detail': { label: 'reports', href: '#reports' },
  'tenant-detail': { label: 'tenants', href: '#admin?tab=tenants' },
  'finding-detail': { label: 'findings', href: '#findings' },
  'finding-group-detail': { label: 'findings', href: '#findings' },
  'evidence-detail': { label: 'findings', href: '#findings' },
  'check-detail': { label: 'check library', href: '#checks' },
  'policy-detail': { label: 'validation schedules', href: '#test-policies' },
  'queue-detail': { label: 'SOC console', href: '#internal-soc' }
};

/** `link` overrides the route default, e.g. a scan or run returning to its own target. */
export function DetailBackLink({ route, link }: { route: RouteId; link?: DetailListLink }) {
  const listLink = link ?? DETAIL_LIST_LINKS[route];
  if (!listLink) return null;
  return (
    <p className="stack-tight detail-crumb">
      <AnchorButton size="sm" variant="ghost" href={listLink.href}><ArrowLeft size={14} aria-hidden="true" />Back to {listLink.label}</AnchorButton>
    </p>
  );
}
