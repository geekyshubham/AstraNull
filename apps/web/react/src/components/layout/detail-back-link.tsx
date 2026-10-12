import { ArrowLeft } from 'lucide-react';
import type { RouteId } from '../../lib/types';
import { AnchorButton } from '../ui/button';

export type DetailListLink = { label: string; href: string };

export const DETAIL_LIST_LINKS: Partial<Record<RouteId, DetailListLink>> = {
  'run-detail': { label: 'Test runs', href: '#runs' },
  'target-detail': { label: 'Targets', href: '#targets' },
  'report-detail': { label: 'Reports', href: '#reports' },
  'tenant-detail': { label: 'Admin console', href: '#admin' },
  'finding-detail': { label: 'Findings', href: '#findings' },
  'evidence-detail': { label: 'Findings', href: '#findings' },
  'check-detail': { label: 'Check library', href: '#checks' },
  'policy-detail': { label: 'Validation schedules', href: '#test-policies' },
  'queue-detail': { label: 'SOC console', href: '#internal-soc' }
};

export function DetailBackLink({ route, link }: { route: RouteId; link?: DetailListLink }) {
  const listLink = link ?? DETAIL_LIST_LINKS[route];
  if (!listLink) return null;
  return (
    <p className="stack-tight detail-crumb">
      <AnchorButton size="sm" variant="ghost" href={listLink.href}><ArrowLeft size={14} aria-hidden="true" />Back to {listLink.label}</AnchorButton>
    </p>
  );
}
