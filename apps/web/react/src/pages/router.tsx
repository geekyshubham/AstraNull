import { FileQuestion } from 'lucide-react';
import { EmptyState } from '../components/ui/empty-state';
import { PortalLoadingSkeleton } from '../lib/empty-from-api';
import type { PortalConfig, PortalData, RouteId, Session } from '../lib/types';
import { DetailRoutePage, ReportDetailPage } from './detail-pages';
import { ValidationSurfacePage } from './functional-surfaces';
import { DashboardPage } from './dashboard-page';
import {
  PolicyPage,
  ReportsPage,
  SettingsPage,
  StaffSurfacePage,
  SubscriptionPage,
  SupportPage,
  TargetGroupsPage
} from './page-components';
import { IntegrationPage } from './integrations-page';
import { AuditPage, NotificationsPage, ReleaseEvidencePage, SocConsolePage } from './governance-pages';
import { TargetsPage } from './targets-page';
import { VectorLibraryPage } from './vector-library-page';
import { ScanDetailView } from './scan-detail-view';

const DETAIL_ROUTES = new Set<RouteId>([
  'target-group-detail',
  'target-detail',
  'run-detail',
  'finding-detail',
  'evidence-detail',
  'check-detail',
  'policy-detail',
  'tenant-detail',
  'queue-detail'
]);

const VALIDATION_LIST_ROUTES = new Set<RouteId>(['runs', 'findings']);

function routeHydrationLabel(route: RouteId) {
  return `Loading ${route.replaceAll('-', ' ')}`;
}

type RouteViewProps = {
  route: RouteId;
  data: PortalData;
  config: PortalConfig;
  session: Session;
  onRefresh: () => Promise<void>;
  hydrating: boolean;
};

export function RouteView({ route, data, config, session, onRefresh, hydrating }: RouteViewProps) {
  if (hydrating) {
    return <PortalLoadingSkeleton rows={4} label={routeHydrationLabel(route)} />;
  }
  if (route === 'not-found') {
    return (
      <div className="content">
        <h1>Portal route not found.</h1>
        <EmptyState
          icon={FileQuestion}
          title="This path is not part of the current portal."
          body="This route alias is not served by the AstraNull React portal. Removed aliases are not redirected, so the address is reported as-is rather than silently resolving to another page."
          actionLabel="Open dashboard"
          actionHref="#dashboard"
        />
      </div>
    );
  }
  if (route === 'dashboard') return <DashboardPage data={data} config={config} session={session} onRefresh={onRefresh} />;
  if (route === 'target-groups') {
    return <TargetGroupsPage data={data} config={config} session={session} onRefresh={onRefresh} />;
  }
  if (route === 'targets') {
    return <TargetsPage data={data} config={config} session={session} onRefresh={onRefresh} />;
  }
  if (DETAIL_ROUTES.has(route)) {
    return <DetailRoutePage route={route} data={data} config={config} session={session} onRefresh={onRefresh} />;
  }
  if (route === 'scan-detail') {
    return <ScanDetailView data={data} config={config} session={session} onRefresh={onRefresh} />;
  }
  if (route === 'test-policies') {
    return <PolicyPage data={data} config={config} session={session} onRefresh={onRefresh} />;
  }
  if (route === 'checks') {
    return <VectorLibraryPage data={data} config={config} session={session} onRefresh={onRefresh} />;
  }
  if (VALIDATION_LIST_ROUTES.has(route)) {
    return <ValidationSurfacePage route={route} data={data} config={config} session={session} onRefresh={onRefresh} />;
  }
  if (route === 'integrations') {
    return <IntegrationPage data={data} config={config} session={session} onRefresh={onRefresh} />;
  }
  if (route === 'reports') {
    return <ReportsPage data={data} config={config} session={session} onRefresh={onRefresh} />;
  }
  if (route === 'report-detail') {
    return <ReportDetailPage data={data} config={config} session={session} onRefresh={onRefresh} />;
  }
  if (route === 'notifications') {
    return <NotificationsPage data={data} config={config} session={session} onRefresh={onRefresh} />;
  }
  if (route === 'audit') return <AuditPage data={data} session={session} onRefresh={onRefresh} />;
  if (route === 'release-evidence') return <ReleaseEvidencePage data={data} session={session} />;
  if (route === 'support') return <SupportPage data={data} session={session} config={config} />;
  if (route === 'subscription') return <SubscriptionPage data={data} />;
  if (route === 'internal-soc') {
    return (
      <SocConsolePage
        data={data}
        config={config}
        session={session}
        onRefresh={onRefresh}
        staffSocSurface
      />
    );
  }
  if (route === 'admin') {
    return <StaffSurfacePage route={route} data={data} config={config} session={session} onRefresh={onRefresh} />;
  }
  if (route === 'settings') {
    return <SettingsPage data={data} config={config} session={session} onRefresh={onRefresh} />;
  }
  return (
    <div className="content">
      <h1>Portal route unavailable</h1>
      <EmptyState
        icon={FileQuestion}
        title="This route is not available."
        body="Open the dashboard to continue in the current AstraNull portal."
        actionLabel="Open dashboard"
        actionHref="#dashboard"
      />
    </div>
  );
}