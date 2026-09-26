import { LockKeyhole } from 'lucide-react';
import { Card, CardContent } from './card';
import { EmptyState } from './empty-state';

const DEFAULT_BODY = 'Your role does not include this permission. Ask a tenant owner or admin if you need access.';

export function RoleRestrictedNotice({ title, body = DEFAULT_BODY }: { title: string; body?: string }) {
  return <EmptyState icon={LockKeyhole} title={title} body={body} />;
}

export function RoleRestrictedCard({ title, body }: { title: string; body?: string }) {
  return (
    <Card density="compact" data-role-restricted="true">
      <CardContent>
        <RoleRestrictedNotice title={title} body={body} />
      </CardContent>
    </Card>
  );
}
