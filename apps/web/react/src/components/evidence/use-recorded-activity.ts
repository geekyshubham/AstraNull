import { useCallback, useEffect, useRef, useState } from 'react';
import { requestJson, sessionIdentity } from '../../lib/api';
import { createActivityReaderKey, createRecordedActivityReader, EMPTY_ACTIVITY_STATE, type ActivitySubscription, type RecordedActivityReader, type RecordedActivityState } from '../../lib/recorded-activity.mjs';
import type { PortalConfig, Session } from '../../lib/types';

// Concurrent table / Inspector / console consumers share one passive poller, not separate feeds.
const activityReaderKey = createActivityReaderKey();
const readers = new Map<string, { reader: RecordedActivityReader; users: number }>();

export function useRecordedActivity({ config, session, id, kind = 'run', paused = false }: {
  config: PortalConfig; session: Session; id: string; kind?: 'run' | 'scan'; paused?: boolean;
}) {
  const scope = sessionIdentity(session);
  const key = activityReaderKey({ identity: scope, authMode: config.authMode, session, kind, id });
  const [committed, setCommitted] = useState<{ key: string; state: RecordedActivityState }>({ key: '', state: EMPTY_ACTIVITY_STATE });
  const subscription = useRef<ActivitySubscription | null>(null);
  const readerRef = useRef<RecordedActivityReader | null>(null);
  const pausedRef = useRef(paused);
  pausedRef.current = paused;

  useEffect(() => {
    if (!key) return undefined;
    let current = true;
    let entry = readers.get(key);
    if (!entry) {
      entry = { reader: createRecordedActivityReader({ kind, id, read: async (path, options) => requestJson(config, session, path, options) }), users: 0 };
      readers.set(key, entry);
    }
    entry.users += 1;
    readerRef.current = entry.reader;
    // Read the exact scope on subscribe; a paused display may retain it, never the prior tenant.
    setCommitted({ key, state: entry.reader.getState() });
    const listener = (state: RecordedActivityState) => { if (current) setCommitted({ key, state }); };
    const connected = entry.reader.subscribe(listener, !pausedRef.current);
    subscription.current = connected;
    return () => {
      current = false;
      connected.unsubscribe();
      subscription.current = null;
      readerRef.current = null;
      entry.users -= 1;
      if (!entry.users) { entry.reader.dispose(); readers.delete(key); }
    };
    // key includes exact execution, tenant/user/role and an opaque credential epoch; unrelated shell hydrates do not restart it.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);

  useEffect(() => { subscription.current?.setActive(!paused); }, [key, paused]);
  const refresh = useCallback(() => readerRef.current?.refresh(), [key]);
  return { ...(committed.key === key ? committed.state : EMPTY_ACTIVITY_STATE), refresh };
}
