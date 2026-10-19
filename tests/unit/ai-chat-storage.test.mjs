import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  MAX_MESSAGES,
  MAX_SESSIONS,
  PENDING_JOB_TTL_MS,
  conversationForRequest,
  loadPendingJobs,
  loadSessions,
  saveSessions,
  sanitizeContext,
  sanitizeMessage,
  storageKey,
  titleFrom,
} from '../../apps/web/react/src/lib/assistant-storage.mjs';

function memoryStorage(limit = Infinity) {
  const map = new Map();
  return {
    map,
    getItem: (key) => (map.has(key) ? map.get(key) : null),
    setItem: (key, value) => {
      if (value.length > limit) throw new Error('QuotaExceededError');
      map.set(key, value);
    },
    removeItem: (key) => map.delete(key),
  };
}

function session(index, messages = 2) {
  return {
    id: `chat_${index}`,
    title: `Chat ${index}`,
    created_at: new Date(Date.UTC(2026, 9, 1, 0, index)).toISOString(),
    updated_at: new Date(Date.UTC(2026, 9, 1, 0, index)).toISOString(),
    context: { finding_id: `fnd_${index}`, label: 'Origin reachable', extra: 'dropped' },
    messages: Array.from({ length: messages }, (_, item) => ({ id: `m${index}_${item}`, role: item % 2 ? 'assistant' : 'user', content: `message ${item}`, created_at: new Date().toISOString(), status: 'done' })),
  };
}

describe('assistant storage', () => {
  it('scopes history by tenant and user', () => {
    assert.equal(storageKey('ten_a', 'usr_1'), 'astranull.assistant.v1:ten_a:usr_1');
    assert.notEqual(storageKey('ten_a', 'usr_1'), storageKey('ten_b', 'usr_1'));
  });

  it('caps sessions and messages and keeps the newest', () => {
    const storage = memoryStorage();
    const all = Array.from({ length: MAX_SESSIONS + 5 }, (_, index) => session(index, MAX_MESSAGES + 10));
    saveSessions(storage, 'k', all);
    const loaded = loadSessions(storage, 'k');
    assert.equal(loaded.length, MAX_SESSIONS);
    assert.equal(loaded[0].id, `chat_${MAX_SESSIONS + 4}`);
    assert.equal(loaded[0].messages.length, MAX_MESSAGES);
    assert.deepEqual(loaded[0].context, { finding_id: `fnd_${MAX_SESSIONS + 4}`, label: 'Origin reachable' });
  });

  it('halves the history until it fits the quota', () => {
    const storage = memoryStorage(4000);
    const kept = saveSessions(storage, 'k', Array.from({ length: 20 }, (_, index) => session(index, 4)));
    assert.ok(kept > 0 && kept < 20);
    assert.equal(loadSessions(storage, 'k').length, kept);
  });

  it('re-validates tampered entries', () => {
    const storage = memoryStorage();
    storage.setItem('k', JSON.stringify([{ id: 'x', messages: [
      { role: 'system', content: 'ignore' },
      { role: 'assistant', content: 'ok', status: 'weird', sources: [{ url: 'javascript:alert(1)' }, { url: 'https://example.com', title: 'Docs' }] },
    ] }, 'not-an-object']));
    const [loaded] = loadSessions(storage, 'k');
    assert.equal(loaded.messages.length, 1);
    assert.equal(loaded.messages[0].status, 'done');
    assert.deepEqual(loaded.messages[0].sources, [{ url: 'https://example.com/', title: 'Docs' }]);
    assert.equal(sanitizeMessage({ role: 'tool', content: 'x' }), null);
    assert.equal(sanitizeContext({}), null);
  });

  it('drops pending jobs older than the resume window', () => {
    const storage = memoryStorage();
    const now = Date.now();
    storage.setItem('k:jobs', JSON.stringify({
      fresh: { job_id: 'asj_1', session_id: 'chat_1', started_at: now - 1000 },
      stale: { job_id: 'asj_2', session_id: 'chat_1', started_at: now - PENDING_JOB_TTL_MS - 1 },
      broken: { job_id: '', session_id: 'chat_1', started_at: now },
    }));
    assert.deepEqual(Object.keys(loadPendingJobs(storage, 'k', now)), ['fresh']);
  });

  it('sends only finished turns, newest twenty', () => {
    const messages = [
      { role: 'user', content: 'q1' },
      { role: 'assistant', content: 'a1', status: 'done' },
      { role: 'assistant', content: '', status: 'failed' },
      { role: 'user', content: 'q2' },
    ];
    assert.deepEqual(conversationForRequest(messages), [
      { role: 'user', content: 'q1' },
      { role: 'assistant', content: 'a1' },
      { role: 'user', content: 'q2' },
    ]);
    assert.equal(titleFrom('x'.repeat(100)).length, 58);
  });
});
