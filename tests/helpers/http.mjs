export async function request(baseUrl, method, path, { headers = {}, body, rawBody } = {}) {
  let payload;
  if (rawBody !== undefined) {
    payload = rawBody;
  } else if (body !== undefined) {
    payload = JSON.stringify(body);
  }
  const res = await fetch(`${baseUrl}${path}`, {
    method,
    headers: {
      ...(payload !== undefined ? { 'Content-Type': 'application/json' } : {}),
      ...headers,
    },
    body: payload,
    signal: AbortSignal.timeout(Number(process.env.ASTRANULL_TEST_HTTP_TIMEOUT_MS ?? 30_000)),
  });
  const text = await res.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = { raw: text };
  }
  return {
    status: res.status,
    json,
    text,
    headers: Object.fromEntries(res.headers.entries()),
  };
}

/**
 * Shut a test server down completely, awaiting the close.
 *
 * Resource hygiene, not a bug fix. A file like server-postgres-mode.test.mjs binds ~66
 * servers in one process; `server.close()` un-awaited leaves the listener and any
 * ESTABLISHED keep-alive sockets outliving the test that created them, so descriptors
 * accumulate for the rest of the run. `closeAllConnections()` destroys the sockets
 * `close()` deliberately leaves serving, and awaiting the callback means the port is
 * actually released before the next test binds.
 *
 * Explicitly NOT a fix for the intermittent wrong-status failures in that file. That was
 * the hypothesis this helper was written under, and it was measured and refuted: the
 * failure rate was 3/150 before and 3/150 after, and it survives both
 * `--test-concurrency=1` and a forced `Connection: close`. Do not cite this helper as
 * having fixed a flake.
 *
 * Resolves rather than rejects when the server was never listening: ERR_SERVER_NOT_RUNNING
 * in cleanup is not a test failure, and rejecting there would mask the real assertion.
 */
export async function closeServer(server) {
  if (!server) return;
  server.closeAllConnections?.();
  await new Promise((resolve) => {
    server.close(() => resolve());
  });
}

export function demoHeaders(role = 'admin', tenant = 'ten_demo', user = 'usr_admin') {
  return {
    'x-tenant-id': tenant,
    'x-user-id': user,
    'x-role': role,
  };
}

export function signedSessionHeaders(
  role = 'admin',
  tenant = 'ten_demo',
  user = 'usr_admin',
  secret,
  mintFn,
) {
  const token = mintFn(
    { tenantId: tenant, userId: user, role },
    secret,
  );
  return { Authorization: `Bearer ${token}` };
}

export function staffHeaders(role = 'internal_admin', staffId = 'staff_admin') {
  return {
    'x-principal-type': 'staff',
    'x-staff-id': staffId,
    'x-staff-role': role,
  };
}

export function agentHeaders(credential, tenant = 'ten_demo') {
  return {
    'x-tenant-id': tenant,
    'x-user-id': 'agent',
    Authorization: `Bearer ${credential}`,
  };
}