import { spawnSync } from 'node:child_process';

const DEFAULT_APP_NAME = 'astranull';

/**
 * @param {string} [appName]
 */
export function resolveDigitalOceanAppId(appName = DEFAULT_APP_NAME) {
  const result = spawnSync(
    'doctl',
    ['apps', 'list', '--format', 'ID,Spec.Name', '--no-header'],
    { encoding: 'utf8' },
  );
  if (result.status !== 0) {
    const detail = [result.stdout, result.stderr].filter(Boolean).join('\n').trim();
    throw new Error(`doctl apps list failed${detail ? `: ${detail}` : ''}`);
  }

  for (const line of String(result.stdout ?? '').split('\n')) {
    const [id, name] = line.trim().split(/\s+/, 2);
    if (name === appName && id) return id;
  }

  throw new Error(`DigitalOcean app "${appName}" was not found.`);
}

/**
 * @param {string} appId
 */
export function resolveDigitalOceanWebInstanceName(appId) {
  const result = spawnSync('doctl', ['apps', 'list-instances', appId, 'web', '-o', 'json'], {
    encoding: 'utf8',
  });
  if (result.status !== 0) {
    const detail = [result.stdout, result.stderr].filter(Boolean).join('\n').trim();
    throw new Error(`doctl apps list-instances failed${detail ? `: ${detail}` : ''}`);
  }

  const instances = JSON.parse(String(result.stdout ?? '[]').trim() || '[]');
  const instanceName = instances.find((row) => row?.instance_name)?.instance_name;
  if (!instanceName) {
    throw new Error(`No running web instance found for app ${appId}.`);
  }
  return instanceName;
}

/**
 * @param {string} databaseUrl
 */
export function redactDatabaseUrl(databaseUrl) {
  try {
    const url = new URL(databaseUrl);
    if (url.password) url.password = '***';
    return url.toString();
  } catch {
    return '<invalid-database-url>';
  }
}

/**
 * Resolve hosted App Platform Postgres URL via doctl console.
 *
 * @param {{
 *   appId?: string,
 *   appName?: string,
 *   instanceName?: string,
 *   envVar?: string,
 * }} [options]
 */
export function resolveDigitalOceanDatabaseUrl(options = {}) {
  const explicit = String(process.env.ASTRANULL_DATABASE_URL ?? '').trim();
  if (explicit) return explicit;

  const appId = options.appId ?? resolveDigitalOceanAppId(options.appName ?? DEFAULT_APP_NAME);
  const instanceName = options.instanceName ?? resolveDigitalOceanWebInstanceName(appId);
  const envVar = options.envVar ?? 'ASTRANULL_DATABASE_URL';

  const expectScript = `
set timeout 60
spawn doctl apps console ${appId} web --instance-name ${instanceName}
expect {
  -re {[#$%>] } {
    send "printenv ${envVar}\\r"
    exp_continue
  }
  -re {postgresql://[^\\r\\n]+} {
    puts $expect_out(0,string)
    send "exit\\r"
  }
  timeout { exit 1 }
  eof
}
`;

  const result = spawnSync('expect', ['-c', expectScript], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  if (result.status !== 0) {
    const detail = [result.stdout, result.stderr].filter(Boolean).join('\n').trim();
    throw new Error(`Failed to read ${envVar} from App Platform console${detail ? `: ${detail}` : ''}`);
  }

  const match = String(result.stdout ?? '').match(/postgresql:\/\/[^\s]+/);
  if (!match) {
    throw new Error(`App Platform console did not return a PostgreSQL URL for ${envVar}.`);
  }

  return match[0];
}