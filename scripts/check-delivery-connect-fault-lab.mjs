import assert from 'node:assert/strict';
import { readFileSync, realpathSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, resolve } from 'node:path';
import { randomUUID } from 'node:crypto';
import { spawnSync } from 'node:child_process';

const root = realpathSync(resolve(dirname(fileURLToPath(import.meta.url)), '..'));
export const CONNECT_FAULT_LAB_CONFIG = Object.freeze(JSON.parse(readFileSync(resolve(root, 'tests/fixtures/check-delivery-connect-fault-lab.json'), 'utf8')));

export function connectFaultContainerArguments(name) {
  const config = CONNECT_FAULT_LAB_CONFIG;
  assert.match(name, /^astranull-connect-fault-[a-f0-9-]+$/);
  assert.match(config.image, /^sha256:[a-f0-9]{64}$/);
  return ['create', '--name', name, '--pull', 'never', '--network', 'none', '--read-only',
    '--cap-drop', 'ALL', '--cap-add', 'NET_ADMIN', '--cap-add', 'NET_RAW',
    '--security-opt', 'no-new-privileges', '--cpus', String(config.cpus),
    '--memory', String(config.memory_bytes), '--memory-swap', String(config.memory_bytes),
    '--pids-limit', String(config.pids_limit), '--user', '0:0',
    '--mount', `type=bind,src=${root},dst=/source,readonly`,
    '--tmpfs', `/scratch:rw,noexec,nosuid,nodev,size=${config.scratch_bytes},mode=0700`,
    '--workdir', '/scratch', '--entrypoint', '/usr/bin/timeout', config.image,
    '--signal=KILL', String(config.runtime_seconds), '/usr/local/bin/node',
    '/source/tests/fixtures/check-delivery-connect-fault-preflight.mjs'];
}

export function assertConnectFaultContainerIsolation(container) {
  const { HostConfig: host, Config: config, Mounts: mounts } = container;
  assert.equal(container.Image, CONNECT_FAULT_LAB_CONFIG.image);
  assert.equal(host.NetworkMode, 'none');
  assert.equal(host.Privileged, false);
  assert.equal(host.ReadonlyRootfs, true);
  assert.equal(host.PidMode, '');
  assert.notEqual(host.IpcMode, 'host');
  assert.equal(host.NanoCpus, CONNECT_FAULT_LAB_CONFIG.cpus * 1e9);
  assert.equal(host.Memory, CONNECT_FAULT_LAB_CONFIG.memory_bytes);
  assert.equal(host.MemorySwap, CONNECT_FAULT_LAB_CONFIG.memory_bytes);
  assert.equal(host.PidsLimit, CONNECT_FAULT_LAB_CONFIG.pids_limit);
  assert.deepEqual(host.CapDrop, ['ALL']);
  assert.deepEqual(host.CapAdd.map((cap) => cap.replace(/^CAP_/, '')).sort(), ['NET_ADMIN', 'NET_RAW']);
  assert.ok(host.SecurityOpt.includes('no-new-privileges'));
  assert.equal(Object.keys(host.PortBindings ?? {}).length, 0);
  assert.equal(host.PublishAllPorts, false);
  assert.equal(host.Devices?.length ?? 0, 0);
  assert.equal(host.DeviceRequests?.length ?? 0, 0);
  assert.equal(mounts.length, 1);
  assert.equal(mounts[0].Type, 'bind');
  assert.equal(mounts[0].Source, root);
  assert.equal(mounts[0].Destination, '/source');
  assert.equal(mounts[0].RW, false);
  assert.deepEqual(Object.keys(host.Tmpfs), ['/scratch']);
  assert.equal(host.Tmpfs['/scratch'], `rw,noexec,nosuid,nodev,size=${CONNECT_FAULT_LAB_CONFIG.scratch_bytes},mode=0700`);
  assert.equal(config.WorkingDir, '/scratch');
  assert.deepEqual(config.Entrypoint, ['/usr/bin/timeout']);
  assert.deepEqual(config.Cmd, ['--signal=KILL', String(CONNECT_FAULT_LAB_CONFIG.runtime_seconds),
    '/usr/local/bin/node', '/source/tests/fixtures/check-delivery-connect-fault-preflight.mjs']);
}

export function preflightConnectFaultLab() {
  const run = (args, timeout = 10_000) => spawnSync('docker', args, { encoding: 'utf8', timeout, maxBuffer: 1024 * 1024 });
  const cached = run(['image', 'inspect', CONNECT_FAULT_LAB_CONFIG.image]);
  if (cached.status !== 0) {
    console.log(JSON.stringify({ status: 'blocked', blockers: ['pinned_cached_image_unavailable'],
      image: CONNECT_FAULT_LAB_CONFIG.image, detail: cached.error?.message ?? cached.stderr, coverage_receipts: 0 }, null, 2));
    return 2;
  }
  const name = `astranull-connect-fault-${randomUUID()}`;
  try {
    const created = run(connectFaultContainerArguments(name));
    assert.equal(created.status, 0, created.stderr || created.error?.message);
    const inspected = run(['inspect', name]);
    assert.equal(inspected.status, 0, inspected.stderr || inspected.error?.message);
    assertConnectFaultContainerIsolation(JSON.parse(inspected.stdout)[0]);
    const result = run(['start', '--attach', name], (CONNECT_FAULT_LAB_CONFIG.runtime_seconds + 5) * 1000);
    process.stdout.write(result.stdout ?? '');
    if (result.stderr) process.stderr.write(result.stderr);
    assert.ok(!result.error, result.error?.message);
    assert.equal(result.status, 2, 'preflight must remain blocked without independently verified kernel-drop/capture evidence');
    return 2;
  } catch (error) {
    console.log(JSON.stringify({ status: 'blocked', blockers: ['isolation_or_preflight_failed'], detail: error.message, coverage_receipts: 0 }, null, 2));
    return 2;
  } finally {
    const removed = run(['rm', '--force', name]);
    if (removed.status !== 0) throw new Error(`Owned preflight container cleanup failed: ${removed.stderr || removed.error?.message}`);
  }
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  assert.ok(process.argv.slice(2).every((arg) => arg === '--preflight'), 'Only fail-closed preflight is currently implemented');
  process.exitCode = preflightConnectFaultLab();
}
