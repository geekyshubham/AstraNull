import { readFileSync, readdirSync, statfsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { networkInterfaces } from 'node:os';

const config = JSON.parse(readFileSync('/source/tests/fixtures/check-delivery-connect-fault-lab.json', 'utf8'));
const available_tools = {};
for (const tool of ['node', 'timeout', 'iptables', 'nft', 'tcpdump', 'ip', 'ss', 'python3', 'gcc', 'cc']) {
  const found = spawnSync('/bin/sh', ['-c', 'command -v "$1"', 'preflight', tool], { encoding: 'utf8', timeout: 1000 });
  available_tools[tool] = found.status === 0 ? found.stdout.trim() : null;
}
const status = readFileSync('/proc/self/status', 'utf8');
const effective_capabilities = status.match(/^CapEff:\s*(\w+)$/m)?.[1];
const interfaces = readdirSync('/sys/class/net');
const mounts = readFileSync('/proc/self/mountinfo', 'utf8').split('\n');
const sourceMount = mounts.find((line) => line.split(' ')[4] === '/source');
const scratchMount = mounts.find((line) => line.split(' ')[4] === '/scratch');
const loopback = networkInterfaces().lo?.every((row) => row.internal) === true;
const missing_tools = config.required_tools.filter((tool) => !available_tools[tool]);
const blockers = [];
if (missing_tools.length) blockers.push(`missing_tools:${missing_tools.join(',')}`);
if (process.version !== config.node_version) blockers.push('node_version_mismatch');
if (interfaces.length !== 1 || interfaces[0] !== 'lo' || !loopback) blockers.push('nonisolated_network');
if (effective_capabilities !== '0000000000003000') blockers.push('capability_mismatch');
if (!sourceMount?.split(' ')[5].split(',').includes('ro')) blockers.push('source_not_readonly');
if (!scratchMount || Number(statfsSync('/scratch').blocks) * Number(statfsSync('/scratch').bsize) > config.scratch_bytes) blockers.push('scratch_not_bounded');
// Presence is not proof that the container can install a rule or observe a SYN.
// Until exact-endpoint kernel filter/capture preflight exists, execution is blocked.
blockers.push('kernel_drop_and_observation_probe_not_verified');
console.log(JSON.stringify({ schema: config.schema, status: 'blocked', image: config.image,
  platform: process.platform, node: process.version, interfaces, effective_capabilities,
  available_tools, missing_tools, blockers, coverage_receipts: 0 }, null, 2));
process.exitCode = 2;
