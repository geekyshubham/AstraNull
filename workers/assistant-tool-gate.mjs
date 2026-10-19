#!/usr/bin/env node
/** PreToolUse policy: deny before execution, including vendor URLs and redirects. */
import { fileURLToPath } from 'node:url';
import path from 'node:path';

export function assistantToolDecision(payload, allowSearchWeb = false) {
  const allowed = allowSearchWeb && payload?.toolCall?.name === 'search_web';
  return {
    decision: allowed ? 'allow' : 'deny',
    reason: allowed ? 'AstraNull permits web search for this job.' : 'AstraNull denies this tool before execution. Page reads, files, commands, browsers and MCP are not permitted.',
  };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  let input = '';
  let overflow = false;
  for await (const chunk of process.stdin) {
    if (input.length + chunk.length > 65536) overflow = true;
    if (!overflow) input += chunk;
  }
  let payload;
  try { if (!overflow) payload = JSON.parse(input); } catch { /* Malformed hook payloads are denied. */ }
  process.stdout.write(JSON.stringify(assistantToolDecision(payload, process.argv.includes('--allow-search-web'))) + '\n');
}
