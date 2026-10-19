import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { assistantToolDecision } from '../../workers/assistant-tool-gate.mjs';
import { installAssistantToolGate } from '../../workers/assistant-runner.mjs';

test('pre-execution gate allows only the exact search tool and denies tool-less jobs', () => {
  const call = (name) => ({ toolCall: { name, args: { url: 'http://169.254.169.254/latest/meta-data/' } } });
  assert.equal(assistantToolDecision(call('search_web'), true).decision, 'allow');
  for (const name of ['read_url_content', 'run_command', 'write_to_file', 'browser_subagent', 'mcp_search_web', 'SEARCH_WEB', '', 'search_web;read_url_content']) {
    assert.equal(assistantToolDecision(call(name), true).decision, 'deny', name);
  }
  assert.equal(assistantToolDecision(call('search_web'), false).decision, 'deny');
  assert.equal(assistantToolDecision(null, true).decision, 'deny');
});

test('installed wildcard hook denies before dispatch and fails closed on malformed input', async () => {
  const workspace = await mkdtemp(path.join(tmpdir(), "gate-space-'quoted-"));
  try {
    for (const tools of [[], ['search_web', 'read_url_content', 'run_command']]) {
      await installAssistantToolGate(workspace, tools);
      const config = JSON.parse(await readFile(path.join(workspace, '.agents/hooks.json'), 'utf8'));
      const hook = config['astranull-search-only'].PreToolUse[0];
      assert.equal(hook.matcher, '*');
      const decide = (input) => JSON.parse(execFileSync('/bin/sh', ['-c', hook.hooks[0].command], { cwd: path.join(workspace, '.agents'), input, encoding: 'utf8' }));
      for (const url of ['https://developers.cloudflare.com/', 'http://localhost/', 'http://169.254.169.254/']) {
        const decision = decide(JSON.stringify({ toolCall: { name: 'read_url_content', args: { url } } }));
        let dispatched = false;
        if (decision.decision === 'allow') dispatched = true;
        assert.equal(dispatched, false, url);
      }
      assert.equal(decide(JSON.stringify({ toolCall: { name: 'search_web' } })).decision, tools.includes('search_web') ? 'allow' : 'deny');
      for (const input of ['', '{bad json', 'x'.repeat(65537), '{"tool_name":"search_web"}']) {
        assert.equal(decide(input).decision, 'deny');
      }
      await rm(path.join(workspace, '.agents'), { recursive: true });
    }
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
});
