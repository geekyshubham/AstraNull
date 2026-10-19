import assert from 'node:assert/strict';
import { chmod, mkdtemp, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';
import { agyArgs, parseAgyStream, parseToolCall, runAgyJob } from '../../workers/assistant-runner.mjs';

const ALLOWED = ['search_web', 'read_url_content'];
const line = (value) => JSON.stringify(value);
const init = line({ event: 'init', conversation_id: 'c1', init: { model: 'gemini-3.8-flash-low', tools: ['search_web', 'write_to_file'] } });
const search = (state) => line({ event: 'step_update', step_update: { step_index: 2, state, step_type: 'tool', tool_name: 'search_web', tool_info: { name: 'search_web', parameters: { query: 'Cloudflare rate limiting rules' } } } });
const read = line({ event: 'step_update', step_update: { step_index: 3, state: 'DONE', step_type: 'tool', tool_name: 'read_url_content', tool_info: { name: 'read_url_content', parameters: { Url: 'https://developers.cloudflare.com/waf/rate-limiting-rules/' } } } });
const answer = 'Add a rate limiting rule. See https://developers.cloudflare.com/waf/rate-limiting-rules/create-zone-dashboard/.';
const delta = line({ event: 'step_update', step_update: { step_index: 4, state: 'ACTIVE', step_type: 'agent_response', text_delta: answer } });
const result = (status = 'SUCCESS', response = answer) => line({ event: 'result', result: { status, response, num_turns: 1 } });
const SUCCESS = [init, search('ACTIVE'), search('DONE'), read, delta, result()].join('\n');
const DISALLOWED = [init, line({ event: 'step_update', step_update: { step_type: 'tool', state: 'ACTIVE', tool_name: 'write_to_file', tool_info: { name: 'write_to_file', parameters: { TargetFile: '/tmp/x' } } } }), result()].join('\n');

describe('agy stream parsing', () => {
  it('collects the answer, searches and sources', () => {
    const parsed = parseAgyStream(SUCCESS, ALLOWED);
    assert.equal(parsed.content, answer);
    assert.equal(parsed.resultStatus, 'SUCCESS');
    assert.equal(parsed.disallowedTool, '');
    assert.deepEqual(parsed.searches, ['Cloudflare rate limiting rules']);
    assert.deepEqual(parsed.sources.map((source) => source.url), [
      'https://developers.cloudflare.com/waf/rate-limiting-rules/',
      'https://developers.cloudflare.com/waf/rate-limiting-rules/create-zone-dashboard/',
    ]);
  });

  it('flags any tool outside the allow list', () => {
    assert.equal(parseAgyStream(DISALLOWED, ALLOWED).disallowedTool, 'write_to_file');
  });

  it('falls back to streamed text and reports a non-success result', () => {
    const parsed = parseAgyStream([init, delta, 'not json', result('ERROR', undefined)].join('\n'), ALLOWED);
    assert.equal(parsed.resultStatus, 'ERROR');
    assert.equal(parsed.content, answer);
  });

  it('never asks agy to skip permissions', () => {
    const args = agyArgs({ prompt: 'p', model: 'gemini-3.8-flash-high', timeout_seconds: 120 });
    assert.ok(!args.includes('--dangerously-skip-permissions'));
    for (const flag of ['--sandbox', '--mode', 'plan', '--output-format', 'stream-json', '--print-timeout', '120s']) assert.ok(args.includes(flag), flag);
  });
});

describe('tool fence parsing', () => {
  it('reads the first astranull-tool block', () => {
    const reply = 'Let me check.\n```astranull-tool\n{"name": "query_data", "args": {"dataset": "findings"}}\n```\n```astranull-tool\n{"name": "list_targets"}\n```';
    assert.deepEqual(parseToolCall(reply), { name: 'query_data', args: { dataset: 'findings' } });
    assert.deepEqual(parseToolCall('```astranull-tool\n{"name":"list_targets"}\n```'), { name: 'list_targets', args: {} });
  });

  it('ignores plain answers and flags malformed calls', () => {
    assert.equal(parseToolCall('Use a rate limiting rule.\n```json\n{"name":"x"}\n```'), null);
    for (const bad of ['{not json', '{"name":"rm -rf"}', '{"name":"list_targets","args":[1]}', '{"args":{}}']) {
      assert.deepEqual(parseToolCall(`\`\`\`astranull-tool\n${bad}\n\`\`\``), { invalid: true }, bad);
    }
  });
});

describe('agy job execution', () => {
  let dir;
  const script = async (name, body) => {
    const file = path.join(dir, name);
    await writeFile(file, `#!/usr/bin/env node\n${body}\n`);
    await chmod(file, 0o755);
    return file;
  };
  const job = { job_id: 'asj_1', prompt: 'How do I fix it?', model: 'gemini-3.8-flash-high', allowed_tools: ALLOWED, timeout_seconds: 1 };
  const workspaces = async () => (await readdir(tmpdir())).filter((name) => name.startsWith('astranull-assistant-')).length;

  before(async () => { dir = await mkdtemp(path.join(tmpdir(), 'fake-agy-')); });
  after(async () => { await rm(dir, { recursive: true, force: true }); });

  it('returns the answer from a successful run and removes the workspace', async () => {
    const before = await workspaces();
    const bin = await script('agy-ok', `const fs=require('fs');if(fs.readdirSync(process.cwd()).length)process.exit(9);if(process.env.SECRET_FROM_PARENT)process.exit(8);process.stdout.write(${JSON.stringify(SUCCESS)}+'\\n')`);
    const out = await runAgyJob(job, { agyBin: bin, env: { ...process.env, SECRET_FROM_PARENT: 'x' } });
    assert.equal(out.status, 'done');
    assert.equal(out.content, answer);
    assert.deepEqual(out.searches, ['Cloudflare rate limiting rules']);
    assert.equal(await workspaces(), before);
  });

  it('kills the run when a disallowed tool starts', async () => {
    const bin = await script('agy-bad', `process.stdout.write(${JSON.stringify(DISALLOWED.split('\n').slice(0, 2).join('\n'))}+'\\n');setInterval(()=>{},1000)`);
    const out = await runAgyJob({ ...job, timeout_seconds: 30 }, { agyBin: bin });
    assert.deepEqual({ status: out.status, error: out.error }, { status: 'failed', error: 'disallowed_tool' });
  });

  it('fails a run that reports an error or never finishes', async () => {
    const error = await script('agy-error', `process.stdout.write(${JSON.stringify(result('ERROR', ''))}+'\\n')`);
    assert.deepEqual(await runAgyJob(job, { agyBin: error }), { status: 'failed', error: 'agy_failed', detail: 'step 1 result=ERROR content=0' });
    assert.deepEqual(await runAgyJob(job, { agyBin: path.join(dir, 'missing-agy') }), { status: 'failed', error: 'agy_unavailable', detail: 'step 1' });
  });

  const agentScript = (toolReply) => `const p=process.argv[process.argv.indexOf('-p')+1];const say=(t)=>process.stdout.write(JSON.stringify({event:'result',result:{status:'SUCCESS',response:t}})+'\\n');
if(p.includes('cannot call more data tools'))say('Final without tools.');else if(p.includes('registered as Q1'))say('You have 2 high findings.\\n\\n[[data:Q1|bar]]');else say(${JSON.stringify(toolReply)});`;
  const fence = '```astranull-tool\n{"name":"query_data","args":{"dataset":"findings","group_by":"severity","filters":{"status":"open"}}}\n```';

  it('runs a tool step then answers with a data marker', async () => {
    const bin = await script('agy-agent', agentScript(fence));
    const calls = [];
    const callTool = async (name, args) => {
      calls.push({ name, args });
      return { ok: true, result_text: '<<<UNTRUSTED_DATA_BEGIN tool result query_data>>>\n{"rows":[["high",2]]}\n<<<UNTRUSTED_DATA_END>>>', data_result_id: 'Q1' };
    };
    const out = await runAgyJob({ ...job, timeout_seconds: 10, deadline_seconds: 200, max_tool_calls: 8, tools: true }, { agyBin: bin, callTool });
    assert.equal(out.status, 'done');
    assert.match(out.content, /\[\[data:Q1\|bar\]\]/);
    assert.deepEqual(calls, [{ name: 'query_data', args: { dataset: 'findings', group_by: 'severity', filters: { status: 'open' } } }]);
    assert.deepEqual(out.tool_calls, [{ name: 'query_data', summary: 'query_data (dataset=findings, group_by=severity, status=open)' }]);
  });

  it('forces a final answer once the tool budget is spent', async () => {
    const bin = await script('agy-loop', agentScript('```astranull-tool\n{"name":"list_targets","args":{}}\n```'));
    let count = 0;
    const callTool = async () => {
      count += 1;
      return count > 2 ? { error: 'tool_call_limit' } : { ok: true, result_text: 'ok' };
    };
    const out = await runAgyJob({ ...job, timeout_seconds: 10, deadline_seconds: 200, max_tool_calls: 8, tools: true }, { agyBin: bin, callTool });
    assert.deepEqual({ status: out.status, content: out.content }, { status: 'done', content: 'Final without tools.' });
    assert.equal(count, 3);
    assert.equal(out.tool_calls.length, 2);
  });

  it('answers without tools when the deadline is close', async () => {
    const bin = await script('agy-late', agentScript(fence));
    let clock = 0;
    const callTool = async () => {
      clock += 130000;
      return { ok: true, result_text: 'ok' };
    };
    const out = await runAgyJob({ ...job, timeout_seconds: 10, deadline_seconds: 200, max_tool_calls: 8, tools: true }, { agyBin: bin, callTool, now: () => clock });
    assert.deepEqual({ status: out.status, content: out.content, calls: out.tool_calls.length }, { status: 'done', content: 'Final without tools.', calls: 1 });
  });

  it('does not run tool fences when the lease has no tools', async () => {
    const bin = await script('agy-notools', agentScript(fence));
    const out = await runAgyJob({ ...job, timeout_seconds: 10 }, { agyBin: bin });
    assert.equal(out.status, 'done');
    assert.deepEqual(out.tool_calls, []);
  });

  it('kills a run that outlives its time limit', async () => {
    const hang = await script('agy-hang', 'setInterval(()=>{},1000)');
    assert.equal((await runAgyJob({ ...job, timeout_seconds: 0 }, { agyBin: hang, graceSeconds: 0.3 })).error, 'runner_timeout');
  });
});

describe('assistant runner page-read allowlist', () => {
  it('kills a read_url_content call to a non-documentation or private host', async () => {
    const { parseAgyStream } = await import('../../workers/assistant-runner.mjs');
    const step = (url) => JSON.stringify({ event: 'step_update', step_update: { step_type: 'tool', state: 'ACTIVE', tool_name: 'read_url_content', tool_info: { name: 'read_url_content', parameters: { url } } } });
    const allowed = new Set(['search_web', 'read_url_content']);
    assert.equal(parseAgyStream(step('https://developers.cloudflare.com/waf/rate-limiting-rules/'), allowed).disallowedTool, '');
    for (const url of ['http://169.254.169.254/latest/meta-data/', 'https://evil.example.com/?d=secret', 'http://localhost:3006/v1/findings', 'https://10.0.0.5/', 'https://docs.aws.amazon.com.evil.net/x']) {
      assert.equal(parseAgyStream(step(url), allowed).disallowedTool, 'read_url_content:blocked_host', url);
    }
  });
});
