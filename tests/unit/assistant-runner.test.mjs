import assert from 'node:assert/strict';
import { chmod, mkdtemp, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { stat, readFile } from 'node:fs/promises';
import { after, before, describe, it } from 'node:test';
import { agyArgs, parseAgyStream, parseToolCall, runAgyJob, runAssistantRunner } from '../../workers/assistant-runner.mjs';

const ALLOWED = ['search_web'];
const line = (value) => JSON.stringify(value);
const init = line({ event: 'init', conversation_id: 'c1', init: { model: 'gemini-3.8-flash-low', tools: ['search_web', 'write_to_file'] } });
const search = (state) => line({ event: 'step_update', step_update: { step_index: 2, state, step_type: 'tool', tool_name: 'search_web', tool_info: { name: 'search_web', parameters: { query: 'Cloudflare rate limiting rules' } } } });
const read = line({ event: 'step_update', step_update: { step_index: 3, state: 'DONE', step_type: 'tool', tool_name: 'read_url_content', tool_info: { name: 'read_url_content', parameters: { Url: 'https://developers.cloudflare.com/waf/rate-limiting-rules/' } } } });
const answer = 'Add a rate limiting rule. See https://developers.cloudflare.com/waf/rate-limiting-rules/create-zone-dashboard/.';
const delta = line({ event: 'step_update', step_update: { step_index: 4, state: 'ACTIVE', step_type: 'agent_response', text_delta: answer } });
const result = (status = 'SUCCESS', response = answer) => line({ event: 'result', result: { status, response, num_turns: 1 } });
const SUCCESS = [init, search('ACTIVE'), search('DONE'), delta, result()].join('\n');
const DISALLOWED = [init, line({ event: 'step_update', step_update: { step_type: 'tool', state: 'ACTIVE', tool_name: 'write_to_file', tool_info: { name: 'write_to_file', parameters: { TargetFile: '/tmp/x' } } } }), result()].join('\n');

describe('agy stream parsing', () => {
  it('collects the answer, searches and sources', () => {
    const parsed = parseAgyStream(SUCCESS, ALLOWED);
    assert.equal(parsed.content, answer);
    assert.equal(parsed.resultStatus, 'SUCCESS');
    assert.equal(parsed.disallowedTool, '');
    assert.deepEqual(parsed.searches, ['Cloudflare rate limiting rules']);
    assert.deepEqual(parsed.sources.map((source) => source.url), [
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
    const bin = await script('agy-ok', `const fs=require('fs');if(JSON.stringify(fs.readdirSync(process.cwd()))!==JSON.stringify(['.agents']))process.exit(9);if(!fs.existsSync('.agents/hooks.json'))process.exit(7);if(process.env.SECRET_FROM_PARENT)process.exit(8);process.stdout.write(${JSON.stringify(SUCCESS)}+'\\n')`);
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

describe('assistant runner page-read policy', () => {
  it('rejects every page read even when an older lease lists it as allowed', () => {
    const step = (url) => JSON.stringify({ event: 'step_update', step_update: { step_type: 'tool', state: 'ACTIVE', tool_name: 'read_url_content', tool_info: { name: 'read_url_content', parameters: { url } } } });
    for (const url of ['https://developers.cloudflare.com/waf/rate-limiting-rules/', 'http://169.254.169.254/latest/meta-data/', 'https://evil.example.com/?d=secret', 'http://localhost:3006/v1/findings', 'https://10.0.0.5/', 'https://docs.aws.amazon.com.evil.net/x']) {
      assert.equal(parseAgyStream(step(url), ['search_web', 'read_url_content']).disallowedTool, 'read_url_content', url);
    }
  });
});

describe('assistant runner lifecycle', () => {
  const TOKEN = 'runner-token-synthetic-0123456789abcdef';
  const KEY = 'sk-test-synthetic-key-0123456789';
  let dir;
  before(async () => { dir = await mkdtemp(path.join(tmpdir(), 'runner-life-')); });
  after(async () => { await rm(dir, { recursive: true, force: true }); });

  const collector = () => {
    const lines = [];
    return { lines, info: (line) => lines.push(['info', line]), warn: (line) => lines.push(['warn', line]) };
  };
  const runFor = async (env, ms, extra = {}) => {
    const log = collector();
    const controller = new AbortController();
    const done = runAssistantRunner({ env, log, signal: controller.signal, ...extra });
    await new Promise((resolve) => setTimeout(resolve, ms));
    controller.abort();
    return { result: await done, log };
  };

  it('idles with one reason line and a heartbeat when the runner token is missing', async () => {
    const heartbeat = path.join(dir, 'idle-token.heartbeat');
    const { result, log } = await runFor({ ASTRANULL_WORKER_HEARTBEAT_FILE: heartbeat, ASTRANULL_ASSISTANT_LLM_API_KEY: KEY }, 100);
    assert.equal(result.mode, 'idle');
    assert.equal(log.lines.length, 1);
    assert.match(log.lines[0][1], /idle.*ASTRANULL_ASSISTANT_RUNNER_TOKEN/);
    assert.ok(!log.lines[0][1].includes(KEY));
    assert.match(await readFile(heartbeat, 'utf8'), /^\d{4}-\d{2}-\d{2}T/);
    assert.equal((await stat(heartbeat)).mode & 0o777, 0o600);
  });

  it('idles when the openai backend has no base URL or no API key without leaking the token', async () => {
    for (const extra of [{ ASTRANULL_ASSISTANT_LLM_API_KEY: KEY }, { ASTRANULL_ASSISTANT_LLM_BASE_URL: 'https://llm.example.com/v1' }]) {
      const heartbeat = path.join(dir, `idle-${Object.keys(extra)[0]}.heartbeat`);
      const { result, log } = await runFor({ ASTRANULL_ASSISTANT_RUNNER_TOKEN: TOKEN, ASTRANULL_ASSISTANT_RUNNER_BACKEND: 'openai', ASTRANULL_WORKER_HEARTBEAT_FILE: heartbeat, ...extra }, 100);
      assert.equal(result.mode, 'idle');
      assert.equal(log.lines.length, 1);
      assert.match(log.lines[0][1], /idle/);
      assert.ok(!log.lines[0][1].includes(TOKEN) && !log.lines[0][1].includes(KEY));
      assert.ok((await stat(heartbeat)).isFile());
    }
  });

  it('idles on an invalid backend name or invalid static headers instead of crashing', async () => {
    const base = { ASTRANULL_ASSISTANT_RUNNER_TOKEN: TOKEN };
    const bad = await runFor({ ...base, ASTRANULL_ASSISTANT_RUNNER_BACKEND: 'other' }, 50);
    assert.equal(bad.result.mode, 'idle');
    const headers = await runFor({ ...base, ASTRANULL_ASSISTANT_RUNNER_BACKEND: 'openai', ASTRANULL_ASSISTANT_LLM_BASE_URL: 'https://llm.example.com/v1', ASTRANULL_ASSISTANT_LLM_API_KEY: KEY, ASTRANULL_ASSISTANT_LLM_HEADERS: '{"Authorization":"x"}' }, 50);
    assert.equal(headers.result.mode, 'idle');
    assert.match(headers.log.lines[0][1], /ASTRANULL_ASSISTANT_LLM_HEADERS/);
  });

  it('idles when the agy backend is selected but the executable is missing', async () => {
    const { result, log } = await runFor({ ASTRANULL_ASSISTANT_RUNNER_TOKEN: TOKEN, PATH: dir, AGY_BIN: 'agy-not-installed' }, 50);
    assert.equal(result.mode, 'idle');
    assert.match(log.lines[0][1], /agy/);
  });

  it('survives an unwritable heartbeat path', async () => {
    const { result, log } = await runFor({ ASTRANULL_WORKER_HEARTBEAT_FILE: path.join(dir, 'missing-dir', 'hb') }, 50);
    assert.equal(result.mode, 'idle');
    assert.ok(log.lines.some(([level]) => level === 'warn'));
  });

  it('refreshes the heartbeat while polling an empty queue', async () => {
    const heartbeat = path.join(dir, 'poll.heartbeat');
    let leases = 0;
    const server = http.createServer((req, res) => {
      leases += 1;
      assert.equal(req.headers.authorization, `Bearer ${TOKEN}`);
      res.writeHead(204).end();
    });
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    try {
      const { result, log } = await runFor({
        ASTRANULL_API_URL: `http://127.0.0.1:${server.address().port}`,
        ASTRANULL_ASSISTANT_RUNNER_TOKEN: TOKEN,
        ASTRANULL_ASSISTANT_RUNNER_BACKEND: 'openai',
        ASTRANULL_ASSISTANT_LLM_BASE_URL: 'https://llm.example.com/v1',
        ASTRANULL_ASSISTANT_LLM_API_KEY: KEY,
        ASTRANULL_WORKER_HEARTBEAT_FILE: heartbeat,
      }, 300);
      assert.equal(result.mode, 'stopped');
      assert.ok(leases >= 1);
      assert.ok((await stat(heartbeat)).isFile());
      assert.match(log.lines[0][1], /polling.*backend=openai/);
      assert.ok(!JSON.stringify(log.lines).includes(KEY) && !JSON.stringify(log.lines).includes(TOKEN));
    } finally {
      server.closeAllConnections?.();
      await new Promise((resolve) => server.close(resolve));
    }
  });
});
