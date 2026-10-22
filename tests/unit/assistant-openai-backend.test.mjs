import assert from 'node:assert/strict';
import { chmod, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import http from 'node:http';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { after, afterEach, before, describe, it } from 'node:test';
import { createOpenAiStepRunner, parseLlmBaseUrl, parseStaticHeaders, resolveOpenAiConfig, resolveRunnerBackend } from '../../workers/assistant-openai-backend.mjs';
import { runAssistantJob } from '../../workers/assistant-runner.mjs';

const KEY = 'sk-test-synthetic-key-0123456789';
const completion = (content, extra = {}) => ({ choices: [{ finish_reason: 'stop', message: { role: 'assistant', content, ...extra } }] });
const fence = '```astranull-tool\n{"name":"list_targets","args":{}}\n```';
const job = { job_id: 'asj_1', prompt: 'How do I fix it?', model: 'gemini-3.8-flash-high', allowed_tools: ['search_web'], timeout_seconds: 5 };
const toolJob = { ...job, timeout_seconds: 10, deadline_seconds: 200, max_tool_calls: 8, tools: true };

describe('openai-compatible backend', () => {
  let server;
  let base;
  let dir;
  let requests;
  let handler;

  before(async () => {
    dir = await mkdtemp(path.join(tmpdir(), 'fake-llm-'));
    server = http.createServer((req, res) => {
      let body = '';
      req.on('data', (chunk) => { body += chunk; });
      req.on('end', () => {
        const parsed = body ? JSON.parse(body) : {};
        requests.push({ url: req.url, auth: req.headers.authorization, headers: req.headers, body: parsed });
        handler(req, res, parsed);
      });
    });
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    base = `http://127.0.0.1:${server.address().port}/v1`;
  });
  after(async () => {
    server.closeAllConnections?.();
    await new Promise((resolve) => server.close(resolve));
    await rm(dir, { recursive: true, force: true });
  });
  afterEach(() => { requests = []; });

  const reply = (status, payload) => (req, res) => {
    res.writeHead(status, { 'content-type': 'application/json' });
    res.end(JSON.stringify(payload));
  };
  const config = (extra = {}) => resolveOpenAiConfig({ ASTRANULL_ASSISTANT_LLM_BASE_URL: base, ASTRANULL_ASSISTANT_LLM_API_KEY: KEY, ...extra });
  const step = async (extra) => createOpenAiStepRunner(await config(extra));

  it('runs one step against chat/completions with bearer auth, no tools and room for reasoning', async () => {
    requests = [];
    handler = reply(200, completion('Add a rate limit rule.', { reasoning_content: 'SECRET-REASONING' }));
    const out = await runAssistantJob(job, await step());
    assert.equal(out.status, 'done');
    assert.equal(out.content, 'Add a rate limit rule.');
    assert.ok(!JSON.stringify(out).includes('SECRET-REASONING'));
    assert.equal(requests.length, 1);
    const [{ url, auth, body }] = requests;
    assert.equal(url, '/v1/chat/completions');
    assert.equal(auth, `Bearer ${KEY}`);
    assert.equal(body.model, 'deepseek-v4-flash');
    assert.ok(body.max_tokens >= 4096);
    assert.ok(!('tools' in body) && !('functions' in body));
    assert.match(body.messages[0].content, /Web search and page browsing are not available/);
  });

  it('drives the tool-fence loop to a final answer', async () => {
    requests = [];
    handler = (req, res, body) => {
      const prompt = body.messages[0].content;
      const text = prompt.includes('Tool result (data') ? 'You have 2 targets.' : fence;
      reply(200, completion(text))(req, res);
    };
    const calls = [];
    const callTool = async (name, args) => {
      calls.push({ name, args });
      return { ok: true, result_text: 'two rows' };
    };
    const out = await runAssistantJob(toolJob, await step(), { callTool });
    assert.deepEqual({ status: out.status, content: out.content }, { status: 'done', content: 'You have 2 targets.' });
    assert.deepEqual(calls, [{ name: 'list_targets', args: {} }]);
    assert.equal(out.tool_calls.length, 1);
    assert.equal(requests.length, 2);
  });

  it('answers insight jobs with no tools', async () => {
    handler = reply(200, completion('{"summary":"ok","takeaways":["a"]}'));
    const out = await runAssistantJob({ ...job, allowed_tools: [], timeout_seconds: 90, deadline_seconds: 90, tools: false, max_tool_calls: 0 }, await step());
    assert.equal(out.status, 'done');
    assert.equal(out.content, '{"summary":"ok","takeaways":["a"]}');
  });

  it('retries empty content once then fails with a clear error', async () => {
    requests = [];
    handler = reply(200, completion('', { reasoning_content: 'thinking only' }));
    const out = await runAssistantJob(job, await step());
    assert.deepEqual({ status: out.status, error: out.error }, { status: 'failed', error: 'llm_empty_response' });
    assert.equal(requests.length, 2);
    requests = [];
    let count = 0;
    handler = (req, res) => reply(200, completion(count++ ? 'Second try.' : ' '))(req, res);
    assert.equal((await runAssistantJob(job, await step())).content, 'Second try.');
  });

  it('maps upstream failures without leaking bodies, prompts or keys', async () => {
    for (const [status, error] of [[401, 'llm_auth_failed'], [403, 'llm_auth_failed'], [429, 'llm_rate_limited'], [500, 'llm_unavailable'], [503, 'llm_unavailable'], [400, 'llm_failed']]) {
      handler = reply(status, { error: { message: `leak ${KEY} How do I fix it?` } });
      const out = await runAssistantJob(job, await step());
      assert.equal(out.status, 'failed');
      assert.equal(out.error, error);
      assert.ok(!JSON.stringify(out).includes(KEY));
      assert.ok(!JSON.stringify(out).includes('leak'));
      assert.ok(!JSON.stringify(out).includes('fix it'));
    }
  });

  it('maps a slow upstream to llm_timeout', async () => {
    handler = () => {};
    const out = await runAssistantJob({ ...job, timeout_seconds: 1 }, await step());
    assert.deepEqual({ status: out.status, error: out.error }, { status: 'failed', error: 'llm_timeout' });
  });

  it('maps malformed bodies and unreachable hosts', async () => {
    handler = (req, res) => { res.writeHead(200); res.end('not json'); };
    assert.equal((await runAssistantJob(job, await step())).error, 'llm_bad_response');
    handler = (req, res) => { res.writeHead(302, { location: 'http://127.0.0.1:1/' }); res.end(); };
    assert.equal((await runAssistantJob(job, await step())).error, 'llm_unreachable');
    const dead = await resolveOpenAiConfig({ ASTRANULL_ASSISTANT_LLM_BASE_URL: 'http://127.0.0.1:1', ASTRANULL_ASSISTANT_LLM_API_KEY: KEY });
    assert.equal((await runAssistantJob(job, createOpenAiStepRunner(dead))).error, 'llm_unreachable');
  });

  it('keeps the key out of logs, argv and results', async () => {
    const keyFile = path.join(dir, 'key');
    await writeFile(keyFile, `  ${KEY}\n`, { mode: 0o600 });
    const resolved = await resolveOpenAiConfig({ ASTRANULL_ASSISTANT_LLM_BASE_URL: base, ASTRANULL_ASSISTANT_LLM_API_KEY_FILE: keyFile });
    assert.equal(resolved.apiKey, KEY);
    handler = reply(200, completion('Fine.'));
    const out = await runAssistantJob(job, createOpenAiStepRunner(resolved));
    assert.ok(!JSON.stringify(out).includes(KEY));
    assert.ok(!process.argv.join(' ').includes(KEY));

    const env = { PATH: process.env.PATH, ASTRANULL_ASSISTANT_RUNNER_TOKEN: 'x'.repeat(40), ASTRANULL_API_URL: 'http://127.0.0.1:1', ASTRANULL_ASSISTANT_RUNNER_BACKEND: 'openai', ASTRANULL_ASSISTANT_LLM_BASE_URL: base, ASTRANULL_ASSISTANT_LLM_API_KEY_FILE: keyFile };
    const child = spawn(process.execPath, ['workers/assistant-runner.mjs'], { env, stdio: ['ignore', 'pipe', 'pipe'] });
    let output = '';
    child.stdout.on('data', (chunk) => { output += chunk; });
    child.stderr.on('data', (chunk) => { output += chunk; });
    await new Promise((resolve) => setTimeout(resolve, 1500));
    child.kill('SIGKILL');
    assert.match(output, /backend=openai model=deepseek-v4-flash endpoint=http:\/\/127\.0\.0\.1:/);
    assert.ok(!output.includes(KEY));
    assert.ok(!child.spawnargs.join(' ').includes(KEY));
  });

  it('stops reading an oversized response body at the cap', async () => {
    const chunk = 'x'.repeat(256 * 1024);
    let written = 0;
    handler = (req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      const pump = () => {
        while (written < 64 * 1024 * 1024) {
          written += chunk.length;
          if (!res.write(chunk)) { res.once('drain', pump); return; }
        }
        res.end();
      };
      res.on('close', () => { written = Infinity; });
      pump();
    };
    const out = await runAssistantJob(job, await step());
    assert.deepEqual({ status: out.status, error: out.error }, { status: 'failed', error: 'llm_bad_response' });
    assert.ok(written < 64 * 1024 * 1024 || written === Infinity, 'the stream is cancelled before the peer finishes writing');
  });

  it('rejects a declared oversized Content-Length without reading the body', async () => {
    handler = (req, res) => {
      res.writeHead(200, { 'content-type': 'application/json', 'content-length': String(5_000_000) });
      res.write('{');
    };
    const out = await runAssistantJob(job, await step());
    assert.deepEqual({ status: out.status, error: out.error }, { status: 'failed', error: 'llm_bad_response' });
  });

  it('requires a private key file and a key', async () => {
    const open = path.join(dir, 'open-key');
    await writeFile(open, KEY, { mode: 0o644 });
    await chmod(open, 0o644);
    await assert.rejects(resolveOpenAiConfig({ ASTRANULL_ASSISTANT_LLM_BASE_URL: base, ASTRANULL_ASSISTANT_LLM_API_KEY_FILE: open }), /0600/);
    await assert.rejects(resolveOpenAiConfig({ ASTRANULL_ASSISTANT_LLM_BASE_URL: base }), /API key is required/);
  });

  it('validates the base URL and bounded options', async () => {
    for (const bad of ['', 'not a url', 'ftp://127.0.0.1/v1', 'http://gateway.example.com/v1', 'http://10.0.0.5/v1', 'http://evil.localhost/v1', 'http://api.localhost:8080', 'https://user:pw@gateway.example.com/v1', 'https://gateway.example.com/v1?key=1']) {
      assert.throws(() => parseLlmBaseUrl(bad), /ASTRANULL_ASSISTANT_LLM_BASE_URL/, bad);
    }
    for (const good of ['http://127.0.0.1:8080/v1', 'http://localhost:8080', 'http://[::1]:8080/v1', 'https://gateway.example.com/v1/']) {
      assert.doesNotThrow(() => parseLlmBaseUrl(good), good);
    }
    assert.equal((await config({ ASTRANULL_ASSISTANT_LLM_MODEL: '' })).model, 'deepseek-v4-flash');
    await assert.rejects(config({ ASTRANULL_ASSISTANT_LLM_MAX_TOKENS: '10' }), /MAX_TOKENS/);
    await assert.rejects(config({ ASTRANULL_ASSISTANT_LLM_TIMEOUT_SECONDS: '9999' }), /TIMEOUT_SECONDS/);
    await assert.rejects(config({ ASTRANULL_ASSISTANT_LLM_MODEL: 'bad model;rm' }), /MODEL/);
  });

  it('sends validated static headers while keeping bearer auth and content type authoritative', async () => {
    requests = [];
    handler = reply(200, completion('ok'));
    const headers = JSON.stringify({ 'User-Agent': 'astranull-assistant-runner/1.0', 'x-opencode-session': 'astranull-production' });
    const out = await runAssistantJob(job, await step({ ASTRANULL_ASSISTANT_LLM_HEADERS: headers }));
    assert.equal(out.status, 'done');
    assert.equal(requests[0].headers['user-agent'], 'astranull-assistant-runner/1.0');
    assert.equal(requests[0].headers['x-opencode-session'], 'astranull-production');
    assert.equal(requests[0].auth, `Bearer ${KEY}`);
    assert.equal(requests[0].headers['content-type'], 'application/json');
  });

  it('sends no extra headers when none are configured', async () => {
    assert.deepEqual((await config()).headers, {});
    assert.deepEqual(parseStaticHeaders('  '), {});
  });

  it('rejects unsafe static headers without echoing their values', () => {
    const secretValue = 'value-that-must-not-leak';
    const bad = [
      '{',
      '[]',
      'null',
      '"x"',
      JSON.stringify({ 'bad name': 'v' }),
      JSON.stringify({ '': 'v' }),
      JSON.stringify({ 'x-a': 1 }),
      JSON.stringify({ 'x-a': '' }),
      JSON.stringify({ 'x-a': 'line\nbreak' }),
      JSON.stringify({ 'x-a': 'caf\u00e9' }),
      JSON.stringify({ 'x-a': 'a'.repeat(257) }),
      JSON.stringify({ 'x-a': 'v', 'X-A': 'w' }),
      JSON.stringify(Object.fromEntries(Array.from({ length: 9 }, (_, index) => [`x-h${index}`, 'v']))),
      ...['Authorization', 'HOST', 'Content-Type', 'content-length', 'Cookie', 'Transfer-Encoding', 'CONNECTION'].map((name) => JSON.stringify({ [name]: secretValue })),
    ];
    for (const raw of bad) {
      assert.throws(() => parseStaticHeaders(raw), (error) => /ASTRANULL_ASSISTANT_LLM_HEADERS/.test(error.message) && !error.message.includes(secretValue), raw.slice(0, 40));
    }
    const eight = Object.fromEntries(Array.from({ length: 8 }, (_, index) => [`x-h${index}`, 'v']));
    assert.equal(Object.keys(parseStaticHeaders(JSON.stringify(eight))).length, 8);
    assert.equal(parseStaticHeaders(JSON.stringify({ 'X-Mixed-Case': 'a b' }))['x-mixed-case'], 'a b');
  });

  it('keeps agy as the default backend', () => {
    assert.equal(resolveRunnerBackend({}), 'agy');
    assert.equal(resolveRunnerBackend({ ASTRANULL_ASSISTANT_RUNNER_BACKEND: '' }), 'agy');
    assert.equal(resolveRunnerBackend({ ASTRANULL_ASSISTANT_RUNNER_BACKEND: 'OpenAI' }), 'openai');
    assert.throws(() => resolveRunnerBackend({ ASTRANULL_ASSISTANT_RUNNER_BACKEND: 'other' }), /agy/);
  });
});
