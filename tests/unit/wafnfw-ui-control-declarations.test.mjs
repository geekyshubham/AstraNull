import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { CHECK_CATALOG, checkAdditionalInputReason, checkRequiresAdditionalInput, getCheckById } from '../../src/contracts/checks.mjs';
import { normalizeControlDeclarations } from '../../src/contracts/controlDeclarations.mjs';
import {
  DECLARATION_SECTION_GROUPS,
  checkPrerequisite,
  controlsHref,
  declarationSectionStates,
  declarationPresent,
  declarationSummary,
  declarationsDraftSignature,
  declarationsFromDraft,
  draftFromDeclarations,
  emptyConnectionLimit,
  emptyNetworkRule,
  serverFieldErrors,
  targetRunnableIndex,
  validateDeclarationsDraft,
} from '../../apps/web/react/src/lib/control-declarations.mjs';
import { assessmentChecks, runAllChecks } from '../../apps/web/react/src/lib/domain-checks.mjs';

const TARGET = { id: 'tgt_demo', kind: 'fqdn', value: 'shop.example.test' };
const STORED = {
  version: 1,
  network_policy: [
    { protocol: 'tcp', port: 22, action: 'deny', address_family: 'any', note: 'Bastion only' },
    { protocol: 'udp', port: 161, action: 'deny', address_family: 'ipv6' },
  ],
  waf: {
    block_signature: { header_name: 'x-blocked-by', header_value: 'edge-waf', status_codes: [403, 429] },
    expected_action: 'block',
    rate_limit_canary: { path: '/rl-canary', method: 'GET', threshold: 5, window_seconds: 10, expected_action: 'block_or_challenge' },
    marker_paths: ['/api/search'],
  },
  origin: { lockdown_expected: true },
  perspectives: { allowlisted_perspective_ids: ['default'], denied_perspective_ids: [] },
  canary_sink: { url: 'https://shop.example.test/sink' },
  connection_limits: [{ protocol: 'tcp', port: 443, max_connections_per_source: 4 }],
  updated_at: '2030-01-01T00:00:00.000Z',
  updated_by: 'usr_demo',
};

describe('control declarations draft round trip', () => {
  it('maps a stored document to a draft and back to the same full-replace body the server accepts', () => {
    const body = declarationsFromDraft(draftFromDeclarations(STORED));
    const { updated_at: _at, updated_by: _by, ...expected } = STORED;
    assert.deepEqual(body, expected);
    assert.deepEqual(normalizeControlDeclarations(body, { target: TARGET }), expected, 'the server normalizes the body to the same document');
  });

  it('keeps the rate-limit canary action and defaults a legacy canary to block, as the server does', () => {
    const draft = draftFromDeclarations(STORED);
    assert.equal(draft.rate_expected_action, 'block_or_challenge');
    assert.equal(declarationsFromDraft(draft).waf.rate_limit_canary.expected_action, 'block_or_challenge');
    const legacy = { version: 1, waf: { rate_limit_canary: { path: '/rl-canary', method: 'GET', threshold: 5, window_seconds: 10 } } };
    const body = declarationsFromDraft(draftFromDeclarations(legacy));
    assert.equal(body.waf.rate_limit_canary.expected_action, 'block');
    assert.deepEqual(normalizeControlDeclarations(body, { target: TARGET }), body);
    assert.notEqual(declarationsDraftSignature({ ...draft, rate_expected_action: 'block' }), declarationsDraftSignature(draft));
  });

  it('rejects an unknown rate-limit canary action and maps the server error to the same field', () => {
    const draft = { ...draftFromDeclarations(STORED), rate_expected_action: 'challenge' };
    assert.equal(validateDeclarationsDraft(draft, { target: TARGET })['waf.rate_limit_canary.expected_action'], 'Choose Block or Block or challenge.');
    let payload;
    try {
      normalizeControlDeclarations(declarationsFromDraft(draft), { target: TARGET });
    } catch (error) {
      payload = { error: 'invalid_control_declarations', field: error.field, message: error.message };
    }
    assert.equal(payload?.field, 'waf.rate_limit_canary.expected_action');
    assert.ok(serverFieldErrors(payload)['waf.rate_limit_canary.expected_action']);
  });

  it('omits empty sections instead of sending blank objects', () => {
    const body = declarationsFromDraft(draftFromDeclarations({ version: 1 }));
    assert.deepEqual(body, { version: 1 });
    assert.equal(declarationSummary({ version: 1 }).empty, true);
    assert.equal(declarationSummary(STORED).deniedRules, 2);
  });

  it('ignores row keys when deciding whether there are unsaved changes', () => {
    const left = draftFromDeclarations(STORED);
    const right = draftFromDeclarations(STORED);
    assert.notEqual(left.network_policy[0].key, right.network_policy[0].key);
    assert.equal(declarationsDraftSignature(left), declarationsDraftSignature(right));
    assert.notEqual(declarationsDraftSignature({ ...left, expected_action: 'challenge' }), declarationsDraftSignature(right));
  });
});

describe('client validation mirrors the server contract with field paths', () => {
  it('flags bad ports, duplicates, header tokens, paths and an off-host sink with server field names', () => {
    const draft = draftFromDeclarations({});
    draft.network_policy = [{ ...emptyNetworkRule(), port: '70000' }, { ...emptyNetworkRule(), port: '22' }, { ...emptyNetworkRule(), port: '22' }];
    draft.block_header_name = 'x blocked';
    draft.block_header_value = 'yes';
    draft.block_status_codes = '403, 200';
    draft.rate_limit_enabled = true;
    draft.rate_path = 'rl';
    draft.rate_threshold = '11';
    draft.rate_window = '0';
    draft.marker_paths = ['/ok', 'https://elsewhere.test/'];
    draft.canary_sink_url = 'https://other.test/sink';
    draft.connection_limits = [{ ...emptyConnectionLimit(), port: '443', max: '12' }];
    const errors = validateDeclarationsDraft(draft, { target: TARGET, perspectiveIds: ['default'] });
    for (const field of [
      'network_policy[0].port', 'network_policy[2].port', 'waf.block_signature.header_name', 'waf.block_signature.status_codes',
      'waf.rate_limit_canary.path', 'waf.rate_limit_canary.threshold', 'waf.rate_limit_canary.window_seconds',
      'waf.marker_paths[1]', 'canary_sink.url', 'connection_limits[0].max_connections_per_source',
    ]) assert.ok(errors[field], `expected an error on ${field}`);
    assert.equal(errors['network_policy[1].port'], undefined);
    assert.match(errors['network_policy[2].port'], /Duplicates rule 2/);
  });

  it('accepts a valid document with no errors', () => {
    assert.deepEqual(validateDeclarationsDraft(draftFromDeclarations(STORED), { target: TARGET, perspectiveIds: ['default'] }), {});
  });

  it('turns a 400 invalid_control_declarations response into inline field errors', () => {
    const fields = serverFieldErrors({
      error: 'invalid_control_declarations',
      field: 'network_policy[3].port',
      message: 'network_policy[3].port must be an integer between 1 and 65535.',
      errors: [{ field: 'network_policy[3].port', message: 'network_policy[3].port must be an integer between 1 and 65535.' }],
    });
    assert.deepEqual(fields, { 'network_policy[3].port': 'Must be an integer between 1 and 65535.' });
    assert.deepEqual(serverFieldErrors({ error: 'forbidden' }), {});
  });
});

describe('check prerequisites', () => {
  const check = (id) => getCheckById(id) ?? CHECK_CATALOG.find((entry) => entry.check_id === id);

  const served = (entry, declarations, perspectiveCount = 1) => {
    const env = { ASTRANULL_PROBE_PERSPECTIVES: JSON.stringify(Array.from({ length: perspectiveCount }, (_, index) => ({ id: index ? `p${index}` : 'default', label: `P${index}` }))) };
    const context = { target: TARGET, declarations, env };
    const requires = checkRequiresAdditionalInput(entry, context);
    return { ...entry, requires_additional_input: requires, additional_input_reason: requires ? checkAdditionalInputReason(entry, context) : null };
  };
  const answerFor = (entry, declarations, perspectiveCount) => targetRunnableIndex([served(entry, declarations, perspectiveCount)]);

  it('waits for the server answer, then reports the declared TCP deny rule it names', () => {
    const deny = check('nfw.declared_deny_tcp.safe');
    assert.equal(checkPrerequisite(deny, { declarations: STORED, target: TARGET }).state, 'checking', 'no client guess before the server answers');
    const unmet = checkPrerequisite(deny, { declarations: { version: 1 }, serverRunnableIndex: answerFor(deny, { version: 1 }) });
    assert.equal(unmet.reason, 'declared_tcp_deny_required');
    assert.equal(unmet.label, 'Needs a declared TCP deny rule');
    assert.equal(unmet.section, 'network');
    assert.deepEqual(unmet.missing, ['network_policy']);
    assert.equal(checkPrerequisite(deny, { declarations: STORED, serverRunnableIndex: answerFor(deny, STORED) }).state, 'ready');
  });

  it('reports needs a port from the server reason and SOC only for SOC body checks', () => {
    const portless = check('l3.tcp_flag_anomaly.readiness');
    const unmet = checkPrerequisite(portless, { serverRunnableIndex: answerFor(portless, { version: 1 }) });
    assert.equal(unmet.state, 'needs_port');
    assert.equal(unmet.label, 'Needs a port');
    assert.equal(checkPrerequisite(portless, { serverRunnableIndex: answerFor(portless, STORED) }).state, 'ready', 'a declared TCP rule with a port satisfies it on the server');
    assert.equal(checkPrerequisite(check('waf.body_json_marker.soc'), { declarations: STORED, target: TARGET }).state, 'soc_only');
  });

  it('needs two perspectives for the allowlist check, as the server says', () => {
    const allowlist = check('nfw.perspective_allowlist.safe');
    const denied = { ...STORED, perspectives: { allowlisted_perspective_ids: [], denied_perspective_ids: ['default'] } };
    assert.equal(checkPrerequisite(allowlist, { serverRunnableIndex: answerFor(allowlist, denied, 1) }).state, 'needs_perspectives');
    assert.equal(checkPrerequisite(allowlist, { serverRunnableIndex: answerFor(allowlist, STORED, 2) }).reason, 'declared_perspectives_required');
    assert.equal(checkPrerequisite(allowlist, { serverRunnableIndex: answerFor(allowlist, denied, 2) }).state, 'ready');
  });

  it('keeps unmet checks out of run-all and the assessment set', () => {
    const deny = check('nfw.declared_deny_tcp.safe');
    const withoutAnswer = assessmentChecks(CHECK_CATALOG, TARGET, { declarations: STORED, perspectiveCount: 1 }).map((entry) => entry.check_id);
    assert.ok(!withoutAnswer.includes(deny.check_id), 'a target-answered check waits for the server');
    const unmetCatalog = CHECK_CATALOG.map((entry) => entry.check_id === deny.check_id ? served(entry, { version: 1 }) : entry);
    const unmet = { declarations: { version: 1 }, perspectiveCount: 1, serverRunnableIndex: targetRunnableIndex(unmetCatalog) };
    assert.ok(!assessmentChecks(unmetCatalog, TARGET, unmet).some((entry) => entry.check_id === deny.check_id));
    const metCatalog = CHECK_CATALOG.map((entry) => entry.check_id === deny.check_id ? served(entry, STORED) : entry);
    const met = { declarations: STORED, perspectiveCount: 1, serverRunnableIndex: targetRunnableIndex(metCatalog) };
    assert.ok(assessmentChecks(metCatalog, TARGET, met).some((entry) => entry.check_id === deny.check_id));
    assert.ok(!runAllChecks(CHECK_CATALOG, TARGET, { declarations: { version: 1 }, perspectiveCount: 1 }).some((entry) => entry.check_id === 'waf.rate_limit_canary.validation'));
  });

  it('agrees with the server on which declarations are present', () => {
    assert.equal(declarationPresent(STORED, 'waf.rate_limit_canary'), true);
    assert.equal(declarationPresent({ origin: { lockdown_expected: false } }, 'origin.lockdown_expected'), false);
    assert.equal(declarationPresent({ perspectives: { allowlisted_perspective_ids: [], denied_perspective_ids: [] } }, 'perspectives'), false);
    assert.equal(controlsHref('tgt 1', 'network'), '#target-detail?id=tgt+1&tab=controls&section=network');
  });
});

describe('control declarations section overview', () => {
  it('groups every editor section exactly once', () => {
    const grouped = DECLARATION_SECTION_GROUPS.flatMap((group) => group.sections);
    const states = declarationSectionStates(null).map((state) => state.id);
    assert.deepEqual([...grouped].sort(), [...states].sort());
    assert.equal(new Set(grouped).size, grouped.length);
  });

  it('reports nothing declared and nothing edited for an empty document', () => {
    const states = declarationSectionStates(null, draftFromDeclarations(null));
    assert.ok(states.every((state) => !state.declared && !state.edited));
    assert.equal(states.find((state) => state.id === 'waf_action').detail, 'Catalog default');
    assert.equal(states.find((state) => state.id === 'marker_paths').detail, 'Root path only');
  });

  it('counts saved sections from the stored document with plain details', () => {
    const states = Object.fromEntries(declarationSectionStates(STORED, draftFromDeclarations(STORED)).map((state) => [state.id, state]));
    assert.ok(Object.values(states).every((state) => state.declared && !state.edited));
    assert.equal(states.network.detail, '2 rules, 2 denied');
    assert.equal(states.connection_limits.detail, '1 limit');
    assert.equal(states.perspectives.detail, '1 allowed, 0 denied');
    assert.equal(states.waf_signature.detail, 'Header x-blocked-by');
    assert.equal(states.waf_action.detail, 'Block');
    assert.equal(states.rate_limit.detail, 'GET /rl-canary');
    assert.equal(states.origin.detail, 'CDN traffic only');
    assert.equal(states.canary_sink.detail, 'URL declared');
    assert.ok(!JSON.stringify(states).includes('edge-waf'), 'the block header value never appears in the overview');
  });

  it('treats an origin declared as directly reachable as declared', () => {
    const origin = declarationSectionStates({ origin: { lockdown_expected: false } }).find((state) => state.id === 'origin');
    assert.equal(origin.declared, true);
    assert.equal(origin.detail, 'Direct access by design');
  });

  it('marks only the sections a draft changes as edited, without counting unsaved values as declared', () => {
    const draft = draftFromDeclarations(STORED);
    draft.block_header_value = 'other-value';
    draft.connection_limits = [];
    const states = Object.fromEntries(declarationSectionStates(STORED, draft).map((state) => [state.id, state]));
    assert.deepEqual(Object.values(states).filter((state) => state.edited).map((state) => state.id).sort(), ['connection_limits', 'waf_signature']);
    assert.equal(states.connection_limits.declared, true, 'declared reflects the saved document until the draft is saved');

    const fresh = draftFromDeclarations(null);
    fresh.network_policy = [{ ...emptyNetworkRule(), port: '22' }];
    const added = declarationSectionStates(null, fresh).find((state) => state.id === 'network');
    assert.equal(added.edited, true);
    assert.equal(added.declared, false);
  });
});
