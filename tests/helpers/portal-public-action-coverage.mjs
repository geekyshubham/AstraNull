import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { parseAst } from 'rolldown/parseAst';
import { recordExistingBehaviorReceipt } from './existing-behavior-coverage.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const UI = 'apps/web/react/src';
export const PUBLIC_ACTION_STATES = Object.freeze(['success', 'busy', 'empty', 'invalid', 'cancel', 'error-retry', 'denial', 'reload']);
const STATES = PUBLIC_ACTION_STATES;
export const PUBLIC_AUTH_LANES = Object.freeze(['visitor', 'password', 'dev-headers', 'staging', 'unknown', 'oidc-disabled', 'idp-redirect']);
const AUTH_OWNERS = new Set(['CredentialLoginPage', 'StaffLoginPage']);
const LOCAL_OWNERS = new Set(['LandingExample', 'CopyValueButton']);
const RECEIPT_SCHEMA = 'portal-action-execution/v1';
const canonicalTime = (value) => typeof value === 'string' && Number.isFinite(Date.parse(value)) && new Date(Date.parse(value)).toISOString() === value;
// Receipts use reviewed fixed observations, not arbitrary interpolated request/storage text.
export const PUBLIC_OBSERVATIONS = Object.freeze({
  invalid: 'Invalid actual user submission is rejected before any mutation request.',
  busy: 'Held mutation shows busy disabled submit and actual keyboard input does not duplicate the request.',
  retry: 'Visible failed request is retried by an actual user control with exactly one additional request.',
  success: 'An actual user submission reaches the expected success UI with the exact reviewed request boundary.',
  reload: 'Actual reload restores the reviewed public destination without replaying a mutation.',
  cancel: 'Actual back navigation abandons the draft without a mutation or persisted credential.',
  secrets: 'One-time codes and plaintext credentials are absent from URL and storage after the reviewed transition.',
  tokenReload: 'Reload after address sanitization shows blank masked manual code fallback and sends no consume request.',
  toggle: 'Actual visibility control changes masked input presentation without sending a request.',
  challenge: 'Server challenge changes the actual workspace or authenticator control and retry uses only prompted fields.',
  denial: 'Actual denied or disabled lane cannot create a session or submit a credential exchange.',
  local: 'Actual local visitor control changes only its rendered state without authentication or signup writes.',
  navigation: 'Actual public link reaches its reviewed mounted destination without a mutation.',
  copy: 'Actual reference copy succeeds or shows the explicit manual fallback without changing the reference.',
  discovery: 'Actual retry reload rediscovers authentication configuration without an authentication exchange.',
  serverIdentity: 'Accepted login stores only the synthetic server session identity and no plaintext credential.',
});
const approvedObservations = new Set(Object.values(PUBLIC_OBSERVATIONS));
const safeObservations = (value) => Array.isArray(value) && value.length > 0 && value.every((item) => approvedObservations.has(item));
const EVENTS = /^on(?:Click|Change|Submit|KeyDown|KeyUp|Input|Toggle|Select|ValueChange|CheckedChange|Close|Cancel|Confirm)$/;
const controls = new Set(['a', 'button', 'form', 'input', 'textarea', 'select', 'summary', 'Button', 'AnchorButton', 'Select']);
const compact = (value) => String(value ?? '').replace(/\s+/g, ' ').trim();
const hash = (value) => createHash('sha256').update(value).digest('hex');
function children(node) {
  return Object.entries(node).filter(([key]) => !['parent', 'loc', 'comments', 'tokens'].includes(key))
    .flatMap(([, value]) => Array.isArray(value) ? value.filter((child) => child?.type) : value?.type ? [value] : []);
}
function walk(node, visit) { if (!node) return; visit(node); for (const child of children(node)) walk(child, visit); }
const raw = (module, node) => compact(module.source.slice(node.start, node.end));

/** Public roots come from actual early-return App branches, never the authenticated role matrix. */
export function buildPublicPortalActionInventory({ root = ROOT } = {}) {
  const modules = new Map();
  const unresolved = [];
  root = fs.realpathSync(root);
  const uiRoot = path.resolve(root, UI);
  const prefix = uiRoot + path.sep;
  const relative = (file) => path.relative(root, file).split(path.sep).join('/');
  function validateSource(file, boundary = root) {
    if (!file.startsWith(boundary + path.sep) || !fs.realpathSync(file).startsWith(boundary + path.sep)) throw new Error('Public source must remain inside its actual root.');
    let cursor = root;
    for (const segment of path.relative(root, file).split(path.sep)) {
      cursor = path.join(cursor, segment);
      if (fs.lstatSync(cursor).isSymbolicLink()) throw new Error('Public source symlinks are not allowed.');
    }
    if (!fs.statSync(file).isFile()) throw new Error('Public source must be a file.');
  }
  function resolve(file, specifier) {
    if (!specifier.startsWith('.')) return null;
    const base = path.resolve(path.dirname(file), specifier);
    return [base, ...['.tsx', '.ts', '.mjs', '.mts', '.jsx', '.js', '/index.tsx', '/index.ts'].map((suffix) => base + suffix)]
      .find((candidate) => candidate.startsWith(prefix) && /\.(?:tsx?|m[jt]s|jsx?)$/.test(candidate) && fs.existsSync(candidate) && fs.statSync(candidate).isFile()) ?? null;
  }
  function load(file) {
    if (modules.has(file)) return modules.get(file);
    validateSource(file, uiRoot);
    const source = fs.readFileSync(file, 'utf8');
    const ast = parseAst(source, { lang: /\.tsx$/.test(file) ? 'tsx' : /\.(ts|mts)$/.test(file) ? 'ts' : 'jsx' }, file);
    const module = { file, source, ast, declarations: new Map(), imports: new Map(), exports: new Map() };
    modules.set(file, module);
    for (const statement of ast.body) {
      if (statement.type === 'ImportDeclaration') {
        const target = resolve(file, statement.source.value);
        if (target && statement.importKind !== 'type') for (const specifier of statement.specifiers) {
          if (specifier.importKind !== 'type') module.imports.set(specifier.local.name, { file: target, name: specifier.type === 'ImportDefaultSpecifier' ? 'default' : specifier.imported?.name ?? specifier.imported?.value });
        }
      }
      const declaration = statement.declaration ?? statement;
      const entries = [];
      if (declaration.type === 'FunctionDeclaration' && declaration.id) entries.push([declaration.id.name, declaration]);
      if (declaration.type === 'VariableDeclaration') for (const item of declaration.declarations) if (item.id.type === 'Identifier') entries.push([item.id.name, item]);
      for (const [name, node] of entries) {
        module.declarations.set(name, node);
        if (statement.type.startsWith('Export')) module.exports.set(statement.type === 'ExportDefaultDeclaration' ? 'default' : name, { file, name });
      }
      if (statement.type === 'ExportNamedDeclaration') for (const specifier of statement.specifiers ?? []) {
        const target = statement.source ? resolve(file, statement.source.value) : file;
        if (target && statement.exportKind !== 'type') module.exports.set(specifier.exported.name ?? specifier.exported.value, { file: target, name: specifier.local.name ?? specifier.local.value });
      }
    }
    return module;
  }
  function value(file, name, seen = new Set()) {
    const key = `${file}#${name}`;
    if (seen.has(key)) return null;
    seen.add(key);
    const module = load(file);
    if (module.declarations.has(name)) return { module, name, node: module.declarations.get(name) };
    const reference = module.imports.get(name) ?? module.exports.get(name);
    return reference?.name ? value(reference.file, reference.name, seen) : null;
  }
  const app = load(path.join(root, UI, 'App.tsx'));
  const appFunction = app.declarations.get('App');
  if (!appFunction) throw new Error('Actual App declaration is required.');
  const mounts = [];
  for (const statement of appFunction.body.body) {
    if (statement.type !== 'IfStatement' || statement.consequent.type !== 'ReturnStatement' || statement.consequent.argument?.type !== 'JSXElement') continue;
    const element = statement.consequent.argument.openingElement;
    const reference = app.imports.get(element.name.name);
    if (!reference) continue;
    function pathnameRoutes(test) {
      if (test.type === 'LogicalExpression' && test.operator === '||') {
        const left = pathnameRoutes(test.left); const right = pathnameRoutes(test.right);
        return left && right ? [...left, ...right] : null;
      }
      if (test.type !== 'BinaryExpression' || test.operator !== '===') return null;
      const pairs = [[test.left, test.right], [test.right, test.left]];
      const pair = pairs.find(([identifier, literal]) => identifier.type === 'Identifier' && identifier.name === 'path'
        && literal.type === 'Literal' && typeof literal.value === 'string' && literal.value.startsWith('/') && !/[?#]/.test(literal.value));
      return pair ? [pair[1].value] : null;
    }
    const routes = pathnameRoutes(statement.test);
    if (!routes) {
      let pathnameDependent = false;
      walk(statement.test, (node) => { if (node.type === 'Identifier' && node.name === 'path') pathnameDependent = true; });
      if (pathnameDependent) unresolved.push({ owner: element.name.name, reason: 'Mounted pathname predicate is not an exact classified equality branch.' });
      continue;
    }
    mounts.push({ owner: element.name.name, file: relative(reference.file), routes: [...new Set(routes)], reference });
  }
  if (!mounts.length) throw new Error('Actual public App branches are required.');
  const reached = new Map();
  const actions = new Map();
  const flowBindings = new Map();
  for (const mount of mounts) {
    const declaration = value(mount.reference.file, mount.reference.name);
    if (!declaration) continue;
    walk(declaration.node, (child) => {
      if (child.type !== 'IfStatement' || child.test.type !== 'BinaryExpression' || child.test.operator !== '==='
        || child.test.left.type !== 'Identifier' || child.test.left.name !== 'flow' || child.test.right.type !== 'Literal'
        || child.consequent.type !== 'ReturnStatement' || child.consequent.argument?.type !== 'JSXElement') return;
      const component = child.consequent.argument.openingElement.name.name;
      if (typeof child.test.right.value === 'string') flowBindings.set(`${declaration.module.file}#${component}`, child.test.right.value);
    });
  }
  const lanesFor = (owner) => AUTH_OWNERS.has(owner)
    ? (owner === 'StaffLoginPage' ? ['dev-headers', 'staging', 'unknown', 'oidc-disabled'] : PUBLIC_AUTH_LANES.filter((lane) => lane !== 'visitor')) : ['visitor'];
  function reach(reference, routes, seen = new Set(), caller = null, inheritedLanes = null) {
    const resolved = value(reference.file, reference.name);
    if (!resolved) { unresolved.push({ owner: reference.name, reason: 'Mounted value declaration could not be resolved.' }); return; }
    const { module, name, node } = resolved;
    const flow = flowBindings.get(`${module.file}#${name}`);
    if (flow) routes = routes.map((route) => `${route.split('?')[0]}?flow=${encodeURIComponent(flow)}`);
    const lanes = AUTH_OWNERS.has(name) ? lanesFor(name) : inheritedLanes ?? lanesFor(name);
    const callerId = caller ? `${caller.file}:${caller.owner}:${caller.line}` : '';
    const key = `${relative(module.file)}#${name}${callerId ? `@${callerId}` : ''}`;
    if (!reached.has(key)) reached.set(key, new Set());
    const newRoutes = routes.filter((route) => !reached.get(key).has(route));
    if (!newRoutes.length || seen.has(key)) return;
    for (const route of newRoutes) reached.get(key).add(route);
    routes = newRoutes;
    const next = new Set([...seen, key]);
    const localSetters = [];
    const localCallbacks = [];
    const reactHooks = new Set();
    for (const statement of module.ast.body) if (statement.type === 'ImportDeclaration' && statement.source.value === 'react') {
      for (const item of statement.specifiers) if (item.imported?.name === 'useState') reactHooks.add(item.local.name);
    }
    walk(node, (part) => {
      if (part.type === 'VariableDeclarator' && part.id.type === 'ArrayPattern' && part.id.elements[1]?.type === 'Identifier'
        && part.init?.type === 'CallExpression' && part.init.callee.type === 'Identifier' && reactHooks.has(part.init.callee.name)) localSetters.push(part.id.elements[1].name);
      if (part.type === 'FunctionDeclaration' && part !== node && part.id) localCallbacks.push({ name: part.id.name, source: raw(module, part) });
    });
    walk(node, (child) => {
      if (child.type === 'Identifier') {
        const dependency = module.declarations.has(child.name) ? { file: module.file, name: child.name } : module.imports.get(child.name);
        if (dependency?.name && child.name !== name) reach(dependency, routes, next, null, lanes);
      }
      if (child.type !== 'JSXElement') return;
      const opening = child.openingElement;
      const tag = opening.name?.name;
      const sourceAttributes = Object.fromEntries(opening.attributes.filter((attr) => attr.type === 'JSXAttribute').map((attr) => [attr.name.name, !attr.value ? 'true' : attr.value.type === 'Literal' ? String(attr.value.value) : raw(module, attr.value.expression ?? attr.value)]));
      const line = module.source.slice(0, opening.start).split('\n').length;
      const dependency = module.declarations.has(tag) ? { file: module.file, name: tag } : module.imports.get(tag);
      if (!controls.has(tag)) {
        if (dependency?.name) reach(dependency, routes, next, { file: relative(module.file), owner: name, line, attributes: sourceAttributes }, lanes);
        return;
      }
      // Canonical primitive callsites retain their own identity; their implementation is a bound source, not a second generic action.
      if (dependency?.name) value(dependency.file, dependency.name);
      const attributes = Object.fromEntries(Object.entries(sourceAttributes).map(([attribute, expression]) => {
        let bound = expression;
        for (const [formal, actual] of Object.entries(caller?.attributes ?? {})) {
          if (bound === formal) bound = actual;
          else if (/^[A-Za-z0-9_-]+$/.test(actual)) bound = bound.replaceAll('${' + formal + '}', actual);
        }
        if (/^`[^$]*`$/.test(bound)) bound = bound.slice(1, -1);
        return [attribute, bound];
      }));
      const handlers = Object.fromEntries(Object.entries(attributes).filter(([key]) => EVENTS.test(key)));
      // Read-only fields are still inventoried; applicability is an explicit contract below.
      const kind = tag === 'form' ? 'form-keyboard' : ['input', 'textarea'].includes(tag) ? 'field' : ['select', 'Select'].includes(tag) ? 'select' : ['a', 'AnchorButton'].includes(tag) ? 'anchor' : 'button';
      const id = `${relative(module.file)}:${name}:${line}:${tag}${callerId ? `@${callerId}` : ''}`;
      const text = [];
      walk(child, (part) => { if (part.type === 'JSXText') text.push(part.value); });
      const guards = [];
      walk(node, (ancestor) => {
        if (ancestor.type === 'IfStatement') {
          if (ancestor.consequent.start <= opening.start && ancestor.consequent.end >= opening.end) guards.push({ expression: raw(module, ancestor.test), polarity: true });
          if (ancestor.alternate?.start <= opening.start && ancestor.alternate.end >= opening.end) guards.push({ expression: raw(module, ancestor.test), polarity: false });
        }
        if (ancestor.type === 'ConditionalExpression') {
          if (ancestor.consequent.start <= opening.start && ancestor.consequent.end >= opening.end) guards.push({ expression: raw(module, ancestor.test), polarity: true });
          if (ancestor.alternate.start <= opening.start && ancestor.alternate.end >= opening.end) guards.push({ expression: raw(module, ancestor.test), polarity: false });
        }
        if (ancestor.type === 'LogicalExpression' && ancestor.operator === '&&' && ancestor.right.start <= opening.start && ancestor.right.end >= opening.end) guards.push({ expression: raw(module, ancestor.left), polarity: true });
      });
      if (!actions.has(id)) actions.set(id, { id, file: relative(module.file), owner: name, line, tag, kind, label: attributes['aria-label'] ?? compact(text.join(' ')), attributes, sourceAttributes, handlers, guards, caller, localSetters, localCallbacks, primitive: dependency ? `${relative(dependency.file)}#${dependency.name}` : null, routes: [], lanes: [] });
      const action = actions.get(id);
      action.routes = [...new Set([...action.routes, ...routes])].sort();
      action.lanes = [...new Set([...action.lanes, ...lanes])].sort();
    });
  }
  for (const mount of mounts) reach(mount.reference, mount.routes);
  const boundFiles = new Set([...modules.keys()]);
  const addFile = (file) => { if (fs.existsSync(file)) { validateSource(file); boundFiles.add(file); } };
  for (const file of ['tests/helpers/portal-public-action-coverage.mjs', 'tests/unit/portal-public-action-coverage.test.mjs',
    'tests/e2e/journeys/portal-public-auth-action-states.spec.mjs', 'tests/helpers/portal-browser-failures.mjs',
    'tests/helpers/portal-playwright-server.mjs', 'tests/helpers/portal-playwright-session.mjs',
    'tests/helpers/existing-behavior-coverage.mjs', 'vite.config.ts', 'playwright.config.mjs', 'apps/web/react/index.html', 'package.json', 'package-lock.json']) addFile(path.join(root, file));
  const fixtures = path.join(root, 'tests/fixtures/public-auth');
  const bindFixtures = (directory) => {
    if (!fs.existsSync(directory)) return;
    if (fs.lstatSync(directory).isSymbolicLink()) throw new Error('Public fixture symlinks are not allowed.');
    for (const entry of fs.readdirSync(directory).sort()) {
      const file = path.join(directory, entry);
      if (fs.lstatSync(file).isDirectory()) bindFixtures(file); else addFile(file);
    }
  };
  bindFixtures(fixtures);
  const sources = [...boundFiles].map((file) => ({ file: relative(file), sha256: hash(fs.readFileSync(file)) })).sort((a, b) => a.file.localeCompare(b.file));
  return { schema: 'portal-public-actions/v1', root, scope: 'actual mounted public and authentication branches; anonymous principal only', mounts: mounts.map(({ reference, ...mount }) => mount), actions: [...actions.values()].sort((a, b) => a.id.localeCompare(b.id)), reachedSymbols: [...reached.keys()].sort(), sources, unresolved, sourceDigest: hash(JSON.stringify(sources)) };
}

function laneGuard(expression, lane, owner) {
  const staff = owner === 'StaffLoginPage';
  const dev = lane === 'dev-headers'; const staging = lane === 'staging';
  const env = {
    authUnknown: lane === 'unknown', isDevHeaders: dev, isOidc: !dev && lane !== 'unknown',
    idpRedirect: lane === 'idp-redirect', loginDisabled: lane === 'oidc-disabled',
    passwordLane: !staff && (lane === 'password' || staging), usePasswordLane: !staff && lane === 'password',
    stagingLane: dev || staging, stagingBypass: staging, showStagingRolePicker: dev || staging,
    showStagingStaffRolePicker: dev || staging, 'config.bundledLoginEnabled': staging,
    'config.passwordLoginEnabled': !staff && (lane === 'password' || staging),
  };
  if (lane === 'visitor') return null;
  try {
    const ast = parseAst(`const value = (${expression});`, { lang: 'js' });
    const evaluate = (node) => {
      if (node.type === 'Literal') return node.value;
      const text = compact(`const value = (${expression});`.slice(node.start, node.end));
      if (Object.hasOwn(env, text)) return env[text];
      if (node.type === 'UnaryExpression' && node.operator === '!') { const value = evaluate(node.argument); return value === null ? null : !value; }
      if (node.type === 'LogicalExpression') {
        const left = evaluate(node.left); const right = evaluate(node.right);
        if (node.operator === '&&') return left === false || right === false ? false : left === null || right === null ? null : Boolean(left && right);
        if (node.operator === '||') return left === true || right === true ? true : left === null || right === null ? null : Boolean(left || right);
      }
      return null;
    };
    const value = evaluate(ast.body[0].declarations[0].init);
    return value === null ? null : Boolean(value);
  } catch { return null; }
}

/** Only proven local non-transitions are N/A. Unknown injected callbacks remain blocking. */
export function publicActionApplicability(action, lane = 'visitor') {
  const decision = (applicable, reason) => ({ applicable, reason });
  const result = Object.fromEntries(STATES.map((state) => [state, decision(null, 'Source callback, caller or transition is not yet classified; it remains blocking.')]));
  if (!PUBLIC_AUTH_LANES.includes(lane) || !(action.lanes ?? ['visitor']).includes(lane)) return result;
  if ((action.guards ?? []).some((guard) => { const value = laneGuard(guard.expression, lane, action.owner); return value !== null && value !== guard.polarity; })) {
    return Object.fromEntries(STATES.map((state) => [state, decision(false, 'Exact source branch polarity excludes this finite authentication lane.')]));
  }
  if (action.attributes.readOnly === 'true' && !Object.keys(action.handlers).length) {
    return Object.fromEntries(STATES.map((state) => [state, decision(false, 'Proven read-only display field has no user handler or owned mutation.')]));
  }
  if (action.kind === 'anchor' && action.attributes.href) {
    for (const state of STATES) result[state] = decision(['success', 'cancel', 'reload'].includes(state), 'Anchor owns destination/back navigation and direct-load continuity, not form validation or request submission.');
    return result;
  }
  if (action.kind === 'form-keyboard' && action.handlers.onSubmit) {
    for (const state of STATES) result[state] = decision(state !== 'cancel', 'Actual source form owns submission validation, pending/retry, denial and no-replay transitions; cancellation belongs to its actual navigation control.');
    // A known name is not enough to resolve a newly injected callback.
    if (!/^(?:submit|\(?event\)?\s*=>)/.test(action.handlers.onSubmit)) for (const state of STATES) result[state] = decision(null, 'Injected form submit callback requires exact defining caller binding.');
    return result;
  }
  if (action.kind === 'field' || action.kind === 'select') {
    if (!Object.keys(action.handlers).length) return result;
    for (const state of STATES) result[state] = decision(['success', 'empty', 'invalid'].includes(state) || state === 'busy' && /loading/.test(action.attributes.disabled ?? ''), 'Source field owns value/empty/invalid feedback and its explicit pending disable; request/cancel/reload belongs to the exact form or link caller.');
    return result;
  }
  const handler = Object.values(action.handlers).join(' ');
  if (action.attributes.type === 'submit') {
    for (const state of STATES) result[state] = decision(['success', 'busy', 'invalid', 'error-retry'].includes(state), 'Submit control owns actual activation and pending/retry; other form/lane outcomes are separate source form obligations.');
    return result;
  }
  const localSetter = /set(?:ShowPassword|Submitted|EditToken|StagingBypass)\(/.test(handler);
  if (localSetter || LOCAL_OWNERS.has(action.owner) || action.tag === 'summary' && !Object.keys(action.handlers).length) {
    for (const state of STATES) result[state] = decision(state === 'success' || action.owner === 'CopyValueButton' && state === 'error-retry', 'Proven local disclosure/value/copy control owns no authentication transaction; clipboard failure remains an explicit local retry obligation.');
    return result;
  }
  if (/window\.location\.reload\(\)/.test(handler)) {
    for (const state of STATES) result[state] = decision(['success', 'error-retry', 'reload'].includes(state), 'Exact discovery retry control owns a real reload and configuration retry, not credential submission.');
  }
  return result;
}

export function publicActionCellId(cell) { return [cell.action, cell.route, cell.principal, cell.role, cell.dataset, cell.lane, cell.state, cell.channel].join('|'); }
export function buildPublicPortalActionCoverage({ inventory = buildPublicPortalActionInventory() } = {}) {
  const cells = inventory.actions.flatMap((action) => action.routes.flatMap((route) => (action.lanes ?? ['visitor']).flatMap((lane) => Object.entries(publicActionApplicability(action, lane)).map(([state, decision]) => {
    const cell = { action: action.id, route, principal: 'visitor', role: 'anonymous', dataset: 'public', lane, state, channel: 'ui', ...decision };
    return { ...cell, id: publicActionCellId(cell) };
  }))));
  return { schema: 'portal-public-coverage/v1', inventory, sourceDigest: inventory.sourceDigest, cells, unclassifiedStates: cells.filter((cell) => cell.applicable === null), unmappedSourceActions: inventory.actions.filter((action) => !action.routes.length || !action.lanes?.length).map((action) => action.id) };
}

function currentCoverage(coverage) {
  const fresh = buildPublicPortalActionCoverage({ inventory: buildPublicPortalActionInventory({ root: coverage.inventory.root ?? ROOT }) });
  if (fresh.sourceDigest !== coverage.sourceDigest || JSON.stringify(fresh.inventory) !== JSON.stringify(coverage.inventory)
    || JSON.stringify(fresh.cells) !== JSON.stringify(coverage.cells)) throw new Error('Public coverage source or canonical inventory/cells are stale or mutated.');
  return fresh;
}

export async function assertPublicPortalAction(testInfo, coverage, query, route, state, assertBehavior) {
  if (!testInfo?.testId || !Array.isArray(testInfo.titlePath) || !testInfo.titlePath.length || testInfo.titlePath.some((item) => typeof item !== 'string' || !item.trim())
    || testInfo.retry !== 0 || typeof testInfo.attach !== 'function' || typeof assertBehavior !== 'function') throw new Error('An actual no-retry test context and behavior assertions are required.');
  currentCoverage(coverage);
  const lane = query.lane ?? 'visitor';
  const matches = coverage.inventory.actions.filter((action) => (!query.id || action.id === query.id) && (!query.owner || action.owner === query.owner) && (!query.kind || action.kind === query.kind)
    && (!query.caller || action.caller?.owner === query.caller) && (!query.handler || Object.values(action.handlers).some((handler) => handler.includes(query.handler)))
    && (!query.label || (typeof query.label === 'string' ? action.label === query.label : query.label.test(action.label)))
    && (!query.name || action.attributes.name === query.name || action.attributes.id === query.name) && action.routes.includes(route) && action.lanes.includes(lane));
  if (matches.length !== 1) throw new Error(`Expected one actual public source action, got ${matches.length}.`);
  const dimensions = { action: matches[0].id, route, principal: 'visitor', role: 'anonymous', dataset: 'public', lane, state, channel: 'ui' };
  const cell = coverage.cells.find((candidate) => candidate.id === publicActionCellId(dimensions));
  if (cell?.applicable !== true) throw new Error('An applicable actual public action obligation is required.');
  const observations = await assertBehavior();
  if (!safeObservations(observations)) throw new Error('Reviewed concrete non-secret public observations are required.');
  currentCoverage(coverage); // Assertions cannot excuse a source edit during execution.
  const receipt = { schema: RECEIPT_SCHEMA, scope: 'public-auth', ...dimensions, cellId: cell.id, observations, testId: testInfo.testId, titlePath: testInfo.titlePath, retry: testInfo.retry, sourceDigest: coverage.sourceDigest, assertionCompletedAt: new Date().toISOString() };
  await testInfo.attach(`portal-public-action-receipt-${hash(cell.id).slice(0, 12)}`, { body: JSON.stringify(receipt), contentType: 'application/json' });
  await recordExistingBehaviorReceipt(testInfo, { channel: 'portal', receipt }, observations);
  return receipt;
}

export function reconcilePublicPortalActionCoverage(coverage, results = []) {
  const rejected = [];
  let authoritative;
  try { authoritative = currentCoverage(coverage); } catch {
    authoritative = { cells: coverage.cells ?? [], inventory: { unresolved: coverage.inventory?.unresolved ?? [] }, unclassifiedStates: coverage.unclassifiedStates ?? [], unmappedSourceActions: coverage.unmappedSourceActions ?? [], sourceDigest: coverage.sourceDigest };
    rejected.push({ reason: 'stale-or-mutated-public-source' });
  }
  const applicable = new Map(authoritative.cells.filter((cell) => cell.applicable === true).map((cell) => [cell.id, cell]));
  const accepted = new Map();
  for (const result of results) for (const receipt of result.receipts ?? []) {
    if (receipt?.scope !== 'public-auth') { rejected.push({ reason: 'wrong-public-scope' }); continue; }
    const cell = applicable.get(receipt.cellId);
    const valid = !rejected.some((item) => item.reason === 'stale-or-mutated-public-source') && result.status === 'passed' && result.retry === 0 && receipt.retry === 0 && receipt.testId === result.testId
      && receipt.schema === RECEIPT_SCHEMA && receipt.sourceDigest === authoritative.sourceDigest
      && cell && publicActionCellId(receipt) === cell.id && safeObservations(receipt.observations) && canonicalTime(receipt.assertionCompletedAt)
      && Array.isArray(receipt.titlePath) && receipt.titlePath.length > 0 && receipt.titlePath.every((item) => typeof item === 'string' && item.trim())
      && (!result.titlePath || JSON.stringify(result.titlePath) === JSON.stringify(receipt.titlePath))
      && (!result.startedAt || canonicalTime(result.startedAt) && Date.parse(receipt.assertionCompletedAt) >= Date.parse(result.startedAt))
      && (!result.finishedAt || canonicalTime(result.finishedAt) && Date.parse(receipt.assertionCompletedAt) <= Date.parse(result.finishedAt));
    if (!valid) rejected.push({ cellId: receipt.cellId, reason: 'invalid-public-action-proof' });
    else if (accepted.has(cell.id)) rejected.push({ cellId: receipt.cellId, reason: 'duplicate-public-action-proof' });
    else accepted.set(cell.id, receipt);
  }
  const uncovered = [...applicable.values()].filter((cell) => !accepted.has(cell.id));
  return { complete: !uncovered.length && !rejected.length && !authoritative.inventory.unresolved.length && !authoritative.unclassifiedStates.length && !authoritative.unmappedSourceActions.length, covered: [...accepted.values()], uncovered, rejected, unclassifiedStates: authoritative.unclassifiedStates, unresolvedSourceRoots: authoritative.inventory.unresolved, unmappedSourceActions: authoritative.unmappedSourceActions };
}
