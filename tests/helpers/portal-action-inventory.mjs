import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { parseAst } from 'rolldown/parseAst';

export const PORTAL_SOURCE_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const UI_ROOT = 'apps/web/react/src';
const ROOT_SYMBOLS = Object.freeze({
  [`${UI_ROOT}/pages/router.tsx`]: ['RouteView'],
  [`${UI_ROOT}/lib/navigation.ts`]: ['NAV_ITEMS', 'DETAIL_ROUTE_ITEMS'],
  [`${UI_ROOT}/components/layout/app-shell.tsx`]: ['AppShell'],
});
const EVENTS = /^(onClick|onChange|onSubmit|onKeyDown|onKeyUp|onInput|onToggle|onConfirm|onCancel|onClose|onSelect|onValueChange|onCheckedChange|onAction|onRetry|onRefresh|onStartScan|onSave|onRemove|onDelete|onEdit|onNavigate|onRouteChange|onOpen|onExport)$/;
const INTRINSIC = new Set(['button', 'a', 'form', 'input', 'textarea', 'select', 'summary']);
const CUSTOM = /(?:Button|Select|Checkbox|Radio|TabsTrigger|MenuItem|EmptyState|ConfirmModal|FormModal)$/;
const compact = (value) => String(value ?? '').replace(/\s+/g, ' ').trim();
function children(node) {
  return Object.entries(node).filter(([key]) => !['parent', 'loc', 'comments', 'tokens'].includes(key)).flatMap(([, value]) => Array.isArray(value) ? value.filter((child) => child?.type) : value?.type ? [value] : []);
}
function each(node, visit, parent = null) { if (!node) return; visit(node, parent); for (const child of children(node)) each(child, visit, node); }
function stringValues(node) { const values = []; each(node, (child) => { if (child.type === 'Literal' && typeof child.value === 'string') values.push(child.value); }); return values; }

/** AST value-declaration/import reachability, not every JSX node in every imported module. Dead prototype exports are excluded. */
export function buildPortalActionInventory({ root = PORTAL_SOURCE_ROOT } = {}) {
  const modules = new Map();
  const graph = new Map();
  const reached = new Set();
  const actions = [];
  const actionInputs = new Map();
  const callerProps = new Map();
  const unresolved = [];
  const uiPrefix = path.join(root, UI_ROOT) + path.sep;
  const relative = (file) => path.relative(root, file).split(path.sep).join('/');
  const keyFor = (file, name) => `${relative(file)}#${name}`;
  function resolve(file, specifier) {
    if (!specifier.startsWith('.')) return null;
    const base = path.resolve(path.dirname(file), specifier);
    const options = [base, ...['.tsx', '.ts', '.mjs', '.mts', '.js', '/index.tsx', '/index.ts'].map((suffix) => base + suffix)];
    return options.find((candidate) => candidate.startsWith(uiPrefix) && /\.(?:tsx?|m[jt]s|jsx?)$/.test(candidate) && fs.existsSync(candidate) && fs.statSync(candidate).isFile()) ?? null;
  }
  function load(file) {
    if (modules.has(file)) return modules.get(file);
    const source = fs.readFileSync(file, 'utf8');
    const ast = parseAst(source, { lang: /\.tsx$/.test(file) ? 'tsx' : /\.(ts|mts)$/.test(file) ? 'ts' : 'jsx' }, file);
    const module = { file, source, ast, values: new Map(), imports: new Map(), importBindings: new Set(), exports: new Map(), stars: [] };
    modules.set(file, module);
    for (const statement of ast.body) {
      if (statement.type === 'ImportDeclaration') {
        if (statement.importKind !== 'type') for (const spec of statement.specifiers) if (spec.importKind !== 'type') module.importBindings.add(spec.local.name);
        const target = resolve(file, statement.source.value);
        if (target && statement.importKind !== 'type') for (const spec of statement.specifiers) {
          if (spec.importKind !== 'type') module.imports.set(spec.local.name, { file: target, name: spec.type === 'ImportDefaultSpecifier' ? 'default' : spec.type === 'ImportNamespaceSpecifier' ? '*' : spec.imported.name ?? spec.imported.value });
        }
        continue;
      }
      if (statement.type === 'ExportAllDeclaration') { const target = resolve(file, statement.source.value); if (target) module.stars.push(target); continue; }
      const decl = statement.declaration ?? statement;
      const declared = [];
      if (['FunctionDeclaration', 'ClassDeclaration'].includes(decl.type) && decl.id) declared.push([decl.id.name, decl]);
      if (decl.type === 'VariableDeclaration') for (const item of decl.declarations) if (item.id.type === 'Identifier') declared.push([item.id.name, item]);
      for (const [name, value] of declared) {
        module.values.set(name, value);
        if (statement.type.startsWith('Export')) module.exports.set(statement.type === 'ExportDefaultDeclaration' ? 'default' : name, { file, name });
      }
      if (statement.type === 'ExportNamedDeclaration') for (const spec of statement.specifiers ?? []) {
        const target = statement.source ? resolve(file, statement.source.value) : file;
        if (target && statement.exportKind !== 'type') module.exports.set(spec.exported.name ?? spec.exported.value, { file: target, name: spec.local.name ?? spec.local.value });
      }
    }
    return module;
  }
  function resolveValue(file, name, seen = new Set()) {
    const marker = `${file}#${name}`; if (seen.has(marker)) return null; seen.add(marker);
    const module = load(file);
    if (module.values.has(name)) return { module, name, node: module.values.get(name) };
    const ref = module.imports.get(name) ?? module.exports.get(name);
    if (ref && ref.name !== '*') return resolveValue(ref.file, ref.name, seen);
    for (const star of module.stars) { const found = resolveValue(star, name, seen); if (found) return found; }
    return null;
  }
  const raw = (module, node) => node ? compact(module.source.slice(node.start, node.end)) : '';
  const attrValue = (module, attr) => !attr?.value ? '' : attr.value.type === 'Literal' ? String(attr.value.value) : attr.value.type === 'JSXExpressionContainer' ? raw(module, attr.value.expression) : raw(module, attr.value);
  const lexicalCache = new Map();
  const writtenReceivers = new Map();
  function lexicalBindings(module, owner, within = null) {
    const marker = `${module.file}#${owner}:${within?.start ?? ''}:${within?.end ?? ''}`;
    if (lexicalCache.has(marker)) return lexicalCache.get(marker);
    const bindings = new Map(module.values); const setterNames = new Set(); const parameterOwners = new Map();
    const declaration = module.values.get(owner);
    const functionRoot = declaration?.type === 'VariableDeclarator' ? declaration.init : declaration;
    const collectScope = (rootNode) => {
      const bindParameter = (param) => {
        if (!param) return;
        if (param.type === 'Identifier') { bindings.delete(param.name); setterNames.delete(param.name); parameterOwners.set(param.name, rootNode); }
        else if (param.type === 'AssignmentPattern') bindParameter(param.left);
        else if (param.type === 'RestElement') bindParameter(param.argument);
        else if (param.type === 'ObjectPattern') for (const property of param.properties) bindParameter(property.type === 'RestElement' ? property.argument : property.value);
        else if (param.type === 'ArrayPattern') for (const element of param.elements) bindParameter(element);
      };
      for (const param of rootNode?.params ?? []) bindParameter(param);
      const nested = [];
      const collect = (node) => {
        if (!node) return;
        if (node.type === 'FunctionDeclaration' && node.id) bindings.set(node.id.name, node);
        if (node !== rootNode && ['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression'].includes(node.type)) {
          if (within && node.start <= within.start && node.end >= within.end) nested.push(node);
          return;
        }
        if (node.type === 'VariableDeclarator') {
          if (node.id.type === 'Identifier') bindings.set(node.id.name, node.init);
          if (node.id.type === 'ArrayPattern' && /useState/.test(raw(module, node.init))) for (const name of node.id.elements.slice(1)) if (name?.name) setterNames.add(name.name);
        }
        for (const child of children(node)) collect(child);
      };
      collect(rootNode);
      // Overlay only the actual enclosing helper, after its outer scope. Sibling
      // callback declarations/locals never shadow the invoked helper's bindings.
      for (const child of nested) collectScope(child);
    };
    collectScope(functionRoot);
    const result = { bindings, setterNames, parameterOwners, functionRoot }; lexicalCache.set(marker, result); return result;
  }
  function registerCaller(module, owner, node) {
    if (node.name?.type !== 'JSXIdentifier') return;
    const target = resolveValue(module.file, node.name.name);
    if (!target) return;
    const key = keyFor(target.module.file, target.name);
    if (!callerProps.has(key)) callerProps.set(key, []);
    callerProps.get(key).push({ module, owner, props: new Map(node.attributes.filter((attr) => attr.type === 'JSXAttribute').map((attr) => [raw(module, attr.name), attr.value?.expression])) });
  }
  function returnedExpression(fn) {
    const body = fn?.body;
    if (!body) return null;
    if (body.type !== 'BlockStatement') return body;
    const returns = [];
    const collect = (node) => {
      if (!node || node !== body && ['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression'].includes(node.type)) return;
      if (node.type === 'ReturnStatement') returns.push(node);
      for (const child of children(node)) collect(child);
    };
    collect(body);
    return returns.length === 1 && body.body.at(-1) === returns[0] ? returns[0].argument : null;
  }
  // Resolve only one demonstrably equivalent source declaration, never a union
  // of differing callers' business effects. Ambiguity remains a blocking gap.
  function resolveCallbackDeclaration(module, owner, node, seen = new Set()) {
    if (!node) return null;
    const marker = `${module.file}:${owner}:${node.start}:${node.end}`;
    if (seen.has(marker)) return null;
    seen = new Set([...seen, marker]);
    if (node.type === 'VariableDeclarator') return resolveCallbackDeclaration(module, owner, node.init, seen);
    if (node.type === 'CallExpression' && node.callee.type === 'Identifier' && node.callee.name === 'useCallback') {
      const imported = module.imports.get('useCallback');
      const reactImport = module.ast.body.some((statement) => statement.type === 'ImportDeclaration' && statement.source.value === 'react' && statement.specifiers.some((specifier) => specifier.local.name === 'useCallback' && specifier.imported?.name === 'useCallback'));
      const scope = lexicalBindings(module, owner, node);
      if (reactImport && !imported && !scope.bindings.has('useCallback') && !scope.parameterOwners.has('useCallback')) return resolveCallbackDeclaration(module, owner, node.arguments[0], seen);
    }
    if (node.type === 'CallExpression' && node.callee.type === 'Identifier' && node.arguments.length === 0) {
      const factory = resolveCallbackDeclaration(module, owner, node.callee, seen);
      if (factory && !factory.node.async && !factory.node.generator) {
        const returned = returnedExpression(factory.node);
        if (returned) return resolveCallbackDeclaration(factory.module, factory.owner, returned, seen);
      }
    }
    if (node.type === 'Identifier') {
      const scope = lexicalBindings(module, owner, node);
      const binding = scope.bindings.get(node.name);
      if (binding) return resolveCallbackDeclaration(module, module.values.get(node.name) === binding ? node.name : owner, binding, seen);
      if (scope.parameterOwners.has(node.name) && scope.parameterOwners.get(node.name) !== scope.functionRoot) return null;
      if (module.imports.has(node.name) && !scope.parameterOwners.has(node.name)) {
        const imported = resolveValue(module.file, node.name);
        return imported ? resolveCallbackDeclaration(imported.module, imported.name, imported.node, seen) : null;
      }
      const callers = callerProps.get(keyFor(module.file, owner)) ?? [];
      if (!callers.length || callers.some((caller) => !caller.props.get(node.name))) return null;
      const candidates = callers.map((caller) => resolveCallbackDeclaration(caller.module, caller.owner, caller.props.get(node.name), seen));
      if (candidates.some((candidate) => !candidate)) return null;
      const identity = (candidate) => `${candidate.module.file}:${candidate.node.start}:${candidate.node.end}`;
      return candidates.every((candidate) => identity(candidate) === identity(candidates[0])) ? candidates[0] : null;
    }
    if (node.type === 'MemberExpression') return resolveMemberCallback(module, owner, node, seen);
    if (['ArrowFunctionExpression', 'FunctionExpression', 'FunctionDeclaration'].includes(node.type)) {
      let body = node.body;
      if (body?.type === 'BlockStatement' && body.body.length === 1 && ['ReturnStatement', 'ExpressionStatement'].includes(body.body[0].type)) body = body.body[0].argument ?? body.body[0].expression;
      while (body?.type === 'AwaitExpression' || body?.type === 'UnaryExpression' && body.operator === 'void') body = body.argument;
      if (body?.type === 'CallExpression' && body.arguments.length === 0 && body.callee.type === 'Identifier') {
        const forwarded = resolveCallbackDeclaration(module, owner, body.callee, seen);
        if (forwarded) return forwarded;
      }
      return { module, owner, node };
    }
    return null;
  }
  function resolveObjectValue(module, owner, node, seen = new Set()) {
    if (!node) return null;
    const marker = `${module.file}:${owner}:${node.start}:${node.end}`;
    if (seen.has(marker)) return null;
    seen = new Set([...seen, marker]);
    if (node.type === 'ObjectExpression' && !node.properties.some((property) => property.type === 'SpreadElement')) return { module, owner, node };
    if (node.type === 'VariableDeclarator') return resolveObjectValue(module, owner, node.init, seen);
    if (node.type === 'Identifier') {
      const scope = lexicalBindings(module, owner, node);
      const binding = scope.bindings.get(node.name);
      if (binding) return resolveObjectValue(module, module.values.get(node.name) === binding ? node.name : owner, binding, seen);
    }
    if (node.type === 'CallExpression' && node.callee.type === 'Identifier' && !node.arguments.length) {
      const factory = resolveCallbackDeclaration(module, owner, node.callee);
      if (factory && !factory.node.async && !factory.node.generator) return resolveObjectValue(factory.module, factory.owner, returnedExpression(factory.node), seen);
    }
    return null;
  }
  function receiverWrites(module) {
    if (!writtenReceivers.has(module.file)) {
      const names = new Set();
      const aliases = [];
      each(module.ast, (child) => {
        if (child.type === 'VariableDeclarator' && child.id.type === 'Identifier' && child.init?.type === 'Identifier') aliases.push([child.id.name, child.init.name]);
        if (!['AssignmentExpression', 'UpdateExpression'].includes(child.type)) return;
        const target = child.left ?? child.argument;
        if (target?.type === 'Identifier') names.add(target.name);
        if (target?.type === 'MemberExpression' && target.object.type === 'Identifier') names.add(target.object.name);
      });
      // Mutating a lexical alias also invalidates its original object. As with
      // writes above, name collisions remain conservatively module-wide.
      let changed;
      do {
        changed = false;
        for (const [left, right] of aliases) if (names.has(left) !== names.has(right)) {
          names.add(left); names.add(right); changed = true;
        }
      } while (changed);
      writtenReceivers.set(module.file, names);
    }
    return writtenReceivers.get(module.file);
  }
  function resolveMemberCallback(module, owner, node, seen = new Set()) {
    if (node?.type !== 'MemberExpression' || node.computed && node.property.type !== 'Literal') return null;
    const propertyName = node.computed ? node.property.value : node.property.name;
    if (node.object.type === 'Identifier' && receiverWrites(module).has(node.object.name)) return null;
    const receiver = resolveObjectValue(module, owner, node.object);
    if (!receiver) return null;
    const properties = receiver.node.properties.filter((property) => !property.computed && (property.key?.name ?? property.key?.value) === propertyName);
    const property = properties.at(-1);
    return property && property.kind !== 'get' && property.kind !== 'set' ? resolveCallbackDeclaration(receiver.module, receiver.owner, property.value, seen) : null;
  }
  function isNativeCollectionMethod(module, owner, node) {
    if (node?.object?.type !== 'Identifier' || node.property?.name !== 'delete') return false;
    function collection(active, activeOwner, value, seen = new Set()) {
      if (!value) return false;
      const marker = `${active.file}:${activeOwner}:${value.start}:${value.end}`;
      if (seen.has(marker)) return false;
      seen = new Set([...seen, marker]);
      const scope = lexicalBindings(active, activeOwner, value);
      if (value.type === 'VariableDeclarator') return collection(active, activeOwner, value.init, seen);
      if (value.type === 'Identifier') {
        if (receiverWrites(active).has(value.name)) return false;
        return collection(active, activeOwner, scope.bindings.get(value.name), seen);
      }
      if (value.type === 'CallExpression' && value.callee.type === 'Identifier') {
        const helper = resolveCallbackDeclaration(active, activeOwner, value.callee);
        if (helper && !helper.node.async && !helper.node.generator) return collection(helper.module, helper.owner, returnedExpression(helper.node), seen);
      }
      return value.type === 'NewExpression' && value.callee.type === 'Identifier' && ['Set', 'Map', 'URLSearchParams'].includes(value.callee.name)
        && !scope.bindings.has(value.callee.name) && !scope.parameterOwners.has(value.callee.name) && !active.importBindings.has(value.callee.name);
    }
    return collection(module, owner, node.object);
  }
  function isNativeCallable(module, owner, node, seen = new Set()) {
    if (node?.type === 'VariableDeclarator') return isNativeCallable(module, owner, node.init, seen);
    if (node?.type !== 'Identifier') return false;
    const marker = `${module.file}:${owner}:${node.start}:${node.end}`;
    if (seen.has(marker)) return false;
    seen = new Set([...seen, marker]);
    const scope = lexicalBindings(module, owner, node);
    if (scope.bindings.has(node.name)) return isNativeCallable(module, owner, scope.bindings.get(node.name), seen);
    return !scope.parameterOwners.has(node.name) && !module.importBindings.has(node.name) && ['encodeURIComponent', 'decodeURIComponent', 'encodeURI', 'decodeURI'].includes(node.name);
  }
  function actionTraits(module, owner, container, attrs, gates) {
    const earlyGates = [];
    // Only unconditional owner-level early exits constrain every action. Nested
    // callbacks/conditional branches must not leak their permissions into siblings.
    const ownerNode = module.values.get(owner);
    const ownerFunction = ownerNode?.type === 'VariableDeclarator' ? ownerNode.init : ownerNode;
    for (const node of ownerFunction?.body?.body ?? []) if (node.type === 'IfStatement') {
      const exits = node.consequent.type === 'BlockStatement' ? node.consequent.body : [node.consequent];
      if (exits.some((child) => child.type === 'ReturnStatement' && (!child.argument || child.argument.type === 'Literal' && child.argument.value === null))) earlyGates.push(node.test);
    }
    gates = [...gates, ...earlyGates];
    const { bindings } = lexicalBindings(module, owner);
    const callbackNodes = [...attrs].filter(([name]) => EVENTS.test(name)).map(([, attr]) => attr.value?.expression).filter(Boolean);
    const pending = callbackNodes.map((node) => resolveCallbackDeclaration(module, owner, node) ?? { module, owner, node });
    const visited = new Map();
    const effects = new Map();
    const fragments = [];
    const requests = [];
    const eligibilityPermissionCalls = [];
    const earlyCallbackGuards = [];
    const unresolvedCallbacks = new Set();
    const bindInjected = (active, activeOwner, node, schedule = (resolved) => pending.push(resolved)) => {
      const resolved = resolveCallbackDeclaration(active, activeOwner, node);
      if (!resolved) return false;
      schedule(resolved);
      return true;
    };
    for (const node of callbackNodes) {
      if (node.type === 'Identifier' && !bindings.has(node.name) && !lexicalBindings(module, owner).setterNames.has(node.name) && !module.imports.has(node.name) && !bindInjected(module, owner, node)) unresolvedCallbacks.add(node.name);
      if (node.type === 'MemberExpression' && !resolveMemberCallback(module, owner, node)) unresolvedCallbacks.add(raw(module, node));
    }
    let localChange = false;
    function argumentBinding(binding, seen = new Set()) {
      const node = binding?.node;
      if (node?.type !== 'Identifier') return binding;
      const marker = `${binding.module.file}:${binding.owner}:${node.start}:${node.end}`;
      if (seen.has(marker)) return binding;
      seen = new Set([...seen, marker]);
      if (binding.argumentsByName?.has(node.name)) return argumentBinding(binding.argumentsByName.get(node.name), seen);
      if (receiverWrites(binding.module).has(node.name)) return { ...binding, node: null, knownAbsent: false };
      const declaration = lexicalBindings(binding.module, binding.owner, node).bindings.get(node.name);
      const value = declaration?.type === 'VariableDeclarator' ? declaration.init : declaration;
      if (value?.type === 'Identifier') return argumentBinding({ ...binding, node: value }, seen);
      if (['Literal', 'TemplateLiteral', 'ObjectExpression'].includes(value?.type)) return { ...binding, node: value };
      return binding;
    }
    function visitEntry(entry) {
      const { module: active, owner: activeOwner, node } = entry;
      const argumentsByName = entry.argumentsByName ?? new Map();
      const eligibility = entry.eligibility === undefined ? true : entry.eligibility;
      const marker = node && `${active.file}:${node.start}:${node.end}:${eligibility}:${[...argumentsByName].map(([name, value]) => `${name}=${value.module.file}:${value.node?.start}:${value.node?.end}`).join(',')}`;
      if (!node || visited.has(marker)) return effects.get(marker) ?? { alwaysBoundary: false, mayBoundary: false };
      visited.set(marker, entry); fragments.push(raw(active, node));
      const scope = lexicalBindings(active, activeOwner, node);
      let beforeBoundary = eligibility;
      let sawBoundary = false;
      let returnedBeforeBoundary = false;
      const schedule = (target) => {
        // Follow the invoked callee before analysing later statements. A completed
        // earlier request cannot acquire eligibility from its later refresh hooks.
        const effect = visitEntry({ ...target, eligibility: beforeBoundary });
        if (effect.mayBoundary) sawBoundary = true;
        if (effect.alwaysBoundary) beforeBoundary = false;
        else if (effect.mayBoundary && beforeBoundary !== false) beforeBoundary = null;
      };
      const boundArgument = (argument) => {
        const resolved = argumentBinding({ module: active, owner: activeOwner, node: argument, argumentsByName });
        if (resolved.node !== argument) return resolved;
        if (argument?.type === 'CallExpression' && argument.callee.type === 'Identifier' && argument.arguments.length === 0) {
          const helper = resolveValue(active.file, argument.callee.name);
          const statements = helper?.node?.body?.body;
          if (statements?.length === 1 && statements[0].type === 'ReturnStatement' && statements[0].argument?.type === 'Literal') return { module: helper.module, owner: helper.name, node: statements[0].argument };
        }
        return resolved;
      };
      const invokeTarget = (target, call) => {
        const bound = new Map(target.argumentsByName ?? []);
        const assigned = new Set();
        const assignments = (node) => {
          if (!node || node !== target.node && ['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression'].includes(node.type)) return;
          if (['AssignmentExpression', 'UpdateExpression'].includes(node.type) && (node.left ?? node.argument)?.type === 'Identifier') assigned.add((node.left ?? node.argument).name);
          for (const child of children(node)) assignments(child);
        };
        assignments(target.node);
        const targetScope = lexicalBindings(target.module, target.owner, target.node);
        const bindPattern = (pattern, binding) => {
          if (!pattern) return;
          if (pattern.type === 'AssignmentPattern') {
            const value = !binding || binding.knownAbsent ? { module: target.module, owner: target.owner, node: pattern.right, argumentsByName: bound } : binding;
            bindPattern(pattern.left, value);
          } else if (pattern.type === 'Identifier') {
            const absent = { module: target.module, owner: target.owner, node: null, knownAbsent: true };
            if (assigned.has(pattern.name)) bound.set(pattern.name, { ...absent, knownAbsent: false });
            else if (targetScope.bindings.has(pattern.name)) bound.delete(pattern.name);
            else bound.set(pattern.name, argumentBinding(binding ?? absent));
          } else if (pattern.type === 'ObjectPattern') {
            const object = argumentBinding(binding);
            // A spread, accessor or computed property can replace/run arbitrary
            // callbacks. Do not union it with the explicit properties beside it.
            if (object?.node?.type !== 'ObjectExpression' || object.node.properties.some((property) => property.type !== 'Property' || property.computed || ['get', 'set'].includes(property.kind))) {
              for (const property of pattern.properties) if (property.type === 'Property') bindPattern(property.value, { module: target.module, owner: target.owner, node: null, knownAbsent: false });
              return;
            }
            for (const property of pattern.properties) {
              if (property.type !== 'Property') continue;
              if (property.computed) { bindPattern(property.value, { module: target.module, owner: target.owner, node: null, knownAbsent: false }); continue; }
              const key = property.key.name ?? property.key.value;
              const actual = object.node.properties.filter((item) => (item.key.name ?? item.key.value) === key).at(-1);
              bindPattern(property.value, actual ? { ...object, node: actual.value } : { ...object, node: null, knownAbsent: true });
            }
          }
        };
        for (let index = 0; index < target.node.params.length; index++) {
          const argument = call.arguments[index] ? boundArgument(call.arguments[index]) : null;
          bindPattern(target.node.params[index], argument);
        }
        schedule({ ...target, argumentsByName: bound });
      };
      const eachEffect = (current, visit, parent = null) => {
        if (!current || /^TS/.test(current.type) && !['TSAsExpression', 'TSSatisfiesExpression', 'TSNonNullExpression'].includes(current.type) || current !== node && ['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression'].includes(current.type)) return;
        visit(current, parent);
        if (['IfStatement', 'ConditionalExpression', 'LogicalExpression'].includes(current.type)) {
          const conditional = current.type !== 'LogicalExpression';
          eachEffect(conditional ? current.test : current.left, visit, current);
          const beforeBranch = beforeBoundary;
          eachEffect(conditional ? current.consequent : current.right, visit, current);
          const afterConsequent = beforeBoundary;
          beforeBoundary = beforeBranch;
          if (conditional) eachEffect(current.alternate, visit, current);
          // A boundary in only one branch does not establish that a later check
          // is always post-request. Keep that possible eligibility unresolved.
          beforeBoundary = beforeBoundary === afterConsequent ? beforeBoundary : null;
        } else for (const next of children(current)) eachEffect(next, visit, current);
        if (current.type === 'ReturnStatement' && beforeBoundary !== false) returnedBeforeBoundary = true;
      };
      eachEffect(node, (child) => {
        if (child.type === 'Identifier' && scope.setterNames.has(child.name)) localChange = true;
        if (child.type === 'IfStatement' && beforeBoundary === true && node.body?.body?.includes(child)) earlyCallbackGuards.push({ module: active, owner: activeOwner, node: child });
        // A closure read is value provenance, not another execution of its
        // initializer. Only actual invoked callees contribute transaction effects.
        if (child.type !== 'CallExpression') return;
        const callee = raw(active, child.callee);
        if (beforeBoundary !== false && /^(?:sessionHasPermission|staffSessionHasPermission|roleHasPermission)$/.test(callee)) eligibilityPermissionCalls.push({ module: active, owner: activeOwner, node: child });
        if (['requestJson', 'requestSocJson', 'fetch'].includes(callee)) {
          const endpointBinding = boundArgument(child.arguments[callee === 'fetch' ? 0 : 2]);
          const optionsBinding = boundArgument(child.arguments[callee === 'fetch' ? 1 : 3]);
          const endpoint = endpointBinding.node;
          const options = optionsBinding.node;
          const method = options?.properties?.find((property) => (property.key?.name ?? property.key?.value) === 'method')?.value;
          requests.push({ callee, endpoint: raw(endpointBinding.module, endpoint), endpointShape: endpoint?.type === 'TemplateLiteral' ? endpoint.quasis.map((part) => part.value.cooked).join(':id') : endpoint?.value ?? null, method: method?.value ?? (method ? raw(optionsBinding.module, method) : options && options.type !== 'ObjectExpression' ? null : 'GET') });
          beforeBoundary = false;
          sawBoundary = true;
          if (options && options.type !== 'ObjectExpression' || method && method.type !== 'Literal') unresolvedCallbacks.add(`${callee}: unresolved request options/method`);
        } else if (child.callee.type === 'Identifier' && argumentsByName.has(callee)) {
          // An invoked parameter executes exactly the callback its caller passed.
          const bound = argumentBinding(argumentsByName.get(callee));
          const declared = resolveCallbackDeclaration(bound.module, bound.owner, bound.node);
          if (declared) invokeTarget({ ...declared, argumentsByName: bound.argumentsByName }, child);
          else if (!(bound.knownAbsent && child.optional)) unresolvedCallbacks.add(`${callee}: unresolved invoked parameter`);
        } else if (child.callee.type === 'Identifier' && scope.parameterOwners.has(callee) && !scope.bindings.has(callee)) {
          if (!bindInjected(active, activeOwner, child.callee, schedule)) unresolvedCallbacks.add(callee);
        } else if (child.callee.type === 'Identifier' && (scope.bindings.has(callee) || active.imports.has(callee))) {
          let target = scope.bindings.has(callee) ? { module: active, owner: active.values.get(callee) === scope.bindings.get(callee) ? callee : activeOwner, node: scope.bindings.get(callee) } : (() => { const imported = resolveValue(active.file, callee); return imported ? { module: imported.module, owner: imported.name, node: imported.node } : null; })();
          if (target?.node?.type === 'VariableDeclarator') target = { ...target, node: target.node.init };
          if (target && !['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression'].includes(target.node?.type)) target = resolveCallbackDeclaration(target.module, target.owner, target.node);
          if (target) invokeTarget(target, child);
          else if (!isNativeCallable(active, activeOwner, child.callee)) unresolvedCallbacks.add(`${callee}: unresolved callable declaration`);
        } else if (child.callee.type === 'Identifier' && /^(on[A-Z]|handle|submit|save|create|delete|retry|refresh)/.test(callee) && !scope.bindings.has(callee) && !scope.setterNames.has(callee) && !active.imports.has(callee) && !bindInjected(active, activeOwner, child.callee, schedule)) unresolvedCallbacks.add(callee);
        else if (child.callee.type === 'MemberExpression' && /^(?:export|verify|submit|save|create|delete|update|retry|refresh|on[A-Z])/.test(child.callee.property?.name ?? '')) {
          const target = resolveMemberCallback(active, activeOwner, child.callee);
          const receiver = child.callee.object;
          const nativeDomCall = ['URL.createObjectURL', 'URL.revokeObjectURL', 'document.createElement'].includes(callee) && receiver.type === 'Identifier'
            && !scope.bindings.has(receiver.name) && !scope.parameterOwners.has(receiver.name) && !active.importBindings.has(receiver.name);
          if (target) invokeTarget(target, child);
          else if (!isNativeCollectionMethod(active, activeOwner, child.callee) && !nativeDomCall) unresolvedCallbacks.add(callee);
        }
      });
      const effect = { alwaysBoundary: sawBoundary && beforeBoundary === false && !returnedBeforeBoundary, mayBoundary: sawBoundary };
      effects.set(marker, effect);
      return effect;
    }
    while (pending.length) visitEntry(pending.pop());
    // A directly forwarded callback is just as unresolved as onClick={() => onRefresh()}.
    const callbackSource = fragments.join('\n');
    const guardSource = gates.map((gate) => raw(module, gate)).join('\n');
    const permissionSource = [...gates];
    each({ type: 'Program', body: gates }, (node) => { if (node.type === 'Identifier' && bindings.has(node.name)) permissionSource.push(bindings.get(node.name)); });
    function hasAuthorizationReference(active, activeOwner, node, seen = new Set()) {
      if (!node) return false;
      const marker = `${active.file}:${activeOwner}:${node.start}:${node.end}`;
      if (seen.has(marker)) return false;
      seen = new Set([...seen, marker]);
      if (node.type === 'CallExpression' && /^(?:sessionHasPermission|staffSessionHasPermission|roleHasPermission)$/.test(raw(active, node.callee))) return true;
      if (node.type === 'MemberExpression' && /^session\.(?:role|staff_role)$/.test(raw(active, node))) return true;
      if (node.type === 'Identifier') {
        const binding = lexicalBindings(active, activeOwner, node).bindings.get(node.name);
        if (binding && !['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression'].includes(binding.type) && hasAuthorizationReference(active, activeOwner, binding, seen)) return true;
      }
      if (node.type === 'CallExpression' && node.callee.type === 'Identifier' && !['requestJson', 'requestSocJson', 'fetch'].includes(node.callee.name)) {
        const helper = resolveCallbackDeclaration(active, activeOwner, node.callee);
        const returned = helper ? returnedExpression(helper.node) : null;
        if (returned && hasAuthorizationReference(helper.module, helper.owner, returned, seen)) return true;
      }
      return children(node).some((child) => !['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression'].includes(child.type) && hasAuthorizationReference(active, activeOwner, child, seen));
    }
    function permissionGuard(active, activeOwner, node, invert = false, seen = new Set()) {
      if (!node) return null;
      if (node.type === 'Identifier') {
        const marker = `${active.file}:${activeOwner}:${node.name}`;
        if (seen.has(marker)) return null;
        const binding = lexicalBindings(active, activeOwner, node).bindings.get(node.name);
        return binding ? permissionGuard(active, activeOwner, binding, invert, new Set([...seen, marker])) : null;
      }
      if (node.type === 'VariableDeclarator') return permissionGuard(active, activeOwner, node.init, invert, seen);
      if (node.type === 'UnaryExpression' && node.operator === '!') return permissionGuard(active, activeOwner, node.argument, !invert, seen);
      if (node.type === 'LogicalExpression') {
        const operator = invert ? (node.operator === '&&' ? '||' : '&&') : node.operator;
        const left = permissionGuard(active, activeOwner, node.left, invert, seen);
        const right = permissionGuard(active, activeOwner, node.right, invert, seen);
        if (operator === '&&') return left && right ? { operator, left, right } : left ?? right;
        return left && right ? { operator, left, right } : null;
      }
      if (node.type === 'BinaryExpression' && ['===', '!=='].includes(node.operator)) {
        const roleNode = node.left.type === 'Literal' ? node.right : node.left;
        const literal = node.left.type === 'Literal' ? node.left : node.right;
        const roleSource = raw(active, roleNode);
        const declaration = active.values.get(activeOwner);
        const roleParameter = roleNode.type === 'Identifier' && declaration?.params?.some((param) => param.name === roleNode.name && /role/i.test(param.name));
        if (literal.type === 'Literal' && typeof literal.value === 'string' && (roleParameter || /^session\.(?:role|staff_role)$/.test(roleSource))) return { roles: [literal.value], principal: roleSource.includes('staff_role') ? 'staff' : 'customer', invert: invert !== (node.operator === '!==') };
      }
      if (node.type === 'CallExpression' && node.callee.type === 'Identifier' && node.arguments.some((arg) => /^session\.(?:role|staff_role)$/.test(raw(active, arg)))) {
        const helper = resolveValue(active.file, node.callee.name);
        const statements = helper?.node?.body?.body;
        if (statements?.length === 1 && statements[0].type === 'ReturnStatement') {
          const marker = `${helper.module.file}:${helper.name}:role-helper`;
          if (!seen.has(marker)) return permissionGuard(helper.module, helper.name, statements[0].argument, invert, new Set([...seen, marker]));
        }
      }
      if (node.type === 'CallExpression' && /^(sessionHasPermission|staffSessionHasPermission|roleHasPermission)$/.test(raw(active, node.callee))) {
        const permission = node.arguments.find((arg) => arg.type === 'Literal' && typeof arg.value === 'string' && /^[a-z_]+(?::[a-z_]+)+$/.test(arg.value))?.value;
        return permission ? { permission, principal: raw(active, node.callee).startsWith('staff') ? 'staff' : 'customer', invert } : null;
      }
      return null;
    }
    function unresolvedGuard(active, activeOwner, node, invert = false, seen = new Set()) {
      if (!node) return false;
      const marker = `${active.file}:${activeOwner}:${node.start}:${node.end}:${invert}`;
      if (seen.has(marker)) return false;
      seen = new Set([...seen, marker]);
      if (hasAuthorizationReference(active, activeOwner, node) && !permissionGuard(active, activeOwner, node, invert)) return true;
      if (node.type === 'Identifier') {
        const binding = lexicalBindings(active, activeOwner, node).bindings.get(node.name);
        return binding ? unresolvedGuard(active, activeOwner, binding, invert, seen) : false;
      }
      if (node.type === 'VariableDeclarator') return unresolvedGuard(active, activeOwner, node.init, invert, seen);
      if (node.type === 'UnaryExpression' && node.operator === '!') return unresolvedGuard(active, activeOwner, node.argument, !invert, seen);
      if (node.type === 'LogicalExpression') return unresolvedGuard(active, activeOwner, node.left, invert, seen) || unresolvedGuard(active, activeOwner, node.right, invert, seen);
      return false;
    }
    let unresolvedAuthorization = gates.some((gate) => unresolvedGuard(module, owner, gate, earlyGates.includes(gate)));
    const authorizationGuards = [...gates.filter((gate) => !earlyGates.includes(gate)).map((gate) => permissionGuard(module, owner, gate)), ...earlyGates.map((gate) => permissionGuard(module, owner, gate, true))].filter(Boolean);
    for (const { node: child, module: active, owner: activeOwner } of earlyCallbackGuards) {
      const exits = child.consequent.type === 'BlockStatement' ? child.consequent.body : [child.consequent];
      if (!exits.some((statement) => statement.type === 'ReturnStatement' && (!statement.argument || statement.argument.type === 'Literal' && statement.argument.value === null))) continue;
      const guard = permissionGuard(active, activeOwner, child.test, true);
      if (guard) authorizationGuards.push(guard);
      if (unresolvedGuard(active, activeOwner, child.test, true)) unresolvedAuthorization = true;
    }
    const permissionNames = (sources) => {
      const names = new Set();
      for (const { node, module: active } of sources) each(node, (child) => {
        if (child.type === 'CallExpression' && /(?:sessionHasPermission|staffSessionHasPermission|roleHasPermission)$/.test(raw(active, child.callee))) {
          const permission = child.arguments.find((arg) => arg.type === 'Literal' && typeof arg.value === 'string' && /^[a-z_]+(?::[a-z_]+)+$/.test(arg.value));
          if (permission) names.add(permission.value);
        }
      });
      return names;
    };
    const guardSources = permissionSource.map((node) => ({ node, module }));
    const permissions = permissionNames([...guardSources, ...eligibilityPermissionCalls]);
    const referencedPermissions = permissionNames([...guardSources, ...visited.values()]);
    const resolvedPermissions = new Set();
    const guardPermissions = (guard) => { if (guard.permission) resolvedPermissions.add(guard.permission); if (guard.left) guardPermissions(guard.left); if (guard.right) guardPermissions(guard.right); };
    for (const guard of authorizationGuards) guardPermissions(guard);
    const controls = [];
    each(container, (child) => { if (child.type === 'JSXAttribute') controls.push([raw(module, child.name), attrValue(module, child)]); });
    return {
      callbackProvenance: [...visited.values()].map(({ module: active, owner: activeOwner, node }) => ({ file: relative(active.file), owner: activeOwner, line: active.source.slice(0, node.start).split('\n').length })),
      requests: [...new Map(requests.map((request) => [JSON.stringify(request), request])).values()],
      localChange, unresolvedCallbacks: [...unresolvedCallbacks], permissions: [...permissions], referencedPermissions: [...referencedPermissions], authorizationGuards, authorizationUnresolved: unresolvedAuthorization || [...permissions].some((permission) => !resolvedPermissions.has(permission)) || eligibilityPermissionCalls.some(({ module: active, owner: activeOwner, node }) => !permissionGuard(active, activeOwner, node)), guards: compact(guardSource),
      validation: controls.some(([name]) => ['required', 'min', 'max', 'pattern', 'minLength', 'maxLength'].includes(name)) || /validate\w*\(|setFieldErrors\(|setError\(/.test(callbackSource),
      confirmation: /(?:confirm\(|confirmAction\(|setReviewing\(true\)|set\w*Review\()/.test(callbackSource),
      busy: controls.some(([name, value]) => /loading|busy|disabled/.test(name) && /busy|loading|pending|submitting|saving|creating|sending|rotating|revoking|working/i.test(value)) || /setBusy\(|runSettingsAction\(/.test(callbackSource),
      navigation: /(?:navigate\(|onRouteChange\(|location\.(?:hash|href))/.test(callbackSource),
      clipboard: /navigator\.clipboard/.test(callbackSource),
      emptySurface: /EmptyState|TableLoadError/.test(owner) || /(?:length\s*===\s*0|!\w+\.length)/.test(guardSource),
    };
  }
  function recordAction(module, node, parent, owner, gates = []) {
    const tag = raw(module, node.name);
    const attrs = new Map(node.attributes.filter((attr) => attr.type === 'JSXAttribute').map((attr) => [raw(module, attr.name), attr]));
    const handlers = [...attrs.keys()].filter((name) => EVENTS.test(name));
    const propsAction = [...attrs.keys()].some((name) => /^(actionLabel|actionHref|confirmLabel)$/.test(name));
    if (!INTRINSIC.has(tag) && !CUSTOM.test(tag) && !handlers.length && !propsAction) return;
    if (tag === 'input' && attrValue(module, attrs.get('type')) === 'hidden') return;
    const container = parent?.type === 'JSXElement' ? parent : node;
    const text = (container.children ?? []).map((child) => child.type === 'JSXText' ? compact(child.value) : child.type === 'JSXExpressionContainer' ? raw(module, child) : '').filter(Boolean).join(' ');
    const label = ['data-portal-action', 'aria-label', 'label', 'actionLabel', 'confirmLabel', 'title', 'name', 'placeholder'].map((name) => attrValue(module, attrs.get(name))).find(Boolean) || text || tag;
    const kind = tag === 'form' ? 'form-keyboard' : tag === 'a' || attrs.has('href') || attrs.has('actionHref') ? 'anchor'
      : /Select|select/.test(tag) ? 'select' : /Checkbox|Radio/.test(tag) || ['checkbox', 'radio'].includes(attrValue(module, attrs.get('type'))) ? 'checkable'
        : /input|textarea/.test(tag) ? 'field' : tag === 'summary' ? 'disclosure' : /Menu/.test(tag) ? 'menu' : propsAction ? 'action-slot' : 'activate';
    const file = relative(module.file);
    const identity = `${file}#${owner}:${kind}:${createHash('sha256').update(raw(module, container)).digest('hex').slice(0, 12)}`;
    const attributes = Object.fromEntries([...attrs].filter(([name]) => ['type', 'role', 'href', 'disabled', 'loading', 'busy', 'aria-busy', 'actionHref', 'data-portal-action', 'required', 'min', 'max', 'pattern'].includes(name)).map(([name, attr]) => [name, attrValue(module, attr)]));
    const context = /toolbar|page-header/.test(raw(module, container)) ? 'toolbar' : /row|table|item/.test(raw(module, container)) ? 'row' : /EmptyState/.test(tag) ? 'empty-cta' : 'content';
    actionInputs.set(identity, { module, owner, container, attrs, gates });
    actions.push({ id: identity, file, owner, symbol: keyFor(module.file, owner), position: node.start, line: module.source.slice(0, node.start).split('\n').length, tag, kind, context, label: compact(label), handlers: Object.fromEntries(handlers.map((name) => [name, attrValue(module, attrs.get(name))])), attributes, traits: { ...actionTraits(module, owner, container, attrs, gates), modalBoundary: /^(FormModal|ConfirmModal)$/.test(tag) } });
  }
  function follow(file, name, caller, routeConstraint = null) {
    const resolved = resolveValue(file, name);
    if (!resolved) return;
    const { module, node } = resolved;
    const key = keyFor(module.file, resolved.name);
    if (caller) { if (!graph.has(caller)) graph.set(caller, []); graph.get(caller).push({ key, routes: routeConstraint }); }
    if (reached.has(key)) return;
    reached.add(key);
    function walk(child, parent, constraint = null, gates = []) {
      if (!child || /^TS/.test(child.type) && !['TSAsExpression', 'TSSatisfiesExpression', 'TSNonNullExpression'].includes(child.type)) return;
      if (child.type === 'IfStatement' && /\broute\s*===/.test(raw(module, child.test))) {
        const literalRoutes = stringValues(child.test).filter((value) => /^[a-z]+(?:-[a-z]+)*$/.test(value));
        walk(child.test, child, constraint);
        walk(child.consequent, child, literalRoutes.length ? literalRoutes : constraint);
        walk(child.alternate, child, constraint);
        return;
      }
      if (child.type === 'ConditionalExpression') {
        walk(child.test, child, constraint, gates);
        walk(child.consequent, child, constraint, [...gates, child.test]);
        walk(child.alternate, child, constraint, [...gates, { type: 'UnaryExpression', operator: '!', argument: child.test, start: child.test.start, end: child.test.end }]);
        return;
      }
      if (child.type === 'LogicalExpression' && child.operator === '&&') {
        walk(child.left, child, constraint, gates);
        walk(child.right, child, constraint, [...gates, child.left]);
        return;
      }
      if (child.type === 'JSXOpeningElement') registerCaller(module, resolved.name, child);
      if (child.type === 'JSXOpeningElement') { const before = actions.length; recordAction(module, child, parent, resolved.name, gates); if (actions.length > before) actions[actions.length - 1].routeConstraint = constraint; }
      if (child.type === 'JSXIdentifier' && parent?.type === 'JSXOpeningElement' && parent.name === child) follow(module.file, child.name, key, constraint);
      if (child.type === 'Identifier') {
        const property = (parent?.type === 'MemberExpression' && parent.property === child && !parent.computed) || ((parent?.type === 'Property' || parent?.type === 'MethodDefinition') && parent.key === child && !parent.computed);
        if (!property && (module.values.has(child.name) || module.imports.has(child.name))) follow(module.file, child.name, key, constraint);
      }
      for (const next of children(child)) walk(next, child, constraint, gates);
    }
    walk(node, null);
  }
  for (const [file, names] of Object.entries(ROOT_SYMBOLS)) for (const name of names) {
    const target = path.join(root, file);
    if (!fs.existsSync(target) || !resolveValue(target, name)) unresolved.push(`${file}#${name}`);
    else follow(target, name);
  }
  const nav = load(path.join(root, `${UI_ROOT}/lib/navigation.ts`));
  const routeItems = (name) => {
    const result = []; each(nav.values.get(name), (node) => { if (node.type === 'Property' && (node.key.name ?? node.key.value) === 'id' && typeof node.value.value === 'string') result.push(node.value.value); }); return result;
  };
  const navigation = routeItems('NAV_ITEMS');
  const details = routeItems('DETAIL_ROUTE_ITEMS');
  const routes = [...new Set([...navigation, ...details])];
  const router = load(path.join(root, `${UI_ROOT}/pages/router.tsx`));
  const routeRoots = new Map(routes.map((route) => [route, new Set()]));
  const branchRanges = [];
  each(router.values.get('RouteView'), (node) => {
    if (node.type !== 'IfStatement') return;
    const condition = raw(router, node.test);
    let branchRoutes = stringValues(node.test).filter((value) => routes.includes(value));
    const setMatch = condition.match(/^(\w+)\.has\(route\)$/);
    if (setMatch) branchRoutes = stringValues(router.values.get(setMatch[1])).filter((value) => routes.includes(value));
    if (!branchRoutes.length) return;
    branchRanges.push({ start: node.consequent.start, end: node.consequent.end, routes: branchRoutes });
    each(node.consequent, (child) => {
      if (child.type !== 'JSXOpeningElement' || child.name.type !== 'JSXIdentifier') return;
      const resolved = resolveValue(router.file, child.name.name);
      if (resolved) for (const route of branchRoutes) routeRoots.get(route).add(keyFor(resolved.module.file, resolved.name));
    });
  });
  // App mounts authenticated sibling hosts outside RouteView. Derive them from its actual JSX, not a prototype manifest.
  const sharedRoots = [`${UI_ROOT}/components/layout/app-shell.tsx#AppShell`];
  const appFile = path.join(root, `${UI_ROOT}/App.tsx`);
  if (fs.existsSync(appFile)) {
    const app = load(appFile);
    for (const [owner, declaration] of app.values) each(declaration, (node) => {
      if (node.type === 'JSXOpeningElement' && node.name.type === 'JSXIdentifier' && ['AppShell', 'RouteView'].includes(node.name.name)) registerCaller(app, owner, node);
    });
    each(app.ast, (node) => {
      if (node.type === 'JSXOpeningElement' && node.name.type === 'JSXIdentifier' && ['EvidenceInspectorHost', 'ConfirmModalProvider'].includes(node.name.name)) {
        const resolved = resolveValue(appFile, node.name.name);
        if (resolved) { follow(appFile, node.name.name); sharedRoots.push(keyFor(resolved.module.file, resolved.name)); }
      }
    });
  }
  // All actual caller declarations are known only after reachability traversal.
  // Re-analyse effects with exact equivalent injected callback bindings now available.
  for (const action of actions) {
    const input = actionInputs.get(action.id);
    action.traits = { ...actionTraits(input.module, input.owner, input.container, input.attrs, input.gates), modalBoundary: /^(FormModal|ConfirmModal)$/.test(action.tag) };
  }
  const closure = (seeds, route = null) => {
    const result = new Set(); const pending = [...seeds];
    while (pending.length) { const key = pending.pop(); if (result.has(key)) continue; result.add(key); pending.push(...(graph.get(key) ?? []).filter((edge) => !route || !edge.routes || edge.routes.includes(route)).map((edge) => edge.key)); }
    return result;
  };
  const shellKeys = closure(sharedRoots);
  const routeClosures = new Map([...routeRoots].map(([route, roots]) => [route, closure(roots, route)]));
  const unique = new Map();
  for (const item of actions) {
    item.routes = shellKeys.has(item.symbol) ? [...routes] : routes.filter((route) => routeClosures.get(route).has(item.symbol));
    if (item.symbol === `${UI_ROOT}/pages/router.tsx#RouteView`) item.routes = [...new Set(branchRanges.filter((range) => item.position >= range.start && item.position <= range.end).flatMap((range) => range.routes))];
    if (item.routeConstraint) item.routes = item.routes.filter((route) => item.routeConstraint.includes(route));
    item.reachability = shellKeys.has(item.symbol) ? 'shared-shell' : 'router-value-symbol';
    const existing = unique.get(item.id);
    if (existing) existing.sourceOccurrences.push(item.line);
    else unique.set(item.id, { ...item, sourceOccurrences: [item.line] });
  }
  const excludedActions = [];
  const shippedActions = [...unique.values()].filter((action) => {
    if (!action.routes.length && action.symbol === `${UI_ROOT}/pages/router.tsx#RouteView` && routes.every((route) => routeRoots.get(route)?.size)) {
      excludedActions.push({ ...action, reason: 'Unreachable final fallback: every navigation/detail route has an earlier explicit router branch; unknown routes hit the earlier not-found branch.' });
      return false;
    }
    if (!action.routes.length) {
      excludedActions.push({ ...action, reason: 'No routed component/value-symbol closure reaches this action under its route branch constraints; retained as an explicit unmounted/dead source exclusion, not shipped coverage.' });
      return false;
    }
    return true;
  });
  return { schema: 'portal-semantic-actions/v1', scope: 'authenticated customer/staff navigation and detail portal only', scopeExclusions: [{ file: `${UI_ROOT}/App.tsx`, branch: 'public landing/login/signup/password-reset/staff-login', reason: 'Public/auth visitor entrypoints are outside this authenticated navigation/router action slice. Their separate suites need executed receipts; this inventory does not claim all public UI coverage.' }], sourceRoot: root, roots: ROOT_SYMBOLS, mountSource: fs.existsSync(appFile) ? `${UI_ROOT}/App.tsx` : null, navigation, details, routes,
    actions: shippedActions.sort((a, b) => a.id.localeCompare(b.id)), excludedActions, unresolved, reachedSymbols: [...reached].sort() };
}

/** Runtime enumeration retains controls, names, keyboard/forms and denial/disabled presentation; it does NOT click mutators. */
export async function enumeratePortalRuntimeActions(page, { route, role, principal = 'customer', dataset = 'baseline', state = 'success' } = {}) {
  const controls = await page.locator('button,a[href],form,input:not([type="hidden"]),textarea,select,summary,[role="button"],[role="tab"],[role="menuitem"],[role="checkbox"],[role="radio"],[role="option"],[role="combobox"]').evaluateAll((elements) => elements.map((el) => {
    const labels = 'labels' in el ? [...(el.labels ?? [])].map((label) => label.textContent?.trim()).join(' ') : '';
    const rect = el.getBoundingClientRect();
    const labelledBy = (el.getAttribute('aria-labelledby') ?? '').split(/\s+/).filter(Boolean).map((id) => document.getElementById(id)?.textContent ?? '').join(' ');
    const name = el.getAttribute('aria-label') || labelledBy || labels || el.getAttribute('title') || el.textContent?.trim() || el.getAttribute('name') || el.getAttribute('placeholder') || '';
    return { annotation: el.getAttribute('data-portal-action'), tag: el.tagName.toLowerCase(), role: el.getAttribute('role'), type: el.getAttribute('type'), name: name.replace(/\s+/g, ' ').trim(), href: el.getAttribute('href'), visible: rect.width > 0 && rect.height > 0 && getComputedStyle(el).visibility !== 'hidden', disabled: el.matches(':disabled') || el.getAttribute('aria-disabled') === 'true', busy: el.getAttribute('aria-busy') === 'true', keyboard: el.tagName === 'FORM' ? 'submit/Enter' : el.tagName === 'A' ? 'Enter' : 'native/role activation' };
  }));
  return { schema: 'portal-runtime-actions/v1', route, role, principal, dataset, state, controls };
}

export function inventorySourceDigest(inventory, root = inventory.sourceRoot ?? PORTAL_SOURCE_ROOT) {
  const files = [...new Set([...Object.keys(inventory.roots), ...(inventory.mountSource ? [inventory.mountSource] : []), ...inventory.reachedSymbols.map((symbol) => symbol.split('#')[0]), ...inventory.actions.map((action) => action.file)])].sort();
  const hash = createHash('sha256');
  for (const file of files) hash.update(file).update(fs.readFileSync(path.join(root, file)));
  return hash.digest('hex');
}
