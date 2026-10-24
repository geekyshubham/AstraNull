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
const AMBIGUOUS_BINDING = Object.freeze({ type: 'AmbiguousBinding', start: -1, end: -1 });
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
  const routeAccessPolicy = (file) => relative(file).startsWith(`${UI_ROOT}/lib/route-access.`);
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
  const softGates = new WeakSet();
  let finalPass = false;
  const storePublishers = new Map();
  const lexicalCache = new Map();
  const writtenReceivers = new Map();
  function lexicalBindings(module, owner, within = null) {
    const marker = `${module.file}#${owner}:${within?.start ?? ''}:${within?.end ?? ''}`;
    if (lexicalCache.has(marker)) return lexicalCache.get(marker);
    const bindings = new Map(module.values); const setterNames = new Set(); const parameterOwners = new Map(); const tuples = new Map(); const aliases = new Map();
    const declaration = module.values.get(owner);
    const functionRoot = declaration?.type === 'VariableDeclarator' ? declaration.init : declaration;
    const collectScope = (rootNode) => {
      const bindParameter = (param) => {
        if (!param) return;
        if (param.type === 'Identifier') { bindings.delete(param.name); setterNames.delete(param.name); tuples.delete(param.name); aliases.delete(param.name); parameterOwners.set(param.name, rootNode); }
        else if (param.type === 'AssignmentPattern') bindParameter(param.left);
        else if (param.type === 'RestElement') bindParameter(param.argument);
        else if (param.type === 'ObjectPattern') for (const property of param.properties) bindParameter(property.type === 'RestElement' ? property.argument : property.value);
        else if (param.type === 'ArrayPattern') for (const element of param.elements) bindParameter(element);
      };
      for (const param of rootNode?.params ?? []) bindParameter(param);
      const nested = [];
      const declared = new Map();
      const blocks = [rootNode];
      const declare = (name, value) => { if (!declared.has(name)) declared.set(name, []); declared.get(name).push({ value, block: blocks.at(-1) }); };
      const collect = (node) => {
        if (!node) return;
        if (node.type === 'FunctionDeclaration' && node.id) { bindings.set(node.id.name, node); declare(node.id.name, node); }
        if (node !== rootNode && ['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression'].includes(node.type)) {
          if (within && node.start <= within.start && node.end >= within.end) nested.push(node);
          return;
        }
        if (node.type === 'VariableDeclarator') {
          if (node.id.type === 'Identifier') { bindings.set(node.id.name, node.init); declare(node.id.name, node.init); }
          if (node.id.type === 'ArrayPattern' && /useState/.test(raw(module, node.init))) for (const name of node.id.elements.slice(1)) if (name?.name) setterNames.add(name.name);
          if (node.id.type === 'ArrayPattern' && node.init?.type === 'CallExpression') node.id.elements.forEach((element, index) => { if (element?.type === 'Identifier') { tuples.set(element.name, { init: node.init, index }); declare(element.name, null); } });
          if (node.id.type === 'ObjectPattern' && node.init?.type === 'Identifier') for (const property of node.id.properties) if (property.type === 'Property' && !property.computed && property.value.type === 'Identifier') { aliases.set(property.value.name, { object: node.init.name, key: property.key.name ?? property.key.value }); declare(property.value.name, null); }
        }
        const scoped = node !== rootNode && ['BlockStatement', 'ForStatement', 'ForInStatement', 'ForOfStatement', 'CatchClause', 'SwitchStatement'].includes(node.type);
        if (scoped) blocks.push(node);
        for (const child of children(node)) collect(child);
        if (scoped) blocks.pop();
      };
      collect(rootNode);
      // Block-scoped redeclarations resolve to the innermost block holding the reference; otherwise
      // the name is ambiguous and must not silently take the last declaration.
      for (const [name, entries] of declared) {
        if (entries.length < 2) continue;
        const holding = within ? entries.filter(({ block }) => block.start <= within.start && within.end <= block.end) : [];
        const innermost = holding.sort((left, right) => (left.block.end - left.block.start) - (right.block.end - right.block.start));
        const chosen = innermost.length && (innermost.length === 1 || innermost[0].block !== innermost[1].block) ? innermost[0] : null;
        setterNames.delete(name); tuples.delete(name); aliases.delete(name);
        if (chosen?.value) bindings.set(name, chosen.value);
        else bindings.set(name, AMBIGUOUS_BINDING);
      }
      // Overlay only the actual enclosing helper, after its outer scope. Sibling
      // callback declarations/locals never shadow the invoked helper's bindings.
      for (const child of nested) collectScope(child);
    };
    collectScope(functionRoot);
    const result = { bindings, setterNames, parameterOwners, tuples, aliases, functionRoot }; lexicalCache.set(marker, result); return result;
  }
  function registerCaller(module, owner, node) {
    if (node.name?.type !== 'JSXIdentifier') return;
    const target = resolveValue(module.file, node.name.name);
    if (!target) return;
    const key = keyFor(target.module.file, target.name);
    if (!callerProps.has(key)) callerProps.set(key, []);
    callerProps.get(key).push({ module, owner, attributes: node.attributes, spread: node.attributes.some((attr) => attr.type === 'JSXSpreadAttribute'), props: new Map(node.attributes.filter((attr) => attr.type === 'JSXAttribute').map((attr) => [raw(module, attr.name), attr.value?.expression])) });
  }
  const valueReferences = new Map();
  function registerReference(module, owner, node, parent) {
    if (['FunctionDeclaration', 'VariableDeclarator', 'ClassDeclaration'].includes(parent?.type) && parent.id === node) return;
    const target = resolveValue(module.file, node.name);
    if (!target) return;
    const key = keyFor(target.module.file, target.name);
    if (!valueReferences.has(key)) valueReferences.set(key, []);
    valueReferences.get(key).push({ module, owner, node, call: parent?.type === 'CallExpression' && parent.callee === node ? parent : null });
  }
  // Exact direct call sites of a reached function, or null when any unshadowed reference lets it escape.
  function directCallSites(module, owner) {
    const references = (valueReferences.get(keyFor(module.file, owner)) ?? []).filter((reference) => {
      const scope = lexicalBindings(reference.module, reference.owner, reference.node);
      if (scope.parameterOwners.has(reference.node.name)) return false;
      return reference.module.imports.has(reference.node.name) ? !scope.bindings.has(reference.node.name) : scope.bindings.get(reference.node.name) === reference.module.values.get(reference.node.name);
    });
    return references.every((reference) => reference.call) ? references : null;
  }
  function reactHook(module, owner, node, name) {
    const reactImport = module.ast.body.some((statement) => statement.type === 'ImportDeclaration' && statement.source.value === 'react' && statement.specifiers.some((specifier) => specifier.local.name === name && specifier.imported?.name === name));
    const scope = lexicalBindings(module, owner, node);
    return reactImport && !module.imports.has(name) && !scope.bindings.has(name) && !scope.parameterOwners.has(name);
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
  function resolveCallbackDeclaration(module, owner, node, seen = new Set(), options = {}) {
    if (!node) return null;
    const marker = `${module.file}:${owner}:${node.start}:${node.end}`;
    if (seen.has(marker)) return null;
    seen = new Set([...seen, marker]);
    if (node.type === 'VariableDeclarator') return resolveCallbackDeclaration(module, owner, node.init, seen);
    if (node.type === 'CallExpression' && node.callee.type === 'Identifier' && node.callee.name === 'useCallback' && reactHook(module, owner, node, 'useCallback')) return resolveCallbackDeclaration(module, owner, node.arguments[0], seen);
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
      const tuple = !scope.setterNames.has(node.name) && scope.tuples.get(node.name);
      if (tuple && tuple.init.callee.type === 'Identifier') {
        // A custom hook returning one fixed array exposes the exact declaration at that index.
        const factory = resolveCallbackDeclaration(module, owner, tuple.init.callee, seen);
        const returned = factory && !factory.node.async && !factory.node.generator ? returnedExpression(factory.node) : null;
        const element = returned?.type === 'ArrayExpression' ? returned.elements[tuple.index] : null;
        return element && element.type !== 'SpreadElement' ? resolveCallbackDeclaration(factory.module, factory.owner, element, seen) : null;
      }
      if (scope.parameterOwners.has(node.name) && scope.parameterOwners.get(node.name) !== scope.functionRoot) return null;
      if (module.imports.has(node.name) && !scope.parameterOwners.has(node.name)) {
        const imported = resolveValue(module.file, node.name);
        return imported ? resolveCallbackDeclaration(imported.module, imported.name, imported.node, seen) : null;
      }
      const allCallers = callerProps.get(keyFor(module.file, owner)) ?? [];
      const callers = options.suppliedOnly?.has(node.name) ? allCallers.filter((caller) => caller.props.get(node.name)) : allCallers;
      if (!callers.length || callers.some((caller) => !caller.props.get(node.name) || caller.spread)) return null;
      const candidates = callers.map((caller) => resolveCallbackDeclaration(caller.module, caller.owner, caller.props.get(node.name), seen));
      if (candidates.some((candidate) => !candidate)) return null;
      const identity = (candidate) => `${candidate.module.file}:${candidate.node.start}:${candidate.node.end}`;
      return candidates.every((candidate) => identity(candidate) === identity(candidates[0])) ? candidates[0] : null;
    }
    if (node.type === 'ConditionalExpression') {
      const absent = (branch) => branch.type === 'Literal' && branch.raw === 'null'
        || branch.type === 'Identifier' && branch.name === 'undefined' && !lexicalBindings(module, owner, branch).bindings.has('undefined');
      if (absent(node.alternate)) return resolveCallbackDeclaration(module, owner, node.consequent, seen, options);
      if (absent(node.consequent)) return resolveCallbackDeclaration(module, owner, node.alternate, seen, options);
      return null;
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
  // `members` resolves a hook's returned object for member callbacks: its arguments are only read
  // there, and spreads are allowed because the member lookup rejects any spread after the property.
  function resolveObjectValue(module, owner, node, seen = new Set(), members = false) {
    if (!node) return null;
    const marker = `${module.file}:${owner}:${node.start}:${node.end}`;
    if (seen.has(marker)) return null;
    seen = new Set([...seen, marker]);
    if (node.type === 'ObjectExpression' && (members || !node.properties.some((property) => property.type === 'SpreadElement'))) return { module, owner, node };
    if (node.type === 'VariableDeclarator') return resolveObjectValue(module, owner, node.init, seen, members);
    if (node.type === 'Identifier') {
      const scope = lexicalBindings(module, owner, node);
      const binding = scope.bindings.get(node.name);
      if (binding) return resolveObjectValue(module, module.values.get(node.name) === binding ? node.name : owner, binding, seen, members);
    }
    if (members && node.type === 'CallExpression' && node.callee.type === 'Identifier' && node.callee.name === 'useMemo' && reactHook(module, owner, node, 'useMemo') && ['ArrowFunctionExpression', 'FunctionExpression'].includes(node.arguments[0]?.type)) {
      return resolveObjectValue(module, owner, returnedExpression(node.arguments[0]), seen, members);
    }
    if (node.type === 'CallExpression' && node.callee.type === 'Identifier' && (members ? /^use[A-Z]/.test(node.callee.name) : !node.arguments.length)) {
      const factory = resolveCallbackDeclaration(module, owner, node.callee);
      if (factory && !factory.node.async && !factory.node.generator) return resolveObjectValue(factory.module, factory.owner, returnedExpression(factory.node), seen, members);
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
    const receiver = resolveObjectValue(module, owner, node.object, new Set(), true);
    if (!receiver) return null;
    const properties = receiver.node.properties.filter((property) => property.type === 'Property' && !property.computed && (property.key?.name ?? property.key?.value) === propertyName);
    const property = properties.at(-1);
    const lastSpread = receiver.node.properties.findLastIndex((item) => item.type === 'SpreadElement');
    if (!property || receiver.node.properties.indexOf(property) < lastSpread) return null;
    return property.kind !== 'get' && property.kind !== 'set' ? resolveCallbackDeclaration(receiver.module, receiver.owner, property.value, seen) : null;
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
  function conditionalBranches(module, owner, node) {
    if (node.type !== 'ConditionalExpression') return [resolveCallbackDeclaration(module, owner, node)];
    return [node.consequent, node.alternate].filter((branch) => !absentValue(module, owner, branch)).flatMap((branch) => conditionalBranches(module, owner, branch));
  }
  // A ref whose every assignment is null or a `new Promise` executor's resolve/reject only settles
  // a pending promise; the awaiting caller's own action owns whatever follows.
  function promiseSettler(module, owner, node) {
    const binding = lexicalBindings(module, owner, node).bindings.get(node.name);
    if (binding?.type !== 'MemberExpression' || binding.computed || binding.property.name !== 'current' || binding.object.type !== 'Identifier') return false;
    const ref = binding.object.name;
    if (!/^(?:React\.)?useRef\b/.test(raw(module, lexicalBindings(module, owner, binding).bindings.get(ref)))) return false;
    const values = [];
    let escapes = false;
    each(componentRoot(module, owner), (child, parent) => {
      if (child.type === 'Identifier' && child.name === ref && !(parent?.type === 'MemberExpression' && parent.object === child && !parent.computed && parent.property.name === 'current') && !(parent?.type === 'VariableDeclarator' && parent.id === child)) escapes = true;
      if (child.type === 'AssignmentExpression' && raw(module, child.left) === `${ref}.current`) values.push(child.right);
    });
    const executors = [];
    each(componentRoot(module, owner), (child) => {
      if (child.type === 'NewExpression' && child.callee.type === 'Identifier' && child.callee.name === 'Promise' && ['ArrowFunctionExpression', 'FunctionExpression'].includes(child.arguments[0]?.type)) executors.push(child.arguments[0]);
    });
    const settles = (value) => value.type === 'Literal' && value.value === null
      || value.type === 'Identifier' && executors.some((executor) => executor.start <= value.start && value.end <= executor.end && executor.params.slice(0, 2).some((param) => param.type === 'Identifier' && param.name === value.name));
    return !escapes && values.length > 0 && values.every(settles) && !lexicalBindings(module, owner, node).parameterOwners.has('Promise');
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
  const literalStrings = (active, activeOwner, node) => {
    let value = node;
    if (value?.type === 'Identifier') { const binding = lexicalBindings(active, activeOwner, value).bindings.get(value.name); value = binding?.type === 'VariableDeclarator' ? binding.init : binding; }
    if (value?.type === 'CallExpression' && raw(active, value.callee) === 'Object.freeze' && value.arguments.length === 1) value = value.arguments[0];
    return value?.type === 'ArrayExpression' && value.elements.every((element) => element?.type === 'Literal' && typeof element.value === 'string') ? value.elements.map((element) => element.value) : null;
  };
  function permissionGuard(active, activeOwner, node, invert = false, seen = new Set(), principalHint = null) {
    if (!node) return null;
    if (node.type === 'Identifier') {
      const marker = `${active.file}:${activeOwner}:${node.name}`;
      if (seen.has(marker)) return null;
      const scope = lexicalBindings(active, activeOwner, node);
      const binding = scope.bindings.get(node.name);
      if (binding) return permissionGuard(active, activeOwner, binding, invert, new Set([...seen, marker]), principalHint);
      const callers = callerProps.get(keyFor(active.file, activeOwner)) ?? [];
      if (!scope.parameterOwners.has(node.name) || !callers.length || callers.some((caller) => caller.spread || !caller.props.get(node.name))) return null;
      const guards = callers.map((caller) => permissionGuard(caller.module, caller.owner, caller.props.get(node.name), invert, new Set([...seen, marker])));
      return guards.every((guard) => guard && JSON.stringify(guard) === JSON.stringify(guards[0])) ? guards[0] : null;
    }
    if (node.type === 'VariableDeclarator') return permissionGuard(active, activeOwner, node.init, invert, seen, principalHint);
    if (node.type === 'UnaryExpression' && node.operator === '!') return permissionGuard(active, activeOwner, node.argument, !invert, seen, principalHint);
    if (node.type === 'LogicalExpression') {
      const operator = invert ? (node.operator === '&&' ? '||' : '&&') : node.operator;
      const left = permissionGuard(active, activeOwner, node.left, invert, seen, principalHint);
      const right = permissionGuard(active, activeOwner, node.right, invert, seen, principalHint);
      if (operator === '&&') return left && right ? { operator, left, right } : left ?? right;
      return left && right ? { operator, left, right } : null;
    }
    if (node.type === 'BinaryExpression' && ['===', '!=='].includes(node.operator)) {
      const roleNode = node.left.type === 'Literal' ? node.right : node.left;
      const literal = node.left.type === 'Literal' ? node.left : node.right;
      const roleSource = raw(active, roleNode);
      if (literal.type === 'Literal' && ['staff', 'customer'].includes(literal.value) && /(?:^|\.)principal$/.test(roleSource)) return { principals: [literal.value], invert: invert !== (node.operator === '!==') };
      const declaration = active.values.get(activeOwner);
      const roleParameter = roleNode.type === 'Identifier' && declaration?.params?.some((param) => param.name === roleNode.name && /role/i.test(param.name));
      if (literal.type === 'Literal' && typeof literal.value === 'string' && (roleParameter || /^session\.(?:role|staff_role)$/.test(roleSource))) return { roles: [literal.value], principal: principalHint ?? (roleSource.includes('staff_role') ? 'staff' : 'customer'), invert: invert !== (node.operator === '!==') };
    }
    if (node.type === 'CallExpression' && node.callee.type === 'Identifier' && node.arguments.some((arg) => /^session\.(?:role|staff_role)$/.test(raw(active, arg)))) {
      const helper = resolveValue(active.file, node.callee.name);
      const statements = helper?.node?.body?.body;
      if (statements?.length === 1 && statements[0].type === 'ReturnStatement') {
        const marker = `${helper.module.file}:${helper.name}:role-helper`;
        const hint = node.arguments.some((arg) => /^session\.staff_role$/.test(raw(active, arg))) ? 'staff' : 'customer';
        if (!seen.has(marker)) return permissionGuard(helper.module, helper.name, statements[0].argument, invert, new Set([...seen, marker]), hint);
      }
    }
    if (node.type === 'CallExpression' && node.callee.type === 'MemberExpression' && node.callee.property?.name === 'includes' && node.arguments.length === 1) {
      const list = literalStrings(active, activeOwner, node.callee.object);
      const parameters = (active.values.get(activeOwner)?.params ?? []).filter((param) => param.type === 'Identifier' && /role/i.test(param.name));
      if (list && parameters.some((param) => raw(active, node.arguments[0]).includes(param.name))) return { roles: list, principal: principalHint ?? 'customer', invert };
    }
    if (node.type === 'CallExpression' && /^(sessionHasPermission|staffSessionHasPermission|roleHasPermission)$/.test(raw(active, node.callee))) {
      const permission = node.arguments.find((arg) => arg.type === 'Literal' && typeof arg.value === 'string' && /^[a-z_]+(?::[a-z_]+)+$/.test(arg.value))?.value;
      return permission ? { permission, principal: raw(active, node.callee).startsWith('staff') ? 'staff' : 'customer', invert } : null;
    }
    return null;
  }
  const componentRoot = (module, owner) => {
    const declaration = module.values.get(owner);
    let root = declaration?.type === 'VariableDeclarator' ? declaration.init : declaration;
    while (root?.type === 'CallExpression' && /^(?:React\.)?(?:forwardRef|memo)$/.test(raw(module, root.callee)) && root.arguments.length === 1) root = root.arguments[0];
    return root;
  };
  const absentValue = (module, owner, node) => node.type === 'Literal' && node.raw === 'null'
    || node.type === 'Identifier' && node.name === 'undefined' && !lexicalBindings(module, owner, node).bindings.has('undefined');
  // An omitted, undefaulted callback prop leaves no handler when every read is a truthiness test,
  // an optional call, a hook dependency, an intrinsic event attribute, or a child prop that is inert in turn.
  function omissionInert(module, owner, name, seen = new Set()) {
    const marker = `${module.file}#${owner}#${name}`;
    if (seen.has(marker)) return false;
    seen = new Set([...seen, marker]);
    const root = componentRoot(module, owner);
    const pattern = root?.params?.[0];
    const property = pattern?.type === 'ObjectPattern' ? pattern.properties.find((item) => item.type === 'Property' && !item.computed && (item.key.name ?? item.key.value) === name) : null;
    const rest = !property && EVENTS.test(name) ? pattern?.properties?.find((item) => item.type === 'RestElement' && item.argument.type === 'Identifier') : null;
    const whole = pattern?.type === 'Identifier' ? pattern.name : null;
    if (property?.value.type !== 'Identifier' && !rest && !whole) return false;
    const local = property ? property.value.name : rest ? rest.argument.name : whole;
    const ancestors = [];
    let inert = true;
    const requires = (test) => test?.type === 'Identifier' ? test.name === local && !whole
      : test?.type === 'MemberExpression' ? Boolean(whole) && !test.computed && test.object.type === 'Identifier' && test.object.name === whole && test.property.name === name
        : test?.type === 'LogicalExpression' && test.operator === '&&' && (requires(test.left) || requires(test.right));
    const guarded = (node) => ancestors.some((ancestor, index) => {
      const next = ancestors[index + 1] ?? node;
      return (ancestor.type === 'IfStatement' || ancestor.type === 'ConditionalExpression') && ancestor.consequent === next && requires(ancestor.test)
        || ancestor.type === 'LogicalExpression' && ancestor.operator === '&&' && ancestor.right === next && requires(ancestor.left);
    });
    const reference = (node) => {
      const [parent, grand, great] = [ancestors.at(-1), ancestors.at(-2), ancestors.at(-3)];
      if (rest) return parent.type === 'JSXSpreadAttribute' && grand?.type === 'JSXOpeningElement' && grand.name.type === 'JSXIdentifier' && /^[a-z]/.test(grand.name.name);
      if (parent.type === 'MemberExpression' && parent.property === node && !parent.computed) return true;
      if (parent.type === 'Property' && parent.key === node && !parent.shorthand) return true;
      if (guarded(node)) return true;
      if (parent.type === 'CallExpression') return parent.callee === node && parent.optional;
      if (['IfStatement', 'ConditionalExpression'].includes(parent.type)) return parent.test === node;
      if (['LogicalExpression', 'UnaryExpression'].includes(parent.type)) return true;
      if (parent.type === 'ArrayExpression') return grand?.type === 'CallExpression' && grand.arguments[1] === parent && /^use(?:Callback|Effect|LayoutEffect|Memo)$/.test(raw(module, grand.callee));
      if (parent.type !== 'JSXExpressionContainer' || grand?.type !== 'JSXAttribute' || great?.type !== 'JSXOpeningElement' || great.name.type !== 'JSXIdentifier') return false;
      if (/^[a-z]/.test(great.name.name)) return EVENTS.test(raw(module, grand.name));
      const target = resolveValue(module.file, great.name.name);
      return Boolean(target) && omissionInert(target.module, target.name, raw(module, grand.name), seen);
    };
    const visit = (node) => {
      if (!inert || !node) return;
      if (whole && node.type === 'Identifier' && node.name === local && ancestors.length) {
        const parent = ancestors.at(-1);
        if (parent.type === 'MemberExpression' && parent.object === node && !parent.computed && parent.property.name !== name) return;
        if (parent.type !== 'MemberExpression' || parent.object !== node || parent.computed) { inert = false; return; }
        const member = ancestors.pop();
        const ok = reference(member);
        ancestors.push(member);
        if (!ok) inert = false;
        return;
      }
      if (!whole && node.type === 'Identifier' && node.name === local && ancestors.length && !reference(node)) {
        if (process.env.PORTAL_INVENTORY_DEBUG && finalPass) console.error('not inert', keyFor(module.file, owner), name, ancestors.at(-1).type, raw(module, ancestors.at(-2) ?? node).slice(0, 80));
        inert = false; return;
      }
      ancestors.push(node);
      for (const child of children(node)) visit(child);
      ancestors.pop();
    };
    visit(root.body);
    return inert;
  }
  // Every concrete value an expression can carry, following component props, `props.x`,
  // destructured prop aliases and members of resolvable objects back to their declarations.
  // Null means some flow is unknown; `{ omitted }` marks a caller that leaves the prop undefined.
  function flowValues(module, owner, expression, seen = new Set()) {
    if (!expression) return null;
    const marker = `${module.file}:${owner}:${expression.start}:${expression.end}`;
    if (seen.has(marker)) return null;
    seen = new Set([...seen, marker]);
    if (expression.type === 'ConditionalExpression') {
      if (absentValue(module, owner, expression.alternate)) return flowValues(module, owner, expression.consequent, seen);
      if (absentValue(module, owner, expression.consequent)) return flowValues(module, owner, expression.alternate, seen);
      const both = [flowValues(module, owner, expression.consequent, seen), flowValues(module, owner, expression.alternate, seen)];
      return both.every(Boolean) ? both.flat() : null;
    }
    const scope = lexicalBindings(module, owner, expression);
    const root = scope.functionRoot;
    const whole = root?.params?.[0]?.type === 'Identifier' ? root.params[0].name : null;
    const propFlow = (prop) => {
      const callers = callerProps.get(keyFor(module.file, owner)) ?? [];
      if (!callers.length) return null;
      const values = [];
      for (const caller of callers) {
        const supplied = callerValues(caller, prop);
        if (!supplied) return null;
        for (const entry of supplied) {
          if (entry.value === null) { values.push({ omitted: true, inert: omissionInert(module, owner, prop) }); continue; }
          const nested = flowValues(entry.module, entry.owner, entry.value, seen);
          if (!nested) return null;
          values.push(...nested);
        }
      }
      return values;
    };
    if (expression.type === 'Identifier') {
      const binding = scope.bindings.get(expression.name);
      if (binding === AMBIGUOUS_BINDING) return null;
      if (!binding && scope.parameterOwners.get(expression.name) === root && root.params[0]?.type === 'ObjectPattern') {
        const property = root.params[0].properties.find((item) => item.type === 'Property' && !item.computed && item.value.type === 'Identifier' && item.value.name === expression.name);
        return property ? propFlow(property.key.name ?? property.key.value) : null;
      }
      if (binding && ['Identifier', 'MemberExpression', 'ConditionalExpression'].includes(binding.type)) return receiverWrites(module).has(expression.name) ? null : flowValues(module, owner, binding, seen);
      const alias = !binding && scope.aliases.get(expression.name);
      if (alias && whole && alias.object === whole && !scope.bindings.has(whole)) return propFlow(alias.key);
      return [{ module, owner, value: expression }];
    }
    if (expression.type === 'MemberExpression' && !expression.computed) {
      const property = expression.property.name;
      if (expression.object.type === 'Identifier' && expression.object.name === whole && !scope.bindings.has(whole)) return propFlow(property);
      if (expression.object.type === 'Identifier' && receiverWrites(module).has(expression.object.name)) return null;
      const objects = flowValues(module, owner, expression.object, seen);
      if (!objects) return null;
      const values = [];
      for (const object of objects) {
        const mutated = object.value?.type === 'Identifier' && receiverWrites(object.module).has(object.value.name);
        const resolved = !object.omitted && !mutated && resolveObjectValue(object.module, object.owner, object.value, new Set(), true);
        if (!resolved) return null;
        const member = resolved.node.properties.filter((item) => item.type === 'Property' && !item.computed && (item.key?.name ?? item.key?.value) === property).at(-1);
        if (!member || member.kind !== 'init' || resolved.node.properties.indexOf(member) < resolved.node.properties.findLastIndex((item) => item.type === 'SpreadElement')) return null;
        const nested = flowValues(resolved.module, resolved.owner, member.value, seen);
        if (!nested) return null;
        values.push(...nested);
      }
      return values;
    }
    return [{ module, owner, value: expression }];
  }
  // One exact declaration (or only useState setters) behind every supplied flow; any second
  // declaration is a union of differing business effects and stays unresolved.
  function flowCallback(module, owner, node) {
    const flows = flowValues(module, owner, node);
    if (!flows) return null;
    const declarations = new Map();
    let setter = false;
    let supplied = 0;
    for (const flow of flows) {
      if (flow.omitted) { if (!flow.inert) return null; continue; }
      supplied += 1;
      const declaration = resolveCallbackDeclaration(flow.module, flow.owner, flow.value);
      if (declaration) declarations.set(`${declaration.module.file}:${declaration.node.start}:${declaration.node.end}`, declaration);
      else if (terminalCallback(flow)) setter = true;
      else return null;
    }
    if (!supplied || declarations.size > 1 || declarations.size && setter) return null;
    return { declaration: [...declarations.values()][0] ?? null, setter };
  }
  function terminalCallback({ module, owner, value }) {
    if (resolveCallbackDeclaration(module, owner, value)) return true;
    if (value.type !== 'Identifier') return false;
    const scope = lexicalBindings(module, owner, value);
    return !scope.bindings.has(value.name) && scope.setterNames.has(value.name);
  }
  // A primitive's forwarded callback is bound when every value its callers can supply reaches an
  // exact declaration or setter; callers that omit it count separately when omission is inert.
  function callerBinding(module, owner, name) {
    const callers = callerProps.get(keyFor(module.file, owner)) ?? [];
    const states = [];
    const labels = [];
    for (const caller of callers) {
      const supplied = callerValues(caller, name) ?? [{ module: caller.module, owner: caller.owner, value: undefined }];
      for (const entry of supplied) {
        const label = `${relative(entry.module.file)} ${entry.owner} ${entry.value ? raw(entry.module, entry.value) : entry.value === null ? '(omitted)' : '(unknown spread)'}`;
        if (entry.value === null) { states.push(omissionInert(module, owner, name) ? 'omitted' : 'unbound'); labels.push(label); continue; }
        const flows = entry.value ? flowValues(entry.module, entry.owner, entry.value) : null;
        if (!flows) { states.push('unbound'); labels.push(label); continue; }
        for (const flow of flows) { states.push(flow.omitted ? (flow.inert ? 'omitted' : 'unbound') : terminalCallback(flow) ? 'bound' : 'unbound'); labels.push(label); }
      }
    }
    if (process.env.PORTAL_INVENTORY_DEBUG && finalPass) states.forEach((state, index) => { if (state === 'unbound') console.error('unbound', keyFor(module.file, owner), name, '<-', labels[index]); });
    const omitted = states.filter((state) => state === 'omitted').length;
    return { callers: states.length, resolved: states.filter((state) => state === 'bound').length, ...(omitted ? { omitted } : {}) };
  }
  // Every value one JSX caller can supply for a prop, in attribute order: null when omitted, or
  // null for the whole caller when a spread cannot be resolved to exact objects.
  function callerValues(caller, name, seen = new Set()) {
    let values = [{ module: caller.module, owner: caller.owner, value: null }];
    for (const attribute of caller.attributes ?? []) {
      if (attribute.type === 'JSXAttribute') {
        if (raw(caller.module, attribute.name) === name) values = [{ module: caller.module, owner: caller.owner, value: attribute.value?.expression ?? attribute.value ?? attribute }];
        continue;
      }
      const spread = spreadValues(caller.module, caller.owner, attribute.argument, name, seen);
      if (!spread) return null;
      values = values.flatMap((previous) => spread.map((next) => next.value === null ? previous : next));
      if (values.length > 256) return null;
    }
    return values;
  }
  function spreadValues(module, owner, node, name, seen) {
    if (node?.type === 'Identifier' && receiverWrites(module).has(node.name)) return null;
    const object = resolveObjectValue(module, owner, node);
    if (object) {
      const property = object.node.properties.filter((item) => item.type === 'Property' && !item.computed && (item.key.name ?? item.key.value) === name).at(-1);
      if (property && property.kind !== 'init') return null;
      return [{ module: object.module, owner: object.owner, value: property ? property.value : null }];
    }
    const root = componentRoot(module, owner);
    if (node?.type !== 'Identifier' || root?.params?.[0]?.type !== 'Identifier' || root.params[0].name !== node.name || lexicalBindings(module, owner, node).bindings.has(node.name)) return null;
    const marker = `${module.file}#${owner}#${name}`;
    if (seen.has(marker)) return null;
    seen = new Set([...seen, marker]);
    const jsx = callerProps.get(keyFor(module.file, owner)) ?? [];
    const calls = directCallSites(module, owner);
    if (!calls || !jsx.length && !calls.length) return null;
    const values = [];
    for (const caller of jsx) { const supplied = callerValues(caller, name, seen); if (!supplied) return null; values.push(...supplied); }
    for (const { module: active, owner: activeOwner, call } of calls) {
      const argument = resolveObjectValue(active, activeOwner, call.arguments[0]);
      if (!argument) return null;
      const property = argument.node.properties.filter((item) => item.type === 'Property' && !item.computed && (item.key.name ?? item.key.value) === name).at(-1);
      if (property && property.kind !== 'init') return null;
      values.push({ module: argument.module, owner: argument.owner, value: property ? property.value : null });
    }
    return values;
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
    const opening = container.type === 'JSXElement' ? container.openingElement : container;
    const calleeName = opening?.name?.type === 'JSXIdentifier' && /^[A-Z]/.test(opening.name.name) ? opening.name.name : null;
    const callee = calleeName ? resolveValue(module.file, calleeName) : null;
    const calleeFunction = callee?.node?.type === 'VariableDeclarator' ? callee.node.init : callee?.node;
    const calleeGates = callee && callee.name !== owner ? (calleeFunction?.body?.body ?? []).filter((node) => {
      if (node.type !== 'IfStatement') return false;
      const exits = node.consequent.type === 'BlockStatement' ? node.consequent.body : [node.consequent];
      return exits.some((child) => child.type === 'ReturnStatement' && (!child.argument || child.argument.type === 'Literal' && child.argument.value === null));
    }).map((node) => ({ module: callee.module, owner: callee.name, node: node.test })) : [];
    const { bindings } = lexicalBindings(module, owner);
    const callbackNodes = [...attrs].filter(([name]) => EVENTS.test(name)).map(([, attr]) => attr.value?.expression).filter(Boolean);
    const suppliedOnly = new Set(gates.filter((gate) => gate.type === 'Identifier').map((gate) => gate.name));
    const pending = callbackNodes.map((node) => resolveCallbackDeclaration(module, owner, node, new Set(), { suppliedOnly }) ?? { module, owner, node });
    const visited = new Map();
    const effects = new Map();
    const fragments = [];
    const requests = [];
    const eligibilityPermissionCalls = [];
    const earlyCallbackGuards = [];
    const unresolvedCallbacks = new Set();
    const injectedProps = new Map();
    const bindInjected = (active, activeOwner, node, schedule = (resolved) => pending.push(resolved)) => {
      const resolved = resolveCallbackDeclaration(active, activeOwner, node, new Set(), active === module && activeOwner === owner ? { suppliedOnly } : {});
      if (!resolved) return false;
      schedule(resolved);
      return true;
    };
    let localChange = false;
    const flowResolved = (active, activeOwner, node, use) => {
      const flow = flowCallback(active, activeOwner, node);
      if (!flow) return false;
      if (flow.setter) localChange = true;
      if (flow.declaration) use(flow.declaration);
      return true;
    };
    for (const node of callbackNodes) {
      if (node.type === 'Identifier' && !bindings.has(node.name) && !lexicalBindings(module, owner).setterNames.has(node.name) && !module.imports.has(node.name) && !bindInjected(module, owner, node) && !flowResolved(module, owner, node, (declaration) => pending.push(declaration))) unresolvedCallbacks.add(node.name);
      if (node.type === 'MemberExpression' && !resolveMemberCallback(module, owner, node) && !flowResolved(module, owner, node, (declaration) => pending.push(declaration))) unresolvedCallbacks.add(raw(module, node));
    }
    const callerBindings = Object.fromEntries(callbackNodes.filter((node) => node.type === 'Identifier' && unresolvedCallbacks.has(node.name)).map((node) => [node.name, callerBinding(module, owner, node.name)]));
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
        if (beforeBoundary !== false && !routeAccessPolicy(active.file) && /^(?:sessionHasPermission|staffSessionHasPermission|roleHasPermission)$/.test(callee)) eligibilityPermissionCalls.push({ module: active, owner: activeOwner, node: child });
        if (['requestJson', 'requestSocJson', 'fetch'].includes(callee)) {
          const endpointBinding = boundArgument(child.arguments[callee === 'fetch' ? 0 : 2]);
          const optionsBinding = boundArgument(child.arguments[callee === 'fetch' ? 1 : 3]);
          const endpoint = endpointBinding.node;
          const options = optionsBinding.node;
          let method = options?.properties?.find((property) => (property.key?.name ?? property.key?.value) === 'method')?.value;
          let methodModule = optionsBinding.module;
          // `method: options.method` forwards the method of an exact bound options object; absent means GET.
          if (method?.type === 'MemberExpression' && !method.computed && method.object.type === 'Identifier') {
            const source = boundArgument(method.object);
            if (source.node?.type === 'ObjectExpression' && !source.node.properties.some((property) => property.type !== 'Property' || property.computed)) {
              method = source.node.properties.filter((property) => (property.key.name ?? property.key.value) === method.property.name).at(-1)?.value;
              methodModule = source.module;
            } else if (source.knownAbsent) method = undefined;
          }
          requests.push({ callee, endpoint: raw(endpointBinding.module, endpoint), endpointShape: endpoint?.type === 'TemplateLiteral' ? endpoint.quasis.map((part) => part.value.cooked).join(':id') : endpoint?.value ?? null, method: method?.value ?? (method ? raw(methodModule, method) : options && options.type !== 'ObjectExpression' ? null : 'GET') });
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
          if (!bindInjected(active, activeOwner, child.callee, schedule) && !flowResolved(active, activeOwner, child.callee, (declaration) => invokeTarget(declaration, child))) {
            unresolvedCallbacks.add(callee);
            if (scope.parameterOwners.get(callee) === scope.functionRoot && !injectedProps.has(callee)) injectedProps.set(callee, { module: active, owner: activeOwner });
          }
        } else if (child.callee.type === 'Identifier' && (scope.bindings.has(callee) || active.imports.has(callee))) {
          let target = scope.bindings.has(callee) ? { module: active, owner: active.values.get(callee) === scope.bindings.get(callee) ? callee : activeOwner, node: scope.bindings.get(callee) } : (() => { const imported = resolveValue(active.file, callee); return imported ? { module: imported.module, owner: imported.name, node: imported.node } : null; })();
          if (target?.node?.type === 'VariableDeclarator') target = { ...target, node: target.node.init };
          // A local conditional callback runs one of its branches, like an inline conditional does.
          const branches = target?.node?.type === 'ConditionalExpression' ? conditionalBranches(target.module, target.owner, target.node) : null;
          if (branches?.length && branches.every(Boolean)) { for (const branch of branches) invokeTarget(branch, child); return; }
          if (target && !['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression'].includes(target.node?.type)) target = resolveCallbackDeclaration(target.module, target.owner, target.node);
          if (target) invokeTarget(target, child);
          else if (!isNativeCallable(active, activeOwner, child.callee) && !promiseSettler(active, activeOwner, child.callee)) unresolvedCallbacks.add(`${callee}: unresolved callable declaration`);
        } else if (child.callee.type === 'Identifier' && /^(on[A-Z]|handle|submit|save|create|delete|retry|refresh)/.test(callee) && !scope.bindings.has(callee) && !scope.setterNames.has(callee) && !active.imports.has(callee) && !bindInjected(active, activeOwner, child.callee, schedule)) unresolvedCallbacks.add(callee);
        else if (child.callee.type === 'MemberExpression' && /^(?:export|verify|submit|save|create|delete|update|retry|refresh|on[A-Z])/.test(child.callee.property?.name ?? '')) {
          const target = resolveMemberCallback(active, activeOwner, child.callee);
          const receiver = child.callee.object;
          const nativeDomCall = ['URL.createObjectURL', 'URL.revokeObjectURL', 'document.createElement'].includes(callee) && receiver.type === 'Identifier'
            && !scope.bindings.has(receiver.name) && !scope.parameterOwners.has(receiver.name) && !active.importBindings.has(receiver.name);
          if (target) invokeTarget(target, child);
          else if (!isNativeCollectionMethod(active, activeOwner, child.callee) && !nativeDomCall && !flowResolved(active, activeOwner, child.callee, (declaration) => invokeTarget(declaration, child))) unresolvedCallbacks.add(callee);
        }
      });
      const effect = { alwaysBoundary: sawBoundary && beforeBoundary === false && !returnedBeforeBoundary, mayBoundary: sawBoundary };
      effects.set(marker, effect);
      return effect;
    }
    while (pending.length) visitEntry(pending.pop());
    for (const [name, site] of injectedProps) if (!callerBindings[name]) callerBindings[name] = callerBinding(site.module, site.owner, name);
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
    let unresolvedAuthorization = gates.some((gate) => !softGates.has(gate) && unresolvedGuard(module, owner, gate, earlyGates.includes(gate)));
    const authorizationGuards = [...gates.filter((gate) => !earlyGates.includes(gate)).map((gate) => permissionGuard(module, owner, gate)), ...earlyGates.map((gate) => permissionGuard(module, owner, gate, true)), ...calleeGates.map(({ module: active, owner: activeOwner, node }) => permissionGuard(active, activeOwner, node, true))].filter(Boolean);
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
    const referencedPermissions = permissionNames([...guardSources, ...[...visited.values()].filter((entry) => !routeAccessPolicy(entry.module.file))]);
    const resolvedPermissions = new Set();
    const guardPermissions = (guard) => { if (guard.permission) resolvedPermissions.add(guard.permission); if (guard.left) guardPermissions(guard.left); if (guard.right) guardPermissions(guard.right); };
    for (const guard of authorizationGuards) guardPermissions(guard);
    const controls = [];
    each(container, (child) => { if (child.type === 'JSXAttribute') controls.push([raw(module, child.name), attrValue(module, child)]); });
    return {
      callbackProvenance: [...visited.values()].map(({ module: active, owner: activeOwner, node }) => ({ file: relative(active.file), owner: activeOwner, line: active.source.slice(0, node.start).split('\n').length })),
      requests: [...new Map(requests.map((request) => [JSON.stringify(request), request])).values()],
      localChange, unresolvedCallbacks: [...unresolvedCallbacks], callerBindings, permissions: [...permissions], referencedPermissions: [...referencedPermissions], authorizationGuards, authorizationUnresolved: unresolvedAuthorization || [...permissions].some((permission) => !resolvedPermissions.has(permission)) || eligibilityPermissionCalls.some(({ module: active, owner: activeOwner, node }) => !permissionGuard(active, activeOwner, node)), guards: compact(guardSource),
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
      if (child.type === 'IfStatement') {
        const negated = { type: 'UnaryExpression', operator: '!', argument: child.test, start: child.test.start, end: child.test.end };
        softGates.add(child.test); softGates.add(negated);
        walk(child.test, child, constraint, gates);
        walk(child.consequent, child, constraint, [...gates, child.test]);
        if (child.alternate) walk(child.alternate, child, constraint, [...gates, negated]);
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
      if (child.type === 'CallExpression' && child.callee.type === 'Identifier') {
        const published = /^usePublish([A-Z]\w*)$/.exec(child.callee.name);
        if (published) { if (!storePublishers.has(published[1])) storePublishers.set(published[1], new Set()); storePublishers.get(published[1]).add(key); }
      }
      if (child.type === 'JSXOpeningElement') registerCaller(module, resolved.name, child);
      if (child.type === 'JSXOpeningElement') { const before = actions.length; recordAction(module, child, parent, resolved.name, gates); if (actions.length > before) actions[actions.length - 1].routeConstraint = constraint; }
      if (child.type === 'JSXIdentifier' && parent?.type === 'JSXOpeningElement' && parent.name === child) follow(module.file, child.name, key, constraint);
      if (child.type === 'Identifier') {
        const property = (parent?.type === 'MemberExpression' && parent.property === child && !parent.computed) || ((parent?.type === 'Property' || parent?.type === 'MethodDefinition') && parent.key === child && !parent.computed);
        if (!property && (module.values.has(child.name) || module.imports.has(child.name))) { registerReference(module, resolved.name, child, parent); follow(module.file, child.name, key, constraint); }
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
  const hostMounts = new Map();
  function mountGates(ast, target) {
    let found = null;
    const descend = (node, gates) => {
      if (found || !node) return;
      if (node === target) { found = gates; return; }
      if (node.type === 'ConditionalExpression') {
        descend(node.test, gates);
        descend(node.consequent, [...gates, node.test]);
        descend(node.alternate, [...gates, { type: 'UnaryExpression', operator: '!', argument: node.test, start: node.test.start, end: node.test.end }]);
        return;
      }
      if (node.type === 'LogicalExpression' && node.operator === '&&') { descend(node.left, gates); descend(node.right, [...gates, node.left]); return; }
      for (const child of children(node)) descend(child, gates);
    };
    descend(ast, []);
    return found ?? [];
  }
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
        if (resolved) {
          follow(appFile, node.name.name);
          const hostKey = keyFor(resolved.module.file, resolved.name);
          sharedRoots.push(hostKey);
          hostMounts.set(hostKey, { module: app, owner: 'App', gates: mountGates(app.ast, node) });
        }
      }
    });
  }
  // All actual caller declarations are known only after reachability traversal.
  // Re-analyse effects with exact equivalent injected callback bindings now available.
  finalPass = true;
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
  const rootClosures = new Map(sharedRoots.map((root) => [root, closure([root])]));
  const consumedStores = (input) => {
    const names = new Set();
    const scan = (module, owner, node, depth) => {
      if (!node || depth > 4) return;
      each(node, (child) => {
        if (child.type === 'CallExpression' && child.callee.type === 'Identifier') { const used = /^use([A-Z]\w*)$/.exec(child.callee.name); if (used) names.add(used[1]); }
        if (child.type === 'Identifier') { const binding = lexicalBindings(module, owner, child).bindings.get(child.name); if (binding && binding !== node) scan(module, owner, binding, depth + 1); }
      });
    };
    for (const gate of input.gates) scan(input.module, input.owner, gate, 0);
    return [...names].filter((name) => storePublishers.has(name));
  };
  const unique = new Map();
  for (const item of actions) {
    const input = actionInputs.get(item.id);
    const reaching = sharedRoots.filter((root) => rootClosures.get(root).has(item.symbol));
    const mounted = reaching.length === 1 && !routes.some((route) => routeClosures.get(route).has(item.symbol)) ? hostMounts.get(reaching[0]) : null;
    if (mounted) item.traits.authorizationGuards = [...item.traits.authorizationGuards, ...mounted.gates.map((gate) => permissionGuard(mounted.module, mounted.owner, gate)).filter(Boolean)];
    item.routes = shellKeys.has(item.symbol) ? [...routes] : routes.filter((route) => routeClosures.get(route).has(item.symbol));
    if (item.symbol === `${UI_ROOT}/pages/router.tsx#RouteView`) item.routes = [...new Set(branchRanges.filter((range) => item.position >= range.start && item.position <= range.end).flatMap((range) => range.routes))];
    if (item.routeConstraint) item.routes = item.routes.filter((route) => item.routeConstraint.includes(route));
    for (const store of input ? consumedStores(input) : []) {
      const publishing = routes.filter((route) => [...storePublishers.get(store)].some((publisher) => routeClosures.get(route).has(publisher)));
      item.routes = item.routes.filter((route) => publishing.includes(route));
      item.storeBinding = { store, publishingRoutes: publishing };
    }
    item.reachability = shellKeys.has(item.symbol) ? 'shared-shell' : 'router-value-symbol';
    const existing = unique.get(item.id);
    if (existing) existing.sourceOccurrences.push(item.line);
    else unique.set(item.id, { ...item, sourceOccurrences: [item.line] });
  }
  const excludedActions = [];
  function unsuppliedGate(action) {
    const input = actionInputs.get(action.id);
    const callers = callerProps.get(action.symbol) ?? [];
    if (!input || !callers.length || callers.some((caller) => caller.spread)) return null;
    const declaration = input.module.values.get(input.owner);
    const component = declaration?.type === 'VariableDeclarator' ? declaration.init : declaration;
    const properties = component?.params?.[0]?.type === 'ObjectPattern' ? component.params[0].properties : [];
    const falsyDefault = (value) => value?.type === 'Literal' && !value.value;
    for (const gate of input.gates.filter((candidate) => candidate.type === 'Identifier')) {
      const property = properties.find((candidate) => candidate.type === 'Property' && !candidate.computed && (candidate.value.left ?? candidate.value).name === gate.name);
      const defaulted = property?.value.type === 'AssignmentPattern';
      if (property && (!defaulted || falsyDefault(property.value.right)) && callers.every((caller) => !caller.props.has(gate.name))) return gate.name;
    }
    return null;
  }
  const shippedActions = [...unique.values()].filter((action) => {
    const unsupplied = unsuppliedGate(action);
    if (unsupplied) {
      excludedActions.push({ ...action, reason: `Never rendered: the control is gated on the optional prop ${unsupplied}, no mounted caller supplies it and its default is empty; retained as an explicit unreachable-source exclusion, not shipped coverage.` });
      return false;
    }
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
