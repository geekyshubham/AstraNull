#!/usr/bin/env node
/**
 * Strictly regenerates the vendored edge-fingerprint corpus.
 *
 * This ports data and matcher decisions only. It never imports or executes upstream plugin code,
 * performs DNS lookups, or sends HTTP traffic. Python's standard-library `ast` module parses the
 * Python source so helper functions and AND/OR/NOT control flow are retained instead of flattened.
 * Every pinned plugin and matcher call must be represented or generation fails.
 *
 * Usage:
 *   node scripts/generate-edge-signatures.mjs \
 *     --wafw00f <wafw00f clone at the pinned commit> \
 *     --cdncheck <cdncheck clone at the pinned commit> \
 *     [--out src/lib/data/edgeSignatureData.mjs] \
 *     [--manifest src/lib/data/edgeSignatureData.manifest.json]
 */

import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  mkdirSync,
  readdirSync,
  readFileSync,
  writeFileSync,
} from 'node:fs';
import { isIP } from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const EDGE_CORPUS_OUTPUT_VERSION = 2;
export const EDGE_CORPUS_MANIFEST_VERSION = 1;
export const WAFW00F_COMMIT = '69fbe3956bba47a172cf87e40e9037535d32a130';
export const CDNCHECK_COMMIT = 'dac12984ef12fa5663c2b7591d0a304ef27c659b';

const GENERATED_MODULE_PATH = 'src/lib/data/edgeSignatureData.mjs';
const GENERATOR_PATH = 'scripts/generate-edge-signatures.mjs';

const compareCodeUnits = (left, right) => (left < right ? -1 : left > right ? 1 : 0);

const PINNED_INPUTS = Object.freeze({
  wafw00f: Object.freeze({
    pluginCount: 172,
    pluginTreeSha256: '44f4379d119d7cd688b2b8f68e5a1cd9e5bcf150491f46cb438d8a71f223b002',
    licenseSha256: 'fdaaf8393afcbab5a0db158ae742e76ec3803a7c72af19489f5bd521d3db08ea',
  }),
  cdncheck: Object.freeze({
    sourcesDataSha256: '4a7482b64ded7a611e11eadda6730cc8df159942c16713f17bbfecdb8a7cd2a3',
    cnameImplementationSha256: '37182c8c3bc5a6182f2ced734d00fb252c5b0ae08cf284bd0437f44bc305244a',
    licenseSha256: 'cbcdaab87df3175107aa28915bd253cebdd618a49c9ac5d6c669c0b1cbebcacb',
  }),
});

const PYTHON_AST_EXTRACTOR = String.raw`
import ast
import json
import pathlib
import sys

MATCHERS = {
    "matchHeader": ("header", False),
    "matchCookie": ("cookie", False),
    "matchContent": ("content", True),
    "matchStatus": ("status", True),
    "matchReason": ("reason", True),
}

class PortError(Exception):
    pass

def literal(node, context):
    try:
        return ast.literal_eval(node)
    except Exception as exc:
        raise PortError(f"{context}: expected a literal: {exc}") from exc

class PluginPort:
    def __init__(self, plugin, tree):
        self.plugin = plugin
        self.tree = tree
        self.functions = {}
        self.compiled_functions = {}
        self.compiling = set()
        self.reachable_functions = set()
        self.signal_ids = {}
        self.signatures = []

        for node in tree.body:
            if isinstance(node, ast.FunctionDef):
                if node.name in self.functions:
                    raise PortError(f"{plugin}: duplicate function {node.name}")
                if node.decorator_list:
                    raise PortError(f"{plugin}:{node.lineno}: decorated functions are unsupported")
                if node.returns is not None and not (
                        isinstance(node.returns, ast.Name) and node.returns.id == "bool"):
                    raise PortError(f"{plugin}:{node.lineno}: only a bool return annotation is supported")
                if len(node.args.args) != 1 or node.args.args[0].arg != "self":
                    raise PortError(f"{plugin}:{node.lineno}: function {node.name} must take only self")
                if (node.args.posonlyargs or node.args.kwonlyargs or node.args.vararg
                        or node.args.kwarg or node.args.defaults or node.args.kw_defaults):
                    raise PortError(f"{plugin}:{node.lineno}: unsupported arguments on {node.name}")
                self.functions[node.name] = node
            elif isinstance(node, ast.Assign):
                if not any(isinstance(target, ast.Name) and target.id == "NAME" for target in node.targets):
                    raise PortError(f"{plugin}:{node.lineno}: unsupported module assignment")
            elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                pass
            else:
                raise PortError(f"{plugin}:{getattr(node, 'lineno', '?')}: unsupported module statement {type(node).__name__}")

        if "is_waf" not in self.functions:
            raise PortError(f"{plugin}: missing is_waf(self)")

    def signal(self, node):
        node_key = id(node)
        if node_key in self.signal_ids:
            return {"op": "signal", "id": self.signal_ids[node_key]}

        method = node.func.attr
        signal_kind, default_attack = MATCHERS[method]
        if not (isinstance(node.func.value, ast.Name) and node.func.value.id == "self"):
            raise PortError(f"{self.plugin}:{node.lineno}: matcher receiver must be self")
        if any(isinstance(value, ast.Starred) for value in node.args) or any(
                keyword.arg is None for keyword in node.keywords):
            raise PortError(f"{self.plugin}:{node.lineno}: starred matcher arguments are unsupported")

        positional = list(node.args)
        if not positional or len(positional) > 2:
            raise PortError(f"{self.plugin}:{node.lineno}: invalid {method} argument count")
        attack = default_attack
        if len(positional) == 2:
            attack = literal(positional[1], f"{self.plugin}:{node.lineno} attack")
        for keyword in node.keywords:
            if keyword.arg != "attack":
                raise PortError(f"{self.plugin}:{node.lineno}: unsupported {method} keyword {keyword.arg}")
            if len(positional) == 2:
                raise PortError(f"{self.plugin}:{node.lineno}: attack supplied twice")
            attack = literal(keyword.value, f"{self.plugin}:{node.lineno} attack")
        if type(attack) is not bool:
            raise PortError(f"{self.plugin}:{node.lineno}: attack must be a bool literal")

        first = literal(positional[0], f"{self.plugin}:{node.lineno} {method}")
        signature = {
            "signal": signal_kind,
            "tier": "block_page" if attack else "passive",
        }
        if method == "matchHeader":
            if not (isinstance(first, tuple) and len(first) == 2
                    and all(isinstance(value, str) for value in first)):
                raise PortError(f"{self.plugin}:{node.lineno}: matchHeader requires a string pair")
            signature["header"] = first[0]
            signature["pattern"] = first[1]
        elif method in ("matchCookie", "matchContent"):
            if not isinstance(first, str):
                raise PortError(f"{self.plugin}:{node.lineno}: {method} requires a string")
            signature["pattern"] = first
        elif method == "matchStatus":
            if type(first) is not int:
                raise PortError(f"{self.plugin}:{node.lineno}: matchStatus requires an integer")
            signature["status"] = first
        elif method == "matchReason":
            if not isinstance(first, str):
                raise PortError(f"{self.plugin}:{node.lineno}: matchReason requires a string")
            signature["value"] = first

        signal_id = len(self.signatures)
        self.signal_ids[node_key] = signal_id
        self.signatures.append(signature)
        return {"op": "signal", "id": signal_id}

    def expression(self, node):
        if isinstance(node, ast.Constant) and type(node.value) is bool:
            return {"op": "const", "value": node.value}
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            return {"op": "not", "arg": self.expression(node.operand)}
        if isinstance(node, ast.BoolOp) and isinstance(node.op, (ast.And, ast.Or)):
            return {
                "op": "and" if isinstance(node.op, ast.And) else "or",
                "args": [self.expression(value) for value in node.values],
            }
        if isinstance(node, ast.Call):
            if (isinstance(node.func, ast.Attribute)
                    and node.func.attr in MATCHERS):
                return self.signal(node)
            if isinstance(node.func, ast.Name) and node.func.id in self.functions:
                if (len(node.args) != 1 or not isinstance(node.args[0], ast.Name)
                        or node.args[0].id != "self" or node.keywords):
                    raise PortError(f"{self.plugin}:{node.lineno}: helper calls must pass only self")
                return self.function(node.func.id)
        raise PortError(
            f"{self.plugin}:{getattr(node, 'lineno', '?')}: unsupported expression {ast.dump(node, include_attributes=False)}"
        )

    def sequence(self, statements, continuation=None):
        if not statements:
            if continuation is None:
                raise PortError(f"{self.plugin}: reachable function path has no boolean return")
            return continuation

        first = statements[0]
        rest = statements[1:]
        if isinstance(first, ast.Return):
            if rest:
                raise PortError(f"{self.plugin}:{first.lineno}: statements after unconditional return")
            if first.value is None:
                raise PortError(f"{self.plugin}:{first.lineno}: bare return is unsupported")
            return self.expression(first.value)
        if isinstance(first, ast.If):
            condition = self.expression(first.test)
            rest_expression = self.sequence(rest, continuation)
            then_expression = self.sequence(first.body, rest_expression)
            else_expression = self.sequence(first.orelse, rest_expression) if first.orelse else rest_expression
            return {
                "op": "if",
                "condition": condition,
                "then": then_expression,
                "else": else_expression,
            }
        raise PortError(f"{self.plugin}:{first.lineno}: unsupported function statement {type(first).__name__}")

    def function(self, name):
        if name in self.compiled_functions:
            self.reachable_functions.add(name)
            return self.compiled_functions[name]
        if name in self.compiling:
            raise PortError(f"{self.plugin}: recursive helper {name} is unsupported")
        node = self.functions.get(name)
        if node is None:
            raise PortError(f"{self.plugin}: unknown helper {name}")
        self.compiling.add(name)
        self.reachable_functions.add(name)
        compiled = self.sequence(node.body)
        self.compiling.remove(name)
        self.compiled_functions[name] = compiled
        return compiled

    def port(self):
        matcher = self.function("is_waf")
        unreachable_functions = sorted(set(self.functions) - self.reachable_functions)
        if unreachable_functions:
            raise PortError(f"{self.plugin}: unreachable helpers: {', '.join(unreachable_functions)}")

        all_matcher_calls = {
            id(node)
            for function in self.functions.values()
            for node in ast.walk(function)
            if (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in MATCHERS)
        }
        parsed_matcher_calls = set(self.signal_ids)
        if parsed_matcher_calls != all_matcher_calls:
            missing = len(all_matcher_calls - parsed_matcher_calls)
            extra = len(parsed_matcher_calls - all_matcher_calls)
            raise PortError(f"{self.plugin}: matcher-call inventory mismatch (missing={missing}, extra={extra})")
        if not self.signatures:
            raise PortError(f"{self.plugin}: no reachable matcher calls")
        return matcher

def plugin_name(plugin, tree):
    names = []
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "NAME":
                    value = literal(node.value, f"{plugin}:{node.lineno} NAME")
                    if not isinstance(value, str) or not value:
                        raise PortError(f"{plugin}:{node.lineno}: NAME must be a non-empty string")
                    names.append(value)
    if len(names) != 1:
        raise PortError(f"{plugin}: expected exactly one NAME assignment, got {len(names)}")
    return names[0]

def main():
    plugin_dir = pathlib.Path(sys.argv[1])
    files = sorted(path for path in plugin_dir.glob("*.py") if path.name != "__init__.py")
    if not files:
        raise PortError(f"no plugin files found in {plugin_dir}")
    vendors = {}
    total_calls = 0
    for source_path in files:
        plugin = source_path.stem
        try:
            tree = ast.parse(source_path.read_text(encoding="utf-8"), filename=str(source_path))
            port = PluginPort(plugin, tree)
            matcher = port.port()
            vendors[plugin] = {
                "name": plugin_name(plugin, tree),
                "port_status": "supported",
                "signatures": port.signatures,
                "matcher": matcher,
            }
            total_calls += len(port.signatures)
        except (SyntaxError, PortError) as exc:
            raise PortError(f"failed to port {source_path.name}: {exc}") from exc
    print(json.dumps({
        "plugin_count": len(files),
        "matcher_call_count": total_calls,
        "vendors": vendors,
    }, ensure_ascii=False, separators=(",", ":")))

try:
    main()
except Exception as exc:
    print(str(exc), file=sys.stderr)
    sys.exit(1)
`;

function fail(message) {
  throw new Error(`edge-signature generation failed: ${message}`);
}

function parseArgs(argv) {
  const args = { out: GENERATED_MODULE_PATH };
  const valueFlags = new Set(['--wafw00f', '--cdncheck', '--out', '--manifest']);
  for (let index = 2; index < argv.length; index += 1) {
    const key = argv[index];
    if (!valueFlags.has(key)) fail(`unknown argument ${key}`);
    const value = argv[index + 1];
    if (!value || value.startsWith('--')) fail(`${key} requires a value`);
    index += 1;
    if (key === '--wafw00f') args.wafw00f = value;
    if (key === '--cdncheck') args.cdncheck = value;
    if (key === '--out') args.out = value;
    if (key === '--manifest') args.manifest = value;
  }
  if (!args.wafw00f || !args.cdncheck) {
    fail('usage: generate-edge-signatures.mjs --wafw00f <clone> --cdncheck <clone> [--out <path>] [--manifest <path>]');
  }
  if (!args.manifest) {
    args.manifest = args.out.endsWith('.mjs')
      ? `${args.out.slice(0, -4)}.manifest.json`
      : `${args.out}.manifest.json`;
  }
  return args;
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function gitHead(clonePath) {
  try {
    return execFileSync('git', ['-C', clonePath, 'rev-parse', 'HEAD'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    }).trim();
  } catch (error) {
    fail(`cannot read git HEAD for ${clonePath}: ${error.stderr?.trim() || error.message}`);
  }
  return null;
}

function requireHash(label, bytes, expected) {
  const actual = sha256(bytes);
  if (actual !== expected) fail(`${label} SHA-256 ${actual} does not match pinned ${expected}`);
  return actual;
}

/**
 * Hash a directory inventory without relying on tar metadata. Each sorted entry is encoded as:
 * uint32be(path byte length), path bytes, uint64be(content byte length), content bytes.
 */
function hashFileInventory(root, relativePaths) {
  const hash = createHash('sha256');
  for (const relativePath of [...relativePaths].sort()) {
    const pathBytes = Buffer.from(relativePath);
    const content = readFileSync(path.join(root, relativePath));
    const pathLength = Buffer.alloc(4);
    pathLength.writeUInt32BE(pathBytes.length);
    const contentLength = Buffer.alloc(8);
    contentLength.writeBigUInt64BE(BigInt(content.length));
    hash.update(pathLength).update(pathBytes).update(contentLength).update(content);
  }
  return hash.digest('hex');
}

function assertPinnedClone(clonePath, expectedCommit, label) {
  const head = gitHead(clonePath);
  if (head !== expectedCommit) fail(`${label} HEAD ${head} is not pinned commit ${expectedCommit}`);
}

function unsupportedPythonRegexConstruct(pattern) {
  const checks = [
    ['conditional group', /\(\?\(/],
    ['comment group', /\(\?#/],
    ['atomic group', /\(\?>/],
    ['scoped inline flags', /\(\?[aiLmsux-]+:/],
    ['Python string anchor', /\\[AZzG]/],
  ];
  return checks.find(([, expression]) => expression.test(pattern))?.[0] ?? null;
}

/** Translate the small Python-re syntax surface in the pinned corpus, then compile-check it. */
function toJsPattern(pythonPattern, context) {
  const unsupported = unsupportedPythonRegexConstruct(pythonPattern);
  if (unsupported) fail(`${context} uses unsupported ${unsupported}: ${pythonPattern}`);
  let pattern = pythonPattern
    .replace(/\(\?P<([A-Za-z_][A-Za-z0-9_]*)>/g, '(?<$1>')
    .replace(/\(\?P=([A-Za-z_][A-Za-z0-9_]*)\)/g, '\\k<$1>')
    .replace(/\(\?i\)/g, '');
  try {
    new RegExp(pattern, 'i');
  } catch (error) {
    fail(`${context} is not a JavaScript-compatible regex: ${error.message}`);
  }
  return pattern;
}

function normalizeSignature(signature, context) {
  const normalized = { ...signature };
  if (signature.signal === 'header') {
    const header = String(signature.header);
    const exact = /^[A-Za-z0-9-]+$/.test(header);
    normalized.header = exact ? header.toLowerCase() : toJsPattern(header, `${context} header name`);
    normalized.header_kind = exact ? 'exact' : 'regex';
    normalized.pattern = toJsPattern(String(signature.pattern), `${context} header value`);
  } else if (signature.signal === 'cookie' || signature.signal === 'content') {
    normalized.pattern = toJsPattern(String(signature.pattern), `${context} ${signature.signal}`);
  }
  return normalized;
}

/**
 * Parse every plugin with Python AST. Exported so a unit test can prove unsupported syntax fails
 * closed without needing network access or a pinned git checkout.
 */
export function extractWafPluginPrograms(pluginDir, { python = process.env.PYTHON || 'python3' } = {}) {
  const result = spawnSync(python, ['-c', PYTHON_AST_EXTRACTOR, pluginDir], {
    encoding: 'utf8',
    maxBuffer: 32 * 1024 * 1024,
  });
  if (result.error) fail(`could not run ${python}: ${result.error.message}`);
  if (result.status !== 0) fail(result.stderr.trim() || `${python} AST extraction exited ${result.status}`);
  let parsed;
  try {
    parsed = JSON.parse(result.stdout);
  } catch (error) {
    fail(`invalid AST extractor output: ${error.message}`);
  }
  if (!Number.isInteger(parsed.plugin_count) || parsed.plugin_count <= 0) fail('AST extractor returned no plugins');
  if (Object.keys(parsed.vendors ?? {}).length !== parsed.plugin_count) {
    fail(`plugin inventory ${parsed.plugin_count} does not match emitted vendors ${Object.keys(parsed.vendors ?? {}).length}`);
  }

  const vendors = {};
  let normalizedCalls = 0;
  for (const [vendorKey, vendor] of Object.entries(parsed.vendors).sort(([a], [b]) => compareCodeUnits(a, b))) {
    if (vendor.port_status !== 'supported') fail(`${vendorKey} has unsupported port status`);
    const signatures = (vendor.signatures ?? []).map((signature, index) => normalizeSignature(
      signature,
      `${vendorKey} signature ${index}`,
    ));
    if (signatures.length === 0) fail(`${vendorKey} emitted no signatures`);
    normalizedCalls += signatures.length;
    vendors[vendorKey] = { ...vendor, signatures };
  }
  if (normalizedCalls !== parsed.matcher_call_count) {
    fail(`matcher-call inventory ${parsed.matcher_call_count} does not match emitted signatures ${normalizedCalls}`);
  }
  return { vendors, pluginCount: parsed.plugin_count, matcherCallCount: normalizedCalls };
}

function loadWafSignatures(clonePath) {
  assertPinnedClone(clonePath, WAFW00F_COMMIT, 'wafw00f');
  const pluginDir = path.join(clonePath, 'wafw00f', 'plugins');
  const pluginFiles = readdirSync(pluginDir)
    .filter((file) => file.endsWith('.py') && file !== '__init__.py')
    .sort();
  if (pluginFiles.length !== PINNED_INPUTS.wafw00f.pluginCount) {
    fail(`wafw00f has ${pluginFiles.length} plugins; expected ${PINNED_INPUTS.wafw00f.pluginCount}`);
  }
  const relativePaths = pluginFiles.map((file) => path.posix.join('wafw00f', 'plugins', file));
  const pluginInventory = relativePaths.map((relativePath) => ({
    path: relativePath,
    sha256: sha256(readFileSync(path.join(clonePath, relativePath))),
  }));
  const treeHash = hashFileInventory(clonePath, relativePaths);
  if (treeHash !== PINNED_INPUTS.wafw00f.pluginTreeSha256) {
    fail(`wafw00f plugin-tree SHA-256 ${treeHash} does not match pinned ${PINNED_INPUTS.wafw00f.pluginTreeSha256}`);
  }
  requireHash(
    'wafw00f LICENSE',
    readFileSync(path.join(clonePath, 'LICENSE')),
    PINNED_INPUTS.wafw00f.licenseSha256,
  );

  const extracted = extractWafPluginPrograms(pluginDir);
  if (extracted.pluginCount !== pluginFiles.length) {
    fail(`wafw00f filesystem has ${pluginFiles.length} plugins but extractor emitted ${extracted.pluginCount}`);
  }
  return { ...extracted, treeHash, pluginInventory };
}

function validateCidr(cidr, context) {
  const parts = String(cidr).split('/');
  if (parts.length !== 2) fail(`${context} is not CIDR: ${cidr}`);
  const version = isIP(parts[0]);
  const prefix = Number(parts[1]);
  const bits = version === 4 ? 32 : version === 6 ? 128 : 0;
  if (!bits || !Number.isInteger(prefix) || prefix < 0 || prefix > bits) {
    fail(`${context} is not valid CIDR: ${cidr}`);
  }
}

function normalizeRangeGroup(group, label) {
  if (!group || typeof group !== 'object' || Array.isArray(group)) fail(`cdncheck ${label} must be an object`);
  const normalized = {};
  for (const [provider, values] of Object.entries(group).sort(([a], [b]) => compareCodeUnits(a, b))) {
    if (!provider || !Array.isArray(values) || values.length === 0) fail(`cdncheck ${label}.${provider} is empty`);
    const ranges = values.map((value, index) => {
      validateCidr(value, `cdncheck ${label}.${provider}[${index}]`);
      return String(value);
    }).sort();
    normalized[provider] = ranges;
  }
  return normalized;
}

function readCnameType(clonePath) {
  const sourcePath = path.join(clonePath, 'other.go');
  const source = readFileSync(sourcePath);
  requireHash('cdncheck other.go', source, PINNED_INPUTS.cdncheck.cnameImplementationSha256);
  const types = [...source.toString('utf8').matchAll(
    /return\s+true,\s*discovered,\s*"([^"]+)",\s*nil/g,
  )].map((match) => match[1]);
  const unique = [...new Set(types)];
  if (types.length !== 2 || unique.length !== 1) {
    fail(`could not derive one explicit CNAME item type from cdncheck other.go (found ${JSON.stringify(types)})`);
  }
  return unique[0];
}

function normalizeCnameRules(group, type) {
  if (!group || typeof group !== 'object' || Array.isArray(group)) fail('cdncheck common must be an object');
  return Object.entries(group)
    .sort(([a], [b]) => compareCodeUnits(a, b))
    .map(([provider, suffixes]) => {
      if (!provider || !Array.isArray(suffixes) || suffixes.length === 0) {
        fail(`cdncheck common.${provider} is empty`);
      }
      const normalizedSuffixes = suffixes.map((suffix, index) => {
        const value = String(suffix).trim().toLowerCase().replace(/^\.+|\.+$/g, '');
        if (!value || value.includes('/') || value.includes(' ')) {
          fail(`cdncheck common.${provider}[${index}] is not a hostname suffix: ${suffix}`);
        }
        return value;
      }).sort();
      return { provider, type, suffixes: normalizedSuffixes };
    });
}

function loadEdgeRanges(clonePath) {
  assertPinnedClone(clonePath, CDNCHECK_COMMIT, 'cdncheck');
  const sourcePath = path.join(clonePath, 'sources_data.json');
  const source = readFileSync(sourcePath);
  requireHash('cdncheck sources_data.json', source, PINNED_INPUTS.cdncheck.sourcesDataSha256);
  requireHash(
    'cdncheck LICENSE.md',
    readFileSync(path.join(clonePath, 'LICENSE.md')),
    PINNED_INPUTS.cdncheck.licenseSha256,
  );
  let data;
  try {
    data = JSON.parse(source);
  } catch (error) {
    fail(`cdncheck sources_data.json is invalid: ${error.message}`);
  }
  const cdnRanges = normalizeRangeGroup(data.cdn, 'cdn');
  const wafRanges = normalizeRangeGroup(data.waf, 'waf');
  const cnameType = readCnameType(clonePath);
  const cnameRules = normalizeCnameRules(data.common, cnameType);
  const countRanges = (group) => Object.values(group).reduce((sum, values) => sum + values.length, 0);
  const cnameSuffixes = cnameRules.reduce((sum, rule) => sum + rule.suffixes.length, 0);
  return {
    cdnRanges,
    wafRanges,
    cnameRules,
    cnameType,
    report: {
      cdnProviders: Object.keys(cdnRanges).length,
      wafProviders: Object.keys(wafRanges).length,
      cnameProviders: cnameRules.length,
      cdnRanges: countRanges(cdnRanges),
      wafRanges: countRanges(wafRanges),
      cnameSuffixes,
    },
  };
}

function countWafSignatures(vendors) {
  const signatures = Object.values(vendors).flatMap((vendor) => vendor.signatures);
  return {
    passive: signatures.filter((signature) => signature.tier === 'passive').length,
    blockPage: signatures.filter((signature) => signature.tier === 'block_page').length,
  };
}

function renderModule({ vendors, wafReport, ranges, generatorSha256 }) {
  const manifest = {
    output_version: EDGE_CORPUS_OUTPUT_VERSION,
    format: 'astranull-edge-signature-corpus-v2',
    generator: GENERATOR_PATH,
    generator_sha256: generatorSha256,
    output_manifest: 'src/lib/data/edgeSignatureData.manifest.json',
    sources: {
      wafw00f: {
        repository: 'https://github.com/EnableSecurity/wafw00f',
        commit: WAFW00F_COMMIT,
        license: 'BSD-3-Clause',
        license_notice: 'THIRD_PARTY_NOTICES/wafw00f-BSD-3-Clause.txt',
        plugin_tree_sha256: PINNED_INPUTS.wafw00f.pluginTreeSha256,
        plugin_tree_hash_encoding: 'sorted-path-length-content-length-v1',
        plugin_files: wafReport.pluginCount,
        matcher_calls: wafReport.matcherCallCount,
        license_sha256: PINNED_INPUTS.wafw00f.licenseSha256,
      },
      cdncheck: {
        repository: 'https://github.com/projectdiscovery/cdncheck',
        commit: CDNCHECK_COMMIT,
        license: 'MIT',
        license_notice: 'THIRD_PARTY_NOTICES/cdncheck-MIT.txt',
        ported_categories: ['cdn', 'waf', 'common'],
        excluded_categories: [{
          category: 'cloud',
          reason: 'general hosting ranges are not edge-protection evidence',
        }],
        sources_data_sha256: PINNED_INPUTS.cdncheck.sourcesDataSha256,
        cname_implementation_sha256: PINNED_INPUTS.cdncheck.cnameImplementationSha256,
        license_sha256: PINNED_INPUTS.cdncheck.licenseSha256,
        cname_item_type: ranges.cnameType,
      },
    },
  };
  const stats = countWafSignatures(vendors);
  return `/**
 * Vendored edge-fingerprint corpus. GENERATED — do not edit by hand.
 * Regenerate with \`node scripts/generate-edge-signatures.mjs\` from the pinned source commits
 * recorded in EDGE_SIGNATURE_CORPUS_MANIFEST.
 *
 * wafw00f signature data: BSD-3-Clause, Copyright (c) 2009-2026 WAFW00F Developers.
 * cdncheck range/CNAME data: MIT, Copyright (c) 2021 ProjectDiscovery, Inc.
 * Complete notices: THIRD_PARTY_NOTICES/wafw00f-BSD-3-Clause.txt and
 * THIRD_PARTY_NOTICES/cdncheck-MIT.txt.
 */

export const EDGE_SIGNATURE_CORPUS_MANIFEST = Object.freeze(${JSON.stringify(manifest, null, 2)});

/** Strict AST ports of every pinned wafw00f plugin, including its decision tree. */
export const WAF_VENDOR_SIGNATURES = Object.freeze(${JSON.stringify(vendors, null, 2)});

/** CDN provider address ranges (cdncheck sources_data.json \`cdn\`). */
export const CDN_ADDRESS_RANGES = Object.freeze(${JSON.stringify(ranges.cdnRanges, null, 2)});

/** WAF provider address ranges (cdncheck sources_data.json \`waf\`). */
export const WAF_ADDRESS_RANGES = Object.freeze(${JSON.stringify(ranges.wafRanges, null, 2)});

/**
 * CNAME suffix rules (cdncheck \`common\`). The explicit \`type\` is ported from the pinned
 * CheckSuffix implementation; it is not inferred from provider-name overlap.
 */
export const EDGE_CNAME_RULES = Object.freeze(${JSON.stringify(ranges.cnameRules, null, 2)});

export const EDGE_CORPUS_STATS = Object.freeze({
  waf_plugins_total: ${wafReport.pluginCount},
  waf_plugins_supported: ${Object.keys(vendors).length},
  waf_plugins_unsupported: ${wafReport.pluginCount - Object.keys(vendors).length},
  waf_vendors: ${Object.keys(vendors).length},
  passive_signatures: ${stats.passive},
  block_page_signatures: ${stats.blockPage},
  cdn_providers: ${ranges.report.cdnProviders},
  waf_range_providers: ${ranges.report.wafProviders},
  cname_providers: ${ranges.report.cnameProviders},
  cdn_ranges: ${ranges.report.cdnRanges},
  waf_ranges: ${ranges.report.wafRanges},
  cname_suffixes: ${ranges.report.cnameSuffixes},
});
`;
}

function renderOutputManifest({ body, waf, ranges, generatorSha256 }) {
  const outputSha256 = sha256(body);
  const manifest = {
    manifest_version: EDGE_CORPUS_MANIFEST_VERSION,
    format: 'astranull-edge-signature-corpus-manifest-v1',
    output_version: EDGE_CORPUS_OUTPUT_VERSION,
    generator: {
      path: GENERATOR_PATH,
      sha256: generatorSha256,
    },
    sources: {
      wafw00f: {
        repository: 'https://github.com/EnableSecurity/wafw00f',
        commit: WAFW00F_COMMIT,
        plugin_tree_sha256: waf.treeHash,
        plugin_tree_hash_encoding: 'sorted-path-length-content-length-v1',
        plugin_files: waf.pluginInventory,
        matcher_calls: waf.matcherCallCount,
        supported_plugins: Object.keys(waf.vendors).length,
        unsupported_plugins: 0,
        license: {
          path: 'LICENSE',
          sha256: PINNED_INPUTS.wafw00f.licenseSha256,
          notice_path: 'THIRD_PARTY_NOTICES/wafw00f-BSD-3-Clause.txt',
        },
      },
      cdncheck: {
        repository: 'https://github.com/projectdiscovery/cdncheck',
        commit: CDNCHECK_COMMIT,
        ported_categories: ['cdn', 'waf', 'common'],
        excluded_categories: [{
          category: 'cloud',
          reason: 'general hosting ranges are not edge-protection evidence',
        }],
        inputs: [
          { path: 'sources_data.json', sha256: PINNED_INPUTS.cdncheck.sourcesDataSha256 },
          { path: 'other.go', sha256: PINNED_INPUTS.cdncheck.cnameImplementationSha256 },
          { path: 'LICENSE.md', sha256: PINNED_INPUTS.cdncheck.licenseSha256 },
        ],
        cname_item_type: ranges.cnameType,
        license: {
          path: 'LICENSE.md',
          sha256: PINNED_INPUTS.cdncheck.licenseSha256,
          notice_path: 'THIRD_PARTY_NOTICES/cdncheck-MIT.txt',
        },
      },
    },
    output: {
      path: GENERATED_MODULE_PATH,
      sha256: outputSha256,
      bytes: Buffer.byteLength(body),
    },
  };
  return {
    manifest,
    body: `${JSON.stringify(manifest, null, 2)}\n`,
    outputSha256,
  };
}

export function generateEdgeSignatureCorpus({ wafw00f, cdncheck }) {
  const waf = loadWafSignatures(path.resolve(wafw00f));
  const ranges = loadEdgeRanges(path.resolve(cdncheck));
  const generatorSha256 = sha256(readFileSync(fileURLToPath(import.meta.url)));
  const body = renderModule({
    vendors: waf.vendors,
    wafReport: waf,
    ranges,
    generatorSha256,
  });
  const outputManifest = renderOutputManifest({ body, waf, ranges, generatorSha256 });
  return {
    body,
    manifest: outputManifest.body,
    report: {
      plugins: waf.pluginCount,
      matcherCalls: waf.matcherCallCount,
      ...countWafSignatures(waf.vendors),
      ...ranges.report,
      cnameType: ranges.cnameType,
      outputSha256: outputManifest.outputSha256,
    },
  };
}

function main() {
  try {
    const args = parseArgs(process.argv);
    const { body, manifest, report } = generateEdgeSignatureCorpus(args);
    const outPath = path.resolve(args.out);
    const manifestPath = path.resolve(args.manifest);
    mkdirSync(path.dirname(outPath), { recursive: true });
    mkdirSync(path.dirname(manifestPath), { recursive: true });
    writeFileSync(outPath, body);
    writeFileSync(manifestPath, manifest);
    console.log('generate-edge-signatures: ok');
    console.log(`  wafw00f plugins ported : ${report.plugins}/${report.plugins}`);
    console.log(`  matcher calls ported   : ${report.matcherCalls}/${report.matcherCalls}`);
    console.log(`  passive / block-page   : ${report.passive} / ${report.blockPage}`);
    console.log(`  cdn / waf ranges       : ${report.cdnRanges} / ${report.wafRanges}`);
    console.log(`  cname suffixes / type  : ${report.cnameSuffixes} / ${report.cnameType}`);
    console.log(`  output SHA-256         : ${report.outputSha256}`);
    console.log(`  wrote                  : ${path.relative(process.cwd(), outPath)}`);
    console.log(`  manifest               : ${path.relative(process.cwd(), manifestPath)}`);
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
