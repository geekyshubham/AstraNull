/** Offline exhaustive Boolean decision audit against hash-verified upstream plugin functions.
 * No requests or upstream attack payloads are executed. Requires the pinned wafw00f clone.
 * Usage: node scripts/audit-edge-port-decisions.mjs /path/to/pinned/wafw00f
 */
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { WAF_VENDOR_SIGNATURES } from '../src/lib/data/edgeSignatureData.mjs';

const root = path.resolve(process.argv[2] ?? '');
if (!process.argv[2]) throw new Error('Supply the pinned wafw00f clone path.');
const manifest = JSON.parse(readFileSync(new URL('../src/lib/data/edgeSignatureData.manifest.json', import.meta.url)));
const waf = manifest.sources.wafw00f;
if (execFileSync('git', ['-C', root, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim() !== waf.commit) throw new Error('Wrong upstream revision.');
for (const entry of waf.plugin_files) {
  const hash = createHash('sha256').update(readFileSync(path.join(root, entry.path))).digest('hex');
  if (hash !== entry.sha256) throw new Error(`Changed upstream source: ${entry.path}`);
}
const key = (s) => JSON.stringify([s.signal, s.tier, s.header ?? null, s.pattern ?? null, s.status ?? null, s.value ?? null]);

// Instrument only signal truth values; use the shipped decision evaluator unchanged.
const runtimeUrl = new URL('../src/lib/edgeFingerprint.mjs', import.meta.url);
let runtime = readFileSync(runtimeUrl, 'utf8');
const start = runtime.indexOf('function evaluateSignal(');
const end = runtime.indexOf('function evaluateMatcher(', start);
if (start < 0 || end < 0) throw new Error('Decision evaluator boundaries changed.');
runtime = runtime.slice(0, start) + `function evaluateSignal(signature, evidence) {
  const key = JSON.stringify([signature.signal, signature.tier, signature.header ?? null, signature.pattern ?? null, signature.status ?? null, signature.value ?? null]);
  return evidence.values.get(key) ? MATCH_TRUE : MATCH_FALSE;
}\n` + runtime.slice(end) + '\nexport { evaluateMatcher, compilePattern };';
runtime = runtime.replace(/from (['"])(\.\.?\/[^'"]+)\1/g, (_match, quote, relative) => `from ${quote}${new URL(relative, runtimeUrl).href}${quote}`);
const { evaluateMatcher, compilePattern } = await import(`data:text/javascript;base64,${Buffer.from(runtime).toString('base64')}`);

const python = String.raw`
import ast, json, pathlib, re, sys
root = pathlib.Path(sys.argv[1]); vendors = json.load(sys.stdin); output = {}
def pattern(value):
    return re.sub(r'\(\?P=([A-Za-z_][A-Za-z0-9_]*)\)', r'\\k<\1>', re.sub(r'\(\?P<([A-Za-z_][A-Za-z0-9_]*)>', r'(?<\1>', value)).replace('(?i)', '')
for vendor, data in vendors.items():
    signatures = data['signatures']
    def key(s): return json.dumps([s['signal'], s['tier'], s.get('header'), s.get('pattern'), s.get('status'), s.get('value')], ensure_ascii=False, separators=(',', ':'))
    keys = list(dict.fromkeys(key(s) for s in signatures)); positions = {k:i for i,k in enumerate(keys)}
    tree = ast.parse((root / 'wafw00f/plugins' / (vendor + '.py')).read_text())
    # Only definitions run: source imports, module initializers and request engines are excluded.
    definitions = [n for n in tree.body if isinstance(n, ast.FunctionDef)]
    namespace = {'__builtins__': {}, 'bool': bool}
    exec(compile(ast.Module(body=definitions, type_ignores=[]), vendor, 'exec'), namespace)
    class Probe:
        mask = 0
        def __getattr__(self, name):
            if name in namespace: return lambda: namespace[name](self)
            raise AttributeError(name)
        def match(self, signal, tier, header=None, regex=None, status=None, value=None):
            k = json.dumps([signal,tier,header,regex,status,value], ensure_ascii=False, separators=(',', ':'))
            if k not in positions: raise RuntimeError('Unported matcher: ' + vendor + ' ' + k)
            return bool(self.mask & (1 << positions[k]))
        def matchHeader(self, item, attack=False):
            header, regex = item
            header = header.lower() if re.fullmatch('[A-Za-z0-9-]+', header) else pattern(header)
            return self.match('header', 'block_page' if attack else 'passive', header=header, regex=pattern(regex))
        def matchCookie(self, regex, attack=False): return self.match('cookie', 'block_page' if attack else 'passive', regex=pattern(regex))
        def matchContent(self, regex, attack=True): return self.match('content', 'block_page' if attack else 'passive', regex=pattern(regex))
        def matchStatus(self, status, attack=True): return self.match('status', 'block_page' if attack else 'passive', status=status)
        def matchReason(self, value, attack=True): return self.match('reason', 'block_page' if attack else 'passive', value=value)
    if len(keys) > 18: raise RuntimeError('Exhaustive audit bound exceeded for ' + vendor)
    probe = Probe(); decisions = []
    for mask in range(1 << len(keys)):
        probe.mask = mask; decisions.append('1' if namespace['is_waf'](probe) else '0')
    output[vendor] = ''.join(decisions)
# Literal witnesses plus negative/control strings exercise the actual regex engines separately.
patterns = list(dict.fromkeys(s['pattern'] for v in vendors.values() for s in v['signatures'] if 'pattern' in s))
regex_cases = []
def witness(tokens, groups):
    out = ''
    for op, arg in tokens:
        name = str(op)
        if name == 'LITERAL': out += chr(arg)
        elif name == 'NOT_LITERAL': out += 'a' if arg != ord('a') else 'b'
        elif name == 'ANY': out += 'a'
        elif name == 'SUBPATTERN':
            text = witness(arg[-1], groups); out += text
            if arg[0]: groups[arg[0]] = text
        elif name == 'BRANCH': out += witness(arg[1][0], groups)
        elif name in ('MAX_REPEAT', 'MIN_REPEAT'): out += witness(arg[2], groups) * min(arg[0], 128)
        elif name == 'GROUPREF': out += groups.get(arg, '')
        elif name == 'CATEGORY': out += '0' if str(arg) == 'CATEGORY_DIGIT' else ' ' if str(arg) == 'CATEGORY_SPACE' else 'a'
        elif name == 'IN':
            if str(arg[0][0]) == 'NEGATE':
                banned = [value for kind,value in arg[1:] if str(kind) == 'LITERAL']; out += next(c for c in 'az09_!' if ord(c) not in banned)
            else:
                kind, value = arg[0]
                out += chr(value) if str(kind) == 'LITERAL' else chr(value[0]) if str(kind) == 'RANGE' else witness([(kind,value)], groups)
        elif name != 'AT': raise RuntimeError('Unrepresented regex witness token: ' + name)
    return out
for js_pattern in patterns:
    py_pattern = re.sub(r'\\k<([A-Za-z_][A-Za-z0-9_]*)>', r'(?P=\1)', re.sub(r'\(\?<([A-Za-z_][A-Za-z0-9_]*)>', r'(?P<\1>', js_pattern))
    sample = witness(re._parser.parse(py_pattern, re.I), {})
    for value in ['', 'ordinary origin response', sample, sample.upper(), 'prefix ' + sample + ' suffix']:
        regex_cases.append({'pattern':js_pattern, 'value':value, 'matched':bool(re.search(py_pattern, value, re.I))})
print(json.dumps({'decisions':output, 'regex_cases':regex_cases, 'regex_patterns':len(patterns)}))
`;
const audit = JSON.parse(execFileSync('python3', ['-c', python, root], {
  input: JSON.stringify(WAF_VENDOR_SIGNATURES), encoding: 'utf8', maxBuffer: 32 * 1024 * 1024,
}));
const reference = audit.decisions;
let cases = 0;
for (const [vendor, definition] of Object.entries(WAF_VENDOR_SIGNATURES)) {
  const keys = [...new Set(definition.signatures.map(key))];
  if (reference[vendor].length !== 2 ** keys.length) throw new Error(`Incomplete reference: ${vendor}`);
  for (let mask = 0; mask < reference[vendor].length; mask += 1) {
    const values = new Map(keys.map((signal, index) => [signal, Boolean(mask & (1 << index))]));
    const matched = evaluateMatcher(definition.matcher, definition.signatures, { values }) === 1;
    if (matched !== (reference[vendor][mask] === '1')) throw new Error(`Decision mismatch: ${vendor}, mask ${mask}`);
    cases += 1;
  }
}
for (const sample of audit.regex_cases) {
  if (compilePattern(sample.pattern, 'offline audit').test(sample.value) !== sample.matched) {
    throw new Error(`Regex engine mismatch for ${sample.pattern}`);
  }
}
console.log(JSON.stringify({ upstream_commit: waf.commit, plugins: Object.keys(reference).length,
  exhaustive_boolean_cases: cases, regex_patterns: audit.regex_patterns,
  regex_witness_cases: audit.regex_cases.length, mismatches: 0,
  scope: 'Exhaustive complete-signal decisions and representative regex witnesses. Bounded signal collection and unavailable-response semantics are separately tested deliberate deviations.' }, null, 2));
