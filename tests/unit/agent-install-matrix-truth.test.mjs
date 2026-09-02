import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';

const source = readFileSync('apps/web/react/src/components/agents/agent-install-matrix.tsx', 'utf8');
const snippetStart = source.indexOf('function buildDownloadPreparationSnippet');
const snippetEnd = source.indexOf('function ReleaseMetaField', snippetStart);
const snippetSource = source.slice(snippetStart, snippetEnd);

describe('agent install matrix truth', () => {
  it('uses only release distribution metadata and does not synthesize installer or package URLs', () => {
    assert.match(snippetSource, /release\.manifestUrl/);
    assert.match(snippetSource, /release\.signatureUrl/);
    assert.match(snippetSource, /release\.artifactUrl/);
    assert.doesNotMatch(snippetSource, /\/agents\/|install\.sh|docker run|helm upgrade|dpkg|dnf|puppet|ansible/);
  });

  it('rejects redirects and non-HTTPS transport while fetching each accepted URL exactly', () => {
    assert.match(snippetSource, /curl --fail --silent --show-error --proto '=https'/);
    assert.match(snippetSource, /--write-out '%\{http_code\}'/);
    assert.match(snippetSource, /2\?\?\) mv -f/);
    assert.match(snippetSource, /redirects are not followed/);
    assert.doesNotMatch(snippetSource, /--location|(?:^|\s)-L(?:\s|$)/m);
  });

  it('retains checksum and mandatory signature verification before installation', () => {
    assert.match(snippetSource, /sha256sum --check --strict/);
    assert.match(snippetSource, /release\.digest/);
    assert.match(snippetSource, /Signature verification is mandatory before extraction or installation/);
    assert.match(snippetSource, /release\.signingFingerprint/);
  });

  it('prompts for the token and writes a mode-0600 file without interpolating the secret', () => {
    assert.match(snippetSource, /read -r -s -p "Paste one-time bootstrap token: " ASTRANULL_TOKEN/);
    assert.match(snippetSource, /sudo install -d -m 0700 \/var\/lib\/astranull/);
    assert.match(snippetSource, /sudo install -m 0600 \/dev\/null \/var\/lib\/astranull\/bootstrap-token/);
    assert.match(snippetSource, /unset ASTRANULL_TOKEN/);
    assert.doesNotMatch(snippetSource, /tokenSecret|BOOTSTRAP_TOKEN=/);
  });

  it('stops before installation and exposes accessible disabled copy behavior', () => {
    assert.match(snippetSource, /STOP: checksum-verified download and token-file preparation only; the agent is not installed/);
    assert.match(snippetSource, /before extraction or installation/);
    assert.match(source, /disabled=\{!snippet\}/);
    assert.match(source, /aria-label=\{`Copy \$\{activeTab\.label\.toLowerCase\(\)\} commands`\}/);
    assert.match(source, /role="status" aria-live="polite"/);
  });
});
