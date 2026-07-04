import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it } from 'node:test';
import {
  validateWafOpenApi,
  validateWafOpenApiArtifact,
} from '../../scripts/validate-waf-openapi.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, '../..');
const ARTIFACT = path.join(ROOT, 'docs/api/waf-posture-openapi.json');

describe('WAF posture OpenAPI artifact', () => {
  it('parses as JSON and passes structural contract checks', () => {
    const raw = readFileSync(ARTIFACT, 'utf8');
    const doc = JSON.parse(raw);
    const result = validateWafOpenApi(doc);
    assert.equal(result.ok, true, result.errors.join('; '));
  });

  it('validateWafOpenApiArtifact loads the committed artifact from repo root', () => {
    const result = validateWafOpenApiArtifact({ rootDir: ROOT });
    assert.equal(result.ok, true, result.errors.join('; '));
    assert.match(result.artifactPath, /waf-posture-openapi\.json$/);
  });

  it('documents orchestrator execute path with POST and continuation semantics', () => {
    const doc = JSON.parse(readFileSync(ARTIFACT, 'utf8'));
    const execute = doc.paths['/v1/waf/validation-plans/{id}/execute'].post;
    assert.equal(execute.operationId, 'executeValidationPlan');
    const schema =
      execute.responses['200'].content['application/json'].schema.$ref;
    assert.equal(schema, '#/components/schemas/ValidationPlanExecuteResponse');
    const executeSchema = doc.components.schemas.ValidationPlanExecuteResponse;
    assert.ok('continuation_required' in executeSchema.properties);
  });

  it('fails validation when a required orchestrator error code is removed', () => {
    const doc = JSON.parse(readFileSync(ARTIFACT, 'utf8'));
    const apiError = doc.components.schemas.ApiError;
    apiError.properties.error.enum = apiError.properties.error.enum.filter(
      (c) => c !== 'waf_feature_disabled',
    );
    const result = validateWafOpenApi(doc);
    assert.equal(result.ok, false);
    assert.ok(result.errors.some((e) => /waf_feature_disabled/.test(e)));
  });

  it('fails validation when an implemented required path is described as planned', () => {
    const doc = JSON.parse(readFileSync(ARTIFACT, 'utf8'));
    doc.paths['/v1/waf/cve-pipeline/{id}/playbook'].get.description =
      'Planned route (WAF-020); contract documented for OpenAPI parity.';

    const result = validateWafOpenApi(doc);

    assert.equal(result.ok, false);
    assert.ok(result.errors.some((e) => /Planned route/.test(e)));
  });

  it('fails validation when CVE playbook scopes drift from runtime RBAC', () => {
    const doc = JSON.parse(readFileSync(ARTIFACT, 'utf8'));
    doc.paths['/v1/waf/cve-pipeline/{id}/playbook'].get.security = [
      { bearerAuth: ['cve_pipeline:read'] },
    ];

    const result = validateWafOpenApi(doc);

    assert.equal(result.ok, false);
    assert.ok(result.errors.some((e) => /waf:read/.test(e)));
    assert.ok(result.errors.some((e) => /cve_pipeline:read/.test(e)));
  });

  it('documents WAF exception create and list routes with runtime scopes', () => {
    const doc = JSON.parse(readFileSync(ARTIFACT, 'utf8'));
    const create = doc.paths['/v1/waf/assets/{id}/exception'].post;
    assert.equal(create.operationId, 'createWafException');
    assert.deepEqual(create.security, [{ bearerAuth: ['waf:write'] }]);
    assert.equal(
      create.responses['201'].content['application/json'].schema.$ref,
      '#/components/schemas/WafExceptionCreateResponse',
    );

    const list = doc.paths['/v1/waf/exceptions'].get;
    assert.equal(list.operationId, 'listWafExceptions');
    assert.deepEqual(list.security, [{ bearerAuth: ['waf:read'] }]);
    assert.ok(
      doc.components.schemas.ApiError.properties.error.enum.includes('unsafe_waf_evidence'),
    );
    assert.ok(
      doc.components.schemas.ApiError.properties.error.enum.includes('invalid_waf_exception'),
    );
    const createSchema = doc.components.schemas.WafExceptionCreate;
    assert.equal(createSchema.properties.owner.maxLength, 120);
    assert.equal(createSchema.properties.reason.maxLength, 500);
    assert.equal(createSchema.properties.scope_hash.maxLength, 128);
    assert.equal('created_at' in doc.components.schemas.WafException.properties, false);
    assert.equal('updated_at' in doc.components.schemas.WafException.properties, false);
  });
});
