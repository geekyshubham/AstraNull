import { Buffer } from 'node:buffer';
import { signAwsJsonRequest } from './awsSigV4.mjs';
import {
  buildNormalizedSnapshot,
  CONNECTOR_POLL_INVENTORY_PAGE_SIZE,
  CONNECTOR_POLL_MAX_INVENTORY_ITEMS,
  hashRef,
  normalizePolicyMode,
  resolveConnectorPollFetchTimeoutMs,
} from './common.mjs';

const AWS_WAF_SERVICE = 'wafv2';
const AWS_REGION_LABEL = /^[a-z][a-z0-9]*(?:-[a-z0-9]+)+-[0-9]$/;
export const AWS_WAF_RESPONSE_MAX_BYTES = 1024 * 1024;

function providerRequestError(message, { code = 'provider_poll_failed', status, cause } = {}) {
  const error = new Error(message);
  error.code = code;
  if (status !== undefined) error.status = status;
  if (cause !== undefined) error.cause = cause;
  return error;
}

function resolveRegion(config = {}, credentials = {}) {
  const region = String(
    config.region_summary
    ?? config.regionSummary
    ?? credentials.region
    ?? 'us-east-1',
  ).trim().toLowerCase() || 'us-east-1';
  if (!AWS_REGION_LABEL.test(region)) {
    throw providerRequestError('AWS WAF region must be one safe AWS region label.', {
      code: 'credentials_invalid',
    });
  }
  return region;
}

function buildAwsWafEndpoint(region) {
  const hostname = `${AWS_WAF_SERVICE}.${region}.amazonaws.com`;
  const endpoint = new URL(`https://${hostname}/`);
  if (endpoint.protocol !== 'https:'
    || endpoint.hostname !== hostname
    || !endpoint.hostname.endsWith('.amazonaws.com')) {
    throw providerRequestError('AWS WAF endpoint must remain under amazonaws.com.', {
      code: 'credentials_invalid',
    });
  }
  return endpoint;
}

function responseTooLarge() {
  return providerRequestError(
    `AWS WAF API response exceeded the ${AWS_WAF_RESPONSE_MAX_BYTES}-byte limit.`,
    { code: 'provider_response_too_large' },
  );
}

function appendBoundedChunk(chunks, chunk, total) {
  const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
  const nextTotal = total + buffer.byteLength;
  if (nextTotal > AWS_WAF_RESPONSE_MAX_BYTES) throw responseTooLarge();
  chunks.push(buffer);
  return nextTotal;
}

async function readAwsWafResponse(response) {
  const contentLength = Number(response.headers?.get?.('content-length'));
  if (Number.isFinite(contentLength) && contentLength > AWS_WAF_RESPONSE_MAX_BYTES) {
    throw responseTooLarge();
  }

  const chunks = [];
  let total = 0;
  if (typeof response.body?.getReader === 'function') {
    const reader = response.body.getReader();
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        total = appendBoundedChunk(chunks, value, total);
      }
    } finally {
      reader.releaseLock();
    }
    return JSON.parse(Buffer.concat(chunks, total).toString('utf8') || '{}');
  }

  if (response.body && typeof response.body[Symbol.asyncIterator] === 'function') {
    for await (const chunk of response.body) {
      total = appendBoundedChunk(chunks, chunk, total);
    }
    return JSON.parse(Buffer.concat(chunks, total).toString('utf8') || '{}');
  }

  if (typeof response.text === 'function') {
    const text = await response.text();
    if (Buffer.byteLength(text, 'utf8') > AWS_WAF_RESPONSE_MAX_BYTES) throw responseTooLarge();
    return JSON.parse(text || '{}');
  }

  // Test doubles may expose json() without a body stream. Real fetch responses use the
  // streaming branches above, so production consumption is capped before allocation.
  if (typeof response.json === 'function') {
    const parsed = await response.json();
    const serialized = JSON.stringify(parsed ?? {});
    if (Buffer.byteLength(serialized, 'utf8') > AWS_WAF_RESPONSE_MAX_BYTES) throw responseTooLarge();
    return parsed ?? {};
  }
  return {};
}

function webAclMatchesConfig(webAcl, config = {}) {
  const resourceRefHash = config.resource_ref_hash ?? config.resourceRefHash ?? null;
  if (!resourceRefHash) return true;
  const arn = webAcl?.ARN ?? webAcl?.arn ?? webAcl?.id ?? webAcl?.name;
  return hashRef(`aws_waf:webacl:${arn}`) === resourceRefHash;
}

function deriveAwsPolicyMode(webAcl) {
  const defaultAction = webAcl?.DefaultAction ?? webAcl?.defaultAction ?? {};
  if (defaultAction.Block || defaultAction.block) return 'block';
  if (defaultAction.Count || defaultAction.count) return 'monitor';
  if (defaultAction.Allow || defaultAction.allow) return 'monitor';
  return normalizePolicyMode(webAcl?.policy_mode ?? webAcl?.policyMode ?? 'unknown');
}

function countAwsRules(webAcl) {
  const rules = webAcl?.Rules ?? webAcl?.rules ?? [];
  return Array.isArray(rules) ? rules.length : 0;
}

async function awsWafJsonRequest({
  region,
  target,
  body,
  credentials,
  fetchFn,
  timeoutMs,
}) {
  const endpoint = buildAwsWafEndpoint(region);
  const host = endpoint.hostname;
  const payload = JSON.stringify(body ?? {});
  const signedHeaders = signAwsJsonRequest({
    host,
    region,
    service: AWS_WAF_SERVICE,
    body: payload,
    credentials,
    amzTarget: target,
  });
  const boundedTimeoutMs = Number.isFinite(timeoutMs) && timeoutMs > 0
    ? timeoutMs
    : resolveConnectorPollFetchTimeoutMs();
  const controller = new AbortController();
  let timer;
  const deadline = new Promise((_, reject) => {
    timer = setTimeout(() => {
      const error = providerRequestError(
        'Failed to fetch and consume AWS WAF API response within the bounded timeout.',
      );
      controller.abort(error);
      reject(error);
    }, boundedTimeoutMs);
  });

  const request = async () => {
    const response = await fetchFn(endpoint.href, {
      method: 'POST',
      headers: signedHeaders,
      body: payload,
      redirect: 'manual',
      signal: controller.signal,
    });
    if (response.status >= 300 && response.status < 400) {
      throw providerRequestError('AWS WAF API redirects are not followed.', {
        code: 'provider_redirect_not_allowed',
        status: response.status,
      });
    }

    const parsed = await readAwsWafResponse(response);
    if (!response.ok) {
      const code = response.status === 429
        ? 'rate_limited'
        : response.status === 401 || response.status === 403
          ? 'auth_failed'
          : 'provider_poll_failed';
      throw providerRequestError(parsed?.message ?? `AWS WAF API error (${response.status})`, {
        code,
        status: response.status,
      });
    }
    return parsed;
  };

  try {
    return await Promise.race([request(), deadline]);
  } catch (cause) {
    if (cause?.code || cause?.status !== undefined) throw cause;
    throw providerRequestError('Failed to fetch AWS WAF API within the bounded timeout.', { cause });
  } finally {
    clearTimeout(timer);
  }
}

async function listWebAclSummaries({
  region,
  scope,
  credentials,
  fetchFn,
  timeoutMs,
}) {
  const summaries = [];
  let nextMarker;
  let truncated = false;

  while (summaries.length < CONNECTOR_POLL_MAX_INVENTORY_ITEMS) {
    const listBody = await awsWafJsonRequest({
      region,
      target: 'AWSWAF_20190729.ListWebACLs',
      body: {
        Scope: scope,
        Limit: CONNECTOR_POLL_INVENTORY_PAGE_SIZE,
        ...(nextMarker ? { NextMarker: nextMarker } : {}),
      },
      credentials,
      fetchFn,
      timeoutMs,
    });
    if (!Array.isArray(listBody?.WebACLs)) {
      throw providerRequestError('AWS WAF ListWebACLs returned an invalid success body.', {
        code: 'provider_response_invalid',
      });
    }
    const batch = listBody.WebACLs;
    if (batch.length === 0) break;

    const remaining = CONNECTOR_POLL_MAX_INVENTORY_ITEMS - summaries.length;
    summaries.push(...batch.slice(0, remaining));

    const marker = listBody?.NextMarker;
    if (summaries.length >= CONNECTOR_POLL_MAX_INVENTORY_ITEMS) {
      truncated = batch.length > remaining || Boolean(marker);
      break;
    }

    if (!marker) break;
    nextMarker = marker;
  }

  return { summaries, truncated };
}

function normalizePrefetchedWebAcls(prefetched, config, observedAt) {
  const webAcls = Array.isArray(prefetched?.web_acls)
    ? prefetched.web_acls
    : (Array.isArray(prefetched?.webAcls) ? prefetched.webAcls : []);
  const snapshots = [];
  for (const webAcl of webAcls) {
    if (!webAclMatchesConfig(webAcl, config)) continue;
    snapshots.push(buildNormalizedSnapshot({
      provider: 'aws_waf',
      snapshotKind: 'waf_policy',
      resourceRef: webAcl.ARN ?? webAcl.arn ?? webAcl.id ?? webAcl.name,
      displayRef: webAcl.Name ?? webAcl.name ?? webAcl.id,
      summary: {
        hostnames: Array.isArray(webAcl.hostnames) ? webAcl.hostnames : [],
        policy_mode: deriveAwsPolicyMode(webAcl),
        rule_count: countAwsRules(webAcl),
        ...(Array.isArray(webAcl.managed_rule_versions)
          ? { managed_rule_versions: webAcl.managed_rule_versions }
          : {}),
        ...(Array.isArray(webAcl.permission_gaps) ? { permission_gaps: webAcl.permission_gaps } : {}),
      },
      observedAt,
    }));
  }
  return snapshots;
}

/**
 * Read-only AWS WAFv2 metadata poll (fetch + SigV4, no AWS SDK).
 */
export async function pollAwsWaf({
  credentials,
  config = {},
  fetchFn = fetch,
  prefetchedMetadata = null,
  observedAt,
  fetchTimeoutMs,
}) {
  if (prefetchedMetadata) {
    const snapshots = normalizePrefetchedWebAcls(prefetchedMetadata, config, observedAt);
    return {
      snapshots,
      health: snapshots.length > 0 ? 'active' : 'degraded',
      permission_gaps: snapshots.length === 0 ? ['no_webacl_metadata'] : [],
    };
  }

  if (!credentials?.access_key_id || !credentials?.secret_access_key) {
    const err = new Error('AWS WAF credentials missing access_key_id or secret_access_key.');
    err.code = 'credentials_missing';
    throw err;
  }

  const scope = String(config.scope ?? '').toLowerCase() === 'cloudfront' ? 'CLOUDFRONT' : 'REGIONAL';
  const configuredRegion = resolveRegion(config, credentials);
  const region = scope === 'CLOUDFRONT' ? 'us-east-1' : configuredRegion;
  const fetchOptions = {
    timeoutMs: Number.isFinite(fetchTimeoutMs)
      ? fetchTimeoutMs
      : resolveConnectorPollFetchTimeoutMs(),
  };
  const { summaries, truncated } = await listWebAclSummaries({
    region,
    scope,
    credentials,
    fetchFn,
    timeoutMs: fetchOptions.timeoutMs,
  });
  const snapshots = [];
  const permissionGaps = [];
  if (truncated) permissionGaps.push('truncated_inventory');

  for (const summary of summaries) {
    if (!webAclMatchesConfig(summary, config)) continue;
    let webAcl = summary;
    try {
      webAcl = await awsWafJsonRequest({
        region,
        target: 'AWSWAF_20190729.GetWebACL',
        body: {
          Scope: scope,
          Id: summary.Id,
          Name: summary.Name,
        },
        credentials,
        fetchFn,
        ...fetchOptions,
      });
      if (!webAcl?.WebACL || typeof webAcl.WebACL !== 'object' || Array.isArray(webAcl.WebACL)) {
        throw providerRequestError('AWS WAF GetWebACL returned an invalid success body.', {
          code: 'provider_response_invalid',
        });
      }
      webAcl = webAcl.WebACL;
    } catch (err) {
      if (err.status === 403) {
        permissionGaps.push(`get_webacl:${summary.Id}`);
      } else {
        throw err;
      }
    }

    snapshots.push(buildNormalizedSnapshot({
      provider: 'aws_waf',
      snapshotKind: 'waf_policy',
      resourceRef: summary.ARN ?? summary.Arn ?? summary.Id,
      displayRef: summary.Name ?? summary.Id,
      summary: {
        policy_mode: deriveAwsPolicyMode(webAcl),
        rule_count: countAwsRules(webAcl),
        ...(permissionGaps.length > 0 ? { permission_gaps: permissionGaps } : {}),
      },
      observedAt,
    }));
  }

  return {
    snapshots,
    health: permissionGaps.length > 0 ? 'degraded' : 'active',
    permission_gaps: permissionGaps,
    inventory_complete: !truncated,
    inventory_truncated: truncated,
  };
}

export const awsWafProvider = {
  provider: 'aws_waf',
  required_scopes: ['wafv2:ListWebACLs', 'wafv2:GetWebACL'],
  snapshot_kinds: ['waf_policy', 'cloud_asset'],
  poll: pollAwsWaf,
};