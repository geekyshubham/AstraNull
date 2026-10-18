import { Resolver } from 'node:dns/promises';
import { newId } from '../lib/ids.mjs';
import { requirePermission } from '../rbac.mjs';
import {
  ORIGIN_CLUE_LIMITATIONS, OriginClueError, boundedOriginBody, normalizeOriginClue,
  normalizeOriginCollectionBody, originClueDigest, originClueIdempotencyKey, originCluePage,
  originCluesEnabledFor, originHostname, originHostnameInScope, parseOriginClueImport,
  presentOriginCluePage, rejectOriginClue,
} from '../lib/originClues.mjs';

/** Only these explicit DNS questions are allowed. Returned hostnames are never queried. */
export async function collectDeclaredOriginDns(hostnames, includeMail, { resolver: suppliedResolver } = {}) {
  const resolver = suppliedResolver ?? new Resolver({ timeout: 1000, tries: 1 });
  const types = includeMail ? ['A', 'AAAA', 'CNAME', 'MX', 'TXT'] : ['A', 'AAAA', 'CNAME'];
  const questions = hostnames.flatMap((host) => types.map((type) => ({ host, type })));
  const records = []; const sources = []; let next = 0; let queryCount = 0;
  const deadline = Date.now() + 5000;
  async function question({ host, type }) {
    const method = { A: 'resolve4', AAAA: 'resolve6', CNAME: 'resolveCname', MX: 'resolveMx', TXT: 'resolveTxt' }[type];
    let timer;
    try {
      const remaining = deadline - Date.now();
      if (remaining <= 0) throw Object.assign(new Error(), { code: 'ETIMEOUT' });
      const answers = await Promise.race([
        Promise.resolve().then(() => { queryCount += 1; return resolver[method](host); }),
        new Promise((_, reject) => { timer = setTimeout(() => reject(Object.assign(new Error(), { code: 'ETIMEOUT' })), Math.min(1500, remaining)); }),
      ]);
      if (!Array.isArray(answers)) throw new Error('invalid_dns_answer');
      sources.push({ hostname: host, type, status: 'observed', truncated: answers.length > 16 });
      for (const answer of answers.slice(0, 16)) {
        const raw = { associated_hostname: host, candidate_ip: null, source_observed_at: null };
        if (type === 'A' || type === 'AAAA') raw.candidate_ip = typeof answer === 'string' ? answer : answer?.address;
        else if (type === 'CNAME') raw.related_hostname = answer;
        else if (type === 'MX') raw.related_hostname = answer?.exchange;
        else {
          // Preserve SPF text as a bounded reference only, never expand ip4/ip6/include/redirect.
          if (!Array.isArray(answer) || answer.length > 32 || answer.some((chunk) => typeof chunk !== 'string')) continue;
          const value = answer.join('');
          if (!/^v=spf1(?:\s|$)/i.test(value)) continue;
          if (value.length > 512 || /[\u0000-\u001f\u007f]/.test(value)) { sources.push({ hostname: host, type, status: 'record_omitted' }); continue; }
          raw.reference = value;
        }
        records.push({ ...raw, source_kind: `dns_${type.toLowerCase()}`, source_ref: `dns:${host}:${type}` });
      }
    } catch (error) {
      sources.push({ hostname: host, type, status: ['ENODATA', 'ENOTFOUND'].includes(error.code) ? 'no_answer' : 'unavailable' });
    } finally { clearTimeout(timer); }
  }
  try {
    await Promise.all(Array.from({ length: 4 }, async () => {
      while (next < questions.length) { const index = next++; await question(questions[index]); }
    }));
  } finally { resolver.cancel?.(); }
  return { records, sources, query_count: queryCount };
}

function domainTarget(target, ctx) {
  if (!target || target.tenant_id !== ctx.tenantId || target.deleted_at || target.archived_at) rejectOriginClue('not_found', 'Target not found.', 404);
  if (target.kind !== 'fqdn') rejectOriginClue('origin_clues_requires_domain', 'Origin clues support declared fqdn targets only.', 409);
  return originHostname(target.normalized_value ?? target.value);
}
function entry(ctx, targetId, batchId, metadata) {
  return { tenant_id: ctx.tenantId, actor_user_id: ctx.userId, actor_role: ctx.role,
    action: 'target.origin_clues_recorded', resource_type: 'target', resource_id: targetId,
    metadata: { batch_id: batchId, ...metadata } };
}
function present(row) {
  const { tenant_id: _tenant, fingerprint: _fingerprint, ...visible } = row;
  return visible;
}

/** One service and normalization contract over dev-json and PostgreSQL repositories. */
export function createOriginClueService({ repository, collectDns = collectDeclaredOriginDns, now = () => new Date() }) {
  async function guarded(ctx, config, write, fn) {
    try {
      if (!originCluesEnabledFor(config, ctx?.tenantId)) return { error: 'origin_clues_feature_disabled', status: 404 };
      const permission = requirePermission(ctx, write ? 'target_group:write' : 'target_group:read');
      if (!permission.ok) return { ...permission.body, status: permission.status };
      return await fn();
    } catch (error) {
      if (error instanceof OriginClueError) return { error: error.code, status: error.status, message: error.message };
      throw error;
    }
  }
  async function mutate(ctx, targetId, body, options, action) {
    return guarded(ctx, options.runtimeConfig, true, async () => {
      boundedOriginBody(body);
      const key = originClueIdempotencyKey(options.idempotencyKey);
      const requestDigest = originClueDigest({ action, body });
      return repository.withBatch(ctx, targetId, async (tx) => {
        const parent = domainTarget(await tx.getTarget(targetId), ctx);
        const replay = await tx.getBatch(key);
        if (replay) {
          if (replay.request_digest !== requestDigest) rejectOriginClue('origin_clue_idempotency_conflict', 'Idempotency-Key already used for a different request.', 409);
          if (replay.response?.expired === true) rejectOriginClue('origin_clue_response_expired', 'Saved source response expired; submit a separately reviewed new operation.', 410);
          return replay.response;
        }
        let instant = now();
        let clues; let coverage;
        if (action === 'import') {
          const parsed = parseOriginClueImport(body, parent, instant);
          clues = parsed.clues;
          coverage = { partial: true, skipped: parsed.skipped, sources: [{ source_kind: body.source_kind, status: 'supplied_import' }], limitations: [...ORIGIN_CLUE_LIMITATIONS] };
        } else {
          const selected = normalizeOriginCollectionBody(body);
          const hosts = [parent];
          for (const id of selected.related_target_ids) {
            const related = domainTarget(await tx.getTarget(id), ctx);
            originHostnameInScope(related, parent);
            hosts.push(related);
          }
          const collected = await collectDns([...new Set(hosts)], selected.include_mail);
          instant = now();
          clues = []; let omitted = 0;
          for (const record of collected.records.slice(0, 200)) {
            try { clues.push(normalizeOriginClue(record, { parent, sourceKind: record.source_kind, sourceRef: record.source_ref, now: instant, dns: true })); }
            catch (error) { if (!(error instanceof OriginClueError)) throw error; omitted += 1; }
          }
          coverage = { partial: true, sources: collected.sources, query_count: collected.query_count,
            omitted, truncated: collected.records.length > 200, limitations: [...ORIGIN_CLUE_LIMITATIONS,
              'Only explicitly selected declared hostnames were queried; CNAME/MX/SPF references were not resolved and CIDRs were not expanded.',
              'Third-party mail/shared hosting associations do not establish a serving origin.'] };
        }
        const batchId = newId('id');
        const items = []; let created = 0; let deduplicated = 0;
        for (const clue of clues) {
          const row = { ...clue, id: newId('id'), tenant_id: ctx.tenantId, target_id: targetId, batch_id: batchId, fingerprint: clue.source_digest };
          const inserted = await tx.insertClue(row);
          if (inserted.created) created += 1; else deduplicated += 1;
          if (!items.some((item) => item.id === inserted.row.id)) items.push(present(inserted.row));
        }
        const response = { target_id: targetId, created, deduplicated, items, batch_id: batchId, coverage };
        await tx.finish({ id: batchId, idempotency_key: key, request_digest: requestDigest, action, created_at: instant.toISOString(), response },
          entry(ctx, targetId, batchId, { action, created, deduplicated, request_digest: requestDigest,
            source_kinds: [...new Set(clues.map((clue) => clue.source_kind))], partial: true,
            ...(action === 'collect' ? { include_mail: body.include_mail === true, related_target_ids: body.related_target_ids ?? [] } : { import_source_kind: body.source_kind }) }));
        return response;
      });
    });
  }
  return {
    list: (ctx, targetId, query = {}, options = {}) => guarded(ctx, options.runtimeConfig, false, async () => {
      domainTarget(await repository.getTarget(ctx, targetId), ctx);
      const { limit, after } = originCluePage(query, targetId);
      const rows = await repository.list(ctx, targetId, { limit: limit + 1, after });
      const page = presentOriginCluePage(rows.map(present), limit, targetId);
      const coverage = await repository.latestCoverage(ctx, targetId);
      return coverage ? { ...page, coverage } : page;
    }),
    import: (ctx, targetId, body, options = {}) => mutate(ctx, targetId, body, options, 'import'),
    collect: (ctx, targetId, body = {}, options = {}) => mutate(ctx, targetId, body, options, 'collect'),
  };
}
