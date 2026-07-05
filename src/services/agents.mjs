import { audit } from '../audit.mjs';
import { redactAgent } from '../lib/agentAuth.mjs';
import { createAddressedSecret } from '../lib/addressedSecrets.mjs';
import { generateSalt, hashSecretWithSalt } from '../lib/crypto.mjs';
import { newId } from '../lib/ids.mjs';
import { getStore, persistStore } from '../store.mjs';
import { checkProbeEndpointBinding, validateProbeEndpoint } from '../lib/probeEndpoint.mjs';
import { consumeBootstrapToken } from './tokens.mjs';

export function registerAgent(body, tenantId) {
  const secret = body.bootstrap_token;
  if (!secret) return { error: 'missing_token', status: 400 };
  const consumed = consumeBootstrapToken(
    secret,
    { hostname: body.hostname, fingerprint: body.fingerprint },
    tenantId,
  );
  if (consumed.error) {
    return { error: consumed.error, status: 401 };
  }
  const token = consumed.token;
  const id = newId('agent');
  const agentCredential = createAddressedSecret('agc_', token.tenant_id, id);
  const credentialSalt = generateSalt();
  const agent = {
    id,
    tenant_id: token.tenant_id,
    name: body.name ?? body.hostname ?? 'agent',
    hostname: body.hostname ?? 'unknown',
    fingerprint: body.fingerprint ?? null,
    target_group_id: token.target_group_id,
    environment_id: token.environment_id,
    status: 'online',
    capabilities: body.capabilities ?? ['heartbeat', 'canary'],
    last_heartbeat_at: new Date().toISOString(),
    created_at: new Date().toISOString(),
    bootstrap_token_id: token.id,
    credential_salt: credentialSalt,
    credential_hash: hashSecretWithSalt(agentCredential, credentialSalt),
  };
  getStore().agents.push(agent);
  audit({
    tenant_id: agent.tenant_id,
    actor_user_id: 'agent',
    actor_role: 'agent',
    action: 'agent.registered',
    resource_type: 'agent',
    resource_id: id,
  });
  persistStore();
  return { agent: redactAgent(agent), agent_credential: agentCredential };
}

export function listAgents(ctx) {
  return getStore()
    .agents.filter((a) => a.tenant_id === ctx.tenantId)
    .map(redactAgent);
}

export function revokeAgent(ctx, id) {
  const agent = getStore().agents.find((a) => a.id === id && a.tenant_id === ctx.tenantId);
  if (!agent) return null;
  agent.status = 'revoked';
  agent.revoked_at = new Date().toISOString();
  agent.last_token_validation_status = 'invalid';
  audit({
    tenant_id: agent.tenant_id,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'agent.revoked',
    resource_type: 'agent',
    resource_id: id,
  });
  persistStore();
  return { agent: redactAgent(agent) };
}

export function heartbeatAgent(agent, body) {
  agent.last_heartbeat_at = new Date().toISOString();
  agent.status = 'online';
  if (body.version) agent.version = body.version;

  agent.last_token_validation_at = new Date().toISOString();
  agent.last_token_validation_status = 'valid';

  let probeEndpointAccepted = false;
  if (body.probe_endpoint !== undefined) {
    const result = validateProbeEndpoint(body.probe_endpoint);
    if (result.ok) {
      const token = getStore().bootstrapTokens.find((t) => t.id === agent.bootstrap_token_id);
      const prebindFqdn = token?.prebind_fqdn ?? null;
      const targetGroupFqdns = getStore().targets
        .filter(
          (t) => t.tenant_id === agent.tenant_id
            && t.target_group_id === agent.target_group_id
            && t.kind === 'fqdn',
        )
        .map((t) => String(t.value).trim().toLowerCase());
      const binding = checkProbeEndpointBinding(result.normalized, { prebindFqdn, targetGroupFqdns });
      if (!binding.ok) {
        agent.probe_endpoint_status = 'rejected';
        agent.probe_endpoint_error = binding.error;
        probeEndpointAccepted = false;
      } else {
        agent.probe_endpoint = result.normalized;
        agent.probe_endpoint_status = 'reported';
        delete agent.probe_endpoint_error;
        probeEndpointAccepted = true;
      }
    } else {
      agent.probe_endpoint_status = 'rejected';
      agent.probe_endpoint_error = result.error;
      probeEndpointAccepted = false;
    }
  }

  audit({
    tenant_id: agent.tenant_id,
    actor_user_id: 'agent',
    actor_role: 'agent',
    action: 'agent.heartbeat',
    resource_type: 'agent',
    resource_id: agent.id,
    metadata: {
      version: body.version,
      token_valid: true,
      probe_endpoint_accepted: probeEndpointAccepted,
    },
  });
  persistStore();
  return { agent: redactAgent(agent), probe_endpoint_accepted: probeEndpointAccepted };
}

export function pollJobs(agent, timeoutMs = 25_000) {
  const store = getStore();
  const pending = store.agentJobs.filter(
    (j) => j.agent_id === agent.id && j.status === 'pending',
  );

  if (pending.length > 0) {
    return Promise.resolve({ jobs: pending });
  }

  return new Promise((resolve) => {
    const start = Date.now();
    const tick = () => {
      const jobs = getStore().agentJobs.filter(
        (j) => j.agent_id === agent.id && j.status === 'pending',
      );
      if (jobs.length > 0) {
        resolve({ jobs });
        return;
      }
      if (Date.now() - start >= timeoutMs) {
        resolve({ jobs: [] });
        return;
      }
      setTimeout(tick, 500);
    };
    setTimeout(tick, 500);
  });
}

export function ackJob(agent, jobId) {
  const job = getStore().agentJobs.find(
    (j) => j.id === jobId && j.agent_id === agent.id && j.tenant_id === agent.tenant_id,
  );
  if (!job) return null;
  job.status = 'acked';
  job.acked_at = new Date().toISOString();
  audit({
    tenant_id: agent.tenant_id,
    actor_user_id: 'agent',
    actor_role: 'agent',
    action: 'agent.job_acked',
    resource_type: 'agent_job',
    resource_id: jobId,
  });
  persistStore();
  return job;
}

export { pollAgentUpdate, recordAgentUpdateStatus } from './agentUpdates.mjs';

export function enqueueAgentJob({ tenantId, agentId, testRunId, checkId, targetId, nonce_hash, nonce }) {
  const job = {
    id: newId('job'),
    tenant_id: tenantId,
    agent_id: agentId,
    test_run_id: testRunId,
    check_id: checkId,
    target_id: targetId,
    nonce_hash,
    nonce_for_agent: nonce,
    type: 'observe_window',
    status: 'pending',
    created_at: new Date().toISOString(),
  };
  getStore().agentJobs.push(job);
  persistStore();
  return job;
}
