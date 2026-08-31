import { awsWafProvider } from './awsWaf.mjs';
import { cloudflareProvider } from './cloudflare.mjs';
import {
  akamaiEdgeDnsProvider,
  godaddyProvider,
  ibmNs1Provider,
  namecheapProvider,
} from './domainInventory.mjs';

const PROVIDERS = new Map([
  ['cloudflare', cloudflareProvider],
  ['akamai_edgedns', akamaiEdgeDnsProvider],
  ['namecheap', namecheapProvider],
  ['godaddy', godaddyProvider],
  ['ibm_ns1', ibmNs1Provider],
  ['aws_waf', awsWafProvider],
]);

export const OUTBOUND_POLL_PROVIDERS = new Set(PROVIDERS.keys());

export function getConnectorProvider(provider) {
  const key = String(provider ?? '').trim().toLowerCase();
  return PROVIDERS.get(key) ?? null;
}

export function supportsOutboundProviderPoll(provider) {
  return OUTBOUND_POLL_PROVIDERS.has(String(provider ?? '').trim().toLowerCase());
}

export function listConnectorProviders() {
  return [...PROVIDERS.values()].map((entry) => ({
    provider: entry.provider,
    required_scopes: entry.required_scopes,
    snapshot_kinds: entry.snapshot_kinds,
    read_only: true,
  }));
}