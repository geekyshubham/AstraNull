/**
 * Least-privilege setup guides for the Integrations provider directory.
 *
 * Every scope name and console path below was checked against the vendor's
 * public documentation linked in `docs`. AstraNull only issues read requests
 * for the providers marked `credential`; the `manual` providers have no
 * backend poller and never accept a credential.
 *
 * Long-form version: docs/integrations/03-dns-edge-provider-setup.md.
 */

export type ProviderGuideLink = { label: string; href: string };

export type ProviderSetupGuide = {
  /** Directory entry id from integrations-page.tsx. */
  id: string;
  mode: 'credential' | 'manual';
  /** What AstraNull reads when a poll runs (or what you record manually). */
  reads: string;
  /** The minimum permission to grant, in the vendor's own wording. */
  scope: string;
  /** Ordered steps, written for the vendor console. */
  steps: readonly string[];
  /** Credential format accepted by the connector form (credential mode only). */
  credentialFormat?: string;
  /** Operations AstraNull never performs against this provider. */
  never: string;
  /** Common failure and how to resolve it. */
  troubleshooting: string;
  docs: readonly ProviderGuideLink[];
};

export const PROVIDER_SETUP_GUIDES: Readonly<Record<string, ProviderSetupGuide>> = {
  cloudflare: {
    id: 'cloudflare',
    mode: 'credential',
    reads: 'Zone list, then the rulesets attached to each zone.',
    scope: 'Zone > Zone > Read. Add Zone > WAF > Read to include rulesets.',
    steps: [
      'In the Cloudflare dashboard open My Profile > API Tokens and select Create Token.',
      'Choose Create custom token and give it a recognizable name.',
      'Add the permission Zone > Zone > Read, and optionally Zone > WAF > Read.',
      'Under Zone Resources, limit the token to the zones you want validated.',
      'Select Continue to summary, then Create Token, and paste the token here once.',
    ],
    credentialFormat: 'The token string, or {"api_token":"..."}',
    never: 'Never edits DNS records, rules, or zone settings.',
    troubleshooting: 'If the poll reports a rulesets permission gap, the token lacks Zone > WAF > Read. Zones still import; rulesets are skipped.',
    docs: [
      { label: 'Create an API token', href: 'https://developers.cloudflare.com/fundamentals/api/get-started/create-token/' },
      { label: 'List zones API', href: 'https://developers.cloudflare.com/api/resources/zones/methods/list/' },
      { label: 'List zone rulesets API', href: 'https://developers.cloudflare.com/api/resources/rulesets/methods/list/' },
    ],
  },
  akamai_edgedns: {
    id: 'akamai_edgedns',
    mode: 'credential',
    reads: 'Edge DNS zone list and the record sets in each zone.',
    scope: 'API service "DNS—Zone Record Management" at READ-ONLY access.',
    steps: [
      'In Akamai Control Center open Identity and Access Management and create an API client.',
      'Use the advanced option so you can choose individual APIs and access levels.',
      'Grant only DNS—Zone Record Management with READ-ONLY access.',
      'Download the credential and copy host, access_token, client_token and client_secret.',
      'Paste the four values as JSON here once.',
    ],
    credentialFormat: '{"host":"...luna.akamaiapis.net","access_token":"...","client_token":"...","client_secret":"..."}',
    never: 'Never creates, changes, or deletes zones or record sets.',
    troubleshooting: 'A 401 usually means the host does not match the credential set. A 403 means the client lacks the DNS API grant.',
    docs: [
      { label: 'Set up authentication credentials', href: 'https://techdocs.akamai.com/developer/docs/set-up-authentication-credentials' },
      { label: 'Edge DNS API get started', href: 'https://techdocs.akamai.com/edge-dns/reference/get-started' },
      { label: 'Edge DNS API v2', href: 'https://techdocs.akamai.com/edge-dns/reference/edge-dns-api' },
    ],
  },
  godaddy: {
    id: 'godaddy',
    mode: 'credential',
    reads: 'Domain list for the account (Domains v1 list endpoint).',
    scope: 'Production API key and secret. GoDaddy keys are not scoped, so AstraNull only calls the domain list endpoint.',
    steps: [
      'Sign in to the GoDaddy developer portal with the account that holds the domains.',
      'Create an API key for the Production environment, not OTE.',
      'Copy the key and secret immediately; the secret is shown once.',
      'Paste them as JSON here once.',
    ],
    credentialFormat: '{"key":"...","secret":"..."}',
    never: 'Never changes DNS records, contacts, renewals, or purchases.',
    troubleshooting: 'A 403 means the account has no domains or no plan with domain API access. GoDaddy has scheduled key and secret auth for deprecation on Domains APIs; personal access tokens are not yet supported here.',
    docs: [
      { label: 'GoDaddy API authentication', href: 'https://developer.godaddy.com/docs/api-users/auth' },
    ],
  },
  namecheap: {
    id: 'namecheap',
    mode: 'credential',
    reads: 'Domain list via namecheap.domains.getList.',
    scope: 'Namecheap API access with one allowlisted IPv4 egress address. Keys are not scoped, so AstraNull only calls getList.',
    steps: [
      'Confirm eligibility: 20 or more domains, or the account balance or two-year spend threshold Namecheap lists.',
      'Open Profile > Tools > Business & Dev Tools > Namecheap API Access and turn API access on.',
      'Add the AstraNull egress IPv4 address to the whitelist. Ask your operator for it.',
      'Copy the API key. The API username is your Namecheap account username.',
      'Paste the JSON here once, using the same allowlisted address as client_ip.',
    ],
    credentialFormat: '{"api_username":"...","api_key":"...","client_ip":"203.0.113.10","environment":"production"}',
    never: 'Never registers, renews, transfers, or edits domains or host records.',
    troubleshooting: 'An invalid IP error means client_ip is not on the whitelist or differs from the real egress address. Only IPv4 addresses can be whitelisted.',
    docs: [
      { label: 'Namecheap API introduction', href: 'https://www.namecheap.com/support/api/intro/' },
      { label: 'domains.getList reference', href: 'https://www.namecheap.com/support/api/methods/domains/get-list/' },
      { label: 'Namecheap API FAQ', href: 'https://www.namecheap.com/support/knowledgebase/article.aspx/9739/63/api-faq/' },
    ],
  },
  ibm_ns1: {
    id: 'ibm_ns1',
    mode: 'credential',
    reads: 'Zone list for the account.',
    scope: 'DNS permission "View zones" only. Leave "Manage zones" off.',
    steps: [
      'In IBM NS1 Connect open User Settings > Users & teams and select the API keys tab.',
      'Select Create API key and name it for AstraNull.',
      'Under DNS permissions enable View zones only, and clear every other permission.',
      'Save, copy the key, and paste it here once.',
    ],
    credentialFormat: 'The API key string, or {"api_key":"..."}',
    never: 'Never creates or changes zones, records, monitors, or filter chains.',
    troubleshooting: 'A 401 means the key was revoked or mistyped. A 403 means the key does not have View zones.',
    docs: [
      { label: 'Create an API key', href: 'https://www.ibm.com/docs/en/SSSYGZ/account_management/create_an_api_key.html' },
      { label: 'Account permissions', href: 'https://www.ibm.com/docs/en/SSSYGZ/account_management/account_permissions.html' },
    ],
  },
  aws: {
    id: 'aws',
    mode: 'credential',
    reads: 'AWS WAF web ACLs (ListWebACLs, GetWebACL). Route 53 zones are not polled; record them as manual metadata.',
    scope: 'IAM policy allowing wafv2:ListWebACLs and wafv2:GetWebACL. The broader managed policy AWSWAFReadOnlyAccess also works.',
    steps: [
      'In IAM create a customer managed policy that allows only wafv2:ListWebACLs and wafv2:GetWebACL.',
      'Attach it to a dedicated IAM user or role used only by AstraNull.',
      'Create an access key, or issue temporary credentials with a session_token.',
      'Paste the JSON here once. Under Advanced metadata pick Regional or CloudFront scope.',
    ],
    credentialFormat: '{"access_key_id":"...","secret_access_key":"...","region":"us-east-1","session_token":"optional"}',
    never: 'Never creates, updates, or associates web ACLs, rule groups, or IP sets.',
    troubleshooting: 'CloudFront web ACLs only list from us-east-1; AstraNull forces that region when CloudFront scope is selected. AccessDenied means the policy is missing one of the two actions.',
    docs: [
      { label: 'AWS managed policies for AWS WAF', href: 'https://docs.aws.amazon.com/waf/latest/developerguide/security-iam-awsmanpol.html' },
      { label: 'ListWebACLs API', href: 'https://docs.aws.amazon.com/waf/latest/APIReference/API_ListWebACLs.html' },
    ],
  },
  google_cloud_dns: {
    id: 'google_cloud_dns',
    mode: 'manual',
    reads: 'Nothing. You record selected zone metadata as a normalized snapshot.',
    scope: 'No credential is accepted. Whoever exports the metadata needs only DNS Reader (roles/dns.reader) in Google Cloud.',
    steps: [
      'Create a Manual metadata connector for Google Cloud DNS.',
      'Export the zone names and hostnames you want validated from your own Cloud DNS project.',
      'Add a manual snapshot with a display ref, resource hash, and config hash. Do not paste raw provider payloads.',
    ],
    never: 'Never contacts Google Cloud or asks for project access.',
    troubleshooting: 'If a snapshot is rejected, check that display ref, resource hash and config hash are all filled in.',
    docs: [
      { label: 'Cloud DNS overview', href: 'https://docs.cloud.google.com/dns/docs/overview' },
      { label: 'Cloud DNS API reference', href: 'https://docs.cloud.google.com/dns/docs/reference/rest' },
    ],
  },
  azure_dns: {
    id: 'azure_dns',
    mode: 'manual',
    reads: 'Nothing. You record selected zone metadata as a normalized snapshot.',
    scope: 'No credential is accepted. Whoever exports the metadata needs only the Reader role on the DNS zone.',
    steps: [
      'Create a Manual metadata connector for Azure DNS.',
      'Export the zone names and hostnames you want validated from your own subscription.',
      'Add a manual snapshot with a display ref, resource hash, and config hash. Do not paste raw provider payloads.',
    ],
    never: 'Never contacts Azure or asks for subscription access.',
    troubleshooting: 'If a snapshot is rejected, check that display ref, resource hash and config hash are all filled in.',
    docs: [
      { label: 'Azure DNS REST API', href: 'https://learn.microsoft.com/en-us/rest/api/dns/' },
    ],
  },
  hetzner_dns: {
    id: 'hetzner_dns',
    mode: 'manual',
    reads: 'Nothing. You record selected zone metadata as a normalized snapshot.',
    scope: 'No credential is accepted. Hetzner DNS zones are managed in Hetzner Console; export from there.',
    steps: [
      'Create a Manual metadata connector for Hetzner DNS.',
      'Export the zone names and hostnames you want validated from Hetzner Console.',
      'Add a manual snapshot with a display ref, resource hash, and config hash. Do not paste raw provider payloads.',
    ],
    never: 'Never contacts Hetzner or asks for a project API token.',
    troubleshooting: 'If a snapshot is rejected, check that display ref, resource hash and config hash are all filled in.',
    docs: [
      { label: 'Hetzner DNS docs', href: 'https://docs.hetzner.com/networking/dns/' },
    ],
  },
};

export function getProviderSetupGuide(id: string): ProviderSetupGuide | null {
  return PROVIDER_SETUP_GUIDES[id] ?? null;
}
