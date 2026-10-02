# DNS and Edge Provider Setup

## Purpose

Step-by-step, least-privilege setup for every provider in the Integrations > Provider directory. Provider connectors are optional enrichment. Core validation runs from customer-declared targets and external probe evidence only (ADR-0008), so you can skip this page entirely.

The in-app "Setup guide" on each provider card shows the same content (source: `apps/web/react/src/components/integrations/provider-setup-guides.ts`). Keep the two in sync.

## Rules that apply to every provider

- AstraNull only issues read requests. No connector creates, edits, or deletes provider configuration.
- Credentials are stored in the encrypted tenant vault (`POST /v1/secrets`) and are never rendered again.
- Polls are bounded, rate-limited and audited. Failures never block no-access validation.
- Grant the smallest permission listed below and limit it to the zones or accounts you want validated.

## Support matrix

| Directory provider | Backend provider | Mode | Minimum permission |
|---|---|---|---|
| Cloudflare | `cloudflare` | Credential polling | Zone > Zone > Read (plus Zone > WAF > Read for rulesets) |
| Akamai EdgeDNS | `akamai_edgedns` | Credential polling | DNS—Zone Record Management, READ-ONLY |
| GoDaddy | `godaddy` | Credential polling | Production API key and secret (not scoped by GoDaddy) |
| Namecheap | `namecheap` | Credential polling | API access with one whitelisted IPv4 address (not scoped by Namecheap) |
| IBM NS1 | `ibm_ns1` | Credential polling | View zones only |
| AWS WAF | `aws_waf` | Credential polling | `wafv2:ListWebACLs`, `wafv2:GetWebACL` |
| Google Cloud DNS | `generic_waf` | Manual metadata | None accepted |
| Azure DNS | `generic_waf` | Manual metadata | None accepted |
| Hetzner DNS | `generic_waf` | Manual metadata | None accepted |

"Credential polling" means a vault secret is attached and the poll worker can call the provider. A credential-capable provider created without a secret behaves like manual metadata.

## Cloudflare

- Reads: `GET /zones`, then the rulesets for each zone.
- Permission: Zone > Zone > Read. Add Zone > WAF > Read to include rulesets.
- Steps:
  1. Dashboard > My Profile > API Tokens > Create Token.
  2. Create custom token, name it, add the permissions above.
  3. Under Zone Resources, include only the zones to validate.
  4. Continue to summary > Create Token. Paste it once into AstraNull.
- Credential format: the token string, or `{"api_token":"..."}`.
- Never: edits DNS records, rules, or zone settings.
- Troubleshooting: a rulesets permission gap in the poll result means Zone > WAF > Read is missing. Zones still import and the poll is marked degraded.
- Docs: [Create an API token](https://developers.cloudflare.com/fundamentals/api/get-started/create-token/), [List zones](https://developers.cloudflare.com/api/resources/zones/methods/list/), [List zone rulesets](https://developers.cloudflare.com/api/resources/rulesets/methods/list/).

## Akamai EdgeDNS

- Reads: `GET /config-dns/v2/zones?showAll=true` and the record sets for each zone.
- Permission: API service "DNS—Zone Record Management" at READ-ONLY.
- Steps:
  1. Control Center > Identity and Access Management > create an API client.
  2. Use the advanced option to pick individual APIs and access levels.
  3. Grant only DNS—Zone Record Management, READ-ONLY.
  4. Copy `host`, `access_token`, `client_token`, `client_secret` from the credential.
- Credential format: `{"host":"...luna.akamaiapis.net","access_token":"...","client_token":"...","client_secret":"..."}`.
- Never: creates, changes, or deletes zones or record sets.
- Troubleshooting: 401 usually means `host` does not belong to the credential set; 403 means the client lacks the DNS grant.
- Docs: [Set up authentication credentials](https://techdocs.akamai.com/developer/docs/set-up-authentication-credentials), [Edge DNS API get started](https://techdocs.akamai.com/edge-dns/reference/get-started), [Edge DNS API v2](https://techdocs.akamai.com/edge-dns/reference/edge-dns-api).

## GoDaddy

- Reads: `GET /v1/domains` on the production API.
- Permission: a Production API key and secret. GoDaddy keys are not scoped, so AstraNull limits itself to the domain list call.
- Steps:
  1. Sign in to the GoDaddy developer portal with the account that holds the domains.
  2. Create a Production key (not OTE). Copy the key and secret; the secret is shown once.
- Credential format: `{"key":"...","secret":"..."}`.
- Never: changes DNS records, contacts, renewals, or purchases.
- Troubleshooting: 403 means the account has no domains or no plan with domain API access. GoDaddy has scheduled key and secret auth for deprecation on Domains APIs and recommends personal access tokens, which AstraNull does not support yet.
- Docs: [GoDaddy API authentication](https://developer.godaddy.com/docs/api-users/auth).

## Namecheap

- Reads: `namecheap.domains.getList` (production or sandbox endpoint, chosen by `environment`).
- Permission: Namecheap API access with one whitelisted IPv4 address. Keys are not scoped.
- Steps:
  1. Confirm eligibility (20 or more domains, or the balance or spend threshold in Namecheap's API introduction).
  2. Profile > Tools > Business & Dev Tools > Namecheap API Access, turn it on.
  3. Whitelist the AstraNull egress IPv4 address (ask your operator). AstraNull never calls an IP-discovery service.
  4. Copy the API key. The API username is your account username.
- Credential format: `{"api_username":"...","api_key":"...","client_ip":"203.0.113.10","environment":"production"}`.
- Never: registers, renews, transfers, or edits domains or host records.
- Troubleshooting: an invalid IP error means `client_ip` is not whitelisted or differs from the real egress address. Only IPv4 can be whitelisted.
- Docs: [API introduction](https://www.namecheap.com/support/api/intro/), [domains.getList](https://www.namecheap.com/support/api/methods/domains/get-list/), [API FAQ](https://www.namecheap.com/support/knowledgebase/article.aspx/9739/63/api-faq/).

## IBM NS1

- Reads: `GET /v1/zones` with the `X-NSONE-Key` header.
- Permission: DNS "View zones" only. Leave "Manage zones" off.
- Steps:
  1. NS1 Connect > User Settings > Users & teams > API keys > Create API key.
  2. Enable View zones only and clear every other permission.
- Credential format: the key string, or `{"api_key":"..."}`.
- Never: creates or changes zones, records, monitors, or filter chains.
- Troubleshooting: 401 means the key was revoked or mistyped; 403 means it lacks View zones.
- Docs: [Create an API key](https://www.ibm.com/docs/en/SSSYGZ/account_management/create_an_api_key.html), [Account permissions](https://www.ibm.com/docs/en/SSSYGZ/account_management/account_permissions.html).

## AWS WAF

- Reads: `wafv2:ListWebACLs` and `wafv2:GetWebACL`. Route 53 is not polled; record zones as manual metadata.
- Permission: a customer managed IAM policy allowing only the two actions above. The managed policy `AWSWAFReadOnlyAccess` works but is broader.
- Steps:
  1. Create the IAM policy and attach it to a dedicated user or role.
  2. Create an access key, or issue temporary credentials with a `session_token`.
  3. In Advanced metadata choose the web ACL scope: Regional (default) or CloudFront.
- Credential format: `{"access_key_id":"...","secret_access_key":"...","region":"us-east-1","session_token":"optional"}`.
- Never: creates, updates, or associates web ACLs, rule groups, or IP sets.
- Troubleshooting: CloudFront web ACLs only list from us-east-1, so AstraNull forces that region for CloudFront scope. AccessDenied means one action is missing.
- Docs: [AWS managed policies for AWS WAF](https://docs.aws.amazon.com/waf/latest/developerguide/security-iam-awsmanpol.html), [ListWebACLs](https://docs.aws.amazon.com/waf/latest/APIReference/API_ListWebACLs.html).

## Manual metadata providers (Google Cloud DNS, Azure DNS, Hetzner DNS)

There is no backend poller for these providers. The connector is created as `generic_waf` with `owner_hint` set to the directory id, and it never accepts a credential.

1. Create a Manual metadata connector for the provider.
2. Export the zone names and hostnames you want validated from your own console. Whoever exports needs only read access there (Google Cloud: DNS Reader `roles/dns.reader`; Azure: Reader on the DNS zone; Hetzner: zones are managed in Hetzner Console).
3. Add a manual snapshot with a display ref, resource hash, and config hash. Do not paste raw provider payloads.

- Never: contacts the provider or asks for project, subscription, or API token access.
- Troubleshooting: a rejected snapshot is usually missing display ref, resource hash, or config hash.
- Docs: [Cloud DNS overview](https://docs.cloud.google.com/dns/docs/overview), [Cloud DNS API](https://docs.cloud.google.com/dns/docs/reference/rest), [Azure DNS REST API](https://learn.microsoft.com/en-us/rest/api/dns/), [Hetzner DNS docs](https://docs.hetzner.com/networking/dns/).

## Not yet in the directory

`akamai_appsec` (Akamai Application Security configs and policies) has a backend poller but no directory card. It needs a verified access-level label before it is exposed.
