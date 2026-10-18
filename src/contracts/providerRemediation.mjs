const entry = (control, steps, docs) => Object.freeze({ control, steps: Object.freeze([...steps]), docs: Object.freeze([...docs]) });
const family = (providers) => Object.freeze(providers);

const GCP = Object.freeze({
  firewall: 'https://cloud.google.com/firewall/docs/firewalls',
  firewallPolicies: 'https://cloud.google.com/firewall/docs/firewall-policies-overview',
  lbFirewall: 'https://cloud.google.com/load-balancing/docs/firewall-rules',
  armor: 'https://cloud.google.com/armor/docs/cloud-armor-overview',
  armorPolicies: 'https://cloud.google.com/armor/docs/security-policy-overview',
  armorWaf: 'https://cloud.google.com/armor/docs/waf-rules',
  armorRateLimit: 'https://cloud.google.com/armor/docs/rate-limiting-overview',
  armorRulesLanguage: 'https://cloud.google.com/armor/docs/rules-language-reference',
  armorBots: 'https://cloud.google.com/armor/docs/bot-management',
  armorAdaptive: 'https://cloud.google.com/armor/docs/adaptive-protection-overview',
  armorNetworkDdos: 'https://cloud.google.com/armor/docs/advanced-network-ddos',
  armorEnterprise: 'https://cloud.google.com/armor/docs/armor-enterprise-overview',
  sslPolicies: 'https://cloud.google.com/load-balancing/docs/ssl-policies-concepts',
  httpsLb: 'https://cloud.google.com/load-balancing/docs/https',
  backendService: 'https://cloud.google.com/load-balancing/docs/backend-service',
  cdnCaching: 'https://cloud.google.com/cdn/docs/caching',
  dns: 'https://cloud.google.com/dns/docs/overview',
  dnsBestPractices: 'https://cloud.google.com/dns/docs/best-practices',
  apigee: 'https://cloud.google.com/apigee/docs/api-platform/get-started/what-apigee',
  monitoringAlerts: 'https://cloud.google.com/monitoring/alerts',
});

const AWS = Object.freeze({
  securityGroups: 'https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html',
  nacls: 'https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html',
  networkFirewall: 'https://docs.aws.amazon.com/network-firewall/latest/developerguide/what-is-aws-network-firewall.html',
  waf: 'https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html',
  wafRateBased: 'https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-type-rate-based.html',
  wafManaged: 'https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups.html',
  wafTransforms: 'https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-transformation.html',
  wafOversize: 'https://docs.aws.amazon.com/waf/latest/developerguide/waf-oversize-request-components.html',
  wafBotControl: 'https://docs.aws.amazon.com/waf/latest/developerguide/waf-bot-control.html',
  shield: 'https://docs.aws.amazon.com/waf/latest/developerguide/shield-chapter.html',
  ddosOverview: 'https://docs.aws.amazon.com/waf/latest/developerguide/ddos-overview.html',
  ddosWhitepaper: 'https://docs.aws.amazon.com/whitepapers/latest/aws-best-practices-ddos-resiliency/',
  cloudfront: 'https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/Introduction.html',
  cloudfrontHttpVersion: 'https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/http-version.html',
  cloudfrontMethods: 'https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/distribution-web-values-specify.html',
  ddosSimulation: 'https://aws.amazon.com/security/ddos-simulation-testing/',
  cloudfrontCacheKey: 'https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/controlling-the-cache-key.html',
  cloudfrontTls: 'https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/secure-connections-supported-viewer-protocols-ciphers.html',
  cloudfrontVpcOrigins: 'https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-vpc-origins.html',
  prefixLists: 'https://docs.aws.amazon.com/vpc/latest/userguide/working-with-aws-managed-prefix-lists.html',
  albListeners: 'https://docs.aws.amazon.com/elasticloadbalancing/latest/application/create-https-listener.html',
  alb: 'https://docs.aws.amazon.com/elasticloadbalancing/latest/application/introduction.html',
  route53: 'https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/Welcome.html',
  apiGatewayThrottling: 'https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-request-throttling.html',
  shieldResponse: 'https://docs.aws.amazon.com/waf/latest/developerguide/ddos-responding.html',
  cloudwatchAlarms: 'https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch_Alarms.html',
});

const AZURE = Object.freeze({
  nsg: 'https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview',
  firewall: 'https://learn.microsoft.com/en-us/azure/firewall/overview',
  ddos: 'https://learn.microsoft.com/en-us/azure/ddos-protection/ddos-protection-overview',
  ddosRapidResponse: 'https://learn.microsoft.com/en-us/azure/ddos-protection/ddos-rapid-response',
  ddosSimulation: 'https://learn.microsoft.com/en-us/azure/ddos-protection/test-through-simulations',
  waf: 'https://learn.microsoft.com/en-us/azure/web-application-firewall/overview',
  fdRateLimit: 'https://learn.microsoft.com/en-us/azure/web-application-firewall/afds/waf-front-door-rate-limit',
  agRateLimit: 'https://learn.microsoft.com/en-us/azure/web-application-firewall/ag/rate-limiting-overview',
  fdDrs: 'https://learn.microsoft.com/en-us/azure/web-application-firewall/afds/waf-front-door-drs',
  agCrs: 'https://learn.microsoft.com/en-us/azure/web-application-firewall/ag/application-gateway-crs-rulegroups-rules',
  fdCustom: 'https://learn.microsoft.com/en-us/azure/web-application-firewall/afds/waf-front-door-custom-rules',
  agCustom: 'https://learn.microsoft.com/en-us/azure/web-application-firewall/ag/custom-waf-rules-overview',
  agBots: 'https://learn.microsoft.com/en-us/azure/web-application-firewall/ag/bot-protection-overview',
  fdBots: 'https://learn.microsoft.com/en-us/azure/web-application-firewall/afds/waf-front-door-policy-configure-bot-protection',
  agSizeLimits: 'https://learn.microsoft.com/en-us/azure/web-application-firewall/ag/application-gateway-waf-request-size-limits',
  frontDoor: 'https://learn.microsoft.com/en-us/azure/frontdoor/front-door-overview',
  fdCaching: 'https://learn.microsoft.com/en-us/azure/frontdoor/front-door-caching',
  fdTls: 'https://learn.microsoft.com/en-us/azure/frontdoor/end-to-end-tls',
  fdOrigin: 'https://learn.microsoft.com/en-us/azure/frontdoor/origin-security',
  agTls: 'https://learn.microsoft.com/en-us/azure/application-gateway/application-gateway-ssl-policy-overview',
  appGateway: 'https://learn.microsoft.com/en-us/azure/application-gateway/overview',
  dns: 'https://learn.microsoft.com/en-us/azure/dns/dns-overview',
  apim: 'https://learn.microsoft.com/en-us/azure/api-management/api-management-sample-flexible-throttling',
});

const CF = Object.freeze({
  waf: 'https://developers.cloudflare.com/waf/',
  managed: 'https://developers.cloudflare.com/waf/managed-rules/',
  custom: 'https://developers.cloudflare.com/waf/custom-rules/',
  rateLimit: 'https://developers.cloudflare.com/waf/rate-limiting-rules/',
  rulesLanguage: 'https://developers.cloudflare.com/ruleset-engine/rules-language/',
  normalization: 'https://developers.cloudflare.com/rules/normalization/',
  bots: 'https://developers.cloudflare.com/bots/',
  ddos: 'https://developers.cloudflare.com/ddos-protection/',
  ddosBestPractices: 'https://developers.cloudflare.com/ddos-protection/best-practices/',
  ddosSimulate: 'https://developers.cloudflare.com/ddos-protection/reference/simulate-ddos-attack/',
  spectrum: 'https://developers.cloudflare.com/spectrum/',
  magicTransit: 'https://developers.cloudflare.com/magic-transit/',
  networkFirewall: 'https://developers.cloudflare.com/cloudflare-network-firewall/',
  cache: 'https://developers.cloudflare.com/cache/',
  cacheKeys: 'https://developers.cloudflare.com/cache/how-to/cache-keys/',
  ssl: 'https://developers.cloudflare.com/ssl/',
  minTls: 'https://developers.cloudflare.com/ssl/edge-certificates/additional-options/minimum-tls/',
  tunnel: 'https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/',
  aop: 'https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/',
  dns: 'https://developers.cloudflare.com/dns/',
  zoneTransfers: 'https://developers.cloudflare.com/dns/zone-setups/zone-transfers/',
  dnsFirewall: 'https://developers.cloudflare.com/dns/dns-firewall/',
  apiShield: 'https://developers.cloudflare.com/api-shield/',
  connectionLimits: 'https://developers.cloudflare.com/fundamentals/reference/connection-limits/',
  notifications: 'https://developers.cloudflare.com/notifications/',
});

const AK = Object.freeze({
  aap: 'https://techdocs.akamai.com/app-api-protector/docs',
  appsecTerraform: 'https://techdocs.akamai.com/terraform/docs/configure-appsec',
  prolexic: 'https://techdocs.akamai.com/prolexic-routed-gre/docs/welcome',
  networkCloudFirewall: 'https://techdocs.akamai.com/network-cloud-firewall/docs/welcome',
  botManager: 'https://techdocs.akamai.com/bot-manager/docs',
  botManagerTerraform: 'https://techdocs.akamai.com/terraform/docs/set-up-botman',
  propertyManager: 'https://techdocs.akamai.com/property-mgr/docs/welcome-prop-manager',
  allowPost: 'https://techdocs.akamai.com/property-mgr/docs/allow-post',
  readTimeout: 'https://techdocs.akamai.com/property-mgr/docs/read-timeout',
  cacheIdModification: 'https://techdocs.akamai.com/property-mgr/docs/cache-id-modification',
  http2: 'https://techdocs.akamai.com/property-mgr/docs/http2-support',
  http3: 'https://techdocs.akamai.com/property-mgr/docs/http3-support',
  siteShield: 'https://techdocs.akamai.com/site-shield/docs/welcome-site-shield',
  edgeDns: 'https://techdocs.akamai.com/edge-dns/docs/welcome-edge-dns',
  edgeDnsTerraform: 'https://techdocs.akamai.com/terraform/docs/set-up-edgedns',
  cps: 'https://techdocs.akamai.com/cps/docs/welcome-cert-prov-system',
  cloudFirewall: 'https://techdocs.akamai.com/cloud-computing/docs/cloud-firewall',
  apiSecurity: 'https://techdocs.akamai.com/api-security/docs/welcome-to-api-security',
});

const FASTLY = Object.freeze({
  ngwaf: 'https://www.fastly.com/documentation/guides/next-gen-waf/',
  ngwafRules: 'https://www.fastly.com/documentation/guides/next-gen-waf/rules/',
  ngwafRateLimit: 'https://www.fastly.com/documentation/guides/next-gen-waf/rules/working-with-advanced-rate-limiting-rules/',
  ngwafVirtualPatches: 'https://www.fastly.com/documentation/guides/next-gen-waf/virtual-patches-for-cves/',
  ngwafProtectionMode: 'https://www.fastly.com/documentation/guides/next-gen-waf/about-the-protection-mode/',
  botManagement: 'https://www.fastly.com/documentation/guides/security/bot-management/',
  clientChallenges: 'https://www.fastly.com/documentation/guides/security/client-challenges/',
  apiSecurity: 'https://www.fastly.com/documentation/guides/security/api-security/',
  ddos: 'https://www.fastly.com/documentation/guides/security/ddos-protection/',
  rateLimiting: 'https://www.fastly.com/documentation/guides/concepts/rate-limiting/',
  vcl: 'https://www.fastly.com/documentation/reference/vcl/',
  vclRateLimiting: 'https://www.fastly.com/documentation/reference/vcl/functions/rate-limiting/',
  http3: 'https://www.fastly.com/documentation/guides/full-site-delivery/performance/enabling-http3-for-fastly-services/',
  cache: 'https://www.fastly.com/documentation/guides/concepts/cache/',
  publicIpList: 'https://www.fastly.com/documentation/reference/api/utils/public-ip-list/',
  tls: 'https://www.fastly.com/documentation/guides/getting-started/domains/securing-domains/setting-up-tls-with-certificates-fastly-manages/',
  hosts: 'https://www.fastly.com/documentation/guides/getting-started/hosts/working-with-hosts/',
  domains: 'https://www.fastly.com/documentation/guides/getting-started/domains/working-with-domains/',
  logging: 'https://www.fastly.com/documentation/guides/integrations/logging-endpoints/',
});

const GENERIC = Object.freeze({
  dosCheatSheet: 'https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html',
  virtualPatching: 'https://cheatsheetseries.owasp.org/cheatsheets/Virtual_Patching_Cheat_Sheet.html',
  inputValidation: 'https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html',
  restSecurity: 'https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html',
  tlsCheatSheet: 'https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html',
  crs: 'https://owasp.org/www-project-modsecurity-core-rule-set/',
  apiTop10: 'https://owasp.org/API-Security/',
  automatedThreats: 'https://owasp.org/www-project-automated-threats-to-web-applications/',
  cisaDdos: 'https://www.cisa.gov/resources-tools/resources/understanding-and-responding-distributed-denial-service-attacks',
  cisaKev: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
  bcp38: 'https://www.rfc-editor.org/rfc/rfc2827',
  axfr: 'https://www.rfc-editor.org/rfc/rfc5936',
  recursionBcp: 'https://www.rfc-editor.org/rfc/rfc5358',
  secondaryDns: 'https://www.rfc-editor.org/rfc/rfc2182',
  httpSemantics: 'https://www.rfc-editor.org/rfc/rfc9110',
  httpCaching: 'https://www.rfc-editor.org/rfc/rfc9111',
  http2: 'https://www.rfc-editor.org/rfc/rfc9113',
  tlsBcp: 'https://www.rfc-editor.org/rfc/rfc9325',
  nistFirewall: 'https://csrc.nist.gov/pubs/sp/800/41/r1/final',
  nistTls: 'https://csrc.nist.gov/pubs/sp/800/52/r2/final',
  nistIncident: 'https://csrc.nist.gov/pubs/sp/800/61/r3/final',
  nistDns: 'https://csrc.nist.gov/pubs/sp/800/81/r3/final',
  nistTesting: 'https://csrc.nist.gov/pubs/sp/800/115/final',
});

export const PROVIDER_LABELS = Object.freeze({
  gcp: 'Google Cloud',
  aws: 'AWS',
  azure: 'Microsoft Azure',
  cloudflare: 'Cloudflare',
  akamai: 'Akamai',
  fastly: 'Fastly',
  generic: 'Any provider',
});

export const PROVIDER_REMEDIATION = Object.freeze({
  network_firewall_ingress: family({
    gcp: entry('VPC firewall rules (or hierarchical firewall policies)', [
      'Inventory ingress rules with `gcloud compute firewall-rules list --filter="direction=INGRESS"` and remove any rule that allows 0.0.0.0/0 to ports other than the public service ports.',
      'Add an explicit deny for exposed management and data ports, e.g. `gcloud compute firewall-rules create deny-mgmt --direction=INGRESS --action=DENY --rules=tcp:22,tcp:3389,tcp:3306 --source-ranges=0.0.0.0/0 --priority=900 --network=<your-network>`.',
      'Allow administrative access only from `<your-admin-cidr>` or through IAP TCP forwarding, and manage rules as `google_compute_firewall` or `google_compute_firewall_policy_rule` resources in Terraform.',
    ], [GCP.firewall, GCP.firewallPolicies]),
    aws: entry('Security groups and network ACLs', [
      'Find security groups that allow 0.0.0.0/0 or ::/0 on non-public ports (VPC console > Security groups > Inbound rules) and remove those rules.',
      'Scope inbound rules on `aws_security_group_rule` / `aws_vpc_security_group_ingress_rule` to the listener ports and to `<your-admin-cidr>` or a load balancer security group.',
      'Add subnet-level deny entries with `aws_network_acl_rule` for ports that must never be reachable from the internet, and consider AWS Network Firewall for stateful inspection at the VPC edge.',
    ], [AWS.securityGroups, AWS.nacls, AWS.networkFirewall]),
    azure: entry('Network security groups', [
      'Review effective inbound rules (Virtual network > Network security groups > Inbound security rules) and remove rules with source `Any` or `Internet` on non-public ports.',
      'Create explicit deny rules with `azurerm_network_security_rule` (direction Inbound, access Deny) for management and database ports with a lower priority number (evaluated first) than any rule that allows those ports.',
      'Allow administrative access only from `<your-admin-cidr>` or via Azure Bastion, and use Azure Firewall for centralised stateful filtering where several VNets share an edge.',
    ], [AZURE.nsg, AZURE.firewall]),
    cloudflare: entry('Cloudflare Spectrum / Magic Firewall (or origin firewall rules)', [
      'Proxy public HTTP(S) hostnames through Cloudflare and publish non-HTTP TCP/UDP services through Spectrum rather than exposing origin IPs directly.',
      'If you use Magic Transit, add Cloudflare Network Firewall (formerly Magic Firewall) rules that drop traffic to ports that should not be reachable from the internet.',
      'Without Magic Transit, enforce the port allow-list in your origin cloud firewall, because the Cloudflare proxy does not filter traffic sent straight to origin IPs.',
    ], [CF.spectrum, CF.networkFirewall, CF.magicTransit]),
    akamai: entry('Prolexic Network Cloud Firewall (or Akamai Cloud Firewalls for Akamai-hosted compute)', [
      'For Prolexic Routed customers, define Network Cloud Firewall rules that drop inbound traffic to ports and protocols your services do not use.',
      'For Linodes on Akamai Cloud, attach a Cloud Firewall whose inbound policy is Drop and that accepts only the listener ports and `<your-admin-cidr>`.',
      'For origins hosted elsewhere, enforce the same port allow-list in that cloud\'s firewall, since Akamai edge delivery does not filter traffic sent straight to origin IPs.',
    ], [AK.networkCloudFirewall, AK.cloudFirewall]),
    fastly: entry('No Fastly network firewall; restrict at the origin cloud firewall', [
      'Serve public HTTP(S) traffic through Fastly and do not publish origin IPs in DNS.',
      'Apply the port allow-list in the origin\'s cloud firewall (security group, NSG or VPC firewall), accepting only the listener ports and `<your-admin-cidr>`.',
      'Remove any internet-wide allow rule on management or database ports on the origin network.',
    ], [FASTLY.publicIpList]),
    generic: entry('Stateful ingress firewall with default-deny policy', [
      'Set the ingress policy to default-deny and allow only the documented public service ports.',
      'Restrict management protocols (SSH, RDP, database ports) to `<your-admin-cidr>` or a bastion/VPN.',
      'Store firewall policy as code, review changes, and re-run external validation after every change.',
    ], [GENERIC.nistFirewall]),
  }),

  network_connection_limits: family({
    gcp: entry('No per-source connection limit in VPC firewall rules; terminate connections at a Google Cloud load balancer and cap connections at the proxy or host', [
      'Place the service behind an external Application Load Balancer so Google Front Ends terminate client connections.',
      'Cap concurrent connections per source on backend proxies or hosts (for example Envoy `max_connections` or nftables `ct count over <your-limit>`); Cloud Armor rate-based rules limit HTTP request rates, not TCP connections.',
      'For TCP/UDP passthrough services, enforce per-source connection caps on the backend (for example nftables `ct count over <your-limit>`).',
    ], [GCP.armorRateLimit, GCP.firewall]),
    aws: entry('No per-source connection limit in security groups or NACLs; terminate connections at CloudFront or a load balancer and cap connections at the proxy or host', [
      'Front HTTP services with CloudFront or an Application Load Balancer so AWS terminates client TCP connections; AWS WAF rate-based rules limit HTTP request rates, not concurrent connections.',
      'For non-HTTP services, cap concurrent connections per source on the host or proxy (for example nftables `ct count` or HAProxy `src_conn_cur`).',
      'Enable Shield Advanced on exposed Elastic IPs and load balancers if connection floods are a credible risk.',
    ], [AWS.wafRateBased, AWS.shield]),
    azure: entry('No per-source connection limit in network security groups; terminate connections at Front Door or Application Gateway and cap connections at the proxy or host', [
      'Front HTTP services with Front Door or Application Gateway so the edge terminates client TCP connections; WAF rate-limit rules limit HTTP request rates, not concurrent connections.',
      'For non-HTTP services, enforce per-source connection caps on the VM or proxy (for example nftables `ct count` or HAProxy stick tables).',
      'Enable Azure DDoS Protection on the virtual network to mitigate TCP SYN and connection floods.',
    ], [AZURE.fdRateLimit, AZURE.agRateLimit, AZURE.ddos]),
    cloudflare: entry('Cloudflare edge connection termination; network-layer connection protection via Spectrum or Magic Transit DDoS protection', [
      'Proxy HTTP(S) hostnames through Cloudflare so the edge terminates client connections.',
      'Rate limiting rules count HTTP requests, not TCP connections, so do not rely on them for connection exhaustion; keep per-source connection caps on the origin.',
      'For TCP/UDP services, publish them via Spectrum or Magic Transit and keep per-source connection caps on the origin as a backstop.',
    ], [CF.rateLimit, CF.connectionLimits, CF.spectrum]),
    akamai: entry('Akamai edge connection termination; Prolexic for network-layer connection floods', [
      'Deliver the hostname through an Akamai property so the edge terminates client connections.',
      'App & API Protector rate controls limit HTTP request rates, not concurrent connections; cap per-source connections at the origin host or proxy.',
      'For non-HTTP services, use Prolexic or cap per-source connections on the origin host.',
    ], [AK.aap, AK.prolexic]),
    fastly: entry('No Fastly per-source connection limit; the edge terminates client TCP connections, so cap connections at the origin', [
      'Serve the hostname through Fastly so the edge terminates client connections.',
      'Fastly rate limiting (VCL `ratecounter`/`penaltybox` or Next-Gen WAF rules) limits HTTP request rates, not concurrent connections; enforce per-source connection caps on the origin (for example nftables `ct count` or HAProxy stick tables).',
      'Keep per-source connection caps on the origin for any traffic that does not pass through Fastly.',
    ], [FASTLY.vclRateLimiting, FASTLY.ngwafRateLimit, FASTLY.rateLimiting]),
    generic: entry('Per-source concurrent connection limits at the edge proxy or host firewall', [
      'Cap concurrent connections per client address at the reverse proxy (for example nginx `limit_conn` with `limit_conn_zone $binary_remote_addr`).',
      'Add a host firewall limit for non-HTTP services (for example nftables `ct count over <your-limit>`).',
      'Alert when connection counts approach the limit so legitimate shared-NAT clients can be allow-listed.',
    ], [GENERIC.dosCheatSheet]),
  }),

  l3_l4_ddos_protection: family({
    gcp: entry('Cloud Armor network DDoS protection (advanced network DDoS protection with Cloud Armor Enterprise)', [
      'Front internet services with Google Cloud external load balancers, which include default network-layer DDoS protection.',
      'Enroll in Cloud Armor Enterprise, create a regional network policy (`gcloud compute security-policies create <your-policy> --type=CLOUD_ARMOR_NETWORK --region=<your-region>`), set `--network-ddos-protection=ADVANCED` and attach it through a network edge security service.',
      'Avoid exposing VMs with external IPs directly; route traffic through a protected load balancer.',
    ], [GCP.armorNetworkDdos, GCP.armorEnterprise]),
    aws: entry('AWS Shield Standard (automatic) and AWS Shield Advanced', [
      'Front services with CloudFront, Route 53, Global Accelerator or ELB, which receive Shield Standard protection automatically.',
      'Subscribe to Shield Advanced and add protections for exposed resources (`aws_shield_protection` on Elastic IPs, load balancers and distributions).',
      'Associate Shield Advanced protections with health checks so detection uses application health.',
    ], [AWS.shield, AWS.ddosWhitepaper]),
    azure: entry('Azure DDoS Network Protection or DDoS IP Protection', [
      'Create a DDoS protection plan (`azurerm_network_ddos_protection_plan`) and associate it with the virtual networks that hold public IPs.',
      'For a small number of public IPs, enable DDoS IP Protection on each public IP resource instead.',
      'Configure diagnostic logs and alerts on the `IfUnderDDoSAttack` metric for every protected public IP.',
    ], [AZURE.ddos]),
    cloudflare: entry('Cloudflare DDoS managed rulesets (HTTP and network-layer), with Spectrum or Magic Transit for non-HTTP traffic', [
      'Proxy HTTP(S) hostnames through Cloudflare so the HTTP DDoS attack protection managed ruleset applies.',
      'Publish TCP/UDP services via Spectrum, or onboard prefixes to Magic Transit, so network-layer DDoS managed rules protect them.',
      'Make sure origin IPs are not reachable directly, otherwise attackers can bypass Cloudflare.',
    ], [CF.ddos, CF.ddosBestPractices, CF.spectrum]),
    akamai: entry('Akamai Prolexic', [
      'Onboard the affected prefixes or hosts to Prolexic (Routed, Connect or IP Protect) to scrub volumetric and protocol attacks.',
      'Agree mitigation policies and always-on or on-demand mode with the Akamai SOCC, and record the activation procedure in your runbook.',
      'Restrict origin access so traffic that bypasses Prolexic or the Akamai edge is dropped.',
    ], [AK.prolexic]),
    fastly: entry('Fastly edge network and Fastly DDoS Protection cover only traffic proxied through Fastly; no scrubbing for exposed origin IPs', [
      'Serve the HTTP(S) hostname through Fastly so its edge absorbs network-layer floods.',
      'Lock the origin to Fastly IP ranges so attackers cannot target the origin IP directly.',
      'For non-HTTP services or exposed IP ranges, add a network DDoS service from your cloud provider or a scrubbing vendor.',
    ], [FASTLY.ddos, FASTLY.publicIpList]),
    generic: entry('Upstream DDoS scrubbing or always-on network DDoS protection', [
      'Place internet-facing IP space behind an always-on or on-demand scrubbing service or your ISP\'s DDoS mitigation.',
      'Document the activation procedure, contacts and expected time to mitigate.',
      'Minimise the number of directly exposed public IPs and verify origin addresses are not discoverable.',
    ], [GENERIC.cisaDdos, GENERIC.dosCheatSheet]),
  }),

  reflector_service_exposure: family({
    gcp: entry('VPC firewall rules (or hierarchical firewall policies)', [
      'Identify VMs answering on UDP reflector ports (53, 123, 161, 389, 1900, 11211) from the internet.',
      'Deny those ports from 0.0.0.0/0 with `gcloud compute firewall-rules create deny-reflectors --direction=INGRESS --action=DENY --rules=udp:53,udp:123,udp:161,udp:389,udp:1900,udp:11211 --source-ranges=0.0.0.0/0 --network=<your-network>`.',
      'Disable or bind the service to private interfaces if it does not need internet exposure.',
    ], [GCP.firewall, GCP.firewallPolicies]),
    aws: entry('Security groups and network ACLs', [
      'Remove security group rules that allow 0.0.0.0/0 to UDP reflector ports (53, 123, 161, 389, 1900, 11211).',
      'Add `aws_network_acl_rule` deny entries for those ports on public subnets as a second layer.',
      'Disable the service or bind it to private interfaces where internet exposure is not required.',
    ], [AWS.securityGroups, AWS.nacls]),
    azure: entry('Network security groups', [
      'Remove NSG rules that allow `Internet` or `Any` to UDP reflector ports (53, 123, 161, 389, 1900, 11211).',
      'Add explicit deny rules with `azurerm_network_security_rule` for those ports on the subnet and NIC NSGs.',
      'Disable the service or bind it to private interfaces where internet exposure is not required.',
    ], [AZURE.nsg]),
    cloudflare: entry('Cloudflare Network Firewall (formerly Magic Firewall) for Magic Transit prefixes; otherwise the origin cloud firewall', [
      'If the IPs are on Magic Transit, add Cloudflare Network Firewall (formerly Magic Firewall) rules that drop inbound UDP to reflector ports.',
      'Otherwise block the ports in the hosting cloud\'s firewall, because the Cloudflare proxy does not cover UDP services on origin IPs.',
      'Disable or rebind the service to private interfaces if it is not intended to be public.',
    ], [CF.networkFirewall, CF.magicTransit]),
    akamai: entry('Prolexic Network Cloud Firewall (or Akamai Cloud Firewalls for Akamai-hosted compute)', [
      'For Prolexic-protected prefixes, add Network Cloud Firewall rules that drop inbound UDP to reflector ports.',
      'For Linodes on Akamai Cloud, remove reflector ports from the Cloud Firewall inbound accept rules.',
      'Disable or rebind the service to private interfaces if it is not intended to be public.',
    ], [AK.networkCloudFirewall, AK.cloudFirewall]),
    fastly: entry('No Fastly network firewall; Fastly does not carry UDP services, so block reflector ports at the host or cloud firewall', [
      'Block UDP reflector ports (53, 123, 161, 389, 1900, 11211) in the cloud or host firewall of the exposed IP.',
      'Disable or rebind the service to private interfaces if it is not intended to be public.',
    ], [FASTLY.ddos]),
    generic: entry('Host or perimeter firewall denying UDP amplification services', [
      'Disable unused UDP services (memcached UDP, SSDP, CHARGEN, open NTP monlist, open recursive DNS).',
      'Block reflector ports from the internet at the perimeter firewall and bind needed services to private interfaces.',
      'Implement source address validation (BCP 38) on networks you operate.',
    ], [GENERIC.bcp38, GENERIC.cisaDdos]),
  }),

  waf_managed_rules: family({
    gcp: entry('Cloud Armor preconfigured WAF rules (OWASP ModSecurity CRS based)', [
      'Attach a Cloud Armor backend security policy to the external Application Load Balancer backend service.',
      'Add preconfigured rules such as `evaluatePreconfiguredWaf(\'sqli-v33-stable\', {\'sensitivity\': 1})` and `xss-v33-stable` with action `deny(403)`.',
      'Start in preview mode, review logs for false positives, then enforce.',
    ], [GCP.armorWaf, GCP.armorPolicies]),
    aws: entry('AWS WAF managed rule groups', [
      'Create an `aws_wafv2_web_acl` and associate it with the CloudFront distribution, ALB or API Gateway stage.',
      'Add `AWSManagedRulesCommonRuleSet`, `AWSManagedRulesKnownBadInputsRuleSet` and the relevant SQL database or OS rule groups as `managed_rule_group_statement` entries.',
      'Run new groups in Count mode, tune exclusions, then switch to Block.',
    ], [AWS.wafManaged, AWS.waf]),
    azure: entry('Azure WAF managed rule sets (Default Rule Set on Front Door, CRS/DRS on Application Gateway)', [
      'Create a WAF policy (`azurerm_cdn_frontdoor_firewall_policy` or `azurerm_web_application_firewall_policy`) and associate it with the Front Door endpoint or Application Gateway listener.',
      'Enable the latest Microsoft Default Rule Set (or CRS 3.2) in Prevention mode after a Detection-mode tuning period.',
      'Add exclusions only for specific fields that cause verified false positives.',
    ], [AZURE.fdDrs, AZURE.agCrs]),
    cloudflare: entry('Cloudflare Managed Ruleset and Cloudflare OWASP Core Ruleset', [
      'In Security > WAF > Managed rules, deploy the Cloudflare Managed Ruleset for the zone.',
      'Deploy the Cloudflare OWASP Core Ruleset with a paranoia level and score threshold suited to the application.',
      'Review Security Events for false positives and add targeted exceptions instead of disabling whole rulesets.',
    ], [CF.managed, CF.waf]),
    akamai: entry('App & API Protector with Adaptive Security Engine', [
      'Create or update the security configuration and add the hostname to a security policy.',
      'Enable Web Application Firewall protection with the Adaptive Security Engine in automatic mode and set attack groups to deny.',
      'Activate on staging, review alerts, then activate on production.',
    ], [AK.aap, AK.appsecTerraform]),
    fastly: entry('Fastly Next-Gen WAF system signals and templated rules', [
      'Deploy Next-Gen WAF for the service (edge integration or agent) and confirm requests are reported for the site.',
      'Set the site\'s protection mode to Blocking once attack signals have been reviewed.',
      'Enable templated rules relevant to the application and alert on attack signal thresholds.',
    ], [FASTLY.ngwaf, FASTLY.ngwafProtectionMode]),
    generic: entry('WAF with a maintained managed rule set (for example OWASP CRS)', [
      'Deploy a WAF in front of the application with a maintained rule set such as OWASP CRS on ModSecurity or Coraza.',
      'Tune in detection mode, then enable blocking with documented exclusions.',
      'Keep rule sets updated on a defined schedule.',
    ], [GENERIC.crs]),
  }),

  waf_custom_rules: family({
    gcp: entry('Cloud Armor custom rules (custom rules language)', [
      'Add a rule to the backend security policy with an expression such as `request.path.matches(\'<your-path-regex>\')` and action `deny(403)`.',
      'Manage rules in Terraform as `rule` blocks on `google_compute_security_policy` with explicit priorities.',
      'Use preview mode first and check `previewSecurityPolicy` in load balancer logs before enforcing.',
    ], [GCP.armorRulesLanguage, GCP.armorPolicies]),
    aws: entry('AWS WAF custom rules', [
      'Add a rule to the `aws_wafv2_web_acl` using `byte_match_statement`, `regex_pattern_set_reference_statement` or `ip_set_reference_statement` for the signature to block.',
      'Set a custom response code and body so blocks are distinguishable in validation evidence.',
      'Enable WAF logging and verify the rule label appears for matched requests.',
    ], [AWS.waf]),
    azure: entry('Azure WAF custom rules on Front Door or Application Gateway', [
      'Add a `custom_rule` to the WAF policy with match conditions on `RequestUri`, `RequestHeader` or `RemoteAddr` and action Block.',
      'Give custom rules priorities ahead of managed rules where they must take precedence.',
      'Confirm matches in WAF logs (`FrontDoorWebApplicationFirewallLog` or `ApplicationGatewayFirewallLog`).',
    ], [AZURE.fdCustom, AZURE.agCustom]),
    cloudflare: entry('Cloudflare WAF custom rules', [
      'In Security > WAF > Custom rules, create a rule with an expression such as `http.request.uri.path contains "<your-path>"` and action Block.',
      'Manage rules as code with the `cloudflare_ruleset` Terraform resource in the `http_request_firewall_custom` phase.',
      'Check Security Events to confirm the rule matches expected requests only.',
    ], [CF.custom, CF.rulesLanguage]),
    akamai: entry('App & API Protector custom rules', [
      'Create a custom rule in the security configuration with conditions on path, header or query values.',
      'Associate the rule with the security policy and set its action to deny.',
      'Activate on staging, verify with test requests, then activate on production.',
    ], [AK.aap, AK.appsecTerraform]),
    fastly: entry('Fastly Next-Gen WAF request rules (or VCL in vcl_recv)', [
      'Create a Next-Gen WAF request rule with conditions on path, header or IP and action Block.',
      'Alternatively add a VCL condition in `vcl_recv` that calls `error 403` for the matched signature.',
      'Verify blocked requests in Next-Gen WAF request logs or Fastly real-time logs.',
    ], [FASTLY.ngwafRules, FASTLY.vcl]),
    generic: entry('Custom WAF rules with a recognisable block response', [
      'Write custom WAF rules for application-specific abuse patterns and known-bad sources.',
      'Return a consistent block status and body so external validation can attribute blocks.',
      'Review and expire temporary rules on a schedule.',
    ], [GENERIC.crs, GENERIC.inputValidation]),
  }),

  waf_request_normalization: family({
    gcp: entry('Cloud Armor preconfigured WAF rules and rules-language decoding functions', [
      'Prefer preconfigured WAF rules, which evaluate decoded request content, over literal string custom rules.',
      'In custom rules, normalise inputs with functions such as `lower()`, `urlDecode()`, `urlDecodeUni()` and `base64Decode()` before matching.',
      'Re-test encoded variants (percent, double and Unicode encoding) after each rule change.',
    ], [GCP.armorRulesLanguage, GCP.armorWaf]),
    aws: entry('AWS WAF text transformations', [
      'Add `text_transformation` blocks such as `URL_DECODE`, `HTML_ENTITY_DECODE`, `LOWERCASE` and `COMPRESS_WHITE_SPACE` to custom match statements.',
      'Chain transformations in priority order so double-encoded payloads are decoded before matching.',
      'Keep managed rule groups enabled, as they apply their own normalisation.',
    ], [AWS.wafTransforms]),
    azure: entry('Azure WAF custom-rule transforms and managed rule set normalisation', [
      'Add transforms such as `UrlDecode`, `Lowercase`, `Trim` and `HtmlEntityDecode` to custom rule match conditions.',
      'Keep the Default Rule Set or CRS enabled, as managed rules apply their own decoding.',
      'Re-test encoded variants after each rule change.',
    ], [AZURE.fdCustom, AZURE.agCustom]),
    cloudflare: entry('Cloudflare URL normalization and rules-language transformation functions', [
      'Keep URL normalization enabled for incoming URLs (Rules > Settings > Normalization).',
      'In custom rules, wrap fields with functions such as `lower()` and `url_decode()` before comparing.',
      'Keep the Cloudflare Managed Ruleset enabled, as managed rules apply their own decoding.',
    ], [CF.normalization, CF.rulesLanguage]),
    akamai: entry('App & API Protector managed protections (built-in request decoding)', [
      'Rely on App & API Protector Web Application Firewall attack groups rather than literal-string custom rules for encoded attacks.',
      'Write custom rule conditions that cover case and encoding variants of the value being matched.',
      'Re-test encoded variants on staging before activating changes on production.',
    ], [AK.aap, AK.appsecTerraform]),
    fastly: entry('Fastly Next-Gen WAF signals, with VCL decoding functions for custom VCL rules', [
      'Rely on Next-Gen WAF attack signals for encoded payloads rather than literal-string VCL matches.',
      'In custom VCL, normalise values with `urldecode()` and `std.tolower()` before comparison.',
      'Re-test encoded variants after each rule change.',
    ], [FASTLY.ngwaf, FASTLY.vcl]),
    generic: entry('WAF input normalisation before rule evaluation', [
      'Decode URL, HTML entity and Unicode encodings and normalise case and path segments before matching.',
      'Reject requests with invalid or overlong encodings.',
      'Re-test double-encoded and mixed-case variants of blocked payloads.',
    ], [GENERIC.inputValidation, GENERIC.crs]),
  }),

  waf_body_inspection: family({
    gcp: entry('Cloud Armor preconfigured WAF rules on request bodies, with JSON parsing', [
      'Enable JSON body parsing with `gcloud compute security-policies update <your-policy> --json-parsing=STANDARD`.',
      'Confirm preconfigured WAF rules cover the content types your API accepts, and review the request body inspection limit documented for Cloud Armor.',
      'Reject bodies larger than the application needs at the backend or with a custom rule.',
    ], [GCP.armorWaf, GCP.armorPolicies]),
    aws: entry('AWS WAF body inspection size limit and oversize handling', [
      'Set the web ACL body inspection size limit (`association_config` request_body) to cover your largest legitimate request where supported.',
      'Set `oversize_handling` to `MATCH` on `body` and `json_body` match statements so uninspected content is treated as suspicious.',
      'Add a `size_constraint_statement` that blocks bodies above `<your-max-bytes>`.',
    ], [AWS.wafOversize, AWS.waf]),
    azure: entry('Azure WAF request body inspection and size limits', [
      'Enable request body inspection (`request_body_check` / `request_body_check_enabled`) on the WAF policy.',
      'On Application Gateway, set `max_request_body_size_in_kb` and `request_body_inspect_limit_in_kb` to cover legitimate payloads.',
      'Block or reject bodies above the inspected size for sensitive endpoints.',
    ], [AZURE.agSizeLimits, AZURE.waf]),
    cloudflare: entry('Cloudflare WAF body inspection (http.request.body fields)', [
      'Keep the Cloudflare Managed Ruleset enabled so request bodies are inspected up to your plan\'s limit.',
      'Create a custom rule blocking `http.request.body.truncated` on sensitive paths so content beyond the inspected size is not passed unchecked.',
      'Check Security Events for body-based matches after deployment.',
    ], [CF.rulesLanguage, CF.managed]),
    akamai: entry('App & API Protector request body inspection limit', [
      'In the security configuration advanced settings, set the request body inspection limit to cover legitimate payloads.',
      'Confirm the content types your application accepts (JSON, XML, form) are inspected by the Web Application Firewall attack groups.',
      'Reject requests whose bodies exceed what the application needs.',
    ], [AK.aap, AK.appsecTerraform]),
    fastly: entry('Fastly Next-Gen WAF request body inspection', [
      'Deploy Next-Gen WAF so request bodies for your content types are inspected.',
      'In VCL `vcl_recv`, return an error for requests whose `std.atoi(req.http.Content-Length)` exceeds `<your-max-bytes>`.',
      'Confirm body-based attack signals appear in Next-Gen WAF after deployment.',
    ], [FASTLY.ngwaf, FASTLY.vcl]),
    generic: entry('WAF request body parsing and inspection', [
      'Enable body parsing for every content type the application accepts (JSON, XML, multipart, form).',
      'Set the inspection size to cover legitimate payloads and block bodies beyond it.',
      'Re-test payloads placed in JSON and form bodies, not only query strings.',
    ], [GENERIC.crs, GENERIC.inputValidation]),
  }),

  waf_rate_limiting: family({
    gcp: entry('Cloud Armor rate-based rules (throttle / rate_based_ban)', [
      'Add a rule with action `throttle` or `rate_based_ban` to the backend security policy, keyed on `IP` or `HTTP_HEADER` (`http-header` in gcloud).',
      'In Terraform, set `rate_limit_options` on a `google_compute_security_policy` rule with `rate_limit_threshold` count `<your-requests>` per `<your-interval-sec>` seconds.',
      'Set `exceed_action = "deny(429)"` and validate in preview mode before enforcing.',
    ], [GCP.armorRateLimit, GCP.armorPolicies]),
    aws: entry('AWS WAF rate-based rules', [
      'Add a rule with a `rate_based_statement` to the `aws_wafv2_web_acl`, `aggregate_key_type = "IP"` and `limit = <your-requests-per-window>`.',
      'Scope it with a `scope_down_statement` for login, search or API paths that need stricter limits.',
      'Use action Block with a custom 429 response, and monitor the rule\'s CloudWatch metrics.',
    ], [AWS.wafRateBased]),
    azure: entry('Azure WAF rate-limit custom rules on Front Door or Application Gateway', [
      'Add a custom rule with `rule_type = "RateLimitRule"`, a threshold and a duration to the WAF policy.',
      'Group by socket address or client address and scope match conditions to the paths to protect.',
      'Set action Block and confirm blocks in WAF logs; the default block response is 403, and Front Door can return 429 if you set a custom block response status code.',
    ], [AZURE.fdRateLimit, AZURE.agRateLimit]),
    cloudflare: entry('Cloudflare rate limiting rules', [
      'In Security > WAF > Rate limiting rules, create a rule matching the hostname or path with characteristics including IP.',
      'Set requests per period, mitigation timeout and action Block or Managed Challenge.',
      'Manage as code with `cloudflare_ruleset` in the `http_ratelimit` phase.',
    ], [CF.rateLimit]),
    akamai: entry('App & API Protector rate controls', [
      'Enable rate controls in the security policy and add the rate policies relevant to the hostname.',
      'Set average and burst thresholds and the deny action for clients that exceed them.',
      'Activate on staging, validate, then activate on production.',
    ], [AK.aap, AK.appsecTerraform]),
    fastly: entry('Fastly Edge Rate Limiting (VCL ratecounter and penaltybox) or Next-Gen WAF rate limit rules', [
      'Declare a `ratecounter` and `penaltybox` and call `ratelimit.check_rate()` in `vcl_recv` with your threshold and penalty time.',
      'Or create a Next-Gen WAF site rule of type rate limit for the paths to protect.',
      'Return 429 for limited clients and log limit events.',
    ], [FASTLY.vclRateLimiting, FASTLY.ngwafRateLimit, FASTLY.rateLimiting]),
    generic: entry('Per-client HTTP rate limiting at the edge or reverse proxy', [
      'Limit requests per client at the reverse proxy (for example nginx `limit_req_zone` and `limit_req`).',
      'Apply stricter limits to login, search and expensive API paths.',
      'Return 429 Too Many Requests with `Retry-After` and alert on sustained limiting.',
    ], [GENERIC.dosCheatSheet]),
  }),

  waf_bot_management: family({
    gcp: entry('Cloud Armor bot management with reCAPTCHA Enterprise', [
      'Integrate reCAPTCHA Enterprise with the Cloud Armor security policy.',
      'Add rules using `redirect` with type `GOOGLE_RECAPTCHA` or evaluate `token.recaptcha_session.score` for sensitive paths.',
      'Combine with rate-based rules for automated clients that do not run JavaScript.',
    ], [GCP.armorBots]),
    aws: entry('AWS WAF Bot Control', [
      'Add the `AWSManagedRulesBotControlRuleSet` managed rule group to the web ACL at Common or Targeted inspection level.',
      'Use CAPTCHA or Challenge actions for suspected bots on login and checkout paths.',
      'Scope down the rule group to relevant paths to control cost.',
    ], [AWS.wafBotControl]),
    azure: entry('Azure WAF bot protection rule set', [
      'Enable the Microsoft Bot Manager rule set in the Front Door or Application Gateway WAF policy.',
      'Set actions for bad bot and unknown bot categories to Block or Log based on testing.',
      'Add rate-limit custom rules for automation that bot signatures do not catch.',
    ], [AZURE.fdBots, AZURE.agBots]),
    cloudflare: entry('Cloudflare Bot Management (or Super Bot Fight Mode) with Managed Challenge', [
      'Enable Super Bot Fight Mode or Bot Management for the zone.',
      'Create custom rules on `cf.bot_management.score` (Enterprise) to Managed Challenge or block low-score traffic on sensitive paths.',
      'Allow verified bots you depend on.',
    ], [CF.bots]),
    akamai: entry('Akamai Bot Manager', [
      'Enable Bot Manager in the security policy and review the known bot categories.',
      'Set actions per category and enable transactional endpoint protection for login and checkout.',
      'Activate on staging, validate, then activate on production.',
    ], [AK.botManager, AK.botManagerTerraform]),
    fastly: entry('Fastly Bot Management with client challenges', [
      'Enable Fastly Bot Management for the service and review the detected bot categories.',
      'Serve client challenges to suspected bots on login, signup and checkout paths, and allow verified bots you depend on.',
      'Combine with edge rate limiting for high-volume automation.',
    ], [FASTLY.botManagement, FASTLY.clientChallenges]),
    generic: entry('Bot detection with challenge and rate controls', [
      'Classify automated traffic using behavioural signals and known-bot verification.',
      'Challenge suspected automation on login, signup and checkout flows.',
      'Rate limit unauthenticated, high-cost endpoints.',
    ], [GENERIC.automatedThreats]),
  }),

  http_method_policy: family({
    gcp: entry('Cloud Armor custom rules on request.method', [
      'Add a rule with expression `!(request.method in [\'GET\', \'HEAD\', \'POST\'])` and action `deny(403)`, adjusted to the methods the service needs (Cloud Armor deny supports 403, 404 and 502; return 405 at the backend if required).',
      'Scope stricter method sets to paths that should be read-only.',
      'Validate in preview mode before enforcing.',
    ], [GCP.armorRulesLanguage, GCP.armorPolicies]),
    aws: entry('CloudFront allowed HTTP methods and AWS WAF method match rules', [
      'Set CloudFront `allowed_methods` on cache behaviours to the minimum set the path needs.',
      'Add an AWS WAF rule with `field_to_match { method {} }` that blocks unexpected methods (for example TRACE, CONNECT).',
      'Verify unsupported methods return 403 or 405 at the edge.',
    ], [AWS.waf, AWS.cloudfrontMethods]),
    azure: entry('Azure WAF custom rules on RequestMethod', [
      'Add a custom rule with match variable `RequestMethod`, operator Equal and the disallowed methods, action Block.',
      'Scope the rule to paths that should be read-only where appropriate.',
      'Verify unsupported methods are blocked in WAF logs.',
    ], [AZURE.fdCustom, AZURE.agCustom]),
    cloudflare: entry('Cloudflare WAF custom rules on http.request.method', [
      'Create a custom rule with expression `not http.request.method in {"GET" "HEAD" "POST"}` adjusted to your methods, action Block.',
      'Scope stricter rules to read-only paths.',
      'Verify with Security Events.',
    ], [CF.custom, CF.rulesLanguage]),
    akamai: entry('Property Manager allowed-method behaviors and App & API Protector custom rules', [
      'Enable only the method behaviors the property needs (Allow POST, Allow PUT, Allow DELETE, Allow PATCH, Allow OPTIONS).',
      'Add an App & API Protector custom rule denying unexpected methods on sensitive paths.',
      'Activate on staging, verify, then activate on production.',
    ], [AK.allowPost, AK.aap]),
    fastly: entry('Fastly VCL method checks in vcl_recv (or Next-Gen WAF request rules)', [
      'In `vcl_recv`, add `if (req.method !~ "^(GET|HEAD|POST)$") { error 405; }` adjusted to the methods you serve.',
      'Alternatively create a Next-Gen WAF rule that blocks unexpected methods.',
      'Verify unsupported methods are rejected at the edge.',
    ], [FASTLY.vcl, FASTLY.ngwaf]),
    generic: entry('HTTP method allow-list at the edge and application', [
      'Allow only the methods each route needs and return 405 for others.',
      'Disable TRACE and unused WebDAV methods on the web server.',
      'Re-test with unexpected methods after every routing change.',
    ], [GENERIC.httpSemantics, GENERIC.restSecurity]),
  }),

  l7_request_limits: family({
    gcp: entry('External Application Load Balancer timeouts with Cloud Armor request rules', [
      'Set the backend service timeout to the lowest value the application tolerates with `gcloud compute backend-services update <your-backend> --timeout=<your-seconds> --global`.',
      'Set the HTTP keepalive timeout on the target proxy (`--http-keep-alive-timeout-sec`) to a bounded value.',
      'Enforce maximum request body size at the backend and block oversized requests with a Cloud Armor custom rule.',
    ], [GCP.backendService, GCP.httpsLb]),
    aws: entry('ALB / CloudFront timeouts and AWS WAF size constraint rules', [
      'Set `idle_timeout` on the `aws_lb` and the CloudFront origin read and keepalive timeouts to bounded values.',
      'Add an AWS WAF `size_constraint_statement` blocking request bodies, URIs or headers larger than `<your-max-bytes>`.',
      'Return 413 or 431 at the application for oversized requests that reach it.',
    ], [AWS.alb, AWS.waf]),
    azure: entry('Front Door / Application Gateway timeouts with WAF request size limits', [
      'Set the Front Door origin response timeout or the Application Gateway backend `request_timeout` to a bounded value.',
      'Configure WAF `max_request_body_size_in_kb` and `file_upload_limit_in_mb` on Application Gateway policies.',
      'Add custom rules blocking oversized headers or URIs where needed.',
    ], [AZURE.agSizeLimits, AZURE.frontDoor]),
    cloudflare: entry('Cloudflare proxy connection limits with WAF custom rules on request size', [
      'Proxy the hostname through Cloudflare so slow clients are handled at the edge rather than at the origin.',
      'Create a custom rule blocking requests where `http.request.body.size` exceeds `<your-max-bytes>` on paths that do not accept uploads.',
      'Review the plan\'s upload size and origin timeout limits against application needs.',
    ], [CF.connectionLimits, CF.rulesLanguage]),
    akamai: entry('Property Manager Read Timeout behavior with App & API Protector custom rules', [
      'Configure the property\'s Read Timeout behavior to a bounded value for the origin.',
      'Add App & API Protector custom rules blocking oversized requests on paths that do not accept uploads.',
      'Activate on staging, verify, then activate on production.',
    ], [AK.readTimeout, AK.aap]),
    fastly: entry('Fastly backend timeouts and VCL request size checks', [
      'Set backend `connect_timeout`, `first_byte_timeout` and `between_bytes_timeout` to bounded values.',
      'In `vcl_recv`, return an error when `std.atoi(req.http.Content-Length)` exceeds `<your-max-bytes>` on paths that do not accept uploads.',
      'Verify oversized requests are rejected at the edge.',
    ], [FASTLY.hosts, FASTLY.vcl]),
    generic: entry('Request size, header size and timeout limits at the reverse proxy', [
      'Set client header and body timeouts (for example nginx `client_header_timeout`, `client_body_timeout`).',
      'Cap body and header sizes (`client_max_body_size`, `large_client_header_buffers`).',
      'Re-test slow-header and oversized-body scenarios after changes.',
    ], [GENERIC.dosCheatSheet, GENERIC.httpSemantics]),
  }),

  cache_policy: family({
    gcp: entry('Cloud CDN cache modes and cache keys', [
      'Enable Cloud CDN on the backend service and set an appropriate cache mode (`CACHE_ALL_STATIC` or `USE_ORIGIN_HEADERS`).',
      'Exclude irrelevant query parameters from the cache key (`--cache-key-query-string-whitelist`) so cache-busting strings cannot force origin fetches.',
      'Set default and maximum TTLs and enable negative caching.',
    ], [GCP.cdnCaching]),
    aws: entry('CloudFront cache policies', [
      'Attach a cache policy (`aws_cloudfront_cache_policy`) that includes only the query strings, headers and cookies the origin needs.',
      'Set minimum, default and maximum TTLs to cache static and cacheable dynamic content.',
      'Enable Origin Shield to reduce origin fetches during floods.',
    ], [AWS.cloudfrontCacheKey]),
    azure: entry('Azure Front Door caching and query string behavior', [
      'Enable caching on the Front Door route and set query string caching behavior to ignore or include only specified parameters.',
      'Use rule sets to override cache duration for cacheable paths.',
      'Enable compression and confirm cache hit ratio in Front Door metrics.',
    ], [AZURE.fdCaching]),
    cloudflare: entry('Cloudflare Cache Rules and custom cache keys', [
      'Create Cache Rules that mark cacheable paths eligible for cache with an edge TTL.',
      'Customise the cache key to ignore query strings that do not change the response.',
      'Enable Tiered Cache to reduce origin fetches.',
    ], [CF.cache, CF.cacheKeys]),
    akamai: entry('Property Manager caching and Cache ID Modification behaviors', [
      'Set Caching behavior TTLs for cacheable content in the property.',
      'Use Cache ID Modification to exclude query parameters that do not change the response.',
      'Enable tiered distribution to reduce origin load.',
    ], [AK.cacheIdModification, AK.propertyManager]),
    fastly: entry('Fastly cache configuration (TTLs and VCL cache key)', [
      'Set TTLs for cacheable content through cache settings or `beresp.ttl` in `vcl_fetch`.',
      'Normalise the cache key by stripping irrelevant query parameters in `vcl_recv` (for example with `querystring.filter_except`).',
      'Enable shielding to reduce origin fetches.',
    ], [FASTLY.cache, FASTLY.vcl]),
    generic: entry('CDN caching with normalised cache keys', [
      'Cache static and cacheable dynamic responses with explicit `Cache-Control` headers.',
      'Exclude cache-busting query parameters from the cache key.',
      'Monitor cache hit ratio and origin request rate.',
    ], [GENERIC.httpCaching]),
  }),

  tls_configuration: family({
    gcp: entry('Load balancer SSL policies', [
      'Create an SSL policy with `gcloud compute ssl-policies create <your-policy> --profile=MODERN --min-tls-version=1.2`.',
      'Attach it to the target HTTPS or SSL proxy (`--ssl-policy=<your-policy>`).',
      'Use Google-managed or Certificate Manager certificates and verify the served chain.',
    ], [GCP.sslPolicies]),
    aws: entry('CloudFront security policy and ELB TLS security policies', [
      'Set the CloudFront viewer certificate `minimum_protocol_version` to `TLSv1.2_2021` or newer.',
      'Use a current TLS 1.2/1.3 security policy (`ssl_policy`) on ALB and NLB HTTPS/TLS listeners.',
      'Manage certificates with ACM and verify renewal.',
    ], [AWS.cloudfrontTls, AWS.albListeners]),
    azure: entry('Front Door minimum TLS version and Application Gateway SSL policy', [
      'Set the minimum TLS version for Front Door custom domains to TLS 1.2.',
      'Apply a predefined or custom SSL policy with TLS 1.2 or later on Application Gateway listeners.',
      'Use managed certificates or Key Vault certificates with automated renewal.',
    ], [AZURE.fdTls, AZURE.agTls]),
    cloudflare: entry('Cloudflare edge certificates, Minimum TLS Version and TLS 1.3', [
      'Set Minimum TLS Version to 1.2 under SSL/TLS > Edge Certificates.',
      'Enable TLS 1.3 and Always Use HTTPS.',
      'Use Full (strict) encryption mode to the origin.',
    ], [CF.minTls, CF.ssl]),
    akamai: entry('Akamai Certificate Provisioning System (CPS) TLS settings', [
      'Review the enrollment\'s TLS configuration in CPS and disable protocols below TLS 1.2.',
      'Choose a current cipher profile for the enrollment.',
      'Deploy the updated enrollment and verify the served chain and protocols.',
    ], [AK.cps]),
    fastly: entry('Fastly TLS configurations', [
      'Use a Fastly TLS configuration that supports TLS 1.2 and 1.3 only for your domains.',
      'Use Fastly-managed or uploaded certificates with automated renewal.',
      'Redirect HTTP to HTTPS and verify the served chain.',
    ], [FASTLY.tls]),
    generic: entry('Modern TLS configuration (TLS 1.2+ with strong ciphers)', [
      'Disable SSLv3, TLS 1.0 and TLS 1.1 and enable TLS 1.3.',
      'Use forward-secret AEAD cipher suites and valid certificate chains.',
      'Enable HSTS once HTTPS is enforced everywhere.',
    ], [GENERIC.tlsBcp, GENERIC.nistTls, GENERIC.tlsCheatSheet]),
  }),

  http2_http3_protection: family({
    gcp: entry('Google Front End HTTP/2 and HTTP/3 handling on the external Application Load Balancer', [
      'Terminate client HTTP/2 and HTTP/3 at the external Application Load Balancer instead of exposing backends directly.',
      'Disable QUIC on the target HTTPS proxy (`--quic-override=DISABLE`) if HTTP/3 is not needed.',
      'Patch backend HTTP/2 servers (for example against CVE-2023-44487) and attach Cloud Armor rate-based rules.',
    ], [GCP.httpsLb, GCP.armorRateLimit]),
    aws: entry('CloudFront / ALB HTTP/2 termination with AWS WAF and Shield', [
      'Terminate HTTP/2 at CloudFront or an Application Load Balancer and HTTP/3 at CloudFront (ALB does not support HTTP/3) rather than at self-managed servers.',
      'Disable HTTP/3 on the distribution (`http_version`) if it is not needed.',
      'Attach AWS WAF rate-based rules and enable Shield Advanced for request-flood mitigation.',
    ], [AWS.cloudfrontHttpVersion, AWS.wafRateBased]),
    azure: entry('Front Door / Application Gateway HTTP/2 termination with WAF rate limits', [
      'Terminate HTTP/2 at Front Door or Application Gateway rather than at self-managed servers.',
      'Disable HTTP/2 on Application Gateway (`enable_http2 = false`) if not needed.',
      'Add WAF rate-limit rules to absorb request floods.',
    ], [AZURE.frontDoor, AZURE.appGateway]),
    cloudflare: entry('Cloudflare edge HTTP/2 and HTTP/3 protections with HTTP DDoS managed rules', [
      'Proxy the hostname so Cloudflare terminates client HTTP/2 and HTTP/3.',
      'Keep the HTTP DDoS attack protection managed ruleset at default or higher sensitivity.',
      'Patch any origin HTTP/2 servers reachable from Cloudflare.',
    ], [CF.ddos, CF.ddosBestPractices]),
    akamai: entry('Akamai edge HTTP/2 and HTTP/3 termination with App & API Protector', [
      'Enable HTTP/2 (and HTTP/3 if needed) in the property so the Akamai edge terminates client connections.',
      'Apply App & API Protector rate controls for request floods.',
      'Patch origin HTTP/2 servers and restrict origin access to Akamai.',
    ], [AK.http2, AK.http3, AK.aap]),
    fastly: entry('Fastly edge HTTP/2 and HTTP/3 termination', [
      'Serve the hostname through Fastly so client HTTP/2 and HTTP/3 terminate at the edge.',
      'Enable HTTP/3 only if needed (`h3.alt_svc()` in VCL).',
      'Patch origin HTTP/2 servers and restrict origin access to Fastly IP ranges.',
    ], [FASTLY.http3, FASTLY.publicIpList]),
    generic: entry('Patched HTTP/2 and HTTP/3 servers with stream and reset limits', [
      'Patch HTTP/2 servers against known stream-reset and CONTINUATION flood vulnerabilities.',
      'Limit concurrent streams per connection and close connections that exceed reset thresholds.',
      'Disable HTTP/3 where not required.',
    ], [GENERIC.http2]),
  }),

  api_surface_protection: family({
    gcp: entry('Apigee API policies (SpikeArrest, Quota) with Cloud Armor', [
      'Front APIs with Apigee and add SpikeArrest and Quota policies per API product.',
      'Validate requests against the OpenAPI specification (OASValidation policy).',
      'Attach a Cloud Armor policy to the load balancer in front of Apigee.',
    ], [GCP.apigee, GCP.armor]),
    aws: entry('API Gateway throttling and usage plans with AWS WAF', [
      'Set stage and method throttling (rate and burst) on API Gateway.',
      'Use usage plans and API keys for per-client quotas.',
      'Associate an AWS WAF web ACL with the API stage.',
    ], [AWS.apiGatewayThrottling, AWS.waf]),
    azure: entry('API Management rate-limit-by-key and quota-by-key policies with Azure WAF', [
      'Add `rate-limit-by-key` and `quota-by-key` policies keyed on subscription or client IP.',
      'Validate requests with `validate-content` against the API schema.',
      'Front API Management with Front Door or Application Gateway WAF.',
    ], [AZURE.apim, AZURE.waf]),
    cloudflare: entry('Cloudflare API Shield', [
      'Add API endpoints to Endpoint Management and enable Schema Validation with your OpenAPI file.',
      'Enable rate limiting recommendations per endpoint.',
      'Use mTLS or JWT validation for authenticated APIs.',
    ], [CF.apiShield]),
    akamai: entry('App & API Protector API definitions with Akamai API Security', [
      'Register API definitions and enable API request constraints in App & API Protector.',
      'Apply rate controls per API resource.',
      'Use Akamai API Security for API discovery and posture where licensed.',
    ], [AK.aap, AK.apiSecurity]),
    fastly: entry('Fastly API Security (API discovery and enforcement) with Next-Gen WAF rules', [
      'Enable Fastly API Discovery to inventory the API endpoints served through Fastly.',
      'Use API enforcement or Next-Gen WAF request rules to block unknown endpoints and unexpected methods on API paths.',
      'Add Next-Gen WAF rate limiting rules per client for API endpoints.',
    ], [FASTLY.apiSecurity, FASTLY.ngwafRateLimit]),
    generic: entry('API gateway schema validation, authentication and rate limits', [
      'Validate requests against the API schema and reject unknown fields.',
      'Enforce authentication and per-client quotas.',
      'Inventory API endpoints and retire unused ones.',
    ], [GENERIC.apiTop10, GENERIC.restSecurity]),
  }),

  origin_protection: family({
    gcp: entry('VPC firewall rules allowing only Google Front End and health-check ranges', [
      'Allow backend ingress only from `130.211.0.0/22` and `35.191.0.0/16` (health checks and Google Front Ends) plus your proxy-only subnet for Envoy-based regional load balancers.',
      'Remove external IPs from backend VMs and deny other ingress with `--action=DENY`.',
      'Attach a Cloud Armor backend security policy for requests that reach the load balancer.',
    ], [GCP.lbFirewall, GCP.firewall]),
    aws: entry('Security groups referencing the CloudFront origin-facing managed prefix list (or CloudFront VPC origins)', [
      'Allow origin ingress only from the `com.amazonaws.global.cloudfront.origin-facing` managed prefix list.',
      'Prefer CloudFront VPC origins for private ALBs or instances.',
      'Add a secret custom origin header and reject requests without it at the origin.',
    ], [AWS.prefixLists, AWS.cloudfrontVpcOrigins]),
    azure: entry('NSG service tag AzureFrontDoor.Backend with X-Azure-FDID check (or Private Link origins)', [
      'Allow origin ingress only from the `AzureFrontDoor.Backend` service tag.',
      'Reject requests whose `X-Azure-FDID` header does not match your Front Door profile ID.',
      'Prefer Private Link origins where supported.',
    ], [AZURE.fdOrigin, AZURE.nsg]),
    cloudflare: entry('Cloudflare Tunnel or Authenticated Origin Pulls with Cloudflare IP allow-listing', [
      'Connect the origin with Cloudflare Tunnel and close inbound ports.',
      'Otherwise allow only Cloudflare IP ranges and enable Authenticated Origin Pulls (mTLS).',
      'Rotate origin IPs that were previously exposed.',
    ], [CF.tunnel, CF.aop]),
    akamai: entry('Akamai Site Shield (or origin IP allow-listing)', [
      'Enable Site Shield and allow only Site Shield map addresses at the origin firewall.',
      'Add a shared secret header or mTLS between Akamai and the origin.',
      'Rotate origin IPs that were previously exposed.',
    ], [AK.siteShield]),
    fastly: entry('Origin allow-list of Fastly public IP ranges with shared secret header or mTLS', [
      'Allow origin ingress only from Fastly public IP ranges.',
      'Add a shared secret header in VCL and reject requests without it at the origin.',
      'Rotate origin IPs that were previously exposed.',
    ], [FASTLY.publicIpList, FASTLY.vcl]),
    generic: entry('Origin lockdown to the edge provider', [
      'Accept origin traffic only from the edge provider\'s published ranges.',
      'Authenticate the edge with mTLS or a secret header.',
      'Remove origin IPs from DNS history and rotate exposed addresses.',
    ], [GENERIC.dosCheatSheet]),
  }),

  dns_zone_transfer_restriction: family({
    gcp: entry('Cloud DNS is managed and does not serve AXFR; restrict self-managed BIND/secondary transfer ACLs', [
      'Confirm the public zone is served by Cloud DNS (`gcloud dns managed-zones describe <your-zone>`); Cloud DNS nameservers do not answer AXFR/IXFR, so no transfer setting is needed there.',
      'If a nameserver in the NS set is self-managed BIND on Compute Engine, set `allow-transfer { key <your-tsig-key>; <your-secondary-ip>; };` and `allow-transfer { none; };` for all other zones.',
      'Deny TCP 53 from 0.0.0.0/0 to that primary with a VPC firewall rule, allowing only `<your-secondary-ip>`.',
    ], [GCP.dns, GCP.dnsBestPractices]),
    aws: entry('Route 53 does not support AXFR; restrict self-managed BIND/secondary transfer ACLs', [
      'Confirm the public zone is a Route 53 hosted zone; Route 53 nameservers do not answer zone transfer requests.',
      'If a nameserver in the NS set is self-managed BIND on EC2, set `allow-transfer` to `<your-secondary-ip>` with a TSIG key and deny all other sources.',
      'Restrict TCP 53 on that instance\'s security group to `<your-secondary-ip>`.',
    ], [AWS.route53, AWS.securityGroups]),
    azure: entry('Azure DNS does not support zone transfers; restrict self-managed BIND/secondary transfer ACLs', [
      'Confirm the public zone is hosted in Azure DNS; Azure DNS nameservers do not answer zone transfer requests.',
      'If a nameserver in the NS set is self-managed BIND on a VM, set `allow-transfer` to `<your-secondary-ip>` with a TSIG key and deny all other sources.',
      'Restrict TCP 53 on that VM\'s NSG to `<your-secondary-ip>` with an `azurerm_network_security_rule`.',
    ], [AZURE.dns, AZURE.nsg]),
    cloudflare: entry('Cloudflare DNS zone transfers (outgoing transfers restricted to configured peers with TSIG)', [
      'In DNS > Settings, review zone transfer peers and remove any that are not your own secondary nameservers.',
      'Attach a TSIG key to every outgoing transfer peer so only authenticated secondaries can pull the zone.',
      'If Cloudflare is the secondary, restrict AXFR on your own primary to Cloudflare\'s documented transfer IPs with TSIG.',
    ], [CF.zoneTransfers]),
    akamai: entry('Akamai Edge DNS secondary zones (restrict your primary to Akamai zone transfer agents)', [
      'If Edge DNS is secondary for the zone, allow AXFR/IXFR on your primary only from the Akamai zone transfer agent addresses with a TSIG key.',
      'Deny zone transfers from all other sources on the primary (`allow-transfer { none; };` as the default).',
      'Do not list the hidden primary in the public NS set.',
    ], [AK.edgeDns, AK.edgeDnsTerraform]),
    fastly: entry('No Fastly authoritative DNS; restrict zone transfers at your DNS provider or self-managed nameservers', [
      'Identify which provider serves the zone\'s NS records; Fastly does not host authoritative DNS for it.',
      'On self-managed BIND, set `allow-transfer` to `<your-secondary-ip>` with TSIG and deny all other sources.',
      'Block TCP 53 to self-managed primaries from the internet except from secondaries.',
    ], [FASTLY.domains]),
    generic: entry('Zone transfer ACLs with TSIG on authoritative nameservers', [
      'Set `allow-transfer { none; };` globally and permit AXFR/IXFR only to `<your-secondary-ip>` per zone.',
      'Require TSIG (for example HMAC-SHA256) for every transfer peer.',
      'Restrict TCP 53 to secondaries at the firewall and confirm an external `dig AXFR <your-zone> @<your-nameserver>` is refused.',
    ], [GENERIC.axfr, GENERIC.nistDns]),
  }),

  dns_recursion_restriction: family({
    gcp: entry('Cloud DNS public zones are authoritative only; restrict self-managed resolvers with VPC firewall rules', [
      'Serve public zones from Cloud DNS, which answers only for its hosted zones and does not provide open recursion.',
      'For resolvers on Compute Engine, create a VPC firewall rule denying UDP/TCP 53 from 0.0.0.0/0 and allowing only `<your-internal-cidr>`.',
      'Set `recursion no;` on authoritative BIND, or `allow-recursion { <your-internal-cidr>; };` on resolvers.',
    ], [GCP.dns, GCP.firewall]),
    aws: entry('Route 53 is authoritative only and Route 53 Resolver is VPC-internal; restrict self-managed resolvers', [
      'Serve public zones from Route 53 and use Route 53 Resolver (VPC+2 address) for internal recursion.',
      'For self-managed resolvers on EC2, restrict UDP/TCP 53 in the security group to `<your-internal-cidr>`.',
      'Set `recursion no;` on authoritative BIND, or `allow-recursion { <your-internal-cidr>; };` on resolvers.',
    ], [AWS.route53, AWS.securityGroups]),
    azure: entry('Azure DNS is authoritative only; restrict self-managed resolvers with network security groups', [
      'Serve public zones from Azure DNS and use Azure-provided DNS or DNS Private Resolver for internal recursion.',
      'For self-managed resolvers on VMs, restrict UDP/TCP 53 with an NSG rule to `<your-internal-cidr>`.',
      'Set `recursion no;` on authoritative BIND, or `allow-recursion { <your-internal-cidr>; };` on resolvers.',
    ], [AZURE.dns, AZURE.nsg]),
    cloudflare: entry('Cloudflare authoritative DNS is non-recursive; restrict self-managed resolvers at the host firewall', [
      'Serve public zones from Cloudflare DNS, which answers only for zones it hosts.',
      'Disable recursion on any self-managed nameserver that is reachable from the internet.',
      'Restrict UDP/TCP 53 on internal resolvers to `<your-internal-cidr>` in the hosting firewall.',
    ], [CF.dns]),
    akamai: entry('Akamai Edge DNS is authoritative only; restrict self-managed resolvers at the host firewall', [
      'Serve public zones from Edge DNS, which answers only for zones it hosts.',
      'Disable recursion on any self-managed nameserver that is reachable from the internet.',
      'Restrict UDP/TCP 53 on internal resolvers to `<your-internal-cidr>` in the hosting firewall.',
    ], [AK.edgeDns]),
    fastly: entry('No Fastly DNS service; restrict recursion on your DNS provider or self-managed nameservers', [
      'Disable recursion on any self-managed nameserver that is reachable from the internet (`recursion no;`).',
      'Restrict UDP/TCP 53 on internal resolvers to `<your-internal-cidr>` in the cloud or host firewall.',
    ], [FASTLY.domains]),
    generic: entry('Recursion disabled on authoritative servers and resolvers restricted to internal clients', [
      'Set `recursion no;` on authoritative nameservers.',
      'Restrict resolvers with `allow-recursion { <your-internal-cidr>; };` and firewall UDP/TCP 53 to internal clients.',
      'Confirm an external recursive query (`dig +recurse example.com @<your-nameserver>`) returns REFUSED.',
    ], [GENERIC.recursionBcp, GENERIC.nistDns]),
  }),

  dns_ddos_resilience: family({
    gcp: entry('Cloud DNS (anycast managed authoritative DNS)', [
      'Move public zones from self-hosted nameservers to Cloud DNS (`google_dns_managed_zone`), which is served from Google\'s anycast network.',
      'Set TTLs of 300 seconds or more on stable records so resolver caches absorb query floods.',
      'For critical zones, add a secondary DNS provider and publish both providers\' nameservers in the NS set.',
    ], [GCP.dns, GCP.dnsBestPractices]),
    aws: entry('Route 53 with Shield Advanced protection for hosted zones', [
      'Host public zones in Route 53 (`aws_route53_zone`), which is served from AWS anycast edge locations.',
      'Add Shield Advanced protection for the hosted zone (`aws_shield_protection` with the hosted zone ARN).',
      'Set TTLs of 300 seconds or more on stable records and consider a secondary DNS provider for critical zones.',
    ], [AWS.route53, AWS.shield]),
    azure: entry('Azure DNS (anycast managed authoritative DNS)', [
      'Host public zones in Azure DNS (`azurerm_dns_zone`), which is served from Microsoft\'s anycast nameservers.',
      'Set TTLs of 300 seconds or more on stable records so resolver caches absorb query floods.',
      'For critical zones, cohost the domain with a second anycast DNS provider, keep records synchronized through the API or infrastructure as code (Azure DNS does not support zone transfers), and publish both providers\' nameservers.',
    ], [AZURE.dns]),
    cloudflare: entry('Cloudflare DNS (or DNS Firewall in front of self-managed nameservers)', [
      'Host public zones on Cloudflare DNS, or place self-managed nameservers behind Cloudflare DNS Firewall.',
      'Set TTLs of 300 seconds or more on stable records.',
      'For critical zones, configure a secondary DNS provider through zone transfers with TSIG.',
    ], [CF.dns, CF.dnsFirewall]),
    akamai: entry('Akamai Edge DNS', [
      'Host public zones on Edge DNS (primary or secondary) so queries are answered by Akamai\'s anycast nameservers.',
      'Set TTLs of 300 seconds or more on stable records.',
      'Keep the hidden primary unreachable from the internet except for Akamai transfer agents.',
    ], [AK.edgeDns, AK.edgeDnsTerraform]),
    fastly: entry('No Fastly authoritative DNS; use a DDoS-resilient managed DNS provider', [
      'Host the zone with a managed anycast authoritative DNS provider rather than a single self-managed server.',
      'Add a secondary provider for critical zones and set TTLs of 300 seconds or more on stable records.',
    ], [FASTLY.domains]),
    generic: entry('Anycast managed authoritative DNS with a secondary provider', [
      'Serve public zones from an anycast managed DNS service rather than a single self-hosted server.',
      'Add nameservers from a second provider on a separate network (RFC 2182 diversity).',
      'Set TTLs of 300 seconds or more on stable records and monitor resolution from several regions.',
    ], [GENERIC.secondaryDns, GENERIC.cisaDdos]),
  }),

  exploit_mitigation: family({
    gcp: entry('Cloud Armor preconfigured WAF rules for CVEs (cve-canary) and custom rules', [
      'Add a rule with `evaluatePreconfiguredWaf(\'cve-canary\')` and action `deny(403)` to the backend security policy.',
      'For an application-specific vulnerability, add a temporary custom rule matching the exploit path or parameter until the fix ships.',
      'Patch the vulnerable component, confirm the fix, and remove the temporary rule.',
    ], [GCP.armorWaf, GCP.armorRulesLanguage]),
    aws: entry('AWS WAF Known bad inputs managed rule group and custom rules', [
      'Add `AWSManagedRulesKnownBadInputsRuleSet` (and the relevant language or OS rule groups) to the web ACL.',
      'For an application-specific vulnerability, add a temporary custom rule matching the exploit pattern until the fix ships.',
      'Patch the vulnerable component, confirm the fix, and remove the temporary rule.',
    ], [AWS.wafManaged, AWS.waf]),
    azure: entry('Azure WAF managed rule sets and custom rules', [
      'Keep the latest Default Rule Set or CRS version enabled in Prevention mode on the WAF policy.',
      'For an application-specific vulnerability, add a temporary custom rule matching the exploit pattern until the fix ships.',
      'Patch the vulnerable component, confirm the fix, and remove the temporary rule.',
    ], [AZURE.fdDrs, AZURE.agCrs]),
    cloudflare: entry('Cloudflare Managed Ruleset (including emergency rules) and WAF custom rules', [
      'Keep the Cloudflare Managed Ruleset deployed with default actions so new emergency rules apply automatically.',
      'For an application-specific vulnerability, add a temporary WAF custom rule matching the exploit pattern until the fix ships.',
      'Patch the vulnerable component, confirm the fix, and remove the temporary rule.',
    ], [CF.managed, CF.custom]),
    akamai: entry('App & API Protector Adaptive Security Engine with automatic updates and custom rules', [
      'Enable automatic updates for the Adaptive Security Engine so new attack signatures apply without manual review.',
      'For an application-specific vulnerability, add a temporary custom rule matching the exploit pattern until the fix ships.',
      'Patch the vulnerable component, confirm the fix, and remove the temporary rule.',
    ], [AK.aap, AK.appsecTerraform]),
    fastly: entry('Fastly Next-Gen WAF virtual patches for CVEs', [
      'Enable the Next-Gen WAF virtual patches relevant to your stack and set them to block.',
      'For an application-specific vulnerability, add a temporary request rule matching the exploit pattern until the fix ships.',
      'Patch the vulnerable component, confirm the fix, and remove the temporary rule.',
    ], [FASTLY.ngwafVirtualPatches, FASTLY.ngwafRules]),
    generic: entry('WAF virtual patching tied to vulnerability management', [
      'Prioritise internet-facing vulnerabilities listed in the CISA Known Exploited Vulnerabilities catalog.',
      'Deploy a WAF virtual patch that blocks the exploit pattern until the code fix ships.',
      'Remove the virtual patch after the fix is deployed and verified.',
    ], [GENERIC.virtualPatching, GENERIC.cisaKev]),
  }),

  operations_readiness: family({
    gcp: entry('Cloud Armor Adaptive Protection alerts with Cloud Monitoring alerting policies', [
      'Enable Adaptive Protection on backend security policies (`gcloud compute security-policies update <your-policy> --enable-layer7-ddos-defense`).',
      'Create Cloud Monitoring alerting policies on load balancer request rate, 5xx rate and latency with notification channels to the on-call team.',
      'Write a DDoS runbook naming owners, escalation to Google Cloud support, and the Cloud Armor rules to tighten during an attack.',
    ], [GCP.armorAdaptive, GCP.monitoringAlerts]),
    aws: entry('Shield Advanced Shield Response Team access and proactive engagement with CloudWatch alarms', [
      'Grant the Shield Response Team access (`aws_shield_drt_access_role_arn_association`) and enable proactive engagement with emergency contacts.',
      'Create CloudWatch alarms on the `DDoSDetected` metric and on application health metrics, routed to the on-call team.',
      'Write a DDoS runbook naming owners, SRT escalation and the AWS WAF rules to tighten during an attack.',
    ], [AWS.shieldResponse, AWS.cloudwatchAlarms]),
    azure: entry('Azure DDoS Rapid Response with Azure Monitor alerts', [
      'Create Azure Monitor alerts on the `IfUnderDDoSAttack` metric for every protected public IP.',
      'Document how to open a DDoS Rapid Response support request during an active attack (requires DDoS Network Protection).',
      'Write a DDoS runbook naming owners and the WAF rules to tighten during an attack, and rehearse it.',
    ], [AZURE.ddosRapidResponse, AZURE.ddos]),
    cloudflare: entry('Cloudflare DDoS attack notifications with Security Analytics', [
      'Configure HTTP DDoS and network-layer DDoS attack alerts under Notifications, routed to the on-call team.',
      'Document how to raise DDoS managed ruleset sensitivity and enable Under Attack mode during an attack.',
      'Record Cloudflare support escalation paths in the DDoS runbook and rehearse it.',
    ], [CF.notifications, CF.ddosBestPractices]),
    akamai: entry('Akamai Prolexic SOCC runbooks with App & API Protector security alerts', [
      'Agree a DDoS runbook with the Akamai SOCC covering contacts, activation thresholds and mitigation approval.',
      'Configure security alerts for the security configuration and route them to the on-call team.',
      'Rehearse the runbook and keep SOCC contact details current.',
    ], [AK.prolexic, AK.aap]),
    fastly: entry('No Fastly operations-readiness product; build runbooks on Fastly real-time stats, logging endpoints and support escalation', [
      'Stream request logs to a logging endpoint and alert on request rate, error rate and origin latency.',
      'Document how to enable edge rate limits and Next-Gen WAF blocking rules during an attack.',
      'Record Fastly support escalation paths in the DDoS runbook and rehearse it.',
    ], [FASTLY.logging, FASTLY.ddos]),
    generic: entry('DDoS incident response plan with monitoring and escalation', [
      'Write a DDoS response runbook with roles, provider contacts, decision points and communication templates.',
      'Alert on traffic volume, error rate and latency anomalies at the edge and origin.',
      'Rehearse the runbook with tabletop exercises at least annually and after major architecture changes.',
    ], [GENERIC.nistIncident, GENERIC.cisaDdos]),
  }),

  high_scale_ddos_validation: family({
    gcp: entry('No Google Cloud DDoS simulation service; run authorized tests only through an approved vendor under Google Cloud terms', [
      'Review the Google Cloud terms of service and acceptable use policy, and contact your Google Cloud account team before any high-scale test.',
      'Run the test only through AstraNull governance: signed authorization, named vendor, scope, rate ceiling and schedule.',
      'Monitor Cloud Armor and load balancer metrics during the window and keep a kill switch with the vendor.',
    ], [GCP.armor, GCP.armorAdaptive]),
    aws: entry('AWS DDoS simulation testing policy (approved AWS Partners only)', [
      'Follow the AWS DDoS simulation testing policy, which permits tests only by approved AWS Partners.',
      'Run the test only through AstraNull governance: signed authorization, named partner, scope, rate ceiling and schedule.',
      'Monitor Shield and AWS WAF metrics during the window and keep a kill switch with the partner.',
    ], [AWS.ddosOverview, AWS.ddosSimulation, AWS.ddosWhitepaper]),
    azure: entry('Azure DDoS Protection simulation testing with approved partners', [
      'Use one of the simulation partners Microsoft lists for Azure DDoS Protection testing.',
      'Test only public IPs protected by Azure DDoS Protection, through AstraNull governance with signed authorization and schedule.',
      'Monitor DDoS protection metrics during the window and keep a kill switch with the partner.',
    ], [AZURE.ddosSimulation, AZURE.ddos]),
    cloudflare: entry('Cloudflare guidance for simulating DDoS attacks', [
      'Follow Cloudflare\'s guidance on simulating DDoS attacks, including any required notice to Cloudflare.',
      'Run the test only through AstraNull governance with signed authorization, scope, rate ceiling and schedule.',
      'Monitor Security Analytics during the window and keep a kill switch with the test vendor.',
    ], [CF.ddosSimulate]),
    akamai: entry('Akamai Prolexic coordinated validation testing', [
      'Coordinate the test window and scope with the Akamai SOCC before any high-scale traffic.',
      'Run the test only through AstraNull governance with signed authorization, scope, rate ceiling and schedule.',
      'Monitor Prolexic and App & API Protector dashboards during the window and keep a kill switch with the vendor.',
    ], [AK.prolexic]),
    fastly: entry('No Fastly DDoS test service; coordinate with Fastly support before any high-scale test', [
      'Contact Fastly support before scheduling any high-scale test against a Fastly-served hostname.',
      'Run the test only through AstraNull governance with signed authorization, scope, rate ceiling, schedule and a kill switch.',
    ], [FASTLY.ddos]),
    generic: entry('Governed, authorized high-scale DDoS validation', [
      'Obtain written authorization from the asset owner and every upstream provider (cloud, CDN, ISP).',
      'Use a governed test vendor with a defined scope, rate ceiling, schedule and abort criteria.',
      'Monitor service health throughout and keep a tested kill switch.',
    ], [GENERIC.nistTesting]),
  }),
});

export function getProviderRemediation(controlFamily, provider) {
  if (!Object.hasOwn(PROVIDER_REMEDIATION, controlFamily)) return null;
  const providers = PROVIDER_REMEDIATION[controlFamily];
  return Object.hasOwn(providers, provider) ? providers[provider] : null;
}
