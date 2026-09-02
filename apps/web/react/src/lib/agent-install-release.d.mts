export type AgentInstallRelease = {
  id: string;
  version: string;
  artifactName: string;
  digest: string;
  manifestUrl: string;
  signatureUrl: string;
  artifactUrl: string;
  signingFingerprint: string;
  createdAt: string;
};

export function resolveAgentInstallRelease(
  releases: Record<string, unknown>[],
  trustKeys: Record<string, unknown>[]
): { release: AgentInstallRelease | null; reason: string };
