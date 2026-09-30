import { randomBytes } from 'node:crypto';

const PREFIX = {
  tenant: 'ten',
  env: 'env',
  user: 'usr',
  tg: 'tg',
  target: 'tgt',
  policy: 'pol',
  run: 'run',
  event: 'evt',
  finding: 'fnd',
  report: 'rpt',
  hs: 'hsr',
  cust: 'cust',
  evidence: 'evd',
  signup: 'sgn',
  internalAudit: 'iaud',
  approval: 'appr',
  passwordInvite: 'pwi',
  dns: 'dns',
  tv: 'tv',
  loa: 'loa',
  art: 'art',
  scan: 'scan',
  step: 'step',
};

export function newId(kind) {
  const p = PREFIX[kind] ?? 'id';
  return `${p}_${randomBytes(8).toString('hex')}`;
}
