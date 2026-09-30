import path from 'node:path';
import {
  loadConnectorSecretEncryptionKey,
  loadSecretEncryptionKey,
} from '../../lib/secrets.mjs';
import { fileURLToPath } from 'node:url';
import { checkRoleRlsPosture, closePgPool, createPgPool, pingPostgres } from './pool.mjs';
import {
  assertLatestMigrationApplied,
  getLatestMigrationVersion,
  listMigrationFiles,
  runMigrations,
} from './migrations.mjs';
import { createCoreCatalogRepository } from './coreCatalogRepository.mjs';
import { createAuditRepository } from './auditRepository.mjs';
import { createAuthTokenRepository } from './authTokenRepository.mjs';
import { createPasswordAuthRepository } from './passwordAuthRepository.mjs';
import { createPasswordRecoveryDelivery } from './passwordRecoveryDelivery.mjs';
import { createValidationEvidenceRepository } from './validationEvidenceRepository.mjs';
import { createReportRepository } from './reportRepository.mjs';
import { createSecretVaultRepository } from './secretVaultRepository.mjs';
import { createNotificationRepository } from './notificationRepository.mjs';
import { createProbeJobRepository } from './probeJobRepository.mjs';
import { createKillSwitchRepository } from './killSwitchRepository.mjs';
import { createOwnershipVerificationRepository } from './ownershipVerificationRepository.mjs';
import {
  createPostgresDnsOwnershipServices,
  createPostgresOwnershipVerificationServices,
} from './ownershipVerificationServiceAdapters.mjs';
import { createPortalRevampRepository } from './portalRevampRepository.mjs';
import {
  createPostgresPortalRevampServices,
  mergePortalDnsOwnershipServices,
  mergePortalOwnershipVerificationServices,
} from './portalRevampServiceAdapters.mjs';
import { createHighScaleRepository } from './highScaleRepository.mjs';
import { createProductionReleaseEvidenceRepository } from './productionReleaseEvidenceRepository.mjs';
import { createRetentionRepository } from './retentionRepository.mjs';
import { createWafPostureRepository } from './wafPostureRepository.mjs';
import { createWafOffensiveRepository } from './wafOffensiveRepository.mjs';
import { createPostgresWafOffensiveServices } from './wafOffensiveServiceAdapters.mjs';
import { createWafOrchestratorRepository } from './wafOrchestratorRepository.mjs';
import { createInternalManagementRepository } from './internalManagementRepository.mjs';
import {
  createPostgresAuthServices,
  createPostgresPasswordAuthServices,
  createPostgresCatalogServices,
  createPostgresSecretVaultServices,
  createPostgresValidationServices,
  createPostgresReportServices,
  createPostgresNotificationServices,
  createPostgresStateServices,
  createPostgresProbeJobServices,
  createPostgresHighScaleServices,
  createPostgresProductionReleaseEvidenceServices,
  createPostgresRetentionServices,
  createPostgresWafPostureServices,
  createPostgresWafOrchestratorServices,
  createPostgresInternalManagementServices,
} from './serviceAdapters.mjs';
import { createPostgresTestPolicyServices } from './testPolicyServiceAdapters.mjs';
import { createPostgresTestPolicyRepository } from './testPolicyRepository.mjs';
import { createPostgresValidationScanRepository } from './validationScanRepository.mjs';
import { createPostgresValidationScanServices } from './validationScanServiceAdapters.mjs';
import { resolveProbeDispatchConfig } from '../../config.mjs';
import { createPostgresSubscriptionServices } from './subscriptionServiceAdapters.mjs';
import { createPostgresCvePipelineServices } from './cvePipelineServiceAdapters.mjs';
import { createCvePipelineRepository } from './cvePipelineRepository.mjs';
import { createPostgresExternalDiscoveryServices } from './externalDiscoveryServiceAdapters.mjs';
import { createPostgresSupplyChainRiskServices } from './supplyChainRiskServiceAdapters.mjs';
import { createPostgresActionItemServices } from './actionItemServiceAdapters.mjs';
import { createPostgresWafCoverageRollupServices } from './wafCoverageRollupServiceAdapters.mjs';
import { createPostgresWafDriftServices } from './wafDriftServiceAdapters.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, '../../..');

/** @type {readonly string[]} */
export const POSTGRES_RUNTIME_REPOSITORY_KEYS = Object.freeze([
  'coreCatalog',
  'audit',
  'authTokens',
  'passwordAuth',
  'validationEvidence',
  'reports',
  'secretVault',
  'notifications',
  'probeJobs',
  'killSwitch',
  'ownershipVerifications',
  'highScale',
  'productionReleaseEvidence',
  'retention',
  'wafPosture',
  'wafOrchestrator',
  'internalManagement',
  'portalRevamp',
  'testPolicies',
  'validationScans',
]);

/**
 * Probe dispatch config for hook-driven scan advancement in any process that builds this runtime.
 * Invalid or missing signing material fails closed: scan steps are not started until a process
 * with a validated secret advances them.
 *
 * @param {NodeJS.ProcessEnv | Record<string, string | undefined>} env
 */
export function scanRuntimeConfigFromEnv(env) {
  const resolved = resolveProbeDispatchConfig(env);
  return {
    probeMode: resolved.probeMode ?? 'signed-worker',
    probeWorkerSecret: resolved.probeWorkerSecret,
    probeConfigError: resolved.error,
  };
}

/**
 * @returns {string}
 */
export function getDefaultPostgresMigrationsDir() {
  return path.join(REPO_ROOT, 'db', 'migrations');
}

const DEFAULT_REPOSITORY_FACTORIES = {
  coreCatalog: createCoreCatalogRepository,
  audit: createAuditRepository,
  authTokens: createAuthTokenRepository,
  passwordAuth: createPasswordAuthRepository,
  validationEvidence: createValidationEvidenceRepository,
  reports: createReportRepository,
  secretVault: createSecretVaultRepository,
  notifications: createNotificationRepository,
  probeJobs: createProbeJobRepository,
  killSwitch: createKillSwitchRepository,
  ownershipVerifications: createOwnershipVerificationRepository,
  highScale: createHighScaleRepository,
  productionReleaseEvidence: createProductionReleaseEvidenceRepository,
  retention: createRetentionRepository,
  wafPosture: createWafPostureRepository,
  wafOffensive: createWafOffensiveRepository,
  wafOrchestrator: createWafOrchestratorRepository,
  internalManagement: createInternalManagementRepository,
  portalRevamp: createPortalRevampRepository,
  testPolicies: createPostgresTestPolicyRepository,
  validationScans: createPostgresValidationScanRepository,
};

/**
 * @param {NodeJS.ProcessEnv | Record<string, string | undefined>} [env]
 * @param {{
 *   autoMigrate?: boolean,
 *   migrationsDir?: string,
 *   createPool?: (env: NodeJS.ProcessEnv | Record<string, string | undefined>) => import('pg').Pool,
 *   closePool?: (pool: import('pg').Pool) => Promise<void>,
 *   ping?: (pool: import('pg').Pool) => Promise<unknown>,
 *   checkRoleRlsPosture?: typeof checkRoleRlsPosture,
 *   listMigrationFiles?: typeof listMigrationFiles,
 *   getLatestMigrationVersion?: typeof getLatestMigrationVersion,
 *   assertLatestMigrationApplied?: typeof assertLatestMigrationApplied,
 *   runMigrations?: typeof runMigrations,
 *   repositoryFactories?: Partial<typeof DEFAULT_REPOSITORY_FACTORIES>,
 *   authServiceOptions?: Parameters<typeof createPostgresAuthServices>[1],
 *   wafPostureServiceOptions?: Record<string, unknown>,
 *   wafDriftServiceOptions?: Record<string, unknown>,
 * }} [options]
 */
export async function createPostgresRuntime(env = process.env, options = {}) {
  const migrationsDir = options.migrationsDir ?? getDefaultPostgresMigrationsDir();
  const createPoolFn = options.createPool ?? createPgPool;
  const closePoolFn = options.closePool ?? closePgPool;
  const pingFn = options.ping ?? pingPostgres;
  const checkRoleRlsPostureFn = options.checkRoleRlsPosture ?? checkRoleRlsPosture;
  const listFilesFn = options.listMigrationFiles ?? listMigrationFiles;
  const latestVersionFn = options.getLatestMigrationVersion ?? getLatestMigrationVersion;
  const assertLatestFn = options.assertLatestMigrationApplied ?? assertLatestMigrationApplied;
  const runMigrationsFn = options.runMigrations ?? runMigrations;
  const repositoryFactories = { ...DEFAULT_REPOSITORY_FACTORIES, ...options.repositoryFactories };

  const autoMigrate =
    options.autoMigrate === true || String(env.ASTRANULL_POSTGRES_AUTO_MIGRATE ?? '').trim() === '1';

  /** @type {import('pg').Pool | undefined} */
  let pool;
  let closed = false;
  /** @type {{ close?: () => Promise<void> } | undefined} */
  let validationScansRepo;

  const close = async () => {
    if (closed) {
      return;
    }
    closed = true;
    if (validationScansRepo?.close) {
      try {
        await validationScansRepo.close();
      } catch {
        // best-effort: never let lock-pool teardown block the main pool close
      }
    }
    if (pool) {
      await closePoolFn(pool);
    }
  };

  try {
    pool = createPoolFn(env);
    const files = listFilesFn(migrationsDir);
    const latestMigration = latestVersionFn(files);

    await pingFn(pool);

    if (String(env.ASTRANULL_ENFORCE_DATABASE_ROLE ?? '').trim() === '1') {
      const posture = await checkRoleRlsPostureFn(pool);
      if (posture.bypassesRls !== false || posture.ownsTables !== false) {
        throw new Error(
          `Refusing to start: PostgreSQL runtime role ${posture.role ?? 'unknown'} must be a non-owner NOSUPERUSER NOBYPASSRLS role.`,
        );
      }
    }

    if (autoMigrate) {
      await runMigrationsFn(pool, { migrationsDir, files });
    }

    await assertLatestFn(pool, latestMigration);

    /** @type {Record<string, unknown>} */
    const repositories = {};
    const auditRepository = repositoryFactories.audit(pool);
    for (const key of POSTGRES_RUNTIME_REPOSITORY_KEYS) {
      const factory = repositoryFactories[key];
      if (!factory) {
        throw new Error(`Missing repository factory for "${key}".`);
      }
      if (key === 'audit') repositories[key] = auditRepository;
      else if (['coreCatalog', 'testPolicies', 'wafPosture', 'validationScans'].includes(key)) {
        repositories[key] = factory(pool, { auditRepository });
      } else repositories[key] = factory(pool);
    }
    validationScansRepo = repositories.validationScans;

    // Kept outside POSTGRES_RUNTIME_REPOSITORY_KEYS so that stable repository facade
    // remains backward compatible while the production service gains its private ledger.
    const wafOffensiveRepository = repositoryFactories.wafOffensive(pool);
    const testPolicyRepository = repositories.testPolicies;

    const retentionServices = createPostgresRetentionServices(repositories);
    const catalogServices = createPostgresCatalogServices(repositories);
    const authServices = createPostgresAuthServices(repositories, options.authServiceOptions);
    const passwordAuthServices = createPostgresPasswordAuthServices(repositories);
    const validationServices = createPostgresValidationServices(repositories);
    const validationScanServices = createPostgresValidationScanServices(
      {
        validationScans: repositories.validationScans,
        validationEvidence: repositories.validationEvidence,
        coreCatalog: repositories.coreCatalog,
        audit: repositories.audit,
        killSwitch: repositories.killSwitch,
        internalManagement: repositories.internalManagement,
      },
      {
        testRuns: validationServices.testRuns,
        runtimeConfig: options.validationScanRuntimeConfig ?? scanRuntimeConfigFromEnv(env),
      },
    );
    const secretVault = createPostgresSecretVaultServices(repositories, {
      encryptionKey: loadSecretEncryptionKey(env),
      connectorEncryptionKey: loadConnectorSecretEncryptionKey(env),
    });
    const reportServices = createPostgresReportServices(repositories);
    const notificationServices = createPostgresNotificationServices(repositories);
    const stateServices = createPostgresStateServices(repositories);
    const ownershipVerificationBase = createPostgresOwnershipVerificationServices({
      repositories,
      probeJobs: repositories.probeJobs,
      audit: repositories.audit,
    });
    const probeJobServices = createPostgresProbeJobServices(repositories, {
      ownershipVerification: ownershipVerificationBase,
    });
    const highScaleServices = createPostgresHighScaleServices(repositories, {
      notifications: notificationServices,
      onRunTerminal: validationServices.testRuns.notifyRunTerminal,
    });
    const productionReleaseEvidenceServices =
      createPostgresProductionReleaseEvidenceServices(repositories);
    const cvePipelineRepository = createCvePipelineRepository(pool);
    const repositoriesWithCve = {
      ...repositories,
      cvePipeline: cvePipelineRepository,
      wafOffensive: wafOffensiveRepository,
    };
    const wafPostureServices = createPostgresWafPostureServices(repositoriesWithCve, {
      ...(options.wafPostureServiceOptions ?? {}),
      env,
      connectorJobPrivateKey: env.ASTRANULL_CONNECTOR_JOB_PRIVATE_KEY,
      connectorJobPublicKey: env.ASTRANULL_CONNECTOR_JOB_PUBLIC_KEY,
      requireConnectorJobSigner:
        options.wafPostureServiceOptions?.requireConnectorJobSigner === true,
      requireConnectorJobVerifier:
        options.wafPostureServiceOptions?.requireConnectorJobVerifier === true,
    });
    const wafOffensiveServices = createPostgresWafOffensiveServices(
      repositoriesWithCve,
      { wafPostureServices },
    );
    const wafOrchestratorServices = createPostgresWafOrchestratorServices(repositories, {
      ...(options.wafOrchestratorServiceOptions ?? {}),
      testRuns: validationServices.testRuns,
    });
    const cvePipelineServices = createPostgresCvePipelineServices(pool, {
      repositories: {
        cvePipeline: cvePipelineRepository,
        wafPosture: repositories.wafPosture,
        audit: repositories.audit,
        actionItems: repositories.actionItems,
      },
    });
    const externalDiscoveryServices = createPostgresExternalDiscoveryServices(repositories, { pool });
    const supplyChainRiskServices = createPostgresSupplyChainRiskServices(pool);
    const actionItemServices = createPostgresActionItemServices(pool, {
      portalRevamp: repositories.portalRevamp,
    });
    const wafDriftServices = createPostgresWafDriftServices(
      repositories,
      options.wafDriftServiceOptions,
    );
    const wafCoverageRollupServices = createPostgresWafCoverageRollupServices(repositories);
    const internalManagementServices = createPostgresInternalManagementServices(repositories);
    const subscriptionServices = createPostgresSubscriptionServices(repositories);
    const testPolicyServices = createPostgresTestPolicyServices({
      testPolicies: testPolicyRepository,
      coreCatalog: repositories.coreCatalog,
      audit: repositories.audit,
    });
    const dnsOwnershipBase = createPostgresDnsOwnershipServices({
      repositories,
      audit: repositories.audit,
    });
    const portalRevampServices = createPostgresPortalRevampServices({ repositories });
    const ownershipVerification = mergePortalOwnershipVerificationServices(
      ownershipVerificationBase,
      portalRevampServices.portalOwnership,
    );
    const dnsOwnership = mergePortalDnsOwnershipServices(
      dnsOwnershipBase,
      portalRevampServices.portalDns,
    );
    const services = {
      ...catalogServices,
      ...authServices,
      passwordAuth: passwordAuthServices,
      passwordRecoveryDelivery: createPasswordRecoveryDelivery(pool, {
        env,
        ...(options.passwordRecoveryDeliveryOptions ?? {}),
      }),
      ...validationServices,
      ...reportServices,
      secretVault,
      notifications: notificationServices,
      state: stateServices,
      probeJobs: probeJobServices,
      highScale: highScaleServices,
      testPolicies: {
        ...testPolicyServices,
        dispatchDueTestPolicies: (ctx, dispatchOptions = {}) =>
          testPolicyServices.dispatchDueTestPolicies(ctx, {
            ...dispatchOptions,
            startTestRun: validationServices.testRuns.startTestRun,
          }),
      },
      subscriptions: subscriptionServices,
      validationScans: validationScanServices,
      productionReleaseEvidence: productionReleaseEvidenceServices,
      retention: retentionServices,
      wafPosture: {
        ...wafPostureServices,
        getCoverageSummary: portalRevampServices.portalWaf.getCoverageSummary.bind(
          portalRevampServices.portalWaf,
        ),
        getConnectorInventory: portalRevampServices.portalWaf.getConnectorInventory.bind(
          portalRevampServices.portalWaf,
        ),
      },
      wafDrift: wafDriftServices,
      wafCoverageRollup: wafCoverageRollupServices,
      wafOffensive: wafOffensiveServices,
      wafOrchestrator: wafOrchestratorServices,
      cvePipeline: cvePipelineServices,
      externalDiscovery: externalDiscoveryServices,
      supplyChainRisk: supplyChainRiskServices,
      actionItems: actionItemServices,
      internalManagement: internalManagementServices,
      signupIntake: {
        ...internalManagementServices,
        listEvents: portalRevampServices.portalSignup.listEvents.bind(
          portalRevampServices.portalSignup,
        ),
      },
      ownershipVerification,
      dnsOwnership,
      loa: portalRevampServices.loa,
      targetDetail: portalRevampServices.targetDetail,
      remediation: portalRevampServices.remediation,
      findings: {
        ...validationServices.findings,
        getEvidenceBundle: portalRevampServices.portalFindings.getEvidenceBundle.bind(
          portalRevampServices.portalFindings,
        ),
      },
      targetGroups: {
        ...catalogServices.targetGroups,
        restoreArchived: portalRevampServices.portalTargetGroups.restoreArchived.bind(
          portalRevampServices.portalTargetGroups,
        ),
        bulkImportTargets: portalRevampServices.portalTargetGroups.bulkImportTargets.bind(
          portalRevampServices.portalTargetGroups,
        ),
      },
      audit: repositories.audit,
    };

    const health = async () => {
      await pingFn(pool);
      await assertLatestFn(pool, latestMigration);
      return { ok: true, persistence: 'postgres', latestMigration };
    };

    return {
      pool,
      migrationsDir,
      latestMigration,
      repositories,
      services,
      health,
      close,
    };
  } catch (initErr) {
    try {
      await close();
    } catch (cleanupErr) {
      if (initErr && typeof initErr === 'object' && cleanupErr !== initErr) {
        initErr.cleanup_error = cleanupErr;
      }
    }
    throw initErr;
  }
}
