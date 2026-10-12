import { buildCheckDeliveryInventory, accountDeliveryReceipts } from './check-delivery-coverage.mjs';
import { buildPortalActionCoverage, reconcilePortalActionCoverage } from '../helpers/portal-action-coverage.mjs';
import { bindExistingBehaviorSources, reconcileExistingBehaviorCoverage } from '../helpers/existing-behavior-coverage.mjs';

/** Inventory is a requirement, not execution evidence. Only retained current-source invocations can cover it. */
export function buildExistingBehaviorCoverage({ root, files } = {}) {
  return { version: 'existing-behavior-coverage/v1', delivery: buildCheckDeliveryInventory(),
    portal: buildPortalActionCoverage(), sourceBinding: bindExistingBehaviorSources({ root, files }) };
}

export function accountExistingBehaviorCoverage(manifest, invocations) {
  return reconcileExistingBehaviorCoverage(manifest, invocations, {
    reconcilePortal: reconcilePortalActionCoverage, accountDelivery: accountDeliveryReceipts,
  });
}
