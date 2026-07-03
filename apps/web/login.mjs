import {
  fetchPortalConfig,
  loadSession,
  saveSession,
  sessionFromLoginResponse,
} from './portal-auth.mjs';

const form = document.getElementById('loginForm');
const errorEl = document.getElementById('loginError');
const introEl = document.getElementById('loginIntro');
const footnoteEl = document.getElementById('loginFootnote');
const tenantInput = document.getElementById('tenantId');
const roleSelect = document.getElementById('role');
const submitBtn = document.getElementById('loginSubmit');

function showError(message) {
  if (!errorEl) return;
  errorEl.hidden = !message;
  errorEl.textContent = message ?? '';
}

const config = await fetchPortalConfig();
const existing = loadSession();
if (existing?.access_token && existing.principal !== 'staff') {
  window.location.replace(config.portalPath);
}

if (config.authMode === 'dev-headers') {
  if (introEl) {
    introEl.textContent = 'Developer validation mode — continue with local tenant headers (no password required).';
  }
  if (footnoteEl) footnoteEl.textContent = 'Local Docker Compose uses dev-headers auth. Adjust role to preview RBAC in the portal.';
  if (roleSelect) roleSelect.disabled = false;
}

if (!config.bundledLoginEnabled && config.authMode !== 'dev-headers') {
  showError('Enterprise SSO is required for this deployment. Contact your administrator for a login link.');
  if (submitBtn) submitBtn.disabled = true;
}

async function handleLoginSubmit(event) {
  event?.preventDefault();
  showError('');

  const userId = document.getElementById('userId')?.value?.trim() ?? 'usr_admin';
  const tenantId = tenantInput?.value?.trim() ?? 'ten_demo';
  const role = roleSelect?.value ?? 'admin';

  let navigated = false;
  if (submitBtn) {
    submitBtn.disabled = true;
    submitBtn.textContent = 'Signing in…';
  }

  if (config.authMode === 'dev-headers') {
    saveSession({
      mode: 'dev-headers',
      principal: 'customer',
      tenant_id: tenantId,
      user_id: userId,
      role,
    });
    navigated = true;
    window.location.replace(config.portalPath);
    return;
  }

  try {
    const res = await fetch('/v1/auth/bundled-staging-login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', accept: 'application/json' },
      body: JSON.stringify({
        principal: 'customer',
        tenant_id: tenantId,
        user_id: userId,
        role,
      }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      showError(data.message ?? data.error ?? `Login failed (${res.status}).`);
      return;
    }
    try {
      saveSession(sessionFromLoginResponse(data));
    } catch (storageErr) {
      showError(storageErr instanceof Error ? storageErr.message : 'Could not save session in this browser.');
      return;
    }
    navigated = true;
    window.location.replace(config.portalPath);
  } catch (err) {
    showError(err instanceof Error ? err.message : 'Login failed.');
  } finally {
    if (!navigated && submitBtn) {
      submitBtn.disabled = false;
      submitBtn.textContent = 'Continue to portal';
    }
  }
}

form?.addEventListener('submit', handleLoginSubmit);
submitBtn?.addEventListener('click', (event) => {
  if (event.target?.form) return;
  handleLoginSubmit(event);
});