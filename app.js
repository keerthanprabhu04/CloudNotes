/**
 * CloudNotes — Frontend AWS Integration & Application Controller
 *
 * Connects directly to:
 *   1. Amazon Cognito User Pool Public JSON-RPC API (SignUp, ConfirmSignUp, InitiateAuth, GlobalSignOut)
 *   2. Amazon API Gateway HTTP API (Bearer JWT authorized REST endpoints)
 *   3. Private Amazon S3 Bucket (Presigned POST upload & Presigned GET download)
 *
 * Security notes:
 *   - No AWS Access Keys or Secret Keys are stored or used in frontend code.
 *   - Tokens are kept in sessionStorage and never persisted with user passwords.
 */

const CONFIG_STORAGE_KEY = 'cloudnotes_aws_config';
const SESSION_STORAGE_KEY = 'cloudnotes_cognito_session';
const MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024; // 10 MB

const ALLOWED_EXTENSIONS = new Set(['pdf', 'doc', 'docx', 'txt', 'png', 'jpg', 'jpeg']);
const EXTENSION_MIME_MAP = {
  pdf: 'application/pdf',
  doc: 'application/msword',
  docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  txt: 'text/plain',
  png: 'image/png',
  jpg: 'image/jpeg',
  jpeg: 'image/jpeg',
};

/* --------------------------------------------------------------------------
 * Configuration & Session Storage Helpers
 * -------------------------------------------------------------------------- */

function getAwsConfig() {
  const defaults = window.CLOUDNOTES_CONFIG || {};
  let stored = {};
  try {
    stored = JSON.parse(localStorage.getItem(CONFIG_STORAGE_KEY) || '{}');
  } catch {
    stored = {};
  }

  return {
    region: (stored.region || defaults.AWS_REGION || '').trim(),
    userPoolId: (stored.userPoolId || defaults.COGNITO_USER_POOL_ID || '').trim(),
    clientId: (stored.clientId || defaults.COGNITO_APP_CLIENT_ID || '').trim(),
    apiBaseUrl: (stored.apiBaseUrl || defaults.API_BASE_URL || '').trim().replace(/\/+$/, ''),
  };
}

function saveAwsConfig(cfg) {
  localStorage.setItem(
    CONFIG_STORAGE_KEY,
    JSON.stringify({
      region: (cfg.region || '').trim(),
      userPoolId: (cfg.userPoolId || '').trim(),
      clientId: (cfg.clientId || '').trim(),
      apiBaseUrl: (cfg.apiBaseUrl || '').trim().replace(/\/+$/, ''),
    })
  );
}

function isAwsConfigured(cfg = getAwsConfig()) {
  return Boolean(cfg.region && cfg.userPoolId && cfg.clientId && cfg.apiBaseUrl);
}

function getSession() {
  try {
    const raw = sessionStorage.getItem(SESSION_STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (!parsed || !parsed.idToken) return null;
    const claims = decodeJwtPayload(parsed.idToken);
    if (!claims || (claims.exp && claims.exp * 1000 <= Date.now())) {
      return null;
    }
    return { ...parsed, claims };
  } catch {
    return null;
  }
}

function saveSession(tokens) {
  sessionStorage.setItem(SESSION_STORAGE_KEY, JSON.stringify(tokens));
}

function clearSession() {
  sessionStorage.removeItem(SESSION_STORAGE_KEY);
}

async function refreshCognitoSession() {
  try {
    const raw = sessionStorage.getItem(SESSION_STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (!parsed || !parsed.refreshToken) return null;
    const cfg = getAwsConfig();
    if (!cfg.region || !cfg.clientId) return null;
    const res = await cognitoRequest('InitiateAuth', {
      AuthFlow: 'REFRESH_TOKEN_AUTH',
      ClientId: cfg.clientId,
      AuthParameters: { REFRESH_TOKEN: parsed.refreshToken },
    });
    const auth = res.AuthenticationResult;
    if (!auth || !auth.IdToken || !auth.AccessToken) return null;
    saveSession({
      idToken: auth.IdToken,
      accessToken: auth.AccessToken,
      refreshToken: auth.RefreshToken || parsed.refreshToken,
    });
    return getSession();
  } catch {
    return null;
  }
}

async function ensureFreshSession() {
  const active = getSession();
  if (active) {
    const expiresSoon = active.claims.exp && active.claims.exp * 1000 - Date.now() < 60000;
    if (!expiresSoon) return active;
  }
  return refreshCognitoSession();
}

function decodeJwtPayload(token) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const base64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    const json = decodeURIComponent(
      atob(base64)
        .split('')
        .map((c) => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
        .join('')
    );
    return JSON.parse(json);
  } catch {
    return null;
  }
}

/* --------------------------------------------------------------------------
 * Amazon Cognito Identity Provider HTTP Client (No IAM Credentials Required)
 * -------------------------------------------------------------------------- */

async function cognitoRequest(action, payload) {
  const cfg = getAwsConfig();
  if (!cfg.region || !cfg.clientId) {
    throw new Error(
      'AWS Cognito is not configured yet. Open AWS Setup to enter your Region, User Pool ID, App Client ID, and API Base URL.'
    );
  }

  const endpoint = `https://cognito-idp.${cfg.region}.amazonaws.com/`;
  const response = await fetch(endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-amz-json-1.1',
      'X-Amz-Target': `AWSCognitoIdentityProviderService.${action}`,
    },
    body: JSON.stringify(payload),
  });

  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const rawMsg = data.message || data.Message || `Cognito error (${response.status})`;
    if (rawMsg.includes('SECRET_HASH')) {
      throw new Error(
        'This Cognito App Client has a Client Secret enabled, which browser apps cannot use securely. Create a Single-page application (SPA) App Client without a client secret and enable ALLOW_USER_PASSWORD_AUTH, then update your App Client ID in AWS Setup.'
      );
    }
    if (rawMsg.includes('USER_PASSWORD_AUTH')) {
      throw new Error(
        'ALLOW_USER_PASSWORD_AUTH is not enabled on this Cognito App Client. Enable it in your Cognito App Client authentication flows.'
      );
    }
    throw new Error(rawMsg);
  }
  return data;
}

async function cognitoSignUp(name, email, password, phoneNumber = '') {
  const cfg = getAwsConfig();
  const userAttributes = [
    { Name: 'email', Value: email },
    { Name: 'name', Value: name },
  ];
  const cleanPhone = String(phoneNumber || '').replace(/[\s()-]/g, '').trim();
  if (cleanPhone) {
    if (!/^\+[1-9]\d{6,14}$/.test(cleanPhone)) {
      throw new Error('Phone number must use E.164 format with country code (e.g. +919876543210).');
    }
    userAttributes.push({ Name: 'phone_number', Value: cleanPhone });
  }
  return cognitoRequest('SignUp', {
    ClientId: cfg.clientId,
    Username: email,
    Password: password,
    UserAttributes: userAttributes,
  });
}

async function cognitoConfirmSignUp(email, code) {
  const cfg = getAwsConfig();
  return cognitoRequest('ConfirmSignUp', {
    ClientId: cfg.clientId,
    Username: email,
    ConfirmationCode: code,
  });
}

async function cognitoResendCode(email) {
  const cfg = getAwsConfig();
  return cognitoRequest('ResendConfirmationCode', {
    ClientId: cfg.clientId,
    Username: email,
  });
}

async function cognitoLogin(email, password) {
  const cfg = getAwsConfig();
  const res = await cognitoRequest('InitiateAuth', {
    AuthFlow: 'USER_PASSWORD_AUTH',
    ClientId: cfg.clientId,
    AuthParameters: {
      USERNAME: email,
      PASSWORD: password,
    },
  });

  const authResult = res.AuthenticationResult;
  if (!authResult || !authResult.IdToken) {
    throw new Error('Unexpected Cognito authentication response.');
  }

  saveSession({
    idToken: authResult.IdToken,
    accessToken: authResult.AccessToken,
    refreshToken: authResult.RefreshToken,
  });
  return getSession();
}

async function cognitoLogout() {
  const session = getSession();
  if (session && session.accessToken) {
    try {
      await cognitoRequest('GlobalSignOut', {
        AccessToken: session.accessToken,
      });
    } catch {
      // Clear local session regardless of remote signout response
    }
  }
  clearSession();
}

/* --------------------------------------------------------------------------
 * CloudNotes REST API Client (API Gateway + Lambda + S3 Presigned POST/GET)
 * -------------------------------------------------------------------------- */

async function apiRequest(path, options = {}, hasRetried = false) {
  const cfg = getAwsConfig();
  if (!isAwsConfigured(cfg)) {
    throw new Error('AWS API Gateway URL is not configured. Open Settings to configure your deployed stack.');
  }
  const session = await ensureFreshSession();
  if (!session) {
    clearSession();
    window.location.href = 'login.html';
    throw new Error('Your Cognito session expired. Please sign in again.');
  }

  const response = await fetch(`${cfg.apiBaseUrl}${path}`, {
    ...options,
    headers: {
      Authorization: `Bearer ${session.idToken}`,
      'Content-Type': 'application/json',
      ...(options.headers || {}),
    },
  });

  if (response.status === 401 && !hasRetried) {
    const refreshed = await refreshCognitoSession();
    if (refreshed) {
      return apiRequest(path, options, true);
    }
  }

  const rawText = await response.text();
  let parsed = {};
  if (rawText) {
    try {
      parsed = JSON.parse(rawText);
    } catch {
      parsed = rawText;
    }
  }

  if (
    parsed &&
    typeof parsed === 'object' &&
    typeof parsed.statusCode === 'number' &&
    'body' in parsed
  ) {
    let inner = parsed.body;
    if (typeof inner === 'string') {
      try {
        inner = JSON.parse(inner);
      } catch {
        inner = { message: inner };
      }
    }
    if (parsed.statusCode === 401) {
      const detail = (inner && inner.error && inner.error.message) || (inner && inner.message) || '';
      throw new Error(`API returned 401 Unauthorized${detail ? ` (${detail})` : ''}. Check CognitoJwtAuthorizer Issuer URL and Audience.`);
    }
    if (parsed.statusCode >= 400) {
      const msg = (inner && inner.error && inner.error.message) || (inner && inner.message) || `Lambda returned HTTP ${parsed.statusCode}`;
      throw new Error(msg);
    }
    return inner;
  }

  const data = parsed && typeof parsed === 'object' ? parsed : {};
  if (response.status === 401) {
    const detail = (data.error && data.error.message) || data.message || '';
    throw new Error(`API Gateway returned 401 Unauthorized${detail ? ` (${detail})` : ''}. Check CognitoJwtAuthorizer Issuer URL and Audience, or sign out and sign in again.`);
  }
  if (!response.ok) {
    const msg =
      (data.error && data.error.message) ||
      data.message ||
      (typeof parsed === 'string' && parsed ? parsed : '') ||
      `API request failed (${response.status})`;
    throw new Error(msg);
  }
  return parsed;
}

function uploadFileToS3PresignedPost(presignResponse, file, onProgress) {
  return new Promise((resolve, reject) => {
    const postPayload = presignResponse && presignResponse.upload;
    const putUrl =
      (presignResponse && presignResponse.upload_url) ||
      (presignResponse && presignResponse.presigned_url) ||
      (presignResponse && typeof presignResponse.url === 'string' ? presignResponse.url : '');

    if (postPayload && postPayload.url && postPayload.fields && typeof postPayload.fields === 'object') {
      const formData = new FormData();
      Object.entries(postPayload.fields).forEach(([key, value]) => {
        formData.append(key, value);
      });
      // File must be appended last for S3 POST policies
      formData.append('file', file);

      const xhr = new XMLHttpRequest();
      xhr.open('POST', postPayload.url, true);

      xhr.upload.onprogress = (event) => {
        if (event.lengthComputable && typeof onProgress === 'function') {
          onProgress(Math.round((event.loaded / event.total) * 100));
        }
      };

      xhr.onload = () => {
        if (xhr.status >= 200 && xhr.status < 300) {
          resolve();
        } else {
          reject(new Error(`S3 upload failed with HTTP ${xhr.status}`));
        }
      };

      xhr.onerror = () => {
        reject(new Error('Network error while uploading directly to Amazon S3. Check S3 CORS configuration.'));
      };

      xhr.send(formData);
      return;
    }

    if (putUrl) {
      const ext = (file.name.split('.').pop() || '').toLowerCase();
      const contentType = file.type || EXTENSION_MIME_MAP[ext] || 'application/octet-stream';
      const xhr = new XMLHttpRequest();
      xhr.open('PUT', putUrl, true);
      xhr.setRequestHeader('Content-Type', contentType);
      xhr.upload.onprogress = (event) => {
        if (event.lengthComputable && typeof onProgress === 'function') {
          onProgress(Math.round((event.loaded / event.total) * 100));
        }
      };
      xhr.onload = () => {
        if (xhr.status >= 200 && xhr.status < 300) {
          resolve();
        } else {
          reject(new Error(`S3 upload failed with HTTP ${xhr.status}`));
        }
      };
      xhr.onerror = () => {
        reject(new Error('Network error while uploading directly to Amazon S3. Check S3 CORS configuration.'));
      };
      xhr.send(file);
      return;
    }

    const preview =
      typeof presignResponse === 'string'
        ? presignResponse
        : JSON.stringify(presignResponse || {}).slice(0, 180);
    reject(
      new Error(
        `Invalid response from POST /documents/upload-url: missing presigned S3 upload URL/fields (received ${preview}). Deploy CloudNotes/backend/app.py and CloudNotes/backend/utils/ to your AWS Lambda function.`
      )
    );
  });
}

/* --------------------------------------------------------------------------
 * Formatting & UI Helpers
 * -------------------------------------------------------------------------- */

function formatBytes(bytes) {
  const num = Number(bytes) || 0;
  if (num === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  const idx = Math.min(Math.floor(Math.log(num) / Math.log(1024)), units.length - 1);
  const value = num / Math.pow(1024, idx);
  return `${value >= 10 || idx === 0 ? value.toFixed(0) : value.toFixed(1)} ${units[idx]}`;
}

function formatDate(isoString) {
  if (!isoString) return '—';
  const d = new Date(isoString);
  if (Number.isNaN(d.getTime())) return isoString;
  return d.toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  });
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function showToast(message, type = 'info') {
  let stack = document.getElementById('toast-stack');
  if (!stack) {
    stack = document.createElement('div');
    stack.id = 'toast-stack';
    stack.className = 'toast-stack';
    document.body.appendChild(stack);
  }
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.textContent = message;
  stack.appendChild(el);
  setTimeout(() => {
    el.remove();
  }, 4200);
}

/* --------------------------------------------------------------------------
 * Page Initializers
 * -------------------------------------------------------------------------- */

document.addEventListener('DOMContentLoaded', () => {
  const page = document.body.dataset.page;
  if (page === 'landing') initLandingPage();
  if (page === 'login') initLoginPage();
  if (page === 'register') initRegisterPage();
  if (page === 'dashboard') initDashboardPage();
});

function initLandingPage() {
  const session = getSession();
  const primaryBtn = document.getElementById('landing-primary-cta');
  if (session && primaryBtn) {
    primaryBtn.textContent = 'Open Dashboard';
    primaryBtn.href = 'dashboard.html';
  }
}

function bindAwsSetupModal() {
  const modal = document.getElementById('aws-config-modal');
  const openBtn = document.getElementById('open-aws-config');
  const closeBtn = document.getElementById('close-aws-config');
  const form = document.getElementById('aws-config-form');
  if (!modal || !form) return;

  const populate = () => {
    const cfg = getAwsConfig();
    document.getElementById('cfg-region').value = cfg.region;
    document.getElementById('cfg-pool-id').value = cfg.userPoolId;
    document.getElementById('cfg-client-id').value = cfg.clientId;
    document.getElementById('cfg-api-url').value = cfg.apiBaseUrl;
  };

  if (openBtn) {
    openBtn.addEventListener('click', () => {
      populate();
      modal.classList.remove('hidden');
    });
  }
  if (closeBtn) {
    closeBtn.addEventListener('click', () => modal.classList.add('hidden'));
  }

  form.addEventListener('submit', (e) => {
    e.preventDefault();
    saveAwsConfig({
      region: document.getElementById('cfg-region').value,
      userPoolId: document.getElementById('cfg-pool-id').value,
      clientId: document.getElementById('cfg-client-id').value,
      apiBaseUrl: document.getElementById('cfg-api-url').value,
    });
    modal.classList.add('hidden');
    showToast('AWS stack endpoints saved.', 'success');
    window.location.reload();
  });
}

function initLoginPage() {
  if (getSession()) {
    window.location.href = 'dashboard.html';
    return;
  }
  bindAwsSetupModal();

  const banner = document.getElementById('aws-setup-banner');
  if (banner && !isAwsConfigured()) {
    banner.classList.remove('hidden');
  }

  const form = document.getElementById('login-form');
  const errorBox = document.getElementById('login-error');
  const submitBtn = document.getElementById('login-submit');

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    errorBox.classList.add('hidden');

    if (!isAwsConfigured()) {
      errorBox.textContent = 'Please configure your deployed AWS Cognito and API Gateway endpoints first using "Configure AWS Stack".';
      errorBox.classList.remove('hidden');
      return;
    }

    const email = document.getElementById('login-email').value.trim();
    const password = document.getElementById('login-password').value;

    submitBtn.disabled = true;
    submitBtn.textContent = 'Signing in...';

    try {
      await cognitoLogin(email, password);
      window.location.href = 'dashboard.html';
    } catch (err) {
      errorBox.textContent = err.message || 'Unable to sign in.';
      errorBox.classList.remove('hidden');
    } finally {
      submitBtn.disabled = false;
      submitBtn.textContent = 'Sign in';
    }
  });
}

function initRegisterPage() {
  if (getSession()) {
    window.location.href = 'dashboard.html';
    return;
  }
  bindAwsSetupModal();

  const banner = document.getElementById('aws-setup-banner');
  if (banner && !isAwsConfigured()) {
    banner.classList.remove('hidden');
  }

  const registerForm = document.getElementById('register-form');
  const verifyForm = document.getElementById('verify-form');
  const errorBox = document.getElementById('register-error');
  const successBox = document.getElementById('register-success');
  const resendBtn = document.getElementById('resend-code-btn');

  let pendingEmail = '';

  registerForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    errorBox.classList.add('hidden');
    successBox.classList.add('hidden');

    if (!isAwsConfigured()) {
      errorBox.textContent = 'Please configure your deployed AWS Cognito and API Gateway endpoints first.';
      errorBox.classList.remove('hidden');
      return;
    }

    const name = document.getElementById('reg-name').value.trim();
    const email = document.getElementById('reg-email').value.trim();
    const phoneInput = document.getElementById('reg-phone');
    const phone = phoneInput ? phoneInput.value.trim() : '';
    const password = document.getElementById('reg-password').value;
    const submitBtn = document.getElementById('reg-submit');

    submitBtn.disabled = true;
    submitBtn.textContent = 'Creating account...';

    try {
      const res = await cognitoSignUp(name, email, password, phone);
      pendingEmail = email;
      if (res.UserConfirmed) {
        successBox.textContent = 'Account created and confirmed! Redirecting to sign in...';
        successBox.classList.remove('hidden');
        setTimeout(() => {
          window.location.href = 'login.html';
        }, 1200);
      } else {
        registerForm.classList.add('hidden');
        verifyForm.classList.remove('hidden');
        document.getElementById('verify-email-label').textContent = email;
        successBox.textContent = 'Verification code sent to your email address via Amazon Cognito.';
        successBox.classList.remove('hidden');
      }
    } catch (err) {
      errorBox.textContent = err.message || 'Registration failed.';
      errorBox.classList.remove('hidden');
    } finally {
      submitBtn.disabled = false;
      submitBtn.textContent = 'Create account';
    }
  });

  verifyForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    errorBox.classList.add('hidden');
    successBox.classList.add('hidden');

    const code = document.getElementById('verify-code').value.trim();
    const btn = document.getElementById('verify-submit');
    btn.disabled = true;
    btn.textContent = 'Verifying...';

    try {
      await cognitoConfirmSignUp(pendingEmail, code);
      successBox.textContent = 'Email verified! Redirecting to login...';
      successBox.classList.remove('hidden');
      setTimeout(() => {
        window.location.href = 'login.html';
      }, 1200);
    } catch (err) {
      errorBox.textContent = err.message || 'Verification failed.';
      errorBox.classList.remove('hidden');
    } finally {
      btn.disabled = false;
      btn.textContent = 'Verify email';
    }
  });

  if (resendBtn) {
    resendBtn.addEventListener('click', async () => {
      if (!pendingEmail) return;
      try {
        await cognitoResendCode(pendingEmail);
        showToast('Verification code resent.', 'success');
      } catch (err) {
        showToast(err.message || 'Failed to resend code.', 'error');
      }
    });
  }
}

/* --------------------------------------------------------------------------
 * Dashboard Workspace Controller
 * -------------------------------------------------------------------------- */

function initDashboardPage() {
  const session = getSession();
  if (!session) {
    window.location.href = 'login.html';
    return;
  }

  const state = {
    view: 'overview',
    documents: [],
    summary: {
      total_documents: 0,
      total_storage_bytes: 0,
      category_counts: { PDF: 0, DOC: 0, DOCX: 0, TXT: 0, PNG: 0, JPG: 0 },
    },
    search: '',
    fileType: 'ALL',
    loading: false,
    deleteTarget: null,
    selectedFile: null,
  };

  // Populate student profile in sidebar & settings
  const email = session.claims.email || 'Student';
  const name = session.claims.name || email.split('@')[0];
  document.getElementById('sidebar-user-name').textContent = name;
  document.getElementById('sidebar-user-email').textContent = email;
  document.getElementById('profile-name').textContent = name;
  document.getElementById('profile-email').textContent = email;
  document.getElementById('profile-sub').textContent = session.claims.sub || '—';

  // Mobile sidebar drawer toggle
  const sidebar = document.getElementById('sidebar');
  document.getElementById('mobile-menu-btn').addEventListener('click', () => {
    sidebar.classList.toggle('open');
  });

  // View switching
  const navButtons = document.querySelectorAll('[data-nav-view]');
  const switchView = (nextView) => {
    state.view = nextView;
    navButtons.forEach((btn) => {
      btn.classList.toggle('active', btn.dataset.navView === nextView);
    });
    document.querySelectorAll('[data-view-panel]').forEach((panel) => {
      panel.classList.toggle('hidden', panel.dataset.viewPanel !== nextView);
    });
    const titles = {
      overview: 'Dashboard',
      documents: 'My Documents',
      upload: 'Upload Documents',
      profile: 'Profile & Settings',
    };
    document.getElementById('topbar-title').textContent = titles[nextView] || 'Dashboard';
    sidebar.classList.remove('open');
  };

  navButtons.forEach((btn) => {
    btn.addEventListener('click', () => switchView(btn.dataset.navView));
  });

  document.getElementById('topbar-upload-btn').addEventListener('click', () => switchView('upload'));

  // Logout
  const performLogout = async () => {
    await cognitoLogout();
    window.location.href = 'login.html';
  };
  document.getElementById('logout-btn').addEventListener('click', performLogout);
  document.getElementById('profile-logout-btn').addEventListener('click', performLogout);

  // Settings AWS config form
  const cfg = getAwsConfig();
  document.getElementById('settings-region').value = cfg.region;
  document.getElementById('settings-pool-id').value = cfg.userPoolId;
  document.getElementById('settings-client-id').value = cfg.clientId;
  document.getElementById('settings-api-url').value = cfg.apiBaseUrl;
  document.getElementById('settings-aws-form').addEventListener('submit', (e) => {
    e.preventDefault();
    saveAwsConfig({
      region: document.getElementById('settings-region').value,
      userPoolId: document.getElementById('settings-pool-id').value,
      clientId: document.getElementById('settings-client-id').value,
      apiBaseUrl: document.getElementById('settings-api-url').value,
    });
    showToast('AWS endpoints updated.', 'success');
    loadDocuments();
  });

  // Search & Filter controls
  const searchInput = document.getElementById('docs-search-input');
  searchInput.addEventListener('input', (e) => {
    state.search = e.target.value;
    renderDocuments();
  });

  const filterButtons = document.querySelectorAll('[data-filter-type]');
  filterButtons.forEach((btn) => {
    btn.addEventListener('click', () => {
      state.fileType = btn.dataset.filterType;
      filterButtons.forEach((b) => b.classList.toggle('active', b === btn));
      renderDocuments();
    });
  });

  // Delete confirmation modal
  const deleteModal = document.getElementById('delete-modal');
  document.getElementById('cancel-delete-btn').addEventListener('click', () => {
    state.deleteTarget = null;
    deleteModal.classList.add('hidden');
  });
  document.getElementById('confirm-delete-btn').addEventListener('click', async () => {
    if (!state.deleteTarget) return;
    const btn = document.getElementById('confirm-delete-btn');
    btn.disabled = true;
    btn.textContent = 'Deleting...';
    try {
      await apiRequest(`/documents/${encodeURIComponent(state.deleteTarget.document_id)}`, {
        method: 'DELETE',
      });
      showToast(`Deleted "${state.deleteTarget.file_name}".`, 'success');
      deleteModal.classList.add('hidden');
      state.deleteTarget = null;
      await loadDocuments();
    } catch (err) {
      showToast(err.message || 'Delete failed.', 'error');
    } finally {
      btn.disabled = false;
      btn.textContent = 'Delete document';
    }
  });

  // Upload workflow
  const dropzone = document.getElementById('upload-dropzone');
  const fileInput = document.getElementById('upload-file-input');
  const selectedFileCard = document.getElementById('selected-file-card');
  const uploadBtn = document.getElementById('start-upload-btn');
  const progressWrap = document.getElementById('upload-progress-wrap');
  const progressFill = document.getElementById('upload-progress-fill');
  const progressLabel = document.getElementById('upload-progress-label');

  const selectFile = (file) => {
    if (!file) return;
    const ext = (file.name.split('.').pop() || '').toLowerCase();
    if (!ALLOWED_EXTENSIONS.has(ext)) {
      showToast('Unsupported file type. Allowed: PDF, DOC, DOCX, TXT, PNG, JPG.', 'error');
      return;
    }
    if (file.size <= 0 || file.size > MAX_FILE_SIZE_BYTES) {
      showToast('File size must be between 1 byte and 10 MB.', 'error');
      return;
    }
    state.selectedFile = file;
    document.getElementById('selected-file-name').textContent = file.name;
    document.getElementById('selected-file-meta').textContent = `${ext.toUpperCase()} · ${formatBytes(file.size)}`;
    selectedFileCard.classList.remove('hidden');
  };

  dropzone.addEventListener('click', () => fileInput.click());
  fileInput.addEventListener('change', (e) => selectFile(e.target.files[0]));
  dropzone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropzone.classList.add('drag-over');
  });
  dropzone.addEventListener('dragleave', () => dropzone.classList.remove('drag-over'));
  dropzone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropzone.classList.remove('drag-over');
    selectFile(e.dataTransfer.files[0]);
  });

  uploadBtn.addEventListener('click', async () => {
    const file = state.selectedFile;
    if (!file) return;
    const ext = (file.name.split('.').pop() || '').toLowerCase();
    const contentType = file.type || EXTENSION_MIME_MAP[ext] || 'application/octet-stream';

    uploadBtn.disabled = true;
    progressWrap.classList.remove('hidden');
    progressFill.style.width = '5%';
    progressLabel.textContent = 'Requesting presigned S3 upload URL...';

    try {
      const presign = await apiRequest('/documents/upload-url', {
        method: 'POST',
        body: JSON.stringify({
          file_name: file.name,
          content_type: contentType,
          file_size: file.size,
        }),
      });

      progressLabel.textContent = 'Uploading directly to private Amazon S3...';
      await uploadFileToS3PresignedPost(presign, file, (pct) => {
        progressFill.style.width = `${Math.max(10, pct)}%`;
        progressLabel.textContent = `Uploading to Amazon S3... ${pct}%`;
      });

      if (presign.document_id) {
        progressLabel.textContent = 'Finalizing metadata in DynamoDB...';
        await apiRequest('/documents/complete', {
          method: 'POST',
          body: JSON.stringify({ document_id: presign.document_id }),
        });
      }

      progressFill.style.width = '100%';
      showToast(`"${file.name}" uploaded securely.`, 'success');
      state.selectedFile = null;
      fileInput.value = '';
      selectedFileCard.classList.add('hidden');
      await loadDocuments();
      switchView('documents');
    } catch (err) {
      showToast(err.message || 'Upload failed.', 'error');
    } finally {
      uploadBtn.disabled = false;
      progressWrap.classList.add('hidden');
    }
  });

  // Load documents from API Gateway -> Lambda -> DynamoDB
  async function loadDocuments() {
    state.loading = true;
    renderDocuments();

    try {
      const data = await apiRequest('/documents');
      state.documents = data.documents || [];
      state.summary = data.summary || state.summary;
    } catch (err) {
      showToast(err.message || 'Failed to load documents.', 'error');
    } finally {
      state.loading = false;
      renderOverview();
      renderDocuments();
    }
  }

  function renderOverview() {
    const { total_documents, total_storage_bytes, category_counts } = state.summary;
    document.getElementById('kpi-total-docs').textContent = String(total_documents);
    document.getElementById('kpi-total-storage').textContent = formatBytes(total_storage_bytes);
    const pdfCount = category_counts.PDF || 0;
    const docCount = (category_counts.DOC || 0) + (category_counts.DOCX || 0);
    const imgCount = (category_counts.PNG || 0) + (category_counts.JPG || 0);
    const txtCount = category_counts.TXT || 0;

    document.getElementById('kpi-pdf-count').textContent = String(pdfCount);
    document.getElementById('kpi-other-count').textContent = String(docCount + imgCount + txtCount);

    const breakdownEl = document.getElementById('category-breakdown');
    breakdownEl.innerHTML = [
      { label: 'PDF Documents', count: pdfCount },
      { label: 'Word (DOC / DOCX)', count: docCount },
      { label: 'Text Notes (TXT)', count: txtCount },
      { label: 'Images (PNG / JPG)', count: imgCount },
    ]
      .map(
        (row) => `
        <div style="display:flex;justify-content:space-between;padding:10px 0;border-bottom:1px solid var(--border-hairline);">
          <span style="font-size:14px;color:var(--text-secondary);">${row.label}</span>
          <span class="tabular-nums" style="font-weight:600;color:var(--text-primary);">${row.count}</span>
        </div>`
      )
      .join('');

    const recentBody = document.getElementById('recent-uploads-list');
    const recent = state.documents.slice(0, 5);
    if (recent.length === 0) {
      recentBody.innerHTML = `<p style="font-size:14px;color:var(--text-muted);padding:16px 0;">No documents uploaded yet.</p>`;
    } else {
      recentBody.innerHTML = recent
        .map(
          (doc) => `
          <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;padding:11px 0;border-bottom:1px solid var(--border-hairline);">
            <div style="min-width:0;">
              <div style="font-size:14px;font-weight:500;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${escapeHtml(doc.file_name)}</div>
              <div class="tabular-nums" style="font-size:12.5px;color:var(--text-muted);">${escapeHtml(doc.file_type)} · ${formatBytes(doc.file_size)} · ${formatDate(doc.upload_date)}</div>
            </div>
            <button class="btn btn-secondary btn-sm" data-download-id="${escapeHtml(doc.document_id)}">Download</button>
          </div>`
        )
        .join('');

      recentBody.querySelectorAll('[data-download-id]').forEach((btn) => {
        btn.addEventListener('click', () => triggerDownload(btn.dataset.downloadId));
      });
    }
  }

  function renderDocuments() {
    const tbody = document.getElementById('documents-table-body');
    const emptyEl = document.getElementById('documents-empty-state');
    const tableWrap = document.getElementById('documents-table-wrap');

    if (state.loading) {
      tableWrap.classList.remove('hidden');
      emptyEl.classList.add('hidden');
      tbody.innerHTML = `<tr><td colspan="5" style="text-align:center;color:var(--text-muted);padding:28px;">Loading documents from Amazon DynamoDB...</td></tr>`;
      return;
    }

    const term = state.search.trim().toLowerCase();
    const filtered = state.documents.filter((doc) => {
      const matchesSearch = !term || String(doc.file_name || '').toLowerCase().includes(term);
      if (!matchesSearch) return false;
      if (state.fileType === 'ALL') return true;
      if (state.fileType === 'DOC_GROUP') return doc.file_type === 'DOC' || doc.file_type === 'DOCX';
      if (state.fileType === 'IMAGE_GROUP') return doc.file_type === 'PNG' || doc.file_type === 'JPG';
      return doc.file_type === state.fileType;
    });

    if (filtered.length === 0) {
      tableWrap.classList.add('hidden');
      emptyEl.classList.remove('hidden');
      return;
    }

    tableWrap.classList.remove('hidden');
    emptyEl.classList.add('hidden');

    tbody.innerHTML = filtered
      .map(
        (doc) => `
      <tr>
        <td>
          <div style="font-weight:500;">${escapeHtml(doc.file_name)}</div>
        </td>
        <td class="mono" style="font-size:13px;">${escapeHtml(doc.file_type)}</td>
        <td class="tabular-nums text-right">${formatBytes(doc.file_size)}</td>
        <td class="tabular-nums">${formatDate(doc.upload_date)}</td>
        <td class="text-right">
          <div style="display:inline-flex;gap:8px;">
            <button class="btn btn-secondary btn-sm" data-action="download" data-id="${escapeHtml(doc.document_id)}">Download</button>
            <button class="btn btn-ghost btn-sm" style="color:var(--danger);" data-action="delete" data-id="${escapeHtml(doc.document_id)}">Delete</button>
          </div>
        </td>
      </tr>`
      )
      .join('');

    tbody.querySelectorAll('[data-action="download"]').forEach((btn) => {
      btn.addEventListener('click', () => triggerDownload(btn.dataset.id));
    });

    tbody.querySelectorAll('[data-action="delete"]').forEach((btn) => {
      btn.addEventListener('click', () => {
        const doc = state.documents.find((d) => d.document_id === btn.dataset.id);
        if (!doc) return;
        state.deleteTarget = doc;
        document.getElementById('delete-target-name').textContent = doc.file_name;
        deleteModal.classList.remove('hidden');
      });
    });
  }

  async function triggerDownload(documentId) {
    try {
      const res = await apiRequest(`/documents/${encodeURIComponent(documentId)}/download`);
      const link = document.createElement('a');
      link.href = res.download_url;
      link.download = res.file_name || 'document';
      link.rel = 'noopener noreferrer';
      document.body.appendChild(link);
      link.click();
      link.remove();
      showToast(`Downloading "${res.file_name}"...`, 'success');
    } catch (err) {
      showToast(err.message || 'Download failed.', 'error');
    }
  }

  loadDocuments();
}
