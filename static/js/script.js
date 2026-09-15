/* =========================================================
   FraudLens — script.js
   -----------------------------------------------------------
   Auth fallback is intentionally kept in the browser for the
   local/offline login/register flow using localStorage.
   Passwords are never stored in plain text.
========================================================= */

(function () {
  'use strict';

  /* =======================================================
     Local Storage — keys & low level helpers
  ======================================================= */
  const LS_KEYS = {
    USERS: 'fraudLensUsers',
    CURRENT_USER: 'fraudLensCurrentUser',
    LOGGED_IN: 'fraudLensLoggedIn'
  };

  function readJSON(key, fallback) {
    try {
      const raw = localStorage.getItem(key);
      return raw ? JSON.parse(raw) : fallback;
    } catch (e) {
      console.warn('FraudLens: could not parse localStorage key', key, e);
      return fallback;
    }
  }

  function writeJSON(key, value) {
    localStorage.setItem(key, JSON.stringify(value));
  }

  async function hashPasswordBrowser(password) {
    if (!password) return '';

    try {
      if (window.crypto && window.crypto.subtle) {
        const digest = await window.crypto.subtle.digest(
          'SHA-256',
          new TextEncoder().encode(password)
        );
        return Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, '0')).join('');
      }
    } catch (e) {
      console.warn('FraudLens: browser crypto subtle hash failed; using lightweight fallback.', e);
    }

    let hash = 0;
    for (let i = 0; i < password.length; i++) {
      hash = (hash << 5) - hash + password.charCodeAt(i);
      hash |= 0;
    }
    return String(Math.abs(hash));
  }

  /* =======================================================
     User Management
  ======================================================= */
  function getUsers() {
    return readJSON(LS_KEYS.USERS, []);
  }

  function findUserByEmail(email) {
    if (!email) return null;
    const normalized = email.trim().toLowerCase();
    return getUsers().find(u => u.email && u.email.toLowerCase() === normalized) || null;
  }

  function saveUser({ fullName, email, passwordHash }) {
    const users = getUsers();
    const emailKey = email.trim().toLowerCase();

    const existing = users.find(u => u.email && u.email.toLowerCase() === emailKey);
    if (existing) {
      existing.fullName = fullName.trim();
      existing.email = emailKey;
      existing.passwordHash = passwordHash || existing.passwordHash || '';
      existing.createdAt = existing.createdAt || new Date().toISOString();
      writeJSON(LS_KEYS.USERS, users);
      return existing;
    }

    const newUser = {
      id: 'FL-' + Date.now().toString(36).toUpperCase(),
      fullName: fullName.trim(),
      email: emailKey,
      createdAt: new Date().toISOString(),
      passwordHash: passwordHash || ''
    };

    users.push(newUser);
    writeJSON(LS_KEYS.USERS, users);
    return newUser;
  }

  function registerLocalUser({ fullName, email, passwordHash }) {
    const users = getUsers();
    const emailKey = email.trim().toLowerCase();
    const existing = users.find(u => u.email && u.email.toLowerCase() === emailKey);

    if (existing) {
      existing.fullName = fullName.trim();
      existing.email = emailKey;
      existing.passwordHash = passwordHash || existing.passwordHash || '';
      existing.createdAt = existing.createdAt || new Date().toISOString();
      writeJSON(LS_KEYS.USERS, users);
      return existing;
    }

    const newUser = {
      id: 'FL-' + Date.now().toString(36).toUpperCase(),
      fullName: fullName.trim(),
      email: emailKey,
      createdAt: new Date().toISOString(),
      passwordHash
    };

    users.push(newUser);
    writeJSON(LS_KEYS.USERS, users);
    return newUser;
  }

  async function tryLocalLogin(email, password) {
    const localUser = findUserByEmail(email);
    if (!localUser || !localUser.passwordHash) return null;

    const localHash = await hashPasswordBrowser(password);
    if (localUser.passwordHash !== localHash) return null;

    setCurrentUser({
      id: localUser.id,
      full_name: localUser.fullName,
      email: localUser.email,
      created_at: localUser.createdAt,
      is_admin: false
    });

    return localUser;
  }

  function setCurrentUser(user) {
    writeJSON(LS_KEYS.CURRENT_USER, user);
    localStorage.setItem(LS_KEYS.LOGGED_IN, 'true');
  }

  function getCurrentUser() {
    return readJSON(LS_KEYS.CURRENT_USER, null);
  }

  function isLoggedIn() {
    return localStorage.getItem(LS_KEYS.LOGGED_IN) === 'true' && !!getCurrentUser();
  }

  function logoutUser() {
    localStorage.removeItem(LS_KEYS.LOGGED_IN);
    localStorage.removeItem(LS_KEYS.CURRENT_USER);
    // Hit server logout route to clear session cookie, then redirect
    window.location.href = '/logout';
  }

  window.logoutUser = logoutUser;

  /* =======================================================
     CSV Export
  ======================================================= */
  function exportUsersToCSV() {
    const users = getUsers();

    if (!users.length) {
      showToast('No registered users found.', 'error');
      return;
    }

    const headers = ['ID', 'Name', 'Email', 'Registered Date'];

    const rows = users.map(u => [
      u.id,
      u.fullName,
      u.email,
      new Date(u.createdAt).toLocaleString()
    ]);

    const csvContent = [headers, ...rows]
      .map(row => row.map(escapeCSV).join(','))
      .join('\r\n');

    const blob = new Blob([csvContent], {
      type: 'text/csv;charset=utf-8;'
    });

    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');

    link.href = url;
    link.download = 'fraudlens_users.csv';

    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);

    URL.revokeObjectURL(url);

    showToast('Users exported to fraudlens_users.csv', 'success');
  }

  window.exportUsersToCSV = exportUsersToCSV;

  function escapeCSV(value) {
    const str = String(value ?? '');

    if (/[",\n]/.test(str)) {
      return '"' + str.replace(/"/g, '""') + '"';
    }

    return str;
  }

  /* =======================================================
     Notifications (toasts)
  ======================================================= */
  function ensureToastStack() {
    let stack = document.querySelector('.fl-toast-stack');

    if (!stack) {
      stack = document.createElement('div');
      stack.className = 'fl-toast-stack';
      stack.setAttribute('aria-live', 'polite');
      document.body.appendChild(stack);
    }

    return stack;
  }

  function showToast(message, type = 'info') {
    const stack = ensureToastStack();

    const icon =
      type === 'success'
        ? 'bi-check-circle-fill'
        : type === 'error'
        ? 'bi-exclamation-circle-fill'
        : 'bi-info-circle-fill';

    const toast = document.createElement('div');
    toast.className = `fl-toast ${type}`;

    toast.innerHTML = `<i class="bi ${icon}"></i><span>${message}</span>`;

    stack.appendChild(toast);

    setTimeout(() => {
      toast.classList.add('fading');

      setTimeout(() => toast.remove(), 260);
    }, 3200);
  }

  window.showToast = showToast;

  /* =======================================================
     Password UI (show/hide + strength)
  ======================================================= */
  function initPasswordToggle(inputId, btnId) {
    const input = document.getElementById(inputId);
    const btn = document.getElementById(btnId);

    if (!input || !btn) return;

    btn.addEventListener('click', () => {
      const isPwd = input.type === 'password';

      input.type = isPwd ? 'text' : 'password';

      btn.innerHTML = isPwd
        ? '<i class="bi bi-eye-slash"></i>'
        : '<i class="bi bi-eye"></i>';

      btn.setAttribute(
        'aria-label',
        isPwd ? 'Hide password' : 'Show password'
      );
    });
  }

  function scorePasswordStrength(pwd) {
    let score = 0;

    if (pwd.length >= 8) score++;
    if (pwd.length >= 12) score++;
    if (/[A-Z]/.test(pwd) && /[a-z]/.test(pwd)) score++;
    if (/\d/.test(pwd)) score++;
    if (/[^A-Za-z0-9]/.test(pwd)) score++;

    return Math.min(score, 5);
  }

  function initPasswordStrength(inputId, fillId, labelId) {
    const input = document.getElementById(inputId);
    const fill = document.getElementById(fillId);
    const label = document.getElementById(labelId);

    if (!input || !fill || !label) return;

    input.addEventListener('input', () => {
      const score = scorePasswordStrength(input.value);
      const pct = (score / 5) * 100;

      fill.style.width = pct + '%';

      let text = 'Too short';
      let color = 'var(--danger-color)';

      if (input.value.length === 0) {
        text = 'Enter a password';
      } else if (score <= 1) {
        text = 'Weak';
        color = 'var(--danger-color)';
      } else if (score <= 3) {
        text = 'Fair';
        color = 'var(--warning-color)';
      } else {
        text = 'Strong';
        color = 'var(--success-color)';
      }

      fill.style.background = color;
      label.textContent = text;
    });
  }

  /* =======================================================
     Registration
  ======================================================= */
  function initRegisterForm() {
    const form = document.getElementById('registerForm');

    if (!form) return;

    initPasswordToggle('passwordInput', 'togglePassword');
    initPasswordToggle(
      'confirmPasswordInput',
      'toggleConfirmPassword'
    );

    initPasswordStrength(
      'passwordInput',
      'pwStrengthFill',
      'pwStrengthLabel'
    );

    form.addEventListener('submit', async function (e) {
      e.preventDefault();
      clearFieldErrors(form);

      const fullName = document.getElementById('fullNameInput').value.trim();
      const email = document.getElementById('emailInput').value.trim();
      const password = document.getElementById('passwordInput').value;
      const confirmPassword = document.getElementById('confirmPasswordInput').value;
      const termsCheck = document.getElementById('termsCheck');

      let hasError = false;

      if (fullName.length < 2) {
        setFieldError('fullNameInput', 'Please enter your full name.');
        hasError = true;
      }

      if (!isValidEmail(email)) {
        setFieldError('emailInput', 'Please enter a valid email address.');
        hasError = true;
      }

      if (password.length < 8) {
        setFieldError('passwordInput', 'Password must be at least 8 characters.');
        hasError = true;
      }

      if (password !== confirmPassword) {
        setFieldError('confirmPasswordInput', 'Passwords do not match.');
        hasError = true;
      }

      if (termsCheck && !termsCheck.checked) {
        setFieldError('termsCheck', 'Please accept the terms to continue.');
        hasError = true;
      }

      if (hasError) return;

      try {
        const localPasswordHash = await hashPasswordBrowser(password);
        const resp = await fetch('/register', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'same-origin',
          body: JSON.stringify({ fullName, email, password, confirmPassword, localPasswordHash })
        });

        const data = await resp.json().catch(() => ({}));

        if (resp.ok && data.success) {
          showToast(data.message || 'Account created successfully! Redirecting to login…', 'success');
          form.reset();
          document.getElementById('pwStrengthFill').style.width = '0%';

          setTimeout(() => {
            window.location.href = data.redirect || '/login';
          }, 1200);
        } else {
          if (data && data.field) {
            setFieldError(data.field, data.message || 'Please correct this field.');
          } else {
            showFormAlert(form, data.message || 'Could not create account. Please try again.');
          }
        }
      } catch (err) {
        showFormAlert(form, 'Network error. Please try again.');
      }
    });
  }

  /* =======================================================
     Login
  ======================================================= */
  function initLoginForm() {
    const form = document.getElementById('loginForm');

    if (!form) return;

    initPasswordToggle('passwordInput', 'togglePassword');

    form.addEventListener('submit', async function (e) {
      e.preventDefault();
      clearFieldErrors(form);

      const email = document.getElementById('emailInput').value.trim();
      const password = document.getElementById('passwordInput').value;
      const remember = document.getElementById('rememberCheck');

      let hasError = false;

      if (!isValidEmail(email)) {
        setFieldError('emailInput', 'Please enter a valid email address.');
        hasError = true;
      }

      if (!password) {
        setFieldError('passwordInput', 'Please enter your password.');
        hasError = true;
      }

      if (hasError) return;

      try {
        const localPasswordHash = await hashPasswordBrowser(password);
        const resp = await fetch('/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'same-origin',
          body: JSON.stringify({ email, password, localPasswordHash })
        });

        const data = await resp.json().catch(() => ({}));

        if (resp.ok && data.success) {
          if (remember && remember.checked) {
            localStorage.setItem('fraudLensRememberEmail', email);
          }

          showToast(data.message || 'Login successful! Redirecting…', 'success');

          setTimeout(() => {
            window.location.href = data.redirect || '/dashboard';
          }, 900);
        } else {
          // If API returned a field-specific error, display it
          if (data && data.field) {
            setFieldError(data.field, data.message || 'Invalid input.');
          } else {
            showFormAlert(form, data.message || 'Invalid email or password. Please try again, or create an account.');
          }
        }
      } catch (err) {
        showFormAlert(form, 'Network error. Please try again.');
      }
    });

    const rememberedEmail =
      localStorage.getItem('fraudLensRememberEmail');

    if (rememberedEmail) {
      const emailInput =
        document.getElementById('emailInput');

      if (emailInput) {
        emailInput.value = rememberedEmail;
      }

      const remember =
        document.getElementById('rememberCheck');

      if (remember) {
        remember.checked = true;
      }
    }
  }

  /* =======================================================
     Shared form helpers
  ======================================================= */
  function isValidEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  }

  function setFieldError(inputId, message) {
    const input = document.getElementById(inputId);

    if (!input) return;

    input.classList.add('is-invalid');

    let feedback = input
      .closest('.form-group, .mb-3, .input-with-icon')
      ?.querySelector('.invalid-feedback');

    if (!feedback) {
      feedback = document.createElement('div');
      feedback.className = 'invalid-feedback d-block';

      input.insertAdjacentElement(
        'afterend',
        feedback
      );
    }

    feedback.textContent = message;
  }

  function clearFieldErrors(form) {
    form
      .querySelectorAll('.is-invalid')
      .forEach(el => el.classList.remove('is-invalid'));

    form
      .querySelectorAll('.invalid-feedback')
      .forEach(el => el.remove());

    const alertBox = form.querySelector('.form-alert');

    if (alertBox) {
      alertBox.remove();
    }
  }

  function showFormAlert(form, message) {
    let alertBox = form.querySelector('.form-alert');

    if (!alertBox) {
      alertBox = document.createElement('div');

      alertBox.className =
        'form-alert alert alert-danger mt-3 mb-0 py-2 px-3';

      alertBox.style.fontSize = '0.88rem';
      alertBox.setAttribute('role', 'alert');

      form.appendChild(alertBox);
    }

    alertBox.textContent = message;
  }

    /* =======================================================
      Dashboard — auth guard and user profile
    ======================================================= */
  async function initAuthGuard() {
    const guardedPages = [
      'dashboard',
      'sms_detector',
      'link_checker',
      'qr_scanner',
      'safety_hub'
    ];

    let current = window.location.pathname.split('/').pop();
    if (!current) current = 'index';
    if (current.endsWith('.html')) {
      current = current.replace(/\.html$/i, '');
    }

    if (!guardedPages.includes(current)) return null;

    try {
      const resp = await fetch('/api/whoami', { credentials: 'same-origin' });
      const data = await resp.json().catch(() => ({}));
      if (!data.logged_in) {
        window.location.href = '/login';
        return null;
      }
      return data.user || null;
    } catch (e) {
      // On network error, fall back to redirect to login to be safe
      window.location.href = '/login';
      return null;
    }
  }

  function initUserChip(user) {
    const chip = document.getElementById('userChip');
    if (!chip) return;
    if (!user) return;

    const fullName = user.full_name || '';
    const initials = fullName
      .split(' ')
      .map(n => n[0])
      .slice(0, 2)
      .join('')
      .toUpperCase();

    chip.type = 'button';
    chip.setAttribute('aria-label', 'Open My Profile');
    chip.setAttribute('title', 'My Profile');
    chip.innerHTML = `<span class="fl-user-avatar">${escapeHTML(initials)}</span><span>${escapeHTML(fullName)}</span>`;
    chip.addEventListener('click', () => openProfile(user));
  }

  function openProfile(user) {
    let modal = document.getElementById('profileModal');
    if (!modal) {
      modal = document.createElement('div');
      modal.id = 'profileModal';
      modal.className = 'profile-modal-backdrop';
      modal.innerHTML = `
        <section class="profile-modal" role="dialog" aria-modal="true" aria-labelledby="profileTitle">
          <button type="button" class="profile-modal-close" aria-label="Close My Profile"><i class="bi bi-x-lg"></i></button>
          <div class="tool-icon-badge mx-auto mb-3"><i class="bi bi-person-badge"></i></div>
          <h2 id="profileTitle" class="text-center" style="font-size:1.35rem;">My Profile</h2>
          <div class="profile-details mt-4"></div>
        </section>`;
      document.body.appendChild(modal);
      modal.addEventListener('click', (event) => {
        if (event.target === modal || event.target.closest('.profile-modal-close')) modal.remove();
      });
    }

    const createdAt = user.created_at ? new Date(user.created_at).toLocaleString() : 'Not available';
    const status = user.is_active ? 'Active' : 'Inactive';
    modal.querySelector('.profile-details').innerHTML = `
      <div class="profile-row"><span>Full Name</span><strong>${escapeHTML(user.full_name || 'Not available')}</strong></div>
      <div class="profile-row"><span>Email Address</span><strong>${escapeHTML(user.email || 'Not available')}</strong></div>
      <div class="profile-row"><span>Account Status</span><strong>${status}</strong></div>
      <div class="profile-row"><span>Account Created</span><strong>${escapeHTML(createdAt)}</strong></div>`;
    modal.classList.add('is-open');
  }

  function initLogoutButtons() {
    document
      .querySelectorAll('[data-logout]')
      .forEach(btn => {
        btn.addEventListener('click', (e) => {
          e.preventDefault();
          // Clear any local demo storage and call server logout
          localStorage.removeItem(LS_KEYS.LOGGED_IN);
          localStorage.removeItem(LS_KEYS.CURRENT_USER);
          window.location.href = '/logout';
        });
      });
  }

  function renderUsersTable() {
    const tbody =
      document.getElementById('usersTableBody');

    const emptyState =
      document.getElementById('usersEmptyState');

    const wrapper =
      document.getElementById('usersTableWrapper');

    if (!tbody) return;

    const users = getUsers();

    tbody.innerHTML = '';

    if (!users.length) {
      if (wrapper) {
        wrapper.classList.add('d-none');
      }

      if (emptyState) {
        emptyState.classList.remove('d-none');
      }

      return;
    }

    if (wrapper) {
      wrapper.classList.remove('d-none');
    }

    if (emptyState) {
      emptyState.classList.add('d-none');
    }

    users.forEach(u => {
      const tr = document.createElement('tr');

      tr.innerHTML = `
        <td>
          <span
            class="text-muted-soft"
            style="font-family:var(--font-mono); font-size:0.82rem;"
          >${u.id}</span>
        </td>

        <td>${escapeHTML(u.fullName)}</td>

        <td>${escapeHTML(u.email)}</td>

        <td>
          ${new Date(u.createdAt).toLocaleDateString(
            undefined,
            {
              year: 'numeric',
              month: 'short',
              day: 'numeric'
            }
          )}
        </td>
      `;

      tbody.appendChild(tr);
    });
  }

  function escapeHTML(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  function initExportButtons() {
    document
      .querySelectorAll('[data-export-csv]')
      .forEach(btn => {
        btn.addEventListener(
          'click',
          exportUsersToCSV
        );
      });
  }

  function initDashboardStats() {
    const statTotal =
      document.getElementById('statTotalScans');

    const statThreats =
      document.getElementById('statThreats');

    const statSafe =
      document.getElementById('statSafe');

    const statRisk =
      document.getElementById('statRisk');

    if (!statTotal) return;

    // Demo values — will come from SQLite scan history later
    statTotal.textContent = '128';
    statThreats.textContent = '14';
    statSafe.textContent = '114';
    statRisk.textContent = 'Low';
  }

  /* =======================================================
     Cyber Safety Hub — page-specific interactions
  ======================================================= */
  function initSafetyHub() {
    const page = document.getElementById('safetyHubPage');
    if (!page) return;

    // Expandable Cyber Threat cards
    page.querySelectorAll('.cyber-threat-card').forEach(card => {
      const button = card.querySelector('.threat-card-button');
      if (!button) return;

      button.addEventListener('click', () => {
        card.classList.toggle('expanded');
      });
    });

    // Search and filter the threat cards locally
    const search = document.getElementById('safetySearch');
    if (search) {
      search.addEventListener('input', () => {
        const term = search.value.trim().toLowerCase();
        page.querySelectorAll('.cyber-threat-card').forEach(card => {
          const text = (card.dataset.category || '') + ' ' + (card.dataset.title || '');
          const visible = !term || text.toLowerCase().includes(term);
          card.classList.toggle('is-hidden', !visible);
        });
      });
    }

    // Cyber score local browser-only self check
    const questions = Array.from(page.querySelectorAll('.score-question'));
    const scoreNumber = document.getElementById('cyberScore');
    const scoreBand = document.getElementById('scoreBand');
    const scoreReset = document.getElementById('scoreReset');

    function updateScore() {
      if (!scoreNumber || !scoreBand) return;

      const selected = questions.filter(q => q.checked).length;
      const score = Math.round((selected / questions.length) * 100);
      scoreNumber.textContent = `${score}%`;

      let band = 'Needs Improvement';
      if (score >= 81) band = 'Excellent';
      else if (score >= 61) band = 'Good';
      else if (score >= 31) band = 'Getting Safer';

      scoreBand.textContent = band;
      if (score <= 30) {
        scoreBand.style.color = 'var(--danger-color)';
      } else if (score <= 80) {
        scoreBand.style.color = 'var(--warning-color)';
      } else {
        scoreBand.style.color = 'var(--success-color)';
      }
    }

    questions.forEach(question => question.addEventListener('change', updateScore));
    scoreReset?.addEventListener('click', () => {
      questions.forEach(question => question.checked = false);
      updateScore();
    });
    updateScore();

    // Myth vs Fact click flip
    page.querySelectorAll('.myth-button').forEach(button => {
      button.addEventListener('click', () => {
        button.classList.toggle('active');
      });
    });

    // Security tip of the day
    const tips = [
      'Keep your software updated to reduce avoidable risks.',
      'Use a unique password for each important account.',
      'Enable MFA wherever supported by your accounts.',
      'Never share an OTP or UPI PIN with anyone.',
      'Verify payment recipients before sending money.',
      'Check the domain before clicking a link.',
      'Do not install apps from unknown sources.',
      'Review your account recovery email and phone details.',
      'Keep your browser and device security settings updated.',
      'Do not approve unknown QR payment requests.',
      'Check the sender address carefully before opening an email.',
      'Avoid public Wi-Fi for sensitive transactions when possible.',
      'Use trusted payment methods with dispute support.',
      'Never trust screenshots alone as proof of payment.',
      'Report suspicious accounts and messages quickly.',
      'Do not share personal details on social media.',
      'Backup important files and data regularly.',
      'Use official company contact details instead of DMs.',
      'Review active sessions on important accounts.',
      'Pause before reacting to urgent messages or calls.'
    ];

    const tipText = document.getElementById('tipText');
    const tipNext = document.getElementById('nextTip');
    let tipIndex = 0;
    if (tipText && tipNext) {
      tipNext.addEventListener('click', () => {
        tipIndex = (tipIndex + 1) % tips.length;
        tipText.textContent = tips[tipIndex];
        tipText.animate([
          { opacity: 0.45, transform: 'translateY(8px)' },
          { opacity: 1, transform: 'translateY(0)' }
        ], { duration: 260, easing: 'ease' });
      });
      tipText.textContent = tips[tipIndex];
    }
  }

  /* =======================================================
     SMS Detector (demo simulation)
  ======================================================= */
  function initSmsDetector() {
    const textarea =
      document.getElementById('smsInput');

    const analyzeBtn =
      document.getElementById('analyzeSmsBtn');

    if (!textarea || !analyzeBtn) return;

    const clearBtn =
      document.getElementById('clearSmsBtn');

    const exampleBtn =
      document.getElementById('exampleSmsBtn');

    const counter =
      document.getElementById('smsCharCount');

    const loading =
      document.getElementById('smsLoading');

    const resultCard =
      document.getElementById('smsResult');

    const exampleText =
      "URGENT: Your bank account has been suspended. Verify your KYC immediately by clicking [http://bit.ly/verify-kyc-now](http://bit.ly/verify-kyc-now) or your account will be permanently blocked within 24 hours.";

    textarea.addEventListener('input', () => {
      counter.textContent =
        `${textarea.value.length} / 500`;
    });

    clearBtn?.addEventListener('click', () => {
      textarea.value = '';
      counter.textContent = '0 / 500';
      resultCard.classList.add('hidden-result');
    });

    exampleBtn?.addEventListener('click', () => {
      textarea.value = exampleText;

      counter.textContent =
        `${exampleText.length} / 500`;

      textarea.focus();
    });

    analyzeBtn.addEventListener('click', async () => {
      const text = textarea.value.trim();

      if (!text) {
        showToast(
          'Please enter a message to analyze.',
          'error'
        );
        return;
      }
      loading?.classList.add('active');
      resultCard.classList.add('hidden-result');
      try {
        const response = await fetch('/api/detect-sms', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'same-origin',
          body: JSON.stringify({ message: text })
        });
        const data = await response.json().catch(() => ({}));
        if (response.ok && data.success) {
          renderSmsApiResult(data, resultCard);
        } else {
          showToast(data.message || 'SMS analysis failed.', 'error');
        }
      } catch (error) {
        showToast('Network error while analyzing SMS.', 'error');
      } finally {
        loading?.classList.remove('active');
      }
    });
  }

  function renderSmsApiResult(data, resultCard) {
    const level = data.status || 'Unknown';
    const cls = level.toLowerCase().includes('safe') ? 'safe' : level.toLowerCase().includes('suspicious') ? 'medium' : 'high';
    resultCard.classList.remove('hidden-result');
    resultCard.innerHTML = buildResultMarkup({
      title: 'Analysis Result',
      level,
      cls,
      score: data.risk_score ?? 0,
      flags: data.indicators || [],
      recommendation: data.recommendation || ''
    });
  }

  function renderSmsResult(text, resultCard) {
    const lower = text.toLowerCase();

    const flags = [];

    let score = 8;

    const riskyTerms = [
      ['urgent', 'Urgency language'],
      ['verify', 'Requests verification'],
      ['suspend', 'Threatens suspension'],
      ['block', 'Threatens account block'],
      ['kyc', 'References KYC / bank details'],
      ['click', 'Contains a call-to-click'],
      ['bit.ly', 'Shortened / masked link'],
      ['http', 'Contains a link'],
      ['otp', 'Requests OTP'],
      ['prize', 'Too-good-to-be-true offer'],
      ['win', 'Too-good-to-be-true offer'],
      ['password', 'Requests credentials']
    ];

    riskyTerms.forEach(([term, label]) => {
      if (lower.includes(term)) {
        flags.push(label);
        score += 12;
      }
    });

    score = Math.min(score, 96);

    const { level, cls } =
      classifyRisk(score);

    resultCard.classList.remove(
      'hidden-result'
    );

    resultCard.innerHTML =
      buildResultMarkup({
        title: 'Analysis Result',
        level,
        cls,
        score,

        flags: flags.length
          ? flags
          : ['No strong scam indicators detected'],

        recommendation:
          level === 'safe'
            ? 'This message does not show common scam patterns. Still, never share OTPs or passwords over SMS.'
            : level === 'suspicious'
            ? 'This message shows some risky language. Avoid clicking any links and verify with your bank directly.'
            : 'This message shows strong signs of a scam. Do not click any links, reply, or share personal information.'
      });
  }

  /* =======================================================
     Small helpers: runFakeAnalysis, classifyRisk, buildResultMarkup
     These keep the demo interactive and avoid JS errors when the
     full backend is not used.
  ======================================================= */
  function runFakeAnalysis(loadingEl, resultEl, cb) {
    if (loadingEl) loadingEl.style.display = 'inline-block';
    if (resultEl) resultEl.classList.add('hidden-result');

    // Simulate async work
    const delay = 700 + Math.floor(Math.random() * 600);
    setTimeout(() => {
      if (loadingEl) loadingEl.style.display = 'none';
      if (typeof cb === 'function') cb();
    }, delay);
  }

  function classifyRisk(score) {
    // score is 0-100-ish
    if (score >= 70) return { level: 'High', cls: 'high' };
    if (score >= 40) return { level: 'Medium', cls: 'medium' };
    return { level: 'Safe', cls: 'safe' };
  }

  function buildResultMarkup({ title, level, cls, score, flags, recommendation }) {
    const flagsHtml = (flags || []).map(f => `<li>${escapeHTML(f)}</li>`).join('');

    return `
      <div class="result-header">
        <h4>${escapeHTML(title)}</h4>
        <div class="result-badge ${cls}">${escapeHTML(level)}</div>
      </div>

      <div class="result-body mt-3">
        <div><strong>Score:</strong> ${Math.round(score)}</div>
        <p class="mt-2">${escapeHTML(recommendation || '')}</p>

        <div class="mt-3">
          <strong>Indicators:</strong>
          <ul class="mb-0">${flagsHtml}</ul>
        </div>
      </div>
    `;
  }

  /* =======================================================
     QR Scanner (camera only)
  ======================================================= */
  function initQrScanner() {
    const preview = document.getElementById('qrPreviewFrame');
    const startBtn = document.getElementById('startQrCameraBtn');
    const stopBtn = document.getElementById('stopQrCameraBtn');
    const clearBtn = document.getElementById('clearQrScanBtn');
    const status = document.getElementById('qrScanStatus');
    const loading = document.getElementById('qrLoading');
    const resultCard = document.getElementById('qrResult');

    if (!preview || !startBtn || !stopBtn || !clearBtn || !resultCard) return;

    const video = document.createElement('video');
    video.id = 'qrVideo';
    video.autoplay = true;
    video.playsInline = true;
    video.muted = true;
    video.hidden = true;
    preview.appendChild(video);

    let stream = null;
    let scanTimer = null;
    let scanInProgress = false;
    let hasScan = false;
    let nativeDetector = null;
    if ('BarcodeDetector' in window) {
      try {
        nativeDetector = new window.BarcodeDetector({ formats: ['qr_code'] });
      } catch (error) {
        nativeDetector = null;
      }
    }

    function setStatus(message, icon = 'bi-info-circle') {
      if (status) status.innerHTML = `<i class="bi ${icon}"></i><span>${escapeHTML(message)}</span>`;
    }

    function stopCamera() {
      if (scanTimer) { clearTimeout(scanTimer); scanTimer = null; }
      if (stream) stream.getTracks().forEach(track => track.stop());
      stream = null;
      video.pause();
      video.srcObject = null;
      video.hidden = true;
      startBtn.hidden = false;
      stopBtn.hidden = true;
      scanInProgress = false;
      loading?.classList.remove('active');
      if (!hasScan) setStatus('Camera is off. Start scanning when you are ready.');
    }

    async function scanFrame() {
      if (!stream || video.readyState < 2 || !video.videoWidth || !video.videoHeight || scanInProgress) {
        if (stream) scanTimer = setTimeout(scanFrame, 500);
        return;
      }
      scanInProgress = true;
      const canvas = document.createElement('canvas');
      canvas.width = video.videoWidth || 640;
      canvas.height = video.videoHeight || 480;
      const context = canvas.getContext('2d', { alpha: false });
      context.imageSmoothingEnabled = false;
      context.drawImage(video, 0, 0, canvas.width, canvas.height);
      if (nativeDetector) {
        try {
          const codes = await nativeDetector.detect(canvas);
          const decoded = codes[0]?.rawValue || codes[0]?.displayValue || '';
          if (decoded) {
            const found = await analyzeDecodedQr(decoded);
            if (found) {
              hasScan = true;
              clearBtn.hidden = false;
              setStatus('QR code detected. Camera stopped.', 'bi-check-circle');
              stopCamera();
              scanInProgress = false;
              return;
            }
          }
        } catch (error) {
          // Use the server decoder when the browser detector is unavailable.
        }
      }

      if (window.jsQR) {
        try {
          const imageData = context.getImageData(0, 0, canvas.width, canvas.height);
          const code = window.jsQR(imageData.data, imageData.width, imageData.height, {
            inversionAttempts: 'attemptBoth'
          });
          if (code?.data) {
            const found = await analyzeDecodedQr(code.data);
            if (found) {
              hasScan = true;
              clearBtn.hidden = false;
              setStatus('QR code detected. Camera stopped.', 'bi-check-circle');
              stopCamera();
              scanInProgress = false;
              return;
            }
          }
          scanInProgress = false;
          if (stream) scanTimer = setTimeout(scanFrame, 250);
          return;
        } catch (error) {
          // Fall through to the server decoder if the browser decoder fails.
        }
      }

      canvas.toBlob(async (blob) => {
        if (blob && stream) {
          const found = await serverScan(blob, true);
          if (found) {
            hasScan = true;
            clearBtn.hidden = false;
            setStatus('QR code detected. Camera stopped.', 'bi-check-circle');
            stopCamera();
          }
        }
        scanInProgress = false;
        if (stream) scanTimer = setTimeout(scanFrame, 700);
      }, 'image/png');
    }

    async function analyzeDecodedQr(decoded) {
      try {
        const response = await fetch('/api/analyze-qr', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'same-origin',
          body: JSON.stringify({ decoded_data: decoded })
        });
        const data = await response.json().catch(() => ({}));
        if (response.ok && data.success) {
          renderQrResult(data, resultCard);
          return true;
        }
      } catch (error) {
        showToast('Network error while analyzing QR code.', 'error');
      }
      return false;
    }

    async function startCamera() {
      if (!navigator.mediaDevices?.getUserMedia) {
        showToast('Camera is not supported in this browser.', 'error');
        return;
      }
      try {
        stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: { ideal: 'environment' } }, audio: false });
        video.srcObject = stream;
        await video.play();
        video.hidden = false;
        startBtn.hidden = true;
        stopBtn.hidden = false;
        setStatus('Scanning live camera feed for a QR code…', 'bi-broadcast');
        scanFrame();
      } catch (error) {
        stopCamera();
        const message = error.name === 'NotAllowedError' ? 'Camera permission was denied.' : error.name === 'NotFoundError' ? 'No camera was found on this device.' : 'Unable to start the camera.';
        setStatus(message, 'bi-exclamation-circle');
        showToast(message, 'error');
      }
    }

    startBtn.addEventListener('click', startCamera);
    stopBtn.addEventListener('click', () => {
      stopCamera();
      setStatus('Camera stopped. Start again to scan another code.', 'bi-stop-circle');
    });
    clearBtn.addEventListener('click', () => {
      stopCamera();
      hasScan = false;
      resultCard.classList.add('hidden-result');
      clearBtn.hidden = true;
      preview.querySelector('img')?.remove();
      setStatus('Scan cleared. Start the camera to scan another QR code.', 'bi-arrow-counterclockwise');
    });
    window.addEventListener('beforeunload', stopCamera, { once: true });
  }

  // Top-level server scan function used by upload and camera fallback
  async function serverScan(fileOrBlob, cameraFrame = false) {
    const loading = document.getElementById('qrLoading');
    const resultCard = document.getElementById('qrResult');

    if (!cameraFrame) loading?.classList.add('active');
    resultCard.classList.add('hidden-result');

    try {
      const fd = new FormData();
      fd.append('qr_image', fileOrBlob, 'frame.png');

      const resp = await fetch('/api/scan-qr', {
        method: 'POST',
        credentials: 'same-origin',
        headers: cameraFrame ? { 'X-QR-Camera': '1' } : {},
        body: fd
      });
      const data = await resp.json().catch(() => ({}));
      if (!cameraFrame) loading?.classList.remove('active');

      if (resp.ok && data.success) {
        renderQrResult({ decoded_data: data.decoded_data, type: data.type, status: data.status, risk_score: data.risk_score, indicators: data.indicators, recommendation: data.recommendation }, resultCard);
        return true;
      } else {
        if (!cameraFrame || !String(data.message || '').toLowerCase().includes('no qr code')) showToast(data.message || 'QR scan failed.', 'error');
        return false;
      }
    } catch (err) {
      if (!cameraFrame) loading?.classList.remove('active');
      showToast('Network error while scanning QR.', 'error');
      return false;
    }
  }

  function renderQrResult(data, resultCard) {
    const score = data.risk_score ?? 0;
    const level = data.status || 'Unknown';
    const cls = level.toLowerCase().includes('safe') ? 'safe' : level.toLowerCase().includes('suspicious') ? 'medium' : 'high';
    const flags = data.indicators || [];
    const recommendation = data.recommendation || '';

    resultCard.classList.remove('hidden-result');
    const decoded = data.decoded_data || '';
    const decodedHtml = decoded ? `<div class="qr-result-content"><span class="result-label">QR Content</span><strong>${escapeHTML(decoded)}</strong></div>` : '';
    const timeHtml = `<div class="qr-result-time"><i class="bi bi-clock"></i> Scanned ${new Date().toLocaleString()}</div>`;
    resultCard.innerHTML = decodedHtml + buildResultMarkup({
      title: 'QR Analysis',
      level,
      cls,
      score,
      flags,
      recommendation
    }) + timeHtml + `<button type="button" class="btn btn-outline-soft btn-sm mt-3" id="inlineClearQrBtn"><i class="bi bi-arrow-counterclockwise me-1"></i>Clear Scan</button>`;
    resultCard.querySelector('#inlineClearQrBtn')?.addEventListener('click', () => document.getElementById('clearQrScanBtn')?.click());
  }

  /* =======================================================
     Link Checker (demo simulation)
  ======================================================= */
  function initLinkChecker() {
    const input =
      document.getElementById('linkInput');

    const checkBtn =
      document.getElementById('checkLinkBtn');

    if (!input || !checkBtn) return;

    const clearBtn =
      document.getElementById('clearLinkBtn');

    const exampleBtn =
      document.getElementById('exampleLinkBtn');

    const loading =
      document.getElementById('linkLoading');

    const resultCard =
      document.getElementById('linkResult');

    exampleBtn?.addEventListener('click', () => {
      input.value = 'http://bit.ly/verify-account-now';
      input.focus();
    });

    clearBtn?.addEventListener('click', () => {
      input.value = '';
      resultCard.classList.add('hidden-result');
    });

    checkBtn.addEventListener('click', async () => {
      const url = input.value.trim();
      if (!url) {
        showToast('Please enter a URL to check.', 'error');
        return;
      }

      // show loading
      loading?.classList.add('active');
      resultCard.classList.add('hidden-result');

      try {
        const resp = await fetch('/api/check-link', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'same-origin',
          body: JSON.stringify({ url })
        });

        const data = await resp.json().catch(() => ({}));
        loading?.classList.remove('active');

        if (resp.ok && data.success) {
          renderLinkResult(data, resultCard);
        } else {
          showToast(data.message || 'Link check failed.', 'error');
        }
      } catch (err) {
        loading?.classList.remove('active');
        showToast('Network error while checking link.', 'error');
      }
    });
  }

  function renderLinkResult(data, resultCard) {
    const score = data.risk_score ?? 0;
    const level = data.status || 'Unknown';
    const cls = level.toLowerCase().includes('safe') ? 'safe' : level.toLowerCase().includes('suspicious') ? 'medium' : 'high';
    const flags = data.indicators || [];
    const recommendation = data.recommendation || '';

    resultCard.classList.remove('hidden-result');
    const displayUrl = data.url || data.decoded_data || '';
    const linkHtml = displayUrl ? `<div class="mb-2"><strong>URL:</strong> <a href="${escapeHTML(displayUrl)}" target="_blank" rel="noopener noreferrer">${escapeHTML(displayUrl)}</a></div>` : '';

    resultCard.innerHTML = linkHtml + buildResultMarkup({
      title: 'Link Analysis',
      level,
      cls,
      score,
      flags,
      recommendation
    });
  }

  // Initialize page-specific behaviors once DOM is ready
  document.addEventListener('DOMContentLoaded', async () => {
    initLogoutButtons();
    const user = await initAuthGuard();
    // Remove the auth-check attribute so interactions resume
    try { document.documentElement.removeAttribute('data-auth-check'); } catch (e) {}
    initUserChip(user);

    // Page-specific initializers
    if (document.getElementById('loginForm')) {
      initLoginForm();
    }

    if (document.getElementById('registerForm')) {
      initRegisterForm();
    }

    if (document.getElementById('statTotalScans')) {
      renderUsersTable();
      initExportButtons();
    }

    if (document.getElementById('smsInput')) {
      initSmsDetector();
    }

    if (document.getElementById('linkInput')) {
      initLinkChecker();
    }

    if (document.getElementById('qrPreviewFrame')) {
      initQrScanner();
    }

    if (document.getElementById('safetyHubPage')) {
      initSafetyHub();
    }
  });

  // Close IIFE
})();