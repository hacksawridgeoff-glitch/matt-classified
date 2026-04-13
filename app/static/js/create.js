/**
 * create.js — страница создания записки (/).
 *
 * Зависимости:
 *   - crypto.js  (ES module, не изменять)
 *   - modal.js   (openModal / closeModal)
 *
 * Правила безопасности:
 *   - Пароль хранится только в памяти (переменная _password).
 *   - Никаких console.log с plaintext, паролем, ключами.
 *   - Никаких localStorage / sessionStorage.
 */

import { encryptNote } from './crypto.js';
import { openModal, closeModal } from './modal.js';

// ----------------------------------------------------------------
// State
// ----------------------------------------------------------------
let _ttlSeconds = 86400;   // default: 1 день
let _password   = null;    // null = без пароля

const MAX_CHARS = 100_000;

// TTL labels for badge + result card
const TTL_LABELS = {
  900:     '15 минут',
  3600:    '1 час',
  86400:   '1 день',
  604800:  '7 дней',
  2592000: '30 дней',
};

// ----------------------------------------------------------------
// Elements
// ----------------------------------------------------------------
const textarea      = document.getElementById('note-textarea');
const charCounter   = document.getElementById('char-counter');
const btnCreate     = document.getElementById('btn-create');
const createSection = document.getElementById('create-section');
const resultSection = document.getElementById('result-section');
const createError   = document.getElementById('create-error');
const fabGroup      = document.getElementById('fab-group');

const ttlBadge      = document.getElementById('ttl-badge');
const passwordBadge = document.getElementById('password-badge');
const btnTTL        = document.getElementById('btn-ttl');
const btnPassword   = document.getElementById('btn-password');

const resultUrl     = document.getElementById('result-url');
const resultTTLText = document.getElementById('result-ttl-text');
const btnCopyLink   = document.getElementById('btn-copy-link');
const btnNewNote    = document.getElementById('btn-new-note');

// TTL sheet
const ttlRadios     = document.querySelectorAll('input[name="ttl"]');

// Password sheet
const pwdInput      = document.getElementById('pwd-input');
const pwdConfirm    = document.getElementById('pwd-confirm');
const pwdError      = document.getElementById('pwd-error');
const btnSavePwd    = document.getElementById('btn-save-password');
const btnRemovePwd  = document.getElementById('btn-remove-password');

// ----------------------------------------------------------------
// Char counter
// ----------------------------------------------------------------
function updateCounter() {
  const len = textarea.value.length;
  const fmt = len.toLocaleString('ru-RU');
  charCounter.textContent = `${fmt} / 100 000`;
  charCounter.classList.toggle('over-limit', len > MAX_CHARS);
  btnCreate.disabled = len === 0 || len > MAX_CHARS;
}

textarea.addEventListener('input', updateCounter);
updateCounter();

// ----------------------------------------------------------------
// TTL bottom sheet
// ----------------------------------------------------------------
btnTTL.addEventListener('click', () => openModal('modal-ttl', btnTTL));

ttlRadios.forEach(radio => {
  radio.addEventListener('change', () => {
    _ttlSeconds = parseInt(radio.value, 10);
    ttlBadge.textContent = TTL_LABELS[_ttlSeconds] ?? '?';
    closeModal('modal-ttl');
  });
});

// ----------------------------------------------------------------
// Password bottom sheet
// ----------------------------------------------------------------
btnPassword.addEventListener('click', () => {
  // Pre-fill if password already set
  pwdInput.value    = '';
  pwdConfirm.value  = '';
  _hidePwdError();
  openModal('modal-password', btnPassword);
});

function _hidePwdError() {
  pwdError.style.display = 'none';
  pwdError.textContent   = '';
}

function _showPwdError(msg) {
  pwdError.textContent   = msg;
  pwdError.style.display = 'block';
}

btnSavePwd.addEventListener('click', () => {
  const p1 = pwdInput.value;
  const p2 = pwdConfirm.value;

  if (!p1) {
    _showPwdError('Введите пароль.');
    pwdInput.focus();
    return;
  }
  if (p1 !== p2) {
    _showPwdError('Пароли не совпадают.');
    pwdConfirm.focus();
    return;
  }

  _password = p1;
  _applyPasswordState();
  closeModal('modal-password');
});

btnRemovePwd.addEventListener('click', () => {
  _password = null;
  _applyPasswordState();
  closeModal('modal-password');
});

// Enter inside password fields → save
[pwdInput, pwdConfirm].forEach(el => {
  el.addEventListener('keydown', e => {
    if (e.key === 'Enter') btnSavePwd.click();
  });
});

function _applyPasswordState() {
  const hasPassword = _password !== null;
  btnPassword.classList.toggle('active', hasPassword);
  passwordBadge.style.display = hasPassword ? '' : 'none';
}

// ----------------------------------------------------------------
// Create note
// ----------------------------------------------------------------
btnCreate.addEventListener('click', _handleCreate);

async function _handleCreate() {
  const text = textarea.value;
  if (!text || text.length > MAX_CHARS) return;

  _hideCreateError();
  _setCreating(true);

  try {
    const { payload, fragment } = await encryptNote(text, _password || null);

    const resp = await fetch('/api/notes', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        ciphertext:  payload.ciphertext,
        iv:          payload.iv,
        has_password: payload.has_password,
        ttl_seconds: _ttlSeconds,
      }),
    });

    if (resp.status === 201) {
      const data = await resp.json();
      const url  = `${location.origin}/n/${data.id}#${fragment}`;
      _showResult(url);
    } else if (resp.status === 429) {
      _showCreateError('Слишком много запросов. Подождите немного и попробуйте снова.');
      _setCreating(false);
    } else if (resp.status === 503) {
      _showCreateError('Сервис временно недоступен. Попробуйте через несколько секунд.');
      _setCreating(false);
    } else {
      _showCreateError('Не удалось создать записку. Попробуйте ещё раз.');
      _setCreating(false);
    }
  } catch (_err) {
    _showCreateError('Ошибка соединения. Проверьте подключение и попробуйте ещё раз.');
    _setCreating(false);
  }
}

function _setCreating(loading) {
  btnCreate.disabled = loading;
  btnCreate.innerHTML = loading
    ? '<span class="spinner" aria-hidden="true"></span> Создаём…'
    : '&gt; создать записку';
}

function _showCreateError(msg) {
  createError.textContent   = msg;
  createError.style.display = 'block';
}

function _hideCreateError() {
  createError.textContent   = '';
  createError.style.display = 'none';
}

// ----------------------------------------------------------------
// Show result card
// ----------------------------------------------------------------
function _showResult(url) {
  // Fade out create form + FABs
  createSection.classList.add('fade-out');
  fabGroup.classList.add('fade-out');
  btnCreate.style.display = 'none';

  setTimeout(() => {
    createSection.style.display = 'none';
    fabGroup.style.display      = 'none';

    resultUrl.textContent       = url;
    resultTTLText.textContent   = TTL_LABELS[_ttlSeconds] ?? `${_ttlSeconds} с`;
    resultSection.style.display = 'flex';
    resultSection.classList.add('fade-in');

    // Focus the copy button for keyboard users
    btnCopyLink.focus();
  }, 150);
}

// ----------------------------------------------------------------
// Copy link button
// ----------------------------------------------------------------
btnCopyLink.addEventListener('click', async () => {
  const url = resultUrl.textContent;
  if (!url) return;

  try {
    await navigator.clipboard.writeText(url);
    const orig = btnCopyLink.textContent;
    btnCopyLink.textContent = 'Скопировано ✓';
    btnCopyLink.disabled    = true;
    setTimeout(() => {
      btnCopyLink.textContent = orig;
      btnCopyLink.disabled    = false;
    }, 2000);
  } catch (_err) {
    // Fallback: select the text for manual copy
    const range = document.createRange();
    range.selectNode(resultUrl);
    window.getSelection()?.removeAllRanges();
    window.getSelection()?.addRange(range);
  }
});

// ----------------------------------------------------------------
// "Create another" button — reset to initial state
// ----------------------------------------------------------------
btnNewNote.addEventListener('click', () => {
  // Reset state
  _password   = null;
  _ttlSeconds = 86400;

  textarea.value = '';
  updateCounter();
  _applyPasswordState();
  ttlBadge.textContent = TTL_LABELS[86400];

  // Reset TTL radio
  const defaultRadio = document.querySelector('input[name="ttl"][value="86400"]');
  if (defaultRadio) defaultRadio.checked = true;

  // Hide result, show create
  resultSection.style.display  = 'none';
  resultSection.classList.remove('fade-in');

  createSection.style.display  = '';
  createSection.classList.remove('fade-out');
  fabGroup.style.display       = '';
  fabGroup.classList.remove('fade-out');
  btnCreate.style.display      = '';
  btnCreate.disabled           = true;
  btnCreate.innerHTML          = '&gt; создать записку';

  _hideCreateError();
  textarea.focus();
});
