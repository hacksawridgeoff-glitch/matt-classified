/**
 * view.js — страница просмотра записки (/n/{id}).
 */

import { decryptNote, fragmentRequiresPassword } from './crypto.js';

const STATES = [
  'state-initial',
  'state-password',
  'state-loading',
  'state-revealed',
  'state-not-found',
  'state-error',
];

function _show(id) {
  STATES.forEach(s => {
    const el = document.getElementById(s);
    if (!el) return;
    if (s === id) {
      el.style.display = '';
      el.classList.add('fade-in');
    } else {
      el.style.display = 'none';
      el.classList.remove('fade-in');
    }
  });
}

const _noteId = location.pathname.split('/n/')[1]?.split('/')[0] ?? '';
const _rawFragment = location.hash.slice(1);

if (!_rawFragment || !_noteId) {
  _show('state-not-found');
} else {
  _show('state-loading');
  _checkExistence();
}

async function _checkExistence() {
  try {
    const resp = await fetch(`/api/notes/${encodeURIComponent(_noteId)}/exists`);
    if (resp.status === 404) {
      _show('state-not-found');
    } else {
      _show('state-initial');
    }
  } catch (_e) {
    _show('state-initial');
  }
}

const btnShow        = document.getElementById('btn-show');
const btnDecryptPwd  = document.getElementById('btn-decrypt-pwd');
const viewPwdInput   = document.getElementById('view-pwd-input');
const viewPwdError   = document.getElementById('view-pwd-error');
const noteTextEl     = document.getElementById('note-text-content');
const btnCopyText    = document.getElementById('btn-copy-text');
const btnRetry       = document.getElementById('btn-retry');

if (btnShow) {
  btnShow.addEventListener('click', _onShowClick);
}

function _onShowClick() {
  if (!_rawFragment || !_noteId) {
    _show('state-not-found');
    return;
  }
  if (fragmentRequiresPassword(_rawFragment)) {
    _show('state-password');
    requestAnimationFrame(() => viewPwdInput?.focus());
  } else {
    _fetchAndDecrypt(null);
  }
}

if (btnDecryptPwd) {
  btnDecryptPwd.addEventListener('click', _onPasswordSubmit);
}

if (viewPwdInput) {
  viewPwdInput.addEventListener('keydown', e => {
    if (e.key === 'Enter') _onPasswordSubmit();
  });
}

function _onPasswordSubmit() {
  const pwd = viewPwdInput?.value ?? '';
  if (!pwd) {
    _showPwdError('Введите пароль.');
    viewPwdInput?.focus();
    return;
  }
  _hidePwdError();
  _fetchAndDecrypt(pwd);
}

function _showPwdError(msg) {
  if (!viewPwdError) return;
  viewPwdError.textContent   = msg;
  viewPwdError.style.display = 'block';
}

function _hidePwdError() {
  if (!viewPwdError) return;
  viewPwdError.textContent   = '';
  viewPwdError.style.display = 'none';
}

if (btnRetry) {
  btnRetry.addEventListener('click', () => {
    if (_lastPassword !== undefined) {
      _fetchAndDecrypt(_lastPassword);
    } else {
      _onShowClick();
    }
  });
}

let _lastPassword;

async function _fetchAndDecrypt(password) {
  _lastPassword = password;
  _show('state-loading');

  let serverData;

  try {
    const resp = await fetch(`/api/notes/${encodeURIComponent(_noteId)}`);
    if (resp.status === 404) {
      _show('state-not-found');
      return;
    }
    if (!resp.ok) {
      _show('state-error');
      return;
    }
    serverData = await resp.json();
  } catch (_networkErr) {
    _show('state-error');
    return;
  }

  try {
    const plaintext = await decryptNote(serverData, _rawFragment, password);
    _renderNote(plaintext);
  } catch (err) {
    const msg = err?.message ?? '';
    if (msg === 'BAD_PASSWORD') {
      _show('state-password');
      _showPwdError('Неверный пароль.');
      viewPwdInput?.focus();
    } else {
      _show('state-not-found');
    }
  }
}

function _renderNote(plaintext) {
  if (noteTextEl) {
    noteTextEl.textContent = plaintext;
  }
  _show('state-revealed');
  requestAnimationFrame(() => btnCopyText?.focus());
}

if (btnCopyText) {
  btnCopyText.addEventListener('click', async () => {
    const text = noteTextEl?.textContent ?? '';
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      const orig = btnCopyText.textContent;
      btnCopyText.textContent = 'Скопировано ✓';
      btnCopyText.disabled    = true;
      setTimeout(() => {
        btnCopyText.textContent = orig;
        btnCopyText.disabled    = false;
      }, 2000);
    } catch (_err) {
      const range = document.createRange();
      range.selectNode(noteTextEl);
      window.getSelection()?.removeAllRanges();
      window.getSelection()?.addRange(range);
    }
  });
}
