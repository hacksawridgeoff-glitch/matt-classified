/**
 * modal.js — shared modal / bottom-sheet logic.
 *
 * Exports: openModal(id), closeModal(id)
 * Used by both create.js and view.js.
 *
 * Behaviour:
 *   - Opens overlay by adding class "open".
 *   - Traps focus inside sheet while open.
 *   - Closes on: close button click, overlay click, Escape key.
 *   - Returns focus to the trigger element on close.
 *   - Handles the "Почему это безопасно?" modal on both pages.
 */

const FOCUSABLE = [
  'a[href]',
  'button:not([disabled])',
  'input:not([disabled])',
  'select:not([disabled])',
  'textarea:not([disabled])',
  '[tabindex]:not([tabindex="-1"])',
].join(',');

const _triggers = new Map(); // modalId → element that opened it

export function openModal(id, trigger = null) {
  const overlay = document.getElementById(id);
  if (!overlay) return;

  _triggers.set(id, trigger || document.activeElement);
  overlay.classList.add('open');

  const sheet = overlay.querySelector('.sheet');
  if (sheet) {
    // Move focus into the sheet
    requestAnimationFrame(() => {
      const first = sheet.querySelector(FOCUSABLE);
      if (first) first.focus();
      else sheet.focus();
    });
  }

  // Prevent body scroll
  document.body.style.overflow = 'hidden';
}

export function closeModal(id) {
  const overlay = document.getElementById(id);
  if (!overlay) return;

  overlay.classList.remove('open');
  document.body.style.overflow = '';

  // Return focus
  const trigger = _triggers.get(id);
  if (trigger && trigger.focus) {
    requestAnimationFrame(() => trigger.focus());
  }
  _triggers.delete(id);
}

function _trapFocus(overlay, e) {
  const sheet = overlay.querySelector('.sheet');
  if (!sheet) return;
  const focusable = Array.from(sheet.querySelectorAll(FOCUSABLE));
  if (!focusable.length) return;

  const first = focusable[0];
  const last  = focusable[focusable.length - 1];

  if (e.shiftKey) {
    if (document.activeElement === first) { e.preventDefault(); last.focus(); }
  } else {
    if (document.activeElement === last)  { e.preventDefault(); first.focus(); }
  }
}

function _initModal(overlay) {
  const id = overlay.id;

  // Close button(s) inside the sheet
  overlay.querySelectorAll('.sheet-close').forEach(btn => {
    btn.addEventListener('click', () => closeModal(id));
  });

  // Click on overlay backdrop (not on sheet)
  overlay.addEventListener('click', e => {
    if (e.target === overlay) closeModal(id);
  });

  // Escape key + focus trap
  overlay.addEventListener('keydown', e => {
    if (e.key === 'Escape') { e.preventDefault(); closeModal(id); }
    if (e.key === 'Tab')    _trapFocus(overlay, e);
  });
}

// ----------------------------------------------------------------
// Auto-init all overlays present in the DOM
// ----------------------------------------------------------------
document.querySelectorAll('.overlay').forEach(_initModal);

// ----------------------------------------------------------------
// Safety modal triggers (shared by both pages)
// ----------------------------------------------------------------
function _openSafety(trigger) {
  openModal('modal-safety', trigger);
}

const btnHelp      = document.getElementById('btn-help');
const footerVerify = document.getElementById('footer-verify');

if (btnHelp) btnHelp.addEventListener('click', e => _openSafety(e.currentTarget));

if (footerVerify) {
  footerVerify.addEventListener('click', e => {
    e.preventDefault();
    _openSafety(e.currentTarget);
  });
}

// Intercept anchor #how-to-verify on page load (deep link from footer)
if (window.location.hash === '#how-to-verify') {
  window.addEventListener('DOMContentLoaded', () => _openSafety(null), { once: true });
}
