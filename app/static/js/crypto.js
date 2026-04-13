/**
 * Matt // Classified — Crypto Module
 * =====================================
 * ВНИМАНИЕ ДЛЯ PERPLEXITY: этот файл используется КАК ЕСТЬ.
 * НЕ МОДИФИЦИРОВАТЬ логику шифрования. Только импортировать и вызывать.
 *
 * Схема:
 *   - AES-256-GCM для шифрования содержимого
 *   - Случайный 256-битный ключ генерируется на клиенте для каждой записки
 *   - Ключ кодируется в base64url и помещается в URL fragment (#)
 *   - Если задан пароль: дополнительный слой шифрования через PBKDF2 (600000 итераций, SHA-256)
 *   - Все операции — через Web Crypto API (встроено в браузер, не сторонняя библиотека)
 *
 * Формат фрагмента URL:
 *   Без пароля:   #<base64url_key>
 *   С паролем:    #p:<base64url_salt>:<base64url_wrapped_payload_marker>
 *     (наличие префикса "p:" сигнализирует фронтенду запросить пароль)
 *
 * Формат payload, отправляемого на сервер (JSON):
 *   {
 *     "ciphertext": "<base64url>",  // AES-GCM ciphertext (включает auth tag)
 *     "iv": "<base64url>",           // 12 байт
 *     "has_password": true/false
 *   }
 */

// ---------- Base64url helpers ----------

function bytesToBase64url(bytes) {
  let bin = '';
  for (let i = 0; i < bytes.byteLength; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64urlToBytes(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  const bin = atob(str);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

// ---------- Key generation ----------

async function generateKey() {
  return await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
}

async function exportKey(key) {
  const raw = await crypto.subtle.exportKey('raw', key);
  return bytesToBase64url(new Uint8Array(raw));
}

async function importKey(base64urlKey) {
  const raw = base64urlToBytes(base64urlKey);
  return await crypto.subtle.importKey(
    'raw', raw, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
  );
}

// ---------- Password-based key derivation ----------

async function deriveKeyFromPassword(password, salt) {
  const enc = new TextEncoder();
  const passKey = await crypto.subtle.importKey(
    'raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']
  );
  return await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-256' },
    passKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

// ---------- Public API ----------

/**
 * Шифрует текст записки.
 * @param {string} plaintext — исходный текст
 * @param {string|null} password — опциональный пароль
 * @returns {Promise<{payload: object, fragment: string}>}
 *   payload — JSON для отправки на сервер
 *   fragment — строка, которую нужно поставить после # в URL
 */
export async function encryptNote(plaintext, password = null) {
  const enc = new TextEncoder();
  const plaintextBytes = enc.encode(plaintext);

  const key = await generateKey();
  const iv = crypto.getRandomValues(new Uint8Array(12));

  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv }, key, plaintextBytes
  ));

  const payload = {
    ciphertext: bytesToBase64url(ciphertext),
    iv: bytesToBase64url(iv),
    has_password: !!password,
  };

  const rawKeyB64 = await exportKey(key);

  if (!password) {
    return { payload, fragment: rawKeyB64 };
  }

  // Password layer: wrap the raw key with PBKDF2-derived key
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const wrapKey = await deriveKeyFromPassword(password, salt);
  const wrapIv = crypto.getRandomValues(new Uint8Array(12));
  const keyBytes = base64urlToBytes(rawKeyB64);
  const wrappedKey = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: wrapIv }, wrapKey, keyBytes
  ));

  // Fragment carries: marker + salt + wrapIv + wrappedKey
  const fragment = 'p:' + bytesToBase64url(salt) + ':' +
                    bytesToBase64url(wrapIv) + ':' +
                    bytesToBase64url(wrappedKey);

  return { payload, fragment };
}

/**
 * Расшифровывает записку.
 * @param {object} serverData — {ciphertext, iv, has_password} из ответа сервера
 * @param {string} fragment — содержимое после # из URL (без самого #)
 * @param {string|null} password — пароль, если has_password=true
 * @returns {Promise<string>} — расшифрованный текст
 * @throws Error если пароль неверный или данные повреждены
 */
export async function decryptNote(serverData, fragment, password = null) {
  let key;

  if (fragment.startsWith('p:')) {
    if (!password) throw new Error('PASSWORD_REQUIRED');
    const parts = fragment.slice(2).split(':');
    if (parts.length !== 3) throw new Error('BAD_FRAGMENT');
    const [saltB64, wrapIvB64, wrappedKeyB64] = parts;
    const salt = base64urlToBytes(saltB64);
    const wrapIv = base64urlToBytes(wrapIvB64);
    const wrappedKey = base64urlToBytes(wrappedKeyB64);
    const wrapKey = await deriveKeyFromPassword(password, salt);
    let rawKeyBytes;
    try {
      rawKeyBytes = new Uint8Array(await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: wrapIv }, wrapKey, wrappedKey
      ));
    } catch (e) {
      throw new Error('BAD_PASSWORD');
    }
    key = await crypto.subtle.importKey(
      'raw', rawKeyBytes, { name: 'AES-GCM', length: 256 }, false, ['decrypt']
    );
  } else {
    key = await importKey(fragment);
  }

  const ciphertext = base64urlToBytes(serverData.ciphertext);
  const iv = base64urlToBytes(serverData.iv);

  const plaintextBytes = new Uint8Array(await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv }, key, ciphertext
  ));

  return new TextDecoder().decode(plaintextBytes);
}

/**
 * Определяет, требует ли фрагмент пароль — без попытки расшифровки.
 * Используется, чтобы показать пользователю поле ввода пароля.
 */
export function fragmentRequiresPassword(fragment) {
  return fragment.startsWith('p:');
}
