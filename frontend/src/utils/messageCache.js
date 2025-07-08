/**
 * Encrypted offline message cache.
 *
 * This module stores decrypted message history in IndexedDB so the chat
 * interface remains usable without network access. The cached messages are
 * encrypted using a key derived from a user provided password or per-device
 * secret. Messages with an ``expires_at`` timestamp in the past are removed on
 * save and load. ``loadMessages`` additionally accepts a TTL to drop messages
 * that have been stored for longer than desired.
 *
 * Example usage:
 *   await initCacheSecret('myPassword');
 *   await saveMessages(messagesArray);
 *   const msgs = await loadMessages({ ttlMs: 86400000 });
 */

import { arrayBufferToBase64, base64ToArrayBuffer } from './encoding';

const DB_NAME = 'privateline-msgs';
const DB_VERSION = 1;
const STORE_NAME = 'messages';

let aesKey = null; // Derived encryption key used for AES-GCM operations.

function openDB() {
  return new Promise((resolve, reject) => {
    const request = window.indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME);
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

/**
 * Derive and store the AES-GCM key used for encrypting cached messages.
 *
 * The key is derived from ``secret`` using PBKDF2 with a persistent per-device
 * salt stored in ``localStorage``. This function must be called before any
 * messages are saved or loaded.
 *
 * @param {string} secret - Password or device specific secret.
 * @returns {Promise<void>} Resolves once the key material has been derived.
 */
export async function initCacheSecret(secret) {
  if (!secret) throw new Error('Secret required');
  let saltB64 = window.localStorage.getItem('msg_cache_salt');
  if (!saltB64) {
    const saltBytes = window.crypto.getRandomValues(new Uint8Array(16));
    saltB64 = arrayBufferToBase64(saltBytes);
    window.localStorage.setItem('msg_cache_salt', saltB64);
  }
  const salt = base64ToArrayBuffer(saltB64);
  const material = await window.crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    'PBKDF2',
    false,
    ['deriveKey'],
  );
  aesKey = await window.crypto.subtle.deriveKey(
    {
      name: 'PBKDF2', salt, iterations: 200000, hash: 'SHA-256',
    },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

function ensureKey() {
  if (!aesKey) {
    throw new Error('Cache secret not initialized');
  }
}

export async function saveMessages(msgs) {
  ensureKey();
  const db = await openDB();
  const filtered = msgs.filter(
    (m) => !(m.expires_at && new Date(m.expires_at) <= new Date()),
  );
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(JSON.stringify(filtered));
  const buf = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    aesKey,
    encoded,
  );
  const record = {
    iv: arrayBufferToBase64(iv),
    ciphertext: arrayBufferToBase64(buf),
    ts: Date.now(),
  };
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite');
    tx.objectStore(STORE_NAME).put(record, 'list');
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

export async function loadMessages(options = {}) {
  ensureKey();
  const { ttlMs } = options;
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readonly');
    const store = tx.objectStore(STORE_NAME);
    const req = store.get('list');
    req.onsuccess = async () => {
      try {
        const record = req.result;
        if (!record || !record.ciphertext) {
          resolve([]);
          return;
        }
        if (ttlMs && record.ts && Date.now() - record.ts > ttlMs) {
          // Remove stale cache entry
          const delTx = db.transaction(STORE_NAME, 'readwrite');
          delTx.objectStore(STORE_NAME).delete('list');
          resolve([]);
          return;
        }
        const iv = base64ToArrayBuffer(record.iv);
        const ct = base64ToArrayBuffer(record.ciphertext);
        const buf = await window.crypto.subtle.decrypt(
          { name: 'AES-GCM', iv },
          aesKey,
          ct,
        );
        const json = new TextDecoder().decode(buf);
        const msgs = JSON.parse(json);
        const filtered = msgs.filter(
          (m) => !(m.expires_at && new Date(m.expires_at) <= new Date()),
        );
        resolve(filtered);
      } catch (e) {
        reject(e);
      }
    };
    req.onerror = () => reject(req.error);
  });
}
