/*
 * secureStore.js - Lightweight wrapper around IndexedDB for secure key storage.
 *
 * This module persists the encrypted private key material generated during user
 * registration. By centralising IndexedDB interactions, callers can simply
 * `await` the exported functions without worrying about transactions or event
 * wiring. The file now distinguishes between transaction-level failures and
 * individual request errors to make debugging storage issues easier.
 *
 * Example usage:
 *   await saveKeyMaterial({
 *     encrypted_private_key: '...',
 *     salt: '...',
 *     nonce: '...',
 *     fingerprint: '...',
 *   });
 *   const material = await loadKeyMaterial();
 *
 * Assumptions:
 *   - Only a single "material" record is stored.
 *   - Runs in a browser environment with IndexedDB support.
 */

const DB_NAME = 'privateline';
const DB_VERSION = 2;
const STORE_NAME = 'keyMaterial';

/**
 * Open (or create) the IndexedDB store used to persist encrypted key material.
 *
 * The IndexedDB API is event based; this helper wraps it in a Promise so the
 * rest of the module can use async/await. The database contains a single object
 * store keyed by the string "material".
 *
 * @returns {Promise<IDBDatabase>} Resolves with an opened database instance.
 */
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
 * Persist encrypted key material returned during registration.
 *
 * @param {Object} params - Object containing the encrypted key material.
 * @param {string} params.encrypted_private_key - The ciphertext of the private key.
 * @param {string} params.salt - Salt used during key derivation.
 * @param {string} params.nonce - Nonce used for encryption.
 * @param {string} params.fingerprint - Key fingerprint for validation.
 * @returns {Promise<void>} Resolves once the material is written to disk.
 */
/* eslint camelcase: "off" */
export async function saveKeyMaterial({
  encrypted_private_key,
  salt,
  nonce,
  fingerprint,
}) {
  // Basic validation so callers get an immediate, descriptive error rather than
  // an opaque IndexedDB failure.
  if (!encrypted_private_key || !salt || !nonce || !fingerprint) {
    throw new Error('All key material fields must be provided');
  }

  const db = await openDB();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(STORE_NAME, 'readwrite');
    const store = transaction.objectStore(STORE_NAME);
    const request = store.put(
      {
        encrypted_private_key,
        salt,
        nonce,
        fingerprint,
      },
      'material',
    );

    transaction.oncomplete = () => resolve();

    // Handles failures affecting the whole transaction (e.g. aborts or quota
    // exceeded). "transaction.error" is preferred over "request.error" here
    // because the failing request may not be the one we initiated.
    transaction.onerror = () => reject(transaction.error);

    // Handles errors specific to the put() request such as data constraints.
    request.onerror = () => reject(request.error);
  });
}

/**
 * Load previously stored key material used to decrypt the private key.
 *
 * @returns {Promise<Object>} Resolves with the stored key material or an empty
 * object if nothing has been saved yet.
 */
export async function loadKeyMaterial() {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(STORE_NAME, 'readonly');
    const store = transaction.objectStore(STORE_NAME);
    const request = store.get('material');

    request.onsuccess = () => resolve(request.result || {});

    // Propagate errors encountered while reading from the object store.
    request.onerror = () => reject(request.error);
  });
}
