"use strict";
// groupKeyStore.js - Lightweight persistence layer for AES group chat keys.
//
// Stores base64 encoded symmetric keys in IndexedDB so encrypted group messages
// remain decryptable after the browser is closed. The storage format mirrors
// the Android and iOS implementations for cross-platform compatibility.
//
// Usage example:
//   await saveKey(1, "base64key");
//   const b64 = await loadKey(1);
//   const all = await exportAll();

const DB_NAME = "privateline-group-keys";
const DB_VERSION = 1;
const STORE = "keys";

/** Open or create the IndexedDB used for persistence. */
function openDB() {
  return new Promise((resolve, reject) => {
    const req = window.indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE)) {
        db.createObjectStore(STORE);
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

/** Persist ``b64`` as the key for ``groupId``. */
export async function saveKey(groupId, b64) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readwrite");
    tx.objectStore(STORE).put(b64, groupId);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

/** Load the base64 key for ``groupId`` if present. */
export async function loadKey(groupId) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readonly");
    const req = tx.objectStore(STORE).get(groupId);
    req.onsuccess = () => resolve(req.result || null);
    req.onerror = () => reject(req.error);
  });
}

/** Delete the persisted key for ``groupId``. */
export async function deleteKey(groupId) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readwrite");
    tx.objectStore(STORE).delete(groupId);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

/** Return an array of group IDs with stored keys. */
export async function listGroupIds() {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readonly");
    const req = tx.objectStore(STORE).getAllKeys();
    req.onsuccess = () => resolve(req.result || []);
    req.onerror = () => reject(req.error);
  });
}

/** Remove every persisted key. */
export async function clearAll() {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readwrite");
    tx.objectStore(STORE).clear();
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

/** Export all stored keys as an object mapping id to base64 string. */
export async function exportAll() {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readonly");
    const store = tx.objectStore(STORE);
    const req = store.getAllKeys();
    const out = {};
    req.onsuccess = async () => {
      const keys = req.result || [];
      for (const id of keys) {
        // eslint-disable-next-line no-await-in-loop
        out[id] = await new Promise((res, rej) => {
          const r = store.get(id);
          r.onsuccess = () => res(r.result);
          r.onerror = () => rej(r.error);
        });
      }
      resolve(out);
    };
    req.onerror = () => reject(req.error);
  });
}
