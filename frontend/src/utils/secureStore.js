const DB_NAME = 'privateline';
const DB_VERSION = 2;
const STORE_NAME = 'keyMaterial';

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

export async function saveKeyMaterial({ encrypted_private_key, salt, nonce, fingerprint }) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite');
    const store = tx.objectStore(STORE_NAME);
    const req = store.put({ encrypted_private_key, salt, nonce, fingerprint }, 'material');
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(req.error);
  });
}

export async function loadKeyMaterial() {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readonly');
    const store = tx.objectStore(STORE_NAME);
    const req = store.get('material');
    req.onsuccess = () => resolve(req.result || {});
    req.onerror = () => reject(req.error);
  });
}
