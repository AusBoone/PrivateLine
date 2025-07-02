// Utility for caching decrypted messages in IndexedDB so the chat interface
// can function offline. Stored messages mirror the shape returned by the API.
// Expired messages are pruned whenever data is loaded or saved so that the
// cache does not retain messages beyond their lifetime.
//
// Usage:
//   const messages = await loadMessages();
//   await saveMessages(messagesArray);

const DB_NAME = 'privateline-msgs';
const DB_VERSION = 1;
const STORE_NAME = 'messages';

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

export async function saveMessages(msgs) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite');
    const store = tx.objectStore(STORE_NAME);
    const filtered = msgs.filter(
      (m) => !(m.expires_at && new Date(m.expires_at) <= new Date())
    );
    store.put(filtered, 'list');
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

export async function loadMessages() {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readonly');
    const store = tx.objectStore(STORE_NAME);
    const req = store.get('list');
    req.onsuccess = () => {
      const msgs = req.result || [];
      const filtered = msgs.filter(
        (m) => !(m.expires_at && new Date(m.expires_at) <= new Date())
      );
      resolve(filtered);
    };
    req.onerror = () => reject(req.error);
  });
}
