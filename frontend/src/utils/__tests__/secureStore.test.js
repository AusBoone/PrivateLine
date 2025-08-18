/*
 * secureStore.test.js - Verify secureStore IndexedDB error propagation.
 *
 * These tests simulate failure scenarios to ensure that saveKeyMaterial
 * surfaces both transaction-level and request-level errors. A minimal
 * mock IndexedDB implementation triggers the respective onerror handlers.
 */

import { saveKeyMaterial } from '../secureStore';

describe('saveKeyMaterial error handling', () => {
  // Valid key material used across tests. Actual values are irrelevant.
  const material = {
    encrypted_private_key: 'key',
    salt: 'salt',
    nonce: 'nonce',
    fingerprint: 'fp',
  };

  // Preserve the real IndexedDB so our mocks do not affect other tests.
  const realIndexedDB = window.indexedDB;
  afterEach(() => {
    window.indexedDB = realIndexedDB;
  });

  test('rejects with transaction.error when transaction fails', async () => {
    // Simulate a transaction failure by invoking onerror on the transaction.
    window.indexedDB = {
      open: () => {
        const openRequest = {};
        setTimeout(() => {
          const db = {
            transaction: () => {
              const transaction = {
                objectStore: () => ({
                  put: () => ({}), // Request succeeds; failure is on the transaction.
                }),
              };
              setTimeout(() => {
                transaction.error = new Error('tx fail');
                if (transaction.onerror) transaction.onerror();
              }, 0);
              return transaction;
            },
          };
          openRequest.result = db;
          if (openRequest.onsuccess) openRequest.onsuccess();
        }, 0);
        return openRequest;
      },
    };

    await expect(saveKeyMaterial(material)).rejects.toThrow('tx fail');
  });

  test('rejects with request.error when put request fails', async () => {
    // Simulate a put() request failure before the transaction completes.
    window.indexedDB = {
      open: () => {
        const openRequest = {};
        setTimeout(() => {
          const db = {
            transaction: () => {
              const transaction = {
                objectStore: () => ({
                  put: () => {
                    const putRequest = {};
                    setTimeout(() => {
                      putRequest.error = new Error('req fail');
                      if (putRequest.onerror) putRequest.onerror();
                    }, 0);
                    return putRequest;
                  },
                }),
              };
              return transaction;
            },
          };
          openRequest.result = db;
          if (openRequest.onsuccess) openRequest.onsuccess();
        }, 0);
        return openRequest;
      },
    };

    await expect(saveKeyMaterial(material)).rejects.toThrow('req fail');
  });
});

