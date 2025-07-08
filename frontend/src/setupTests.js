import 'fake-indexeddb/auto';

if (typeof global.structuredClone !== 'function') {
  global.structuredClone = (val) => JSON.parse(JSON.stringify(val));
}

// Provide a minimal WebCrypto implementation for modules relying on
// ``window.crypto.subtle`` during tests. Node exposes ``webcrypto``
// which mirrors the browser API sufficiently for our usage.
if (!global.crypto) {
  // eslint-disable-next-line global-require
  global.crypto = require('crypto').webcrypto;
  global.window.crypto = global.crypto;
}
