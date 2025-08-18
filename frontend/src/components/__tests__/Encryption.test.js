/**
 * Unit tests validating the hybrid RSA-OAEP/AES-GCM helpers. The goal is to
 * ensure that extremely long messages can be encrypted and decrypted without
 * data loss, demonstrating the removal of the previous RSA size limitation.
 */
import { encryptMessage, decryptMessage } from '../Chat';

describe('encryptMessage/decryptMessage', () => {
  it('round-trips messages larger than the RSA limit', async () => {
    const { webcrypto } = require('crypto');
    const originalCrypto = global.crypto;
    const originalWindowCrypto = global.window.crypto;
    // Provide the browser-like crypto implementation expected by the helpers
    // without disturbing other jsdom-provided globals.
    global.crypto = webcrypto;
    global.window.crypto = webcrypto;
    if (!global.TextEncoder) {
      const { TextEncoder, TextDecoder } = require('util');
      global.TextEncoder = TextEncoder;
      global.TextDecoder = TextDecoder;
    }
    const { subtle } = webcrypto;

    // Generate a temporary RSA key pair for the test run.
    const keyPair = await subtle.generateKey(
      {
        name: 'RSA-OAEP',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256',
      },
      true,
      ['encrypt', 'decrypt']
    );

    // Convert the public key into PEM format expected by encryptMessage.
    try {
      const spki = await subtle.exportKey('spki', keyPair.publicKey);
      const b64 = Buffer.from(spki).toString('base64');
      const pem = `-----BEGIN PUBLIC KEY-----\n${b64.match(/.{1,64}/g).join('\n')}\n-----END PUBLIC KEY-----`;

      const longMessage = 'x'.repeat(5000); // intentionally exceed RSA's limit
      const encrypted = await encryptMessage(pem, longMessage);
      const decrypted = await decryptMessage(keyPair.privateKey, encrypted);
      expect(decrypted).toBe(longMessage);
    } finally {
      global.crypto = originalCrypto;
      global.window.crypto = originalWindowCrypto;
    }
  });
});
