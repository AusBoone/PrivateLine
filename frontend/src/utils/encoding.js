/**
 * Convert an ArrayBuffer to a base64 encoded string.
 *
 * This is used when encrypting data with the Web Crypto API so the
 * ciphertext can be transmitted as text.
 *
 * @param {ArrayBuffer} buffer - Raw binary data to encode.
 * @returns {string} Base64 representation of ``buffer``.
 */
export function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  bytes.forEach((b) => {
    binary += String.fromCharCode(b);
  });
  return btoa(binary);
}

/**
 * Decode a base64 string back into an ArrayBuffer.
 *
 * @param {string} b64 - Base64 encoded data.
 * @returns {Uint8Array} The decoded bytes.
 */
export function base64ToArrayBuffer(b64) {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Convert a base64url string to a Uint8Array.
 *
 * This helper is primarily used when subscribing to Web Push so the
 * VAPID public key can be provided in binary form.
 */
export function urlB64ToUint8Array(b64) {
  const padding = '='.repeat((4 - (b64.length % 4)) % 4);
  const base64 = (b64 + padding).replace(/-/g, '+').replace(/_/g, '/');
  const raw = atob(base64);
  const output = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; ++i) {
    output[i] = raw.charCodeAt(i);
  }
  return output;
}
