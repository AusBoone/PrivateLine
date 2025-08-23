//
//  DoubleRatchet.swift
//  PrivateLine
//
//  Lightweight symmetric double ratchet matching ``backend/ratchet.py``.
//  Each conversation maintains a 32-byte root key that advances whenever a
//  message is decrypted, providing forward secrecy for data at rest. The
//  encrypted payload is the random 32-byte header concatenated with the
//  AES-GCM ciphertext. The nonce is transmitted separately.
//
//  Usage:
//    let ratchet = DoubleRatchet(rootKey: root)
//    let (cipher, nonce) = try ratchet.encrypt(plain)
//    let msg = try ratchet.decrypt(cipher, nonce: nonce)
//
//  Assumptions:
//  - ``rootKey`` must be exactly 32 bytes
//  - ``nonce`` must be 12 bytes for AES-GCM
//  - ``ciphertext`` is ``header`` (32b) + encrypted bytes + 16b tag
//
import Foundation
import Crypto

/// Stateful symmetric double ratchet used to derive a fresh AES key per message.
/// Mirrors the Python implementation so iOS, Android and the server all derive
/// identical keys.
final class DoubleRatchet {
    /// Current 32-byte root key. Exposed so callers can persist state.
    private(set) var rootKey: Data

    /// Initialise the ratchet with a shared ``rootKey``.
    /// - Parameter rootKey: 32 bytes of secret data.
    init(rootKey: Data) {
        precondition(rootKey.count == 32, "Root key must be 32 bytes")
        self.rootKey = rootKey
    }

    /// Derive an AES-256 key from ``rootKey`` and ``header`` using HKDF.
    /// ``rootKey`` acts as the HKDF salt and the input key material is empty.
    private func deriveKey(header: Data) -> SymmetricKey {
        let ikm = SymmetricKey(data: Data()) // empty input
        let key = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: ikm,
            salt: rootKey,
            info: header,
            outputByteCount: 32
        )
        return key
    }

    /// Encrypt ``plaintext`` and return ``header+ciphertext`` with the nonce.
    /// The root key is not advanced until the peer decrypts the message so both
    /// sides remain in sync.
    func encrypt(_ plaintext: Data) throws -> (ciphertext: Data, nonce: Data) {
        let header = Data((0..<32).map { _ in UInt8.random(in: 0...UInt8.max) })
        let nonceBytes = Data((0..<12).map { _ in UInt8.random(in: 0...UInt8.max) })
        let key = deriveKey(header: header)
        let nonce = try AES.GCM.Nonce(data: nonceBytes)
        let sealed = try AES.GCM.seal(plaintext, using: key, nonce: nonce)
        // ``combined`` would prepend the nonce; we transmit it separately.
        let combined = header + sealed.ciphertext + sealed.tag
        return (combined, nonceBytes)
    }

    /// Decrypt ``ciphertext`` and advance ``rootKey``. Throws when authentication
    /// fails or the inputs are malformed.
    func decrypt(_ ciphertext: Data, nonce: Data) throws -> Data {
        guard ciphertext.count >= 32 else {
            throw NSError(domain: "DoubleRatchet", code: 1,
                          userInfo: [NSLocalizedDescriptionKey: "Ciphertext too short"])
        }
        let header = ciphertext.prefix(32)
        let body = ciphertext.suffix(from: 32)
        guard nonce.count == 12, body.count >= 16 else {
            throw NSError(domain: "DoubleRatchet", code: 2,
                          userInfo: [NSLocalizedDescriptionKey: "Invalid nonce or ciphertext"])
        }
        let key = deriveKey(header: header)
        let nonceObj = try AES.GCM.Nonce(data: nonce)
        let tag = body.suffix(16)
        let ct = body.prefix(body.count - 16)
        let box = try AES.GCM.SealedBox(nonce: nonceObj, ciphertext: ct, tag: tag)
        let plaintext = try AES.GCM.open(box, using: key)
        var hasher = SHA256()
        hasher.update(data: rootKey)
        hasher.update(data: header)
        rootKey = Data(hasher.finalize())
        return plaintext
    }
}
