// Unit tests for ``APIService`` verifying networking logic such as login,
// message retrieval and token refresh. ``URLSession`` is mocked so the tests do
// not require a live backend server.

import XCTest
import CryptoKit
import Security
@testable import PrivateLine

/// Integration style tests covering ``APIService``. Network calls are mocked so
/// the logic can be verified without a running backend.

/// Minimal ``URLSession`` subclass returning queued responses for each request
/// so tests can simulate network interactions.
final class MockURLSession: URLSession {
    var responses: [(Data, URLResponse)] = []
    private(set) var requests: [URLRequest] = []

    override func data(for request: URLRequest) async throws -> (Data, URLResponse) {
        requests.append(request)
        guard !responses.isEmpty else {
            throw URLError(.badServerResponse)
        }
        return responses.removeFirst()
    }
}

/// Exercises the authentication flow and message endpoints of ``APIService``.
/// RSA keys and HTTP responses are stubbed out so crypto and parsing logic can
/// be tested deterministically.
final class APIServicesTests: XCTestCase {
    var session: MockURLSession!
    var api: APIService!
    var publicPem: String!
    let password = "secret"

    override func setUpWithError() throws {
        session = MockURLSession()
        api = APIService(session: session)
        KeychainService.removeToken()
        KeychainService.removeRefreshToken()

        // Generate ephemeral RSA key pair and store encrypted private key
        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: 2048
        ]
        var error: Unmanaged<CFError>?
        guard let priv = SecKeyCreateRandomKey(attrs as CFDictionary, &error) else {
            throw error!.takeRetainedValue() as Error
        }
        let pub = SecKeyCopyPublicKey(priv)!
        let pubData = SecKeyCopyExternalRepresentation(pub, &error)! as Data
        publicPem = pemString(for: pubData, header: "-----BEGIN PUBLIC KEY-----", footer: "-----END PUBLIC KEY-----")
        let privData = SecKeyCopyExternalRepresentation(priv, &error)! as Data
        let privPem = pemString(for: privData, header: "-----BEGIN PRIVATE KEY-----", footer: "-----END PRIVATE KEY-----")

        let salt = Data((0..<16).map { _ in UInt8.random(in: 0...255) })
        let derived = try deriveKey(password: password, salt: salt)
        let nonce = AES.GCM.Nonce()
        let sealed = try AES.GCM.seal(Data(privPem.utf8), using: derived, nonce: nonce)
        let ciphertext = sealed.ciphertext + sealed.tag
        let material = CryptoManager.KeyMaterial(
            encrypted_private_key: ciphertext.base64EncodedString(),
            salt: salt.base64EncodedString(),
            nonce: Data(sealed.nonce).base64EncodedString(),
            fingerprint: nil)
        CryptoManager.storeKeyMaterial(material)
        try CryptoManager.loadPrivateKey(password: password)
    }

    override func tearDownWithError() throws {
        KeychainService.removeToken()
        KeychainService.removeRefreshToken()
    }

    /// Queue a mocked HTTP response.
    /// - Parameters:
    ///   - json: Body returned to the caller.
    ///   - status: HTTP status code to simulate (defaults to ``200``).
    private func enqueue(json: String, status: Int = 200) {
        let data = json.data(using: .utf8)!
        let resp = HTTPURLResponse(url: URL(string: "http://test")!, statusCode: status, httpVersion: nil, headerFields: nil)!
        session.responses.append((data, resp))
    }

    func testLoginParsesToken() async throws {
        // Successful login should set authToken and isAuthenticated
        enqueue(json: "{\"access_token\":\"abc\",\"refresh_token\":\"ref\"}")
        enqueue(json: "{\"pinned_keys\":[]}")
        try await api.login(username: "a", password: password)
        await Task.sleep(50_000_000)
        XCTAssertEqual(api.authToken, "abc")
        XCTAssertTrue(api.isAuthenticated)
        XCTAssertEqual(session.requests.count, 2)
    }

    func testFetchMessagesDecrypts() async throws {
        // Ensure encrypted messages are decrypted correctly
        let fp = CryptoManager.fingerprint(of: publicPem)
        enqueue(json: "{\"access_token\":\"tok\",\"refresh_token\":\"ref\"}")
        enqueue(json: "{\"pinned_keys\":[{\"username\":\"bob\",\"fingerprint\":\"\(fp)\"}]}")
        try await api.login(username: "a", password: password)
        let ciphertext = try CryptoManager.encryptRSA("hi", publicKeyPem: publicPem).base64EncodedString()
        enqueue(json: "{\"messages\":[{\"id\":1,\"content\":\"\(ciphertext)\"}]}")
        let msgs = try await api.fetchMessages()
        XCTAssertEqual(msgs.first?.content, "hi")
    }

    func testSendMessageUsesPinnedKey() async throws {
        // Outgoing messages must use the pinned fingerprint
        let fp = CryptoManager.fingerprint(of: publicPem)
        enqueue(json: "{\"access_token\":\"tok\",\"refresh_token\":\"ref\"}")
        enqueue(json: "{\"pinned_keys\":[{\"username\":\"bob\",\"fingerprint\":\"\(fp)\"}]}")
        try await api.login(username: "a", password: password)
        enqueue(json: "{\"public_key\":\"\(publicPem!)\"}")
        enqueue(json: "{}")
        try await api.sendMessage("hi", to: "bob")
        XCTAssertEqual(session.requests.last?.url?.path, "/messages")
    }

    func testAutomaticRefreshOn401() async throws {
        // When a request returns 401 the service should refresh the token and retry.
        enqueue(json: "{\"access_token\":\"old\",\"refresh_token\":\"ref\"}")
        enqueue(json: "{\"pinned_keys\":[]}")
        try await api.login(username: "a", password: password)

        // First request fails with 401, triggering a refresh which succeeds and retries.
        enqueue(json: "{}", status: 401)
        enqueue(json: "{\"access_token\":\"new\",\"refresh_token\":\"ref2\"}")
        enqueue(json: "{\"messages\":[]}")
        _ = try await api.fetchMessages()

        XCTAssertEqual(api.authToken, "new")
        // 2 login requests + 3 for fetch (401, refresh, retry)
        XCTAssertEqual(session.requests.count, 5)
    }

    func testPinningDelegateAcceptsMatchingCert() throws {
        // Verify that the custom URLSessionDelegate accepts a pinned certificate
        let base64 = "MIIDCTCCAfGgAwIBAgIUQ4ts0UuXVBAe4Ao+YQYGUlGetikwDQYJKoZIhvcNAQELBQAwFDESMBAGA1UEAwwJVGVzdCBDZXJ0MB4XDTI1MDYwODAyMzYzNFoXDTI1MDYwOTAyMzYzNFowFDESMBAGA1UEAwwJVGVzdCBDZXJ0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnN3zYWtPN7AHCv4pj8XU7frxqV62QsXV/2WY165aCusP/d/r7zcK6LHr5AAm237cruxdiq72+AHsGuMMFY34BfQIHBujP3mfRU7lwuafW+jRPdBgsvG/GhVqAqZd4nx1a07kytDOuaw0TTZVIcSDg12uiNRto/QTP1ryXxT9o4tmmyQKcficRzC5hIj5QkNIGb6gFKhkZoirU8FK7ew6S+UCjjzrOvo7V5owGvqxkkZ4DcVs4TI1FILTXET7mQdN7FZCIzEQbKDsghSfOa2CBUBJHLzgFKwBYyFc2QEZBEiY3pWxR50xCo3XG56J/8Yw3mWDExQCinFY+lEu3o1Q3wIDAQABo1MwUTAdBgNVHQ4EFgQU9RUwc5f8zi+HNTnr3f14RQ9wWbIwHwYDVR0jBBgwFoAU9RUwc5f8zi+HNTnr3f14RQ9wWbIwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAdqa0cv7N5ZtS5OnVgG/8LRNyAcBqFNTt871kRjq84hDaHSE1QIrJXXVor1fqel+0oz75IEFBD9JJbOrP+MI8Ubl3kNEg24UK7XKesfNYv9XQUw1JtCxbl0opOWGTkvi+o/X3LQFuopvV/xy1Zh5Q2BMTkG67fS2eXNPXpuBbdoe3uMlmTVKqQYGTNwk0vDvkWsgUM1zJz1wG64b9dk3HEkn/+6incanPLWS+isFEFE+OqtJ2tpY+VOlprHLAmBkUWp+A57+l+9csvKW9R29GvJzTprrjBfQ9iFP+COzE4jFfxzb8xRO6LC/9bejXN3YX5TJDjMRescIpdrybL+br/w=="
        let derData = Data(base64Encoded: base64)!
        let pinnedURL = URL(fileURLWithPath: Bundle.main.bundlePath).appendingPathComponent("server.cer")
        try? derData.write(to: pinnedURL)

        let service = APIService()
        let mirror = Mirror(reflecting: service)
        guard let session = mirror.descendant("session") as? URLSession,
              let delegate = session.delegate else {
            return XCTFail("Missing delegate")
        }
        let cert = SecCertificateCreateWithData(nil, derData as CFData)!
        var trust: SecTrust?
        SecTrustCreateWithCertificates(cert, SecPolicyCreateSSL(true, nil), &trust)
        let challenge = URLAuthenticationChallenge(trust: trust!, proposedCredential: nil, previousFailureCount: 0, failureResponse: nil, error: nil, sender: nil)
        var disposition: URLSession.AuthChallengeDisposition?
        let exp = expectation(description: "challenge")
        delegate.urlSession?(session, didReceive: challenge) { disp, _ in
            disposition = disp
            exp.fulfill()
        }
        wait(for: [exp], timeout: 1)
        XCTAssertEqual(disposition, .useCredential)
    }

    /**
     * Pinning failures should trigger ``showCertificateWarning`` so the UI can
     * inform the user that the app's bundled certificate is outdated.
     */
    func testPinningMismatchSetsWarning() throws {
        // Write the expected pinned certificate to the bundle location.
        let pinnedBase64 = "MIIDCTCCAfGgAwIBAgIUQ4ts0UuXVBAe4Ao+YQYGUlGetikwDQYJKoZIhvcNAQELBQAwFDESMBAGA1UEAwwJVGVzdCBDZXJ0MB4XDTI1MDYwODAyMzYzNFoXDTI1MDYwOTAyMzYzNFowFDESMBAGA1UEAwwJVGVzdCBDZXJ0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnN3zYWtPN7AHCv4pj8XU7frxqV62QsXV/2WY165aCusP/d/r7zcK6LHr5AAm237cruxdiq72+AHsGuMMFY34BfQIHBujP3mfRU7lwuafW+jRPdBgsvG/GhVqAqZd4nx1a07kytDOuaw0TTZVIcSDg12uiNRto/QTP1ryXxT9o4tmmyQKcficRzC5hIj5QkNIGb6gFKhkZoirU8FK7ew6S+UCjjzrOvo7V5owGvqxkkZ4DcVs4TI1FILTXET7mQdN7FZCIzEQbKDsghSfOa2CBUBJHLzgFKwBYyFc2QEZBEiY3pWxR50xCo3XG56J/8Yw3mWDExQCinFY+lEu3o1Q3wIDAQABo1MwUTAdBgNVHQ4EFgQU9RUwc5f8zi+HNTnr3f14RQ9wWbIwHwYDVR0jBBgwFoAU9RUwc5f8zi+HNTnr3f14RQ9wWbIwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAdqa0cv7N5ZtS5OnVgG/8LRNyAcBqFNTt871kRjq84hDaHSE1QIrJXXVor1fqel+0oz75IEFBD9JJbOrP+MI8Ubl3kNEg24UK7XKesfNYv9XQUw1JtCxbl0opOWGTkvi+o/X3LQFuopvV/xy1Zh5Q2BMTkG67fS2eXNPXpuBbdoe3uMlmTVKqQYGTNwk0vDvkWsgUM1zJz1wG64b9dk3HEkn/+6incanPLWS+isFEFE+OqtJ2tpY+VOlprHLAmBkUWp+A57+l+9csvKW9R29GvJzTprrjBfQ9iFP+COzE4jFfxzb8xRO6LC/9bejXN3YX5TJDjMRescIpdrybL+br/w=="
        let pinnedURL = URL(fileURLWithPath: Bundle.main.bundlePath).appendingPathComponent("server.cer")
        try? Data(base64Encoded: pinnedBase64)!.write(to: pinnedURL)

        // Second certificate differs from the pinned one to trigger mismatch.
        let mismatchedBase64 = "MIIDCTCCAfGgAwIBAgIUfr8HrXSxktDFz50uCCyOmqM9CmEwDQYJKoZIhvcNAQELBQAwFDESMBAGA1UEAwwJVGVzdCBDZXJ0MB4XDTI1MDgyMTIyMTkzOVoXDTI2MDgyMTIyMTkzOVowFDESMBAGA1UEAwwJVGVzdCBDZXJ0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6z4pCsIue5vGk5IM9XZYEjm464iaQwchtaIjH88YSQALzQ4OpQeJTpTq6we59rKcOXfGslU1ovlXL5+mquJ2wY/50GWxnpqGdWeipTA3VTp94ANm7MkhkWLZbbO+oYh+Reumu8m6hcAW4sF85PS7vlCUIh2aMRncfb3wTz9ejsFSATrdtSSBFHFzd4/C2XYEpWwkmAKPjhmQVpUbq4M7dEmFtCaAAGheGosIiafpwd+pVuARUkzgbX0ZHmVj5+y/K9u6HIRs/8x3hDmH/6fL9s/Yzty+H2Gi6nTWETvN3KfBOQwioajArqextjnjHCTkxKwq6MH8sxBXCETyT64j3QIDAQABo1MwUTAdBgNVHQ4EFgQUUGmJFVCrged00o3q3xSOlv7H+XgwHwYDVR0jBBgwFoAUUGmJFVCrged00o3q3xSOlv7H+XgwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAjOHlZMozBGGdcshAAiMZYpT05z/Ik5YgpRFRlayYHJIyMAAFIWPewnvmz8vDbZYUKl6FUjw5Ph2keah/y7dRQYGPItl7FAEum4HfmOeDH8debEvJZCM+69bqGv9e/cSKM92PojodnHqG91GW83ShWDS/CHAz2pR+2YeT+J2HTzhFhK4u8vutgKt854ErhspjiZKl0xVDLc6W3rYMQO/RXfd0FIXh72O8/NlV214WgOlrii5lBVOFxjm5D6/LkvYZOQnZBLFsWJ0DrBJckuD9pO7nRpzK2mKebCp6n5GDrs8bQzJjt1ItH6B5Fz5DrQ9FAjgeDxpkWBHgKQUC2s5ZMA=="

        let service = APIService()
        let mirror = Mirror(reflecting: service)
        guard let session = mirror.descendant("session") as? URLSession,
              let delegate = session.delegate else {
            return XCTFail("Missing delegate")
        }

        let mismatchedData = Data(base64Encoded: mismatchedBase64)!
        let cert = SecCertificateCreateWithData(nil, mismatchedData as CFData)!
        var trust: SecTrust?
        SecTrustCreateWithCertificates(cert, SecPolicyCreateSSL(true, nil), &trust)
        let challenge = URLAuthenticationChallenge(trust: trust!, proposedCredential: nil, previousFailureCount: 0, failureResponse: nil, error: nil, sender: nil)
        let exp = expectation(description: "challenge")
        delegate.urlSession?(session, didReceive: challenge) { _ , _ in
            exp.fulfill()
        }
        wait(for: [exp], timeout: 1)

        XCTAssertTrue(service.showCertificateWarning)
    }

    // MARK: - Helpers
    private func pemString(for data: Data, header: String, footer: String) -> String {
        let b64 = data.base64EncodedString(options: [.lineLength64Characters])
        return header + "\n" + b64 + "\n" + footer
    }

    private func deriveKey(password: String, salt: Data) throws -> SymmetricKey {
        var derived = Data(count: 32)
        let status = derived.withUnsafeMutableBytes { derivedBytes in
            salt.withUnsafeBytes { saltBytes in
                CCKeyDerivationPBKDF(
                    CCPBKDFAlgorithm(kCCPBKDF2),
                    password,
                    password.utf8.count,
                    saltBytes.bindMemory(to: UInt8.self).baseAddress!,
                    salt.count,
                    CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                    200000,
                    derivedBytes.bindMemory(to: UInt8.self).baseAddress!,
                    32
                )
            }
        }
        guard status == kCCSuccess else { throw NSError(domain: "PBKDF2", code: Int(status)) }
        return SymmetricKey(data: derived)
    }
}

