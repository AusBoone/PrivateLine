// Unit tests for ``APIService`` verifying networking logic such as login,
// message retrieval and token refresh. ``URLSession`` is mocked so the tests do
// not require a live backend server.
//
// Modifications:
// - Added coverage for HTTP error propagation, ensuring ``sendRequest`` surfaces
//   ``URLError`` codes when the backend returns 4xx or 5xx statuses.
// - Introduced tests validating that cached public keys expire after the
//   configured time-to-live and are refreshed accordingly.

import XCTest
import Crypto
import Security
@testable import PrivateLine

/// Integration style tests covering ``APIService``. Network calls are mocked so
/// the logic can be verified without a running backend.

/// Minimal ``URLSession`` subclass returning queued responses for each request
/// so tests can simulate network interactions.
final class MockURLSession: URLSession {
    var responses: [(Data, URLResponse)] = []
    private(set) var requests: [URLRequest] = []
    private(set) var uploadBodies: [Data] = []

    override func data(for request: URLRequest) async throws -> (Data, URLResponse) {
        requests.append(request)
        guard !responses.isEmpty else {
            throw URLError(.badServerResponse)
        }
        return responses.removeFirst()
    }

    override func upload(for request: URLRequest, from bodyData: Data) async throws -> (Data, URLResponse) {
        // Capture the request and body so tests can inspect multipart form fields.
        requests.append(request)
        uploadBodies.append(bodyData)
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
        api = try APIService(session: session, baseURL: URL(string: "https://example.com/api")!)
        KeychainService.removeToken()
        KeychainService.removeRefreshToken()

        // Generate or load the Secure Enclave key and export its public key.
        do {
            try CryptoManager.loadPrivateKey(password: "")
        } catch {
            throw XCTSkip("Secure Enclave unavailable: \(error)")
        }

        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: "com.privateline.securekey".data(using: .utf8)!,
            kSecReturnRef as String: true
        ]
        var item: CFTypeRef?
        SecItemCopyMatching(query as CFDictionary, &item)
        guard let priv = item as? SecKey,
              let pub = SecKeyCopyPublicKey(priv) else {
            throw XCTSkip("Secure Enclave key not found")
        }
        var error: Unmanaged<CFError>?
        let pubData = SecKeyCopyExternalRepresentation(pub, &error)! as Data
        publicPem = pemString(for: pubData, header: "-----BEGIN PUBLIC KEY-----", footer: "-----END PUBLIC KEY-----")
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

    /// The initializer must reject insecure ``http`` URLs and accept secure
    /// ``https`` URLs so network traffic is always encrypted.
    func testInitializerValidatesURLScheme() {
        XCTAssertThrowsError(try APIService(baseURL: URL(string: "http://insecure")!))
        XCTAssertNoThrow(try APIService(baseURL: URL(string: "https://secure")!))
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

    /// Cached public keys should be reused within the configured TTL and
    /// refreshed afterwards. This verifies that ``APIService`` correctly
    /// discards stale keys to honor server-side rotations while avoiding
    /// redundant network calls for rapid sends.
    func testPublicKeyCacheExpiresAfterTTL() async throws {
        // Recreate the service with a 1-second TTL so the test can exercise
        // both the cached and refreshed paths quickly.
        session = MockURLSession()
        api = try APIService(session: session,
                              publicKeyCacheDuration: 1,
                              baseURL: URL(string: "https://example.com/api")!)

        let fp = CryptoManager.fingerprint(of: publicPem)
        enqueue(json: "{\"access_token\":\"tok\",\"refresh_token\":\"ref\"}")
        enqueue(json: "{\"pinned_keys\":[{\"username\":\"bob\",\"fingerprint\":\"\(fp)\"}]}")
        try await api.login(username: "a", password: password)

        // First message fetches Bob's key from the server and stores it with a timestamp.
        enqueue(json: "{\"public_key\":\"\(publicPem!)\"}")
        enqueue(json: "{}")
        try await api.sendMessage("one", to: "bob")

        // Second message sent immediately should reuse the cached key.
        enqueue(json: "{}")
        try await api.sendMessage("two", to: "bob")
        var keyFetches = session.requests.filter { $0.url?.path.contains("public_key") == true }.count
        XCTAssertEqual(keyFetches, 1)

        // Wait past the TTL and send again; this should trigger a refresh and a
        // second call to the public_key endpoint.
        try await Task.sleep(nanoseconds: 1_100_000_000)
        enqueue(json: "{\"public_key\":\"\(publicPem!)\"}")
        enqueue(json: "{}")
        try await api.sendMessage("three", to: "bob")
        keyFetches = session.requests.filter { $0.url?.path.contains("public_key") == true }.count
        XCTAssertEqual(keyFetches, 2)
    }

    /// File uploads should include AAD fields when provided so the backend can
    /// bind the ciphertext to a specific message and recipient.
    func testUploadFileIncludesAADFields() async throws {
        // Authenticate first so the upload is authorized.
        enqueue(json: "{\"access_token\":\"tok\",\"refresh_token\":\"ref\"}")
        enqueue(json: "{\"pinned_keys\":[]}")
        try await api.login(username: "a", password: password)

        // Upload an attachment providing a message id and recipient metadata.
        enqueue(json: "{\"file_id\":1}")
        let fileData = "hi".data(using: .utf8)!
        let id = try await api.uploadFile(data: fileData, filename: "f.txt", messageId: 7, recipient: "bob")
        XCTAssertEqual(id, 1)

        // Inspect the multipart body to confirm both fields were transmitted.
        guard let body = session.uploadBodies.last, let bodyStr = String(data: body, encoding: .utf8) else {
            return XCTFail("Missing captured upload body")
        }
        XCTAssertTrue(bodyStr.contains("name=\"message_id\""))
        XCTAssertTrue(bodyStr.contains("7"))
        XCTAssertTrue(bodyStr.contains("name=\"recipient\""))
        XCTAssertTrue(bodyStr.contains("bob"))
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

    /// ``sendRequest`` should surface ``URLError(.badServerResponse)`` for 4xx responses.
    func testClientErrorPropagatesURLError() async {
        enqueue(json: "{}", status: 400)
        do {
            try await api.register(username: "u", email: "e", password: "p")
            XCTFail("Expected error for 400 response")
        } catch let err as URLError {
            XCTAssertEqual(err.code, .badServerResponse)
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    /// ``sendRequest`` should surface ``URLError(.cannotConnectToHost)`` for 5xx responses.
    func testServerErrorPropagatesURLError() async {
        enqueue(json: "{}", status: 500)
        do {
            try await api.register(username: "u", email: "e", password: "p")
            XCTFail("Expected error for 500 response")
        } catch let err as URLError {
            XCTAssertEqual(err.code, .cannotConnectToHost)
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    func testPinningDelegateAcceptsEitherFingerprint() throws {
        // Prepare two certificates that will both be considered valid pins.
        let base64A = "MIIDCTCCAfGgAwIBAgIUQ4ts0UuXVBAe4Ao+YQYGUlGetikwDQYJKoZIhvcNAQELBQAwFDESMBAGA1UEAwwJVGVzdCBDZXJ0MB4XDTI1MDYwODAyMzYzNFoXDTI1MDYwOTAyMzYzNFowFDESMBAGA1UEAwwJVGVzdCBDZXJ0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnN3zYWtPN7AHCv4pj8XU7frxqV62QsXV/2WY165aCusP/d/r7zcK6LHr5AAm237cruxdiq72+AHsGuMMFY34BfQIHBujP3mfRU7lwuafW+jRPdBgsvG/GhVqAqZd4nx1a07kytDOuaw0TTZVIcSDg12uiNRto/QTP1ryXxT9o4tmmyQKcficRzC5hIj5QkNIGb6gFKhkZoirU8FK7ew6S+UCjjzrOvo7V5owGvqxkkZ4DcVs4TI1FILTXET7mQdN7FZCIzEQbKDsghSfOa2CBUBJHLzgFKwBYyFc2QEZBEiY3pWxR50xCo3XG56J/8Yw3mWDExQCinFY+lEu3o1Q3wIDAQABo1MwUTAdBgNVHQ4EFgQU9RUwc5f8zi+HNTnr3f14RQ9wWbIwHwYDVR0jBBgwFoAU9RUwc5f8zi+HNTnr3f14RQ9wWbIwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAdqa0cv7N5ZtS5OnVgG/8LRNyAcBqFNTt871kRjq84hDaHSE1QIrJXXVor1fqel+0oz75IEFBD9JJbOrP+MI8Ubl3kNEg24UK7XKesfNYv9XQUw1JtCxbl0opOWGTkvi+o/X3LQFuopvV/xy1Zh5Q2BMTkG67fS2eXNPXpuBbdoe3uMlmTVKqQYGTNwk0vDvkWsgUM1zJz1wG64b9dk3HEkn/+6incanPLWS+isFEFE+OqtJ2tpY+VOlprHLAmBkUWp+A57+l+9csvKW9R29GvJzTprrjBfQ9iFP+COzE4jFfxzb8xRO6LC/9bejXN3YX5TJDjMRescIpdrybL+br/w=="
        let base64B = "MIIDCTCCAfGgAwIBAgIUfr8HrXSxktDFz50uCCyOmqM9CmEwDQYJKoZIhvcNAQELBQAwFDESMBAGA1UEAwwJVGVzdCBDZXJ0MB4XDTI1MDgyMTIyMTkzOVoXDTI2MDgyMTIyMTkzOVowFDESMBAGA1UEAwwJVGVzdCBDZXJ0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6z4pCsIue5vGk5IM9XZYEjm464iaQwchtaIjH88YSQALzQ4OpQeJTpTq6we59rKcOXfGslU1ovlXL5+mquJ2wY/50GWxnpqGdWeipTA3VTp94ANm7MkhkWLZbbO+oYh+Reumu8m6hcAW4sF85PS7vlCUIh2aMRncfb3wTz9ejsFSATrdtSSBFHFzd4/C2XYEpWwkmAKPjhmQVpUbq4M7dEmFtCaAAGheGosIiafpwd+pVuARUkzgbX0ZHmVj5+y/K9u6HIRs/8x3hDmH/6fL9s/Yzty+H2Gi6nTWETvN3KfBOQwioajArqextjnjHCTkxKwq6MH8sxBXCETyT64j3QIDAQABo1MwUTAdBgNVHQ4EFgQUUGmJFVCrged00o3q3xSOlv7H+XgwHwYDVR0jBBgwFoAUUGmJFVCrged00o3q3xSOlv7H+XgwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAjOHlZMozBGGdcshAAiMZYpT05z/Ik5YgpRFRlayYHJIyMAAFIWPewnvmz8vDbZYUKl6FUjw5Ph2keah/y7dRQYGPItl7FAEum4HfmOeDH8debEvJZCM+69bqGv9e/cSKM92PojodnHqG91GW83ShWDS/CHAz2pR+2YeT+J2HTzhFhK4u8vutgKt854ErhspjiZKl0xVDLc6W3rYMQO/RXfd0FIXh72O8/NlV214WgOlrii5lBVOFxjm5D6/LkvYZOQnZBLFsWJ0DrBJckuD9pO7nRpzK2mKebCp6n5GDrs8bQzJjt1ItH6B5Fz5DrQ9FAjgeDxpkWBHgKQUC2s5ZMA=="
        let derA = Data(base64Encoded: base64A)!
        let derB = Data(base64Encoded: base64B)!

        // Write fingerprints for both certs to the bundle so the delegate loads them.
        let fpA = spkiFingerprint(derA)
        let fpB = spkiFingerprint(derB)
        let pinURL = URL(fileURLWithPath: Bundle.main.bundlePath).appendingPathComponent("server_fingerprints.txt")
        let pins = [fpA, fpB].joined(separator: "\n") + "\n"
        try pins.write(to: pinURL, atomically: true, encoding: .utf8)

        let service = try! APIService(baseURL: URL(string: "https://example.com/api")!)
        let mirror = Mirror(reflecting: service)
        guard let session = mirror.descendant("session") as? URLSession,
              let delegate = session.delegate else {
            return XCTFail("Missing delegate")
        }

        // Challenge using certificate A
        let certA = SecCertificateCreateWithData(nil, derA as CFData)!
        var trustA: SecTrust?
        SecTrustCreateWithCertificates(certA, SecPolicyCreateSSL(true, nil), &trustA)
        let chalA = URLAuthenticationChallenge(trust: trustA!, proposedCredential: nil, previousFailureCount: 0, failureResponse: nil, error: nil, sender: nil)
        let expA = expectation(description: "challengeA")
        var dispA: URLSession.AuthChallengeDisposition?
        delegate.urlSession?(session, didReceive: chalA) { disp, _ in
            dispA = disp; expA.fulfill()
        }

        // Challenge using certificate B
        let certB = SecCertificateCreateWithData(nil, derB as CFData)!
        var trustB: SecTrust?
        SecTrustCreateWithCertificates(certB, SecPolicyCreateSSL(true, nil), &trustB)
        let chalB = URLAuthenticationChallenge(trust: trustB!, proposedCredential: nil, previousFailureCount: 0, failureResponse: nil, error: nil, sender: nil)
        let expB = expectation(description: "challengeB")
        var dispB: URLSession.AuthChallengeDisposition?
        delegate.urlSession?(session, didReceive: chalB) { disp, _ in
            dispB = disp; expB.fulfill()
        }

        wait(for: [expA, expB], timeout: 1)
        XCTAssertEqual(dispA, .useCredential)
        XCTAssertEqual(dispB, .useCredential)
    }

    /**
     * Pinning failures should trigger ``showCertificateWarning`` so the UI can
     * inform the user that the app's bundled certificate is outdated.
     */
    func testPinningMismatchSetsWarning() throws {
        // Pinned certificate A
        let base64A = "MIIDCTCCAfGgAwIBAgIUQ4ts0UuXVBAe4Ao+YQYGUlGetikwDQYJKoZIhvcNAQELBQAwFDESMBAGA1UEAwwJVGVzdCBDZXJ0MB4XDTI1MDYwODAyMzYzNFoXDTI1MDYwOTAyMzYzNFowFDESMBAGA1UEAwwJVGVzdCBDZXJ0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnN3zYWtPN7AHCv4pj8XU7frxqV62QsXV/2WY165aCusP/d/r7zcK6LHr5AAm237cruxdiq72+AHsGuMMFY34BfQIHBujP3mfRU7lwuafW+jRPdBgsvG/GhVqAqZd4nx1a07kytDOuaw0TTZVIcSDg12uiNRto/QTP1ryXxT9o4tmmyQKcficRzC5hIj5QkNIGb6gFKhkZoirU8FK7ew6S+UCjjzrOvo7V5owGvqxkkZ4DcVs4TI1FILTXET7mQdN7FZCIzEQbKDsghSfOa2CBUBJHLzgFKwBYyFc2QEZBEiY3pWxR50xCo3XG56J/8Yw3mWDExQCinFY+lEu3o1Q3wIDAQABo1MwUTAdBgNVHQ4EFgQU9RUwc5f8zi+HNTnr3f14RQ9wWbIwHwYDVR0jBBgwFoAU9RUwc5f8zi+HNTnr3f14RQ9wWbIwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAdqa0cv7N5ZtS5OnVgG/8LRNyAcBqFNTt871kRjq84hDaHSE1QIrJXXVor1fqel+0oz75IEFBD9JJbOrP+MI8Ubl3kNEg24UK7XKesfNYv9XQUw1JtCxbl0opOWGTkvi+o/X3LQFuopvV/xy1Zh5Q2BMTkG67fS2eXNPXpuBbdoe3uMlmTVKqQYGTNwk0vDvkWsgUM1zJz1wG64b9dk3HEkn/+6incanPLWS+isFEFE+OqtJ2tpY+VOlprHLAmBkUWp+A57+l+9csvKW9R29GvJzTprrjBfQ9iFP+COzE4jFfxzb8xRO6LC/9bejXN3YX5TJDjMRescIpdrybL+br/w=="
        let pinnedDer = Data(base64Encoded: base64A)!
        let pinURL = URL(fileURLWithPath: Bundle.main.bundlePath).appendingPathComponent("server_fingerprints.txt")
        try spkiFingerprint(pinnedDer).write(to: pinURL, atomically: true, encoding: .utf8)

        // Certificate C is intentionally absent from the pins to simulate a
        // man-in-the-middle or outdated fingerprint scenario. The service should
        // surface a user-facing warning in this case.
        let mismatchedBase64 = "MIIDCTCCAfGgAwIBAgIUHqcBPn3vYFGWf1NIaEd7xDJ50CcwDQYJKoZIhvcNAQELBQAwFDESMBAGA1UEAwwJVGhpcmRDZXJ0MB4XDTI1MDgyMzAwNTkyMloXDTI1MDgyNDAwNTkyMlowFDESMBAGA1UEAwwJVGhpcmRDZXJ0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAn3SooldjTF4QTCzWFa03rqG02lR4fgtahNpq8t0yLBqJXSkp0zaheJy6P768ZtXUVwk0y/NAsUpkFCqufBL9V7H1/uo9ib8LlX30edz51Ux+hma0FsFyAjjNIQZHVfSXTpEfwF/4tGg1z6mqfGJhDcWTCSz1QYTOOqE0XnKxowxiJPkit8YuPuC1UKJqVyVIEAx+eE8izsM8UL8s4faKHj7iRRcnAJKhyII8CMXuul+8NWf9ezd3rPMtcsgn4Kj7uMHJTdIYZlRNv1+qPIQj2M2oF1Kqr4rbm6Jrs77i0ESrkLgxJrM29gCjdP9a2HtlqhrE6X/zANFfmoiiRrTKOQIDAQABo1MwUTAdBgNVHQ4EFgQUaBqZ0vCQ8DZhCydlLH2uZlhbCqowHwYDVR0jBBgwFoAUaBqZ0vCQ8DZhCydlLH2uZlhbCqowDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEADOtHeqC627X7En9EmgXfGodYF3AldBVWv5wbpa7YFFZDRLAbNv62iSBCBYP0CZanxF55mPXEsez/kJJldjIGGCz3bs0I+cf2sdxY+5ECeztyWrTk9k+3u/HknsPR0tFVLGQvVEw8tPrH3ZjiPMe1hArK0sfwrS97gv0WsbreagoVmzJuThFsmIP7miBIwu/3T7/D9pPXnxFBagg8LBMgRutkEnoD46h3kGqVOUHt6zIIEJnIlMn0alSAVp4EP4KQjjxcZ49rqCsBVEf4LLb2taNxgCPckgrdK6LVh6Y12u1sSe+ESUdqmdkmmn49kKyzO9Jvd6JjX2oIboEoL2Ljqw=="

        let service = try! APIService(baseURL: URL(string: "https://example.com/api")!)
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

    /// Helper mirroring the production fingerprint computation so tests can
    /// generate pins from DER certificate data.
    private func spkiFingerprint(_ der: Data) -> String {
        let cert = SecCertificateCreateWithData(nil, der as CFData)!
        let key = SecCertificateCopyKey(cert)!
        let keyData = SecKeyCopyExternalRepresentation(key, nil)! as Data
        let algId: [UInt8] = [0x30,0x0d,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01,0x05,0x00]
        let bitString: [UInt8] = [0x03] + derLength(of: keyData.count + 1) + [0x00] + [UInt8](keyData)
        let spki = Data([0x30] + derLength(of: algId.count + bitString.count) + algId + bitString)
        let digest = SHA256.hash(data: spki)
        return Data(digest).base64EncodedString()
    }

    private func derLength(of length: Int) -> [UInt8] {
        if length < 128 { return [UInt8(length)] }
        var len = length
        var bytes: [UInt8] = []
        while len > 0 {
            bytes.insert(UInt8(len & 0xff), at: 0)
            len >>= 8
        }
        return [0x80 | UInt8(bytes.count)] + bytes
    }

}

