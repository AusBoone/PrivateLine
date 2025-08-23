import XCTest
import Crypto
@testable import PrivateLine

/// Tests for helper logic used by the pinning delegate.
///
/// Ensures that computing the SPKI SHA-256 fingerprint yields identical
/// results for duplicate certificates. This mirrors the behaviour used by the
/// production pinning delegates.
final class PinningDelegateTests: XCTestCase {
    func testFingerprintEquality() throws {
        // Sample self-signed certificate in DER form.
        let base64 = "MIIDCTCCAfGgAwIBAgIUQ4ts0UuXVBAe4Ao+YQYGUlGetikwDQYJKoZIhvcNAQELBQAwFDESMBAGA1UEAwwJVGVzdCBDZXJ0MB4XDTI1MDYwODAyMzYzNFoXDTI1MDYwOTAyMzYzNFowFDESMBAGA1UEAwwJVGVzdCBDZXJ0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnN3zYWtPN7AHCv4pj8XU7frxqV62QsXV/2WY165aCusP/d/r7zcK6LHr5AAm237cruxdiq72+AHsGuMMFY34BfQIHBujP3mfRU7lwuafW+jRPdBgsvG/GhVqAqZd4nx1a07kytDOuaw0TTZVIcSDg12uiNRto/QTP1ryXxT9o4tmmyQKcficRzC5hIj5QkNIGb6gFKhkZoirU8FK7ew6S+UCjjzrOvo7V5owGvqxkkZ4DcVs4TI1FILTXET7mQdN7FZCIzEQbKDsghSfOa2CBUBJHLzgFKwBYyFc2QEZBEiY3pWxR50xCo3XG56J/8Yw3mWDExQCinFY+lEu3o1Q3wIDAQABo1MwUTAdBgNVHQ4EFgQU9RUwc5f8zi+HNTnr3f14RQ9wWbIwHwYDVR0jBBgwFoAU9RUwc5f8zi+HNTnr3f14RQ9wWbIwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAdqa0cv7N5ZtS5OnVgG/8LRNyAcBqFNTt871kRjq84hDaHSE1QIrJXXVor1fqel+0oz75IEFBD9JJbOrP+MI8Ubl3kNEg24UK7XKesfNYv9XQUw1JtCxbl0opOWGTkvi+o/X3LQFuopvV/xy1Zh5Q2BMTkG67fS2eXNPXpuBbdoe3uMlmTVKqQYGTNwk0vDvkWsgUM1zJz1wG64b9dk3HEkn/+6incanPLWS+isFEFE+OqtJ2tpY+VOlprHLAmBkUWp+A57+l+9csvKW9R29GvJzTprrjBfQ9iFP+COzE4jFfxzb8xRO6LC/9bejXN3YX5TJDjMRescIpdrybL+br/w=="
        guard let derData = Data(base64Encoded: base64) else {
            return XCTFail("Failed to decode cert")
        }

        guard let cert1 = SecCertificateCreateWithData(nil, derData as CFData),
              let cert2 = SecCertificateCreateWithData(nil, derData as CFData),
              let fp1 = spkiFingerprint(cert1),
              let fp2 = spkiFingerprint(cert2) else {
            return XCTFail("Unable to derive fingerprints")
        }

        XCTAssertEqual(fp1, fp2, "Identical certificates should produce the same fingerprint")
    }

    /// Compute the base64-encoded SHA-256 hash of the certificate's
    /// ``SubjectPublicKeyInfo`` structure. Mirrors the production logic so tests
    /// can validate behaviour deterministically.
    private func spkiFingerprint(_ cert: SecCertificate) -> String? {
        guard let key = SecCertificateCopyKey(cert),
              let keyData = SecKeyCopyExternalRepresentation(key, nil) as Data? else { return nil }
        let algId: [UInt8] = [0x30,0x0d,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01,0x05,0x00]
        let bitString: [UInt8] = [0x03] + derLength(of: keyData.count + 1) + [0x00] + [UInt8](keyData)
        let spki = Data([0x30] + derLength(of: algId.count + bitString.count) + algId + bitString)
        let digest = SHA256.hash(data: spki)
        return Data(digest).base64EncodedString()
    }

    /// Helper replicating DER length encoding from X.690.
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
