import XCTest
@testable import PrivateLine

final class PinningDelegateTests: XCTestCase {
    func testCertificateDataEquality() throws {
        // Loading the same DER data twice should produce identical certificates
        let base64 = "MIIDCTCCAfGgAwIBAgIUQ4ts0UuXVBAe4Ao+YQYGUlGetikwDQYJKoZIhvcNAQELBQAwFDESMBAGA1UEAwwJVGVzdCBDZXJ0MB4XDTI1MDYwODAyMzYzNFoXDTI1MDYwOTAyMzYzNFowFDESMBAGA1UEAwwJVGVzdCBDZXJ0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnN3zYWtPN7AHCv4pj8XU7frxqV62QsXV/2WY165aCusP/d/r7zcK6LHr5AAm237cruxdiq72+AHsGuMMFY34BfQIHBujP3mfRU7lwuafW+jRPdBgsvG/GhVqAqZd4nx1a07kytDOuaw0TTZVIcSDg12uiNRto/QTP1ryXxT9o4tmmyQKcficRzC5hIj5QkNIGb6gFKhkZoirU8FK7ew6S+UCjjzrOvo7V5owGvqxkkZ4DcVs4TI1FILTXET7mQdN7FZCIzEQbKDsghSfOa2CBUBJHLzgFKwBYyFc2QEZBEiY3pWxR50xCo3XG56J/8Yw3mWDExQCinFY+lEu3o1Q3wIDAQABo1MwUTAdBgNVHQ4EFgQU9RUwc5f8zi+HNTnr3f14RQ9wWbIwHwYDVR0jBBgwFoAU9RUwc5f8zi+HNTnr3f14RQ9wWbIwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAdqa0cv7N5ZtS5OnVgG/8LRNyAcBqFNTt871kRjq84hDaHSE1QIrJXXVor1fqel+0oz75IEFBD9JJbOrP+MI8Ubl3kNEg24UK7XKesfNYv9XQUw1JtCxbl0opOWGTkvi+o/X3LQFuopvV/xy1Zh5Q2BMTkG67fS2eXNPXpuBbdoe3uMlmTVKqQYGTNwk0vDvkWsgUM1zJz1wG64b9dk3HEkn/+6incanPLWS+isFEFE+OqtJ2tpY+VOlprHLAmBkUWp+A57+l+9csvKW9R29GvJzTprrjBfQ9iFP+COzE4jFfxzb8xRO6LC/9bejXN3YX5TJDjMRescIpdrybL+br/w=="
        guard let derData = Data(base64Encoded: base64) else {
            return XCTFail("Failed to decode cert")
        }
        guard let cert1 = SecCertificateCreateWithData(nil, derData as CFData),
              let cert2 = SecCertificateCreateWithData(nil, derData as CFData) else {
            return XCTFail("Unable to create certs")
        }
        let data1 = SecCertificateCopyData(cert1) as Data
        let data2 = SecCertificateCopyData(cert2) as Data
        XCTAssertEqual(data1, data2)
    }
}
