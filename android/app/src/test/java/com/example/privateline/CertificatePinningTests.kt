/*
 * CertificatePinningTests.kt - Ensures that APIService refuses TLS connections
 * when the server certificate does not match the pinned fingerprint. The test
 * uses a self-signed certificate trusted by the client so failures are solely
 * due to the pinning mismatch rather than general TLS validation errors.
 */
package com.example.privateline

import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import org.junit.After
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test
import javax.net.ssl.SSLPeerUnverifiedException

/**
 * Test suite validating that mismatched certificate fingerprints result in a
 * rejected connection, protecting against man-in-the-middle attacks.
 */
class CertificatePinningTests {
    private lateinit var server: MockWebServer

    @Before
    fun setup() {
        server = MockWebServer()
    }

    @After
    fun tearDown() {
        server.shutdown()
    }

    /**
     * The mock server presents a certificate whose fingerprint differs from the
     * one pinned in APIService. Because the client still trusts the certificate
     * authority, the TLS handshake succeeds but the certificate pinner raises
     * an ``SSLPeerUnverifiedException``.
     */
    @Test
    fun mismatchedCertificateIsRejected() {
        // Generate a self-signed certificate for the mock server with the
        // localhost SAN so OkHttp considers it a valid hostname.
        val heldCert = HeldCertificate.Builder()
            .addSubjectAlternativeName("localhost")
            .build()
        val serverCerts = HandshakeCertificates.Builder()
            .heldCertificate(heldCert)
            .build()
        server.useHttps(serverCerts.sslSocketFactory(), false)
        server.enqueue(MockResponse().setResponseCode(200))
        server.start()

        // Build a client that trusts the server's certificate. This isolates
        // the failure to certificate pinning rather than trust chain issues.
        val clientCerts = HandshakeCertificates.Builder()
            .addTrustedCertificate(heldCert.certificate())
            .build()
        val builder = OkHttpClient.Builder()
            .sslSocketFactory(clientCerts.sslSocketFactory(), clientCerts.trustManager)

        val service = APIService(server.url("/").toString().removeSuffix("/"), builder)

        // Executing a request should trigger SSLPeerUnverifiedException due to
        // the mismatched pin, verifying that APIService enforces pinning.
        assertThrows(SSLPeerUnverifiedException::class.java) {
            service.fetchPublicKey("alice")
        }
    }
}

