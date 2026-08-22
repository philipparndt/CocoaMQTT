//
//  WebSocketTLSConfigurationTests.swift
//  CocoaMQTTTests
//

import XCTest
@testable import CocoaMQTT
#if IS_SWIFT_PACKAGE
@testable import CocoaMQTTWebSocket
#endif

final class WebSocketTLSConfigurationTests: XCTestCase {

    /// Self-signed certificate for "cocoamqtt.test", valid until 2126.
    private static let certificateBase64 = """
        MIIDFTCCAf2gAwIBAgIUNVoDzSdRzFzCHBRs5VrGpzmeK2gwDQYJKoZIhvcNAQELBQAwGTEXMBUGA1UEAwwOY29jb2Ft\
        cXR0LnRlc3QwIBcNMjYwODIyMTIxNTA0WhgPMjEyNjA3MjkxMjE1MDRaMBkxFzAVBgNVBAMMDmNvY29hbXF0dC50ZXN0\
        MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA649yK1OZNksPgfb1cm2U7f1TRyHaNXVYtugg0veCABtbna1O\
        b+ZMHIvnASnWKZaJrKt0GL5q8cTdYK0E+DlCIFyOVk99iRAu+HA43eEc2v8Y+b7l6JESyFJtP/sk5IySpi0B1FDiKIyb\
        YSenQctk2cZUX00bH6cQAZQLv9g6akjZAGYQ/54tNguok3+Qv0VYK4CyCOCNh8zmHIzxhAF9XZG0CzQAivT5pi52f6Kn\
        t+tTWOD03rmSlh0sZGz0VtEHRBdj0ZVSpBEEaaYzv4IQqcVmUSztLizktXcq344XpAuJahFgiKpY2uVyXcV5/GPazV7v\
        xVd7OTmCc2hEUcmHqwIDAQABo1MwUTAdBgNVHQ4EFgQUx1gh5YJGxoSRlqFAuL5A+WQW+KowHwYDVR0jBBgwFoAUx1gh\
        5YJGxoSRlqFAuL5A+WQW+KowDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAEg01Dkm8abyMmQBObdNq\
        pO44YSgyDfOD/zpiP7Uy5TfNylOjIbA1gM0ShdbhRRC4ZPXveyUnc2pJpNvhR9lBwiuyOk0C8aagyGKbgijJFF09A6uB\
        aVMgfyRoZYXJ8BeKt+Hp0OZ8uKsvRlon97nLj/KgQ/EREDQWm8DtuVr65drNibPKQsKq/CmXxp49X9lumya3UGo+4oJy\
        hyZGvBG694LuqApP8tOXVBBlSM20pAUtkH+4SzqUK9cRI5ZMc9REwl38CYTZjuj19VAaf7XkPumPXisQ8wAXD5FaEuJF\
        sDNzd0F/+PMq9ncto1Jq2CGE+B+5oEXCF13qj43s7QkD+A==
        """

    private func makeCertificate() throws -> SecCertificate {
        let data = try XCTUnwrap(Data(base64Encoded: Self.certificateBase64))
        return try XCTUnwrap(SecCertificateCreateWithData(nil, data as CFData))
    }

    private func makeTrust() throws -> SecTrust {
        let certificate = try makeCertificate()
        var trust: SecTrust?
        let status = SecTrustCreateWithCertificates(certificate, SecPolicyCreateBasicX509(), &trust)
        XCTAssertEqual(status, errSecSuccess)
        return try XCTUnwrap(trust)
    }

    private func makeWebSocket() -> CocoaMQTTWebSocket {
        CocoaMQTTWebSocket(uri: "/mqtt")
    }

    // MARK: - Settings reach the WebSocket transport

    func testAllowUntrustCACertificateReachesWebSocketSocket() throws {
        let websocket = makeWebSocket()
        let mqtt = CocoaMQTT(clientID: "ws-untrusted", host: "localhost", port: 8083, socket: websocket)

        mqtt.allowUntrustCACertificate = true

        XCTAssertTrue(websocket.allowUntrustCACertificate)
        XCTAssertTrue(mqtt.allowUntrustCACertificate)
    }

    func testServerCACertificatesReachWebSocketSocket() throws {
        let websocket = makeWebSocket()
        let mqtt = CocoaMQTT(clientID: "ws-server-ca", host: "localhost", port: 8083, socket: websocket)

        mqtt.serverCACertificates = [try makeCertificate()]

        XCTAssertEqual(websocket.serverCACertificates?.count, 1)
        XCTAssertEqual(mqtt.serverCACertificates?.count, 1)
    }

    func testSSLSettingsReachWebSocketSocket() throws {
        let websocket = makeWebSocket()
        let mqtt = CocoaMQTT(clientID: "ws-ssl-settings", host: "localhost", port: 8083, socket: websocket)

        mqtt.sslSettings = [kCFStreamSSLCertificates as String: NSArray()]

        XCTAssertNotNil(websocket.sslSettings)
        XCTAssertNotNil(mqtt.sslSettings)
    }

    func testMQTT5AllowUntrustCACertificateReachesWebSocketSocket() throws {
        let websocket = makeWebSocket()
        let mqtt5 = CocoaMQTT5(clientID: "ws5-untrusted", host: "localhost", port: 8083, socket: websocket)

        mqtt5.allowUntrustCACertificate = true

        XCTAssertTrue(websocket.allowUntrustCACertificate)
        XCTAssertTrue(mqtt5.allowUntrustCACertificate)
    }

    // MARK: - Trust evaluation

    func testEvaluateServerTrustDefersWhenNothingIsConfigured() throws {
        let trust = try makeTrust()

        XCTAssertNil(cocoaMQTTEvaluateServerTrust(trust, serverCAs: nil, allowUntrusted: false))
        XCTAssertNil(cocoaMQTTEvaluateServerTrust(trust, serverCAs: [], allowUntrusted: false))
    }

    func testEvaluateServerTrustAcceptsUntrustedWhenAllowed() throws {
        let trust = try makeTrust()

        XCTAssertEqual(cocoaMQTTEvaluateServerTrust(trust, serverCAs: nil, allowUntrusted: true), true)
    }

    func testEvaluateServerTrustDecidesWhenServerCAsAreConfigured() throws {
        let trust = try makeTrust()

        // The outcome depends on the platform's validation, but the custom anchors
        // must be used rather than falling back to the system trust store.
        XCTAssertNotNil(cocoaMQTTEvaluateServerTrust(trust, serverCAs: [try makeCertificate()], allowUntrusted: false))
    }
}
