//
// XChaCha20Poly1305Tests.swift
// SecureBitchatTests
//
// Unit tests for XChaCha20-Poly1305 AEAD encryption.
//
// This is free and unencumbered software released into the public domain.
// For more information, see <https://unproject.org>
//

import XCTest
@testable import SecureBitchat

final class XChaCha20Poly1305Tests: XCTestCase {
    
    var aead: XChaCha20Poly1305AEAD!
    var packetAEAD: SecurePacketAEAD!
    
    override func setUp() {
        super.setUp()
        aead = XChaCha20Poly1305AEAD()
        packetAEAD = SecurePacketAEAD(aead: aead)
    }
    
    func testEncryptionDecryption() throws {
        let key = XChaCha20Poly1305AEAD.generateKey()
        let plaintext = "Secret message".data(using: .utf8)!
        
        guard let nonce = XChaCha20Poly1305AEAD.generateNonce() else {
            XCTFail("Failed to generate nonce")
            return
        }
        
        let ciphertext = try aead.seal(plaintext, using: key, nonce: nonce, authenticating: Data())
        let decrypted = try aead.open(ciphertext, using: key, authenticating: Data())
        
        XCTAssertEqual(decrypted, plaintext)
    }
    
    func testAuthenticatiedEncryption() throws {
        let key = XChaCha20Poly1305AEAD.generateKey()
        let plaintext = "Message with authentication".data(using: .utf8)!
        let additionalData = "Context info".data(using: .utf8)!
        
        guard let nonce = XChaCha20Poly1305AEAD.generateNonce() else {
            XCTFail("Failed to generate nonce")
            return
        }
        
        let ciphertext = try aead.seal(plaintext, using: key, nonce: nonce, authenticating: additionalData)
        
        do {
            _ = try aead.open(ciphertext, using: key, authenticating: Data())
            XCTFail("Should fail without additional data")
        } catch AEADError.authenticationFailed {
            // Expected
        }
    }
    
    func testTamperedCiphertext() throws {
        let key = XChaCha20Poly1305AEAD.generateKey()
        let plaintext = "Original message".data(using: .utf8)!
        
        guard let nonce = XChaCha20Poly1305AEAD.generateNonce() else {
            XCTFail("Failed to generate nonce")
            return
        }
        
        let ciphertext = try aead.seal(plaintext, using: key, nonce: nonce, authenticating: Data())
        
        var tampered = ciphertext
        if tampered.count > 20 {
            tampered[20] ^= 0xFF
        }
        
        do {
            _ = try aead.open(tampered, using: key, authenticating: Data())
            XCTFail("Should fail with tampered ciphertext")
        } catch AEADError.authenticationFailed {
            // Expected
        }
    }
    
    func testPacketEncryption() throws {
        let key = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        
        let packet = SecureBitchatPacket(
            type: 0x01,
            senderID: Data(repeating: 0xAB, count: 8),
            recipientID: nil,
            timestamp: UInt64(Date().timeIntervalSince1970 * 1000),
            payload: Data("Test payload".utf8),
            signature: nil,
            ttl: 7,
            version: 1
        )
        
        let encrypted = try packetAEAD.encryptPacket(packet, key: key)
        let decrypted = try packetAEAD.decryptPacket(encrypted, key: key)
        
        XCTAssertEqual(decrypted.type, packet.type)
        XCTAssertEqual(decrypted.payload, packet.payload)
        XCTAssertEqual(decrypted.senderID, packet.senderID)
    }
    
    func testKeyGeneration() throws {
        let key1 = XChaCha20Poly1305AEAD.generateKey()
        let key2 = XChaCha20Poly1305AEAD.generateKey()
        
        XCTAssertEqual(key1.withUnsafeBytes { Data($0) }.count, 32)
        XCTAssertEqual(key2.withUnsafeBytes { Data($0) }.count, 32)
        XCTAssertNotEqual(key1.withUnsafeBytes { Data($0) }, key2.withUnsafeBytes { Data($0) })
    }
    
    func testNonceUniqueness() throws {
        let key = XChaCha20Poly1305AEAD.generateKey()
        let plaintext = "Test".data(using: .utf8)!
        
        var nonces: Set<String> = []
        
        for _ in 0..<100 {
            guard let nonce = XChaCha20Poly1305AEAD.generateNonce() else {
                continue
            }
            
            let nonceData = nonce.withUnsafeBytes { Data($0) }
            nonces.insert(nonceData.base64EncodedString())
        }
        
        XCTAssertEqual(nonces.count, 100)
    }
    
    func testInvalidKeySize() throws {
        let shortKey = Data((0..<16).map { _ in UInt8.random(in: 0...255) })
        let key = SymmetricKey(data: shortKey)
        let plaintext = "Test".data(using: .utf8)!
        
        guard let nonce = XChaCha20Poly1305AEAD.generateNonce() else {
            XCTFail("Failed to generate nonce")
            return
        }
        
        do {
            _ = try aead.seal(plaintext, using: key, nonce: nonce, authenticating: Data())
            XCTFail("Should fail with invalid key size")
        } catch AEADError.invalidKey {
            // Expected
        }
    }
}
