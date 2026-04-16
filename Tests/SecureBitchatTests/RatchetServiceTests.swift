//
// RatchetServiceTests.swift
// SecureBitchatTests
//
// Unit tests for Double Ratchet encryption.
//
// This is free and unencumbered software released into the public domain.
// For more information, see <https://unproject.org>
//

import XCTest
@testable import SecureBitchat

final class RatchetServiceTests: XCTestCase {
    
    var ratchetService: RatchetService!
    
    override func setUp() {
        super.setUp()
        ratchetService = RatchetService()
    }
    
    func testSessionInitialization() throws {
        let aliceKeyPair = Curve25519.KeyAgreement.PrivateKey()
        let bobKeyPair = Curve25519.KeyAgreement.PrivateKey()
        
        let aliceSession = try ratchetService.initializeSession(
            with: bobKeyPair.publicKey.rawRepresentation,
            theirIdentity: aliceKeyPair.publicKey.rawRepresentation
        )
        
        XCTAssertFalse(aliceSession.rootKey.isEmpty)
        XCTAssertNotNil(aliceSession.sendChainKey)
    }
    
    func testSendReceiveMessages() throws {
        let aliceKeyPair = Curve25519.KeyAgreement.PrivateKey()
        let bobKeyPair = Curve25519.KeyAgreement.PrivateKey()
        
        var aliceSession = try ratchetService.initializeSession(
            with: bobKeyPair.publicKey.rawRepresentation,
            theirIdentity: aliceKeyPair.publicKey.rawRepresentation
        )
        
        let plaintext = "Hello, Bob!".data(using: .utf8)!
        
        let ciphertext = try ratchetService.encrypt(plaintext, in: &aliceSession)
        
        XCTAssertNotEqual(ciphertext, plaintext)
        XCTAssertGreaterThan(ciphertext.count, 0)
    }
    
    func testForwardSecrecy() throws {
        let aliceKeyPair = Curve25519.KeyAgreement.PrivateKey()
        let bobKeyPair = Curve25519.KeyAgreement.PrivateKey()
        
        var aliceSession = try ratchetService.initializeSession(
            with: bobKeyPair.publicKey.rawRepresentation,
            theirIdentity: aliceKeyPair.publicKey.rawRepresentation
        )
        
        let message1 = "Message 1".data(using: .utf8)!
        let message2 = "Message 2".data(using: .utf8)!
        
        let ciphertext1 = try ratchetService.encrypt(message1, in: &aliceSession)
        let ciphertext2 = try ratchetService.encrypt(message2, in: &aliceSession)
        
        XCTAssertNotEqual(ciphertext1, ciphertext2)
        
        try ratchetService.ratchetStep(session: &aliceSession)
        
        let message3 = "Message 3".data(using: .utf8)!
        let ciphertext3 = try ratchetService.encrypt(message3, in: &aliceSession)
        
        XCTAssertNotEqual(ciphertext2, ciphertext3)
    }
    
    func testSessionIdempotency() throws {
        let aliceKeyPair = Curve25519.KeyAgreement.PrivateKey()
        let bobKeyPair = Curve25519.KeyAgreement.PrivateKey()
        
        let aliceSession1 = try ratchetService.initializeSession(
            with: bobKeyPair.publicKey.rawRepresentation,
            theirIdentity: aliceKeyPair.publicKey.rawRepresentation
        )
        
        let aliceSession2 = try ratchetService.initializeSession(
            with: bobKeyPair.publicKey.rawRepresentation,
            theirIdentity: aliceKeyPair.publicKey.rawRepresentation
        )
        
        XCTAssertEqual(aliceSession1.sessionId, aliceSession2.sessionId)
    }
    
    func testMultipleMessagesInOrder() throws {
        let aliceKeyPair = Curve25519.KeyAgreement.PrivateKey()
        let bobKeyPair = Curve25519.KeyAgreement.PrivateKey()
        
        var aliceSession = try ratchetService.initializeSession(
            with: bobKeyPair.publicKey.rawRepresentation,
            theirIdentity: aliceKeyPair.publicKey.rawRepresentation
        )
        
        let messages = ["First", "Second", "Third", "Fourth", "Fifth"]
        
        var ciphertexts: [Data] = []
        for message in messages {
            let plaintext = message.data(using: .utf8)!
            let ciphertext = try ratchetService.encrypt(plaintext, in: &aliceSession)
            ciphertexts.append(ciphertext)
        }
        
        let uniqueCiphertexts = Set(ciphertexts.map { $0 })
        XCTAssertEqual(uniqueCiphertexts.count, 5)
        
        for (index, message) in messages.enumerated() {
            XCTAssertNotEqual(ciphertexts[index], message.data(using: .utf8)!)
        }
    }
}
