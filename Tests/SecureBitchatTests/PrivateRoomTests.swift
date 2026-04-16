//
// PrivateRoomTests.swift
// SecureBitchatTests
//
// Unit tests for PrivateRoomManager.
//
// This is free and unencumbered software released into the public domain.
// For more information, see <https://unproject.org>
//

import XCTest
@testable import SecureBitchat

final class PrivateRoomTests: XCTestCase {
    
    var keychain: SecureKeychainManager!
    var identityManager: SecureIdentityManager!
    var ratchetService: RatchetService!
    var roomManager: PrivateRoomManager!
    
    override func setUp() {
        super.setUp()
        keychain = SecureKeychainManager(serviceName: "TestSecureBitchat")
        ratchetService = RatchetService()
        identityManager = SecureIdentityManager(keychain: keychain)
        roomManager = PrivateRoomManager(keychain: keychain, ratchetService: ratchetService, identityManager: identityManager)
    }
    
    override func tearDown() {
        keychain.deleteAll()
        super.tearDown()
    }
    
    func testCreateRoom() throws {
        let room = try roomManager.createRoom(name: "Test Room", password: "securePassword123")
        
        XCTAssertFalse(room.id.isEmpty)
        XCTAssertEqual(room.name, "Test Room")
        XCTAssertFalse(room.encryptionKeyRef.isEmpty)
    }
    
    func testJoinRoomWithInvite() throws {
        let creatorRoom = try roomManager.createRoom(name: "Creator Room", password: "password123")
        let inviteQR = try roomManager.generateInviteQR(for: creatorRoom)
        
        let joinedRoom = try roomManager.joinRoom(inviteQR: inviteQR, password: "password123")
        
        XCTAssertEqual(joinedRoom.id, creatorRoom.id)
        XCTAssertEqual(joinedRoom.name, creatorRoom.name)
    }
    
    func testEncryptDecryptMessage() throws {
        var room = try roomManager.createRoom(name: "Encrypted Room", password: "testPassword")
        
        let plaintext = "Secret message".data(using: .utf8)!
        
        let ciphertext = try roomManager.encryptMessage(plaintext, for: &room)
        let decrypted = try roomManager.decryptMessage(ciphertext, for: &room)
        
        XCTAssertEqual(decrypted, plaintext)
        XCTAssertNotEqual(ciphertext, plaintext)
    }
    
    func testAddMember() throws {
        var room = try roomManager.createRoom(name: "Group Room", password: "groupPassword")
        let initialKey = room.encryptionKeyRef
        
        let memberKey = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        try roomManager.addMember(memberKey, to: &room)
        
        XCTAssertEqual(room.members.count, 1)
        XCTAssertTrue(room.members.contains(memberKey))
        XCTAssertNotEqual(room.encryptionKeyRef, initialKey)
    }
    
    func testRemoveMember() throws {
        var room = try roomManager.createRoom(name: "Group Room", password: "groupPassword")
        let memberKey = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        try roomManager.addMember(memberKey, to: &room)
        
        try roomManager.removeMember(memberKey, from: &room)
        
        XCTAssertEqual(room.members.count, 0)
        XCTAssertFalse(room.members.contains(memberKey))
    }
    
    func testRekeyRoom() throws {
        var room = try roomManager.createRoom(name: "Rekey Room", password: "rekeyPassword")
        let oldKey = room.encryptionKeyRef
        
        try roomManager.rekeyRoom(&room)
        
        XCTAssertNotEqual(room.encryptionKeyRef, oldKey)
        XCTAssertTrue(room.lastRekeyTime > room.creationTime)
    }
    
    func testLeaveRoom() throws {
        let room = try roomManager.createRoom(name: "Leaving Room", password: "leavePassword")
        
        try roomManager.leaveRoom(room.id)
        
        XCTAssertNil(roomManager.getRoom(room.id))
    }
    
    func testInvalidPassword() throws {
        let room = try roomManager.createRoom(name: "Locked Room", password: "correctPassword")
        let inviteQR = try roomManager.generateInviteQR(for: room)
        
        do {
            _ = try roomManager.joinRoom(inviteQR: inviteQR, password: "wrongPassword")
            XCTFail("Expected key derivation error")
        } catch PrivateRoomError.keyDerivationFailed {
            // Expected - wrong password leads to different key
        } catch {
            // Acceptable - could also be signature verification failure
        }
    }
    
    func testTrafficPadding() throws {
        var room = try roomManager.createRoom(name: "Padding Room", password: "padPassword")
        
        let shortMessage = "Hi".data(using: .utf8)!
        let encrypted = try roomManager.encryptMessage(shortMessage, for: &room)
        
        XCTAssertEqual(encrypted.count % 64, 0)
    }
}
