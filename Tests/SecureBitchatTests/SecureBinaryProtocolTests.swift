//
// SecureBinaryProtocolTests.swift
// SecureBitchatTests
//
// Unit tests for security fixes in SecureBinaryProtocol.
//
// This is free and unencumbered software released into the public domain.
// For more information, see <https://unproject.org>
//

import XCTest
@testable import SecureBitchat

final class SecureBinaryProtocolTests: XCTestCase {
    
    func testBufferOverflowSignature() throws {
        let invalidSignature = Data(repeating: 0xFF, count: 32)
        
        let packet = SecureBitchatPacket(
            type: 0x01,
            senderID: Data(repeating: 0xAB, count: 8),
            recipientID: nil,
            timestamp: UInt64(Date().timeIntervalSince1970 * 1000),
            payload: Data("Test message".utf8),
            signature: invalidSignature,
            ttl: 7,
            version: 1
        )
        
        do {
            _ = try SecureBinaryProtocol.encode(packet)
            XCTFail("Expected buffer overflow error")
        } catch SecureProtocolError.invalidSignature {
            // Expected
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }
    
    func testPayloadTruncationUInt16() throws {
        let largePayload = Data(repeating: 0xAB, count: 70000)
        
        let packet = SecureBitchatPacket(
            type: 0x01,
            senderID: Data(repeating: 0xAB, count: 8),
            recipientID: nil,
            timestamp: UInt64(Date().timeIntervalSince1970 * 1000),
            payload: largePayload,
            signature: nil,
            ttl: 7,
            version: 1
        )
        
        do {
            _ = try SecureBinaryProtocol.encode(packet)
            XCTFail("Expected payload too large error")
        } catch SecureProtocolError.payloadTooLarge {
            // Expected
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }
    
    func testTimestampValidation() throws {
        let oldTimestamp = UInt64((Date().timeIntervalSince1970 - 48 * 60 * 60) * 1000)
        
        let packet = SecureBitchatPacket(
            type: 0x01,
            senderID: Data(repeating: 0xAB, count: 8),
            recipientID: nil,
            timestamp: oldTimestamp,
            payload: Data("Test".utf8),
            signature: nil,
            ttl: 7,
            version: 1
        )
        
        let encoded = try SecureBinaryProtocol.encode(packet, padding: false)
        
        do {
            _ = try SecureBinaryProtocol.decode(encoded)
            XCTFail("Expected timestamp out of range error")
        } catch SecureProtocolError.timestampOutOfRange {
            // Expected
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }
    
    func testMentionsDoSProtection() throws {
        let manyMentions = (0..<15).map { "@user\($0)" }.joined(separator: " ")
        
        do {
            _ = try SecureBinaryProtocol.parseMentions(manyMentions)
            XCTFail("Expected mentions DoS error")
        } catch SecureProtocolError.mentionsDoS {
            // Expected
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }
    
    func testSafeNullTrim() throws {
        let dataWithNulls = Data([0x01, 0x02, 0x03, 0x00, 0x00, 0x00])
        let trimmed = dataWithNulls.safeTrimNullBytes()
        
        XCTAssertEqual(trimmed.count, 3)
        XCTAssertEqual(Array(trimmed), [0x01, 0x02, 0x03])
    }
    
    func testValidPacketEncodingDecoding() throws {
        let payload = Data("Hello, Secure World!".utf8)
        let timestamp = UInt64(Date().timeIntervalSince1970 * 1000)
        
        let packet = SecureBitchatPacket(
            type: 0x01,
            senderID: Data(repeating: 0xAB, count: 8),
            recipientID: nil,
            timestamp: timestamp,
            payload: payload,
            signature: nil,
            ttl: 7,
            version: 1
        )
        
        let encoded = try SecureBinaryProtocol.encode(packet, padding: true)
        let decoded = try SecureBinaryProtocol.decode(encoded)
        
        XCTAssertEqual(decoded.type, packet.type)
        XCTAssertEqual(decoded.senderID, packet.senderID)
        XCTAssertEqual(decoded.payload, packet.payload)
        XCTAssertEqual(decoded.ttl, packet.ttl)
    }
    
    func testCompressionRatioCheck() throws {
        let repetitivePayload = Data(repeating: 0x41, count: 1000)
        
        let packet = SecureBitchatPacket(
            type: 0x01,
            senderID: Data(repeating: 0xAB, count: 8),
            recipientID: nil,
            timestamp: UInt64(Date().timeIntervalSince1970 * 1000),
            payload: repetitivePayload,
            signature: nil,
            ttl: 7,
            version: 1
        )
        
        let encoded = try SecureBinaryProtocol.encode(packet, padding: false)
        let decoded = try SecureBinaryProtocol.decode(encoded)
        
        XCTAssertEqual(decoded.payload, repetitivePayload)
    }
    
    func testMentionParsing() throws {
        let text = "Hello @alice and @bob! Great to meet @charlie."
        let mentions = try SecureBinaryProtocol.parseMentions(text)
        
        XCTAssertEqual(mentions.count, 3)
        XCTAssertTrue(mentions.contains("@alice"))
        XCTAssertTrue(mentions.contains("@bob"))
        XCTAssertTrue(mentions.contains("@charlie"))
    }
}
