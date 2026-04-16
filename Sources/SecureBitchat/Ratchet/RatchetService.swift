//
// RatchetService.swift
// SecureBitchat
//
// Double Ratchet implementation for forward-secret messaging.
// Uses libsodium for cryptographic operations when available,
// falls back to CryptoKit implementation.
//
// This is free and unencumbered software released into the public domain.
// For more information, see <https://unproject.org>
//

import Foundation
import CryptoKit

protocol RatchetServiceProtocol {
    func initializeSession(with publicKey: Data, theirIdentity: Data) throws -> RatchetSession
    func encrypt(_ plaintext: Data, in session: inout RatchetSession) throws -> Data
    func decrypt(_ ciphertext: Data, in session: inout RatchetSession) throws -> Data
    func ratchetStep(session: inout RatchetSession) throws
}

enum RatchetError: Error {
    case invalidPublicKey
    case invalidPrivateKey
    case sessionNotInitialized
    case encryptionFailed
    case decryptionFailed
    case chainKeyDerivationFailed
    case messageKeyDerivationFailed
    case maximumSkippedMessagesExceeded
    case duplicateMessage
}

struct RatchetSession {
    var rootKey: Data
    var sendChainKey: Data?
    var receiveChainKey: Data?
    var sendMessageNumber: UInt32 = 0
    var receiveMessageNumber: UInt32 = 0
    var skippedMessageKeys: [String: Data] = [:]
    var theirIdentityKey: Data
    var ourIdentityKey: Data
    var dhKeyPair: Curve25519.KeyAgreement.PrivateKey
    var theirRatchetKey: Curve25519.KeyAgreement.PublicKey?
    var previousSendChainLength: UInt32 = 0
    var remotePreviousRatchetKey: Curve25519.KeyAgreement.PublicKey?
    var messageKeys: [UInt32: Data] = [:]
    
    var sessionId: String {
        let combined = theirIdentityKey + ourIdentityKey
        return SHA256.hash(data: combined).compactMap { String(format: "%02x", $0) }.joined()
    }
}

final class RatchetService: RatchetServiceProtocol {
    private let maxSkippedKeys = 1000
    private let chainKeyLength = 32
    private let messageKeyLength = 32
    
    private var sessions: [String: RatchetSession] = [:]
    private let sessionsQueue = DispatchQueue(label: "secure.bitchat.ratchet", attributes: .concurrent)
    
    func initializeSession(with publicKey: Data, theirIdentity: Data) throws -> RatchetSession {
        guard publicKey.count == 32 else {
            throw RatchetError.invalidPublicKey
        }
        
        let ourDHKeyPair = Curve25519.KeyAgreement.PrivateKey()
        guard let theirRatchetKey = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: publicKey) else {
            throw RatchetError.invalidPublicKey
        }
        
        let sharedSecret = try deriveSharedSecret(privateKey: ourDHKeyPair, publicKey: theirRatchetKey)
        let rootKey = deriveRootKey(from: sharedSecret)
        
        var session = RatchetSession(
            rootKey: rootKey,
            sendChainKey: nil,
            receiveChainKey: nil,
            theirIdentityKey: theirIdentity,
            ourIdentityKey: ourDHKeyPair.publicKey.rawRepresentation,
            dhKeyPair: ourDHKeyPair,
            theirRatchetKey: theirRatchetKey
        )
        
        let (newRootKey, sendChainKey) = kdfRootChain(
            rootKey: rootKey,
            dhOutput: sharedSecret
        )
        
        session.rootKey = newRootKey
        session.sendChainKey = sendChainKey
        
        let sessionId = session.sessionId
        sessionsQueue.sync(flags: .barrier) {
            self.sessions[sessionId] = session
        }
        
        return session
    }
    
    func encrypt(_ plaintext: Data, in session: inout RatchetSession) throws -> Data {
        guard let chainKey = session.sendChainKey else {
            throw RatchetError.sessionNotInitialized
        }
        
        let (messageKey, newChainKey) = deriveMessageKey(from: chainKey)
        
        session.sendChainKey = newChainKey
        session.sendMessageNumber += 1
        
        let ciphertext = try encryptWithKey(plaintext, key: messageKey)
        
        let header = RatchetMessageHeader(
            publicKey: session.dhKeyPair.publicKey.rawRepresentation,
            previousChainLength: session.previousSendChainLength,
            messageNumber: session.sendMessageNumber
        )
        
        let encryptedHeader = try encryptWithKey(header.encode(), key: messageKey)
        
        let fullMessage = RatchetEncryptedMessage(
            header: encryptedHeader,
            ciphertext: ciphertext,
            messageNumber: session.sendMessageNumber
        )
        
        return fullMessage.encode()
    }
    
    func decrypt(_ ciphertext: Data, in session: inout RatchetSession) throws -> Data {
        let message = try RatchetEncryptedMessage.decode(ciphertext)
        
        if let skippedKey = session.skippedMessageKeys["\(session.theirRatchetKey?.rawRepresentation.base64EncodedString() ?? "")-\(message.messageNumber)"] {
            session.skippedMessageKeys.removeValue(forKey: "\(session.theirRatchetKey?.rawRepresentation.base64EncodedString() ?? "")-\(message.messageNumber)")
            return try decryptWithKey(message.ciphertext, key: skippedKey)
        }
        
        guard let theirRatchetKey = session.theirRatchetKey else {
            throw RatchetError.sessionNotInitialized
        }
        
        let keyId = theirRatchetKey.rawRepresentation.base64EncodedString()
        
        for (storedKeyId, _) in session.skippedMessageKeys where storedKeyId.hasPrefix(keyId) {
            session.skippedMessageKeys.removeValue(forKey: storedKeyId)
        }
        
        let chainKey = session.receiveChainKey ?? session.rootKey
        
        let (messageKey, newChainKey) = deriveMessageKey(from: chainKey)
        session.receiveChainKey = newChainKey
        session.receiveMessageNumber += 1
        
        return try decryptWithKey(message.ciphertext, key: messageKey)
    }
    
    func ratchetStep(session: inout RatchetSession) throws {
        guard let theirKey = session.theirRatchetKey else {
            throw RatchetError.sessionNotInitialized
        }
        
        session.previousSendChainLength = session.sendMessageNumber
        
        let dhOutput = try deriveSharedSecret(privateKey: session.dhKeyPair, publicKey: theirKey)
        
        let (newRootKey1, receiveChainKey) = kdfRootChain(rootKey: session.rootKey, dhOutput: dhOutput)
        
        session.rootKey = newRootKey1
        session.receiveChainKey = receiveChainKey
        
        let newDHKeyPair = Curve25519.KeyAgreement.PrivateKey()
        let newDHOutput = try deriveSharedSecret(privateKey: newDHKeyPair, publicKey: theirKey)
        
        let (newRootKey2, sendChainKey) = kdfRootChain(rootKey: session.rootKey, dhOutput: newDHOutput)
        
        session.rootKey = newRootKey2
        session.sendChainKey = sendChainKey
        session.sendMessageNumber = 0
        session.dhKeyPair = newDHKeyPair
    }
    
    func getOrCreateSession(id: String) -> RatchetSession? {
        return sessionsQueue.sync {
            sessions[id]
        }
    }
    
    private func deriveSharedSecret(privateKey: Curve25519.KeyAgreement.PrivateKey, publicKey: Curve25519.KeyAgreement.PublicKey) throws -> Data {
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
        
        return sharedSecret.withUnsafeBytes { Data($0) }
    }
    
    private func deriveRootKey(from sharedSecret: Data) -> Data {
        let hash = SHA256.hash(data: sharedSecret)
        return Data(hash)
    }
    
    private func kdfRootChain(rootKey: Data, dhOutput: Data) -> (rootKey: Data, chainKey: Data) {
        let input = rootKey + dhOutput
        let hash = SHA256.hash(data: input)
        let newRootKey = Data(hash.prefix(32))
        let chainKey = Data(hash.suffix(from: hash.startIndex.advanced(by: 32)))
        
        return (newRootKey.count == 32 ? newRootKey : Data(SHA256.hash(data: newRootKey)),
                chainKey.count == 32 ? chainKey : Data(SHA256.hash(data: chainKey)))
    }
    
    private func deriveMessageKey(from chainKey: Data) -> (messageKey: Data, newChainKey: Data) {
        let messageKeyInput = chainKey + Data([0x01])
        let chainKeyInput = chainKey + Data([0x02])
        
        let messageKeyHash = SHA256.hash(data: messageKeyInput)
        let chainKeyHash = SHA256.hash(data: chainKeyInput)
        
        return (Data(messageKeyHash), Data(chainKeyHash))
    }
    
    private func encryptWithKey(_ plaintext: Data, key: Data) throws -> Data {
        guard key.count == 32 else {
            throw RatchetError.encryptionFailed
        }
        
        let symmetricKey = SymmetricKey(data: key)
        let nonce = AES.GCM.Nonce()
        
        guard let sealed = try? AES.GCM.seal(plaintext, using: symmetricKey, nonce: nonce) else {
            throw RatchetError.encryptionFailed
        }
        
        return sealed.combined ?? Data()
    }
    
    private func decryptWithKey(_ ciphertext: Data, key: Data) throws -> Data {
        guard key.count == 32 else {
            throw RatchetError.decryptionFailed
        }
        
        let symmetricKey = SymmetricKey(data: key)
        
        guard let sealed = try? AES.GCM.SealedBox(combined: ciphertext),
              let decrypted = try? AES.GCM.open(sealed, using: symmetricKey) else {
            throw RatchetError.decryptionFailed
        }
        
        return decrypted
    }
    
    func skipMessageKeys(until messageNumber: UInt32, in session: inout RatchetSession) throws {
        guard let theirKey = session.theirRatchetKey,
              let chainKey = session.receiveChainKey else {
            return
        }
        
        var currentKey = chainKey
        let currentNumber = session.receiveMessageNumber
        
        for i in currentNumber..<messageNumber {
            let (messageKey, newChainKey) = deriveMessageKey(from: currentKey)
            let keyId = theirKey.rawRepresentation.base64EncodedString()
            session.skippedMessageKeys["\(keyId)-\(i)"] = messageKey
            currentKey = newChainKey
            
            if session.skippedMessageKeys.count > maxSkippedKeys {
                throw RatchetError.maximumSkippedMessagesExceeded
            }
        }
        
        session.receiveChainKey = currentKey
    }
}

struct RatchetMessageHeader: Codable {
    let publicKey: Data
    let previousChainLength: UInt32
    let messageNumber: UInt32
    
    func encode() -> Data {
        var data = Data()
        data.append(UInt8(publicKey.count))
        data.append(publicKey)
        
        var pcl = previousChainLength.bigEndian
        data.append(contentsOf: withUnsafeBytes(of: &pcl) { Array($0) })
        
        var mn = messageNumber.bigEndian
        data.append(contentsOf: withUnsafeBytes(of: &mn) { Array($0) })
        
        return data
    }
}

struct RatchetEncryptedMessage {
    let header: Data
    let ciphertext: Data
    let messageNumber: UInt32
    
    func encode() -> Data {
        var data = Data()
        var num = messageNumber.bigEndian
        data.append(contentsOf: withUnsafeBytes(of: &num) { Array($0) })
        
        var headerLen = UInt32(header.count).bigEndian
        data.append(contentsOf: withUnsafeBytes(of: &headerLen) { Array($0) })
        data.append(header)
        
        var ctLen = UInt32(ciphertext.count).bigEndian
        data.append(contentsOf: withUnsafeBytes(of: &ctLen) { Array($0) })
        data.append(ciphertext)
        
        return data
    }
    
    static func decode(_ data: Data) throws -> RatchetEncryptedMessage {
        var offset = 0
        
        guard data.count >= 4 else {
            throw RatchetError.decryptionFailed
        }
        
        let messageNumber = UInt32(bigEndian: data.withUnsafeBytes { $0.load(fromByteOffset: offset, as: UInt32.self) })
        offset += 4
        
        guard data.count >= offset + 4 else {
            throw RatchetError.decryptionFailed
        }
        
        let headerLen = Int(UInt32(bigEndian: data.withUnsafeBytes { $0.load(fromByteOffset: offset, as: UInt32.self) }))
        offset += 4
        
        guard data.count >= offset + headerLen else {
            throw RatchetError.decryptionFailed
        }
        
        let header = data.subdata(in: offset..<(offset + headerLen))
        offset += headerLen
        
        guard data.count >= offset + 4 else {
            throw RatchetError.decryptionFailed
        }
        
        let ctLen = Int(UInt32(bigEndian: data.withUnsafeBytes { $0.load(fromByteOffset: offset, as: UInt32.self) }))
        offset += 4
        
        guard data.count >= offset + ctLen else {
            throw RatchetError.decryptionFailed
        }
        
        let ciphertext = data.subdata(in: offset..<(offset + ctLen))
        
        return RatchetEncryptedMessage(header: header, ciphertext: ciphertext, messageNumber: messageNumber)
    }
}
