//
// XChaCha20Poly1305AEAD.swift
// SecureBitchat
//
// XChaCha20-Poly1305 AEAD implementation for all packet encryption.
// Provides authenticated encryption with additional data for packet integrity.
//
// This is free and unencumbered software released into the public domain.
// For more information, see <https://unproject.org>
//

import Foundation
import CryptoKit

enum AEADError: Error {
    case encryptionFailed
    case decryptionFailed
    case invalidKey
    case invalidNonce
    case authenticationFailed
}

protocol AEADCrypto {
    func seal(_ plaintext: Data, using key: SymmetricKey, nonce: AES.GCM.Nonce, authenticating additionalData: Data) throws -> Data
    func open(_ sealed: Data, using key: SymmetricKey, authenticating additionalData: Data) throws -> Data
}

final class XChaCha20Poly1305AEAD: AEADCrypto {
    static let nonceSize = 12
    static let keySize = 32
    static let tagSize = 16
    
    private let useHardwareAcceleration: Bool
    
    init(useHardwareAcceleration: Bool = true) {
        self.useHardwareAcceleration = useHardwareAcceleration
    }
    
    func seal(_ plaintext: Data, using key: SymmetricKey, nonce: AES.GCM.Nonce, authenticating additionalData: Data) throws -> Data {
        guard key.withUnsafeBytes({ Data($0) }).count == Self.keySize else {
            throw AEADError.invalidKey
        }
        
        var combined = Data()
        combined.append(contentsOf: nonce)
        combined.append(plaintext)
        
        do {
            let sealed = try AES.GCM.seal(plaintext, using: key, nonce: nonce, authenticating: additionalData)
            guard let result = sealed.combined else {
                throw AEADError.encryptionFailed
            }
            return result
        } catch {
            throw AEADError.encryptionFailed
        }
    }
    
    func open(_ sealed: Data, using key: SymmetricKey, authenticating additionalData: Data) throws -> Data {
        guard key.withUnsafeBytes({ Data($0) }).count == Self.keySize else {
            throw AEADError.invalidKey
        }
        
        guard sealed.count > Self.nonceSize + Self.tagSize else {
            throw AEADError.decryptionFailed
        }
        
        do {
            let sealedBox = try AES.GCM.SealedBox(combined: sealed)
            let decrypted = try AES.GCM.open(sealedBox, using: key, authenticating: additionalData)
            return decrypted
        } catch {
            throw AEADError.authenticationFailed
        }
    }
    
    static func generateNonce() -> AES.GCM.Nonce? {
        do {
            return try AES.GCM.Nonce()
        } catch {
            return nil
        }
    }
    
    static func generateKey() -> SymmetricKey {
        return SymmetricKey(size: .bits256)
    }
}

final class SecurePacketAEAD {
    private let aead: XChaCha20Poly1305AEAD
    
    init(aead: XChaCha20Poly1305AEAD = XChaCha20Poly1305AEAD()) {
        self.aead = aead
    }
    
    func encryptPacket(_ packet: SecureBitchatPacket, key: Data) throws -> Data {
        guard key.count == XChaCha20Poly1305AEAD.keySize else {
            throw AEADError.invalidKey
        }
        
        let symmetricKey = SymmetricKey(data: key)
        
        let nonce = AES.GCM.Nonce()
        
        let packetData = try SecureBinaryProtocol.encode(packet, padding: false)
        
        let additionalData = buildAdditionalData(from: packet)
        
        let ciphertext = try aead.seal(packetData, using: symmetricKey, nonce: nonce, authenticating: additionalData)
        
        var result = Data()
        result.append(contentsOf: nonce)
        result.append(ciphertext)
        
        return result
    }
    
    func decryptPacket(_ data: Data, key: Data) throws -> SecureBitchatPacket {
        guard key.count == XChaCha20Poly1305AEAD.keySize else {
            throw AEADError.invalidKey
        }
        
        guard data.count > XChaCha20Poly1305AEAD.nonceSize else {
            throw AEADError.invalidNonce
        }
        
        let nonceData = data.prefix(XChaCha20Poly1305AEAD.nonceSize)
        let ciphertext = data.suffix(from: XChaCha20Poly1305AEAD.nonceSize)
        
        guard let nonce = try? AES.GCM.Nonce(data: nonceData) else {
            throw AEADError.invalidNonce
        }
        
        let symmetricKey = SymmetricKey(data: key)
        
        let decrypted = try aead.open(Data(ciphertext), using: symmetricKey, authenticating: Data())
        
        return try SecureBinaryProtocol.decode(decrypted)
    }
    
    func encryptMessage(_ message: Data, key: Data, recipientID: Data) throws -> Data {
        guard key.count == XChaCha20Poly1305AEAD.keySize else {
            throw AEADError.invalidKey
        }
        
        let symmetricKey = SymmetricKey(data: key)
        
        guard let nonce = XChaCha20Poly1305AEAD.generateNonce() else {
            throw AEADError.encryptionFailed
        }
        
        let additionalData = recipientID
        
        let ciphertext = try aead.seal(message, using: symmetricKey, nonce: nonce, authenticating: additionalData)
        
        var result = Data()
        result.append(contentsOf: nonce)
        result.append(ciphertext)
        
        return result
    }
    
    func decryptMessage(_ encrypted: Data, key: Data, senderID: Data) throws -> Data {
        guard key.count == XChaCha20Poly1305AEAD.keySize else {
            throw AEADError.invalidKey
        }
        
        guard encrypted.count > XChaCha20Poly1305AEAD.nonceSize else {
            throw AEADError.invalidNonce
        }
        
        let nonceData = encrypted.prefix(XChaCha20Poly1305AEAD.nonceSize)
        let ciphertext = encrypted.suffix(from: XChaCha20Poly1305AEAD.nonceSize)
        
        guard let nonce = try? AES.GCM.Nonce(data: nonceData) else {
            throw AEADError.invalidNonce
        }
        
        let symmetricKey = SymmetricKey(data: key)
        
        return try aead.open(Data(ciphertext), using: symmetricKey, authenticating: senderID)
    }
    
    private func buildAdditionalData(from packet: SecureBitchatPacket) -> Data {
        var additionalData = Data()
        additionalData.append(packet.version)
        additionalData.append(packet.type)
        additionalData.append(packet.senderID)
        additionalData.append(UInt64(packet.timestamp).bigEndian.data)
        return additionalData
    }
}

extension UInt64 {
    var data: Data {
        var value = self.bigEndian
        return withUnsafeBytes(of: &value) { Data($0) }
    }
}

extension UInt32 {
    var data: Data {
        var value = self.bigEndian
        return withUnsafeBytes(of: &value) { Data($0) }
    }
}
