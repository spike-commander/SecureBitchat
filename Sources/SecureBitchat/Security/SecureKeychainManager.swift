//
// SecureKeychainManager.swift
// SecureBitchat
//
// Secure keychain wrapper for storing cryptographic keys and sensitive data.
// Provides additional security measures beyond standard keychain access.
//
// This is free and unencumbered software released into the public domain.
// For more information, see <https://unproject.org>
//

import Foundation
import Security

protocol SecureKeychainManagerProtocol {
    func save(_ data: Data, forKey key: String) -> Bool
    func getData(forKey key: String) -> Data?
    func delete(forKey key: String) -> Bool
    func save(_ value: Double, forKey key: String)
    func getDouble(forKey key: String) -> Double?
    func deleteAll()
}

final class SecureKeychainManager: SecureKeychainManagerProtocol {
    private let serviceName: String
    private let accessGroup: String?
    
    init(serviceName: String = "SecureBitchat", accessGroup: String? = nil) {
        self.serviceName = serviceName
        self.accessGroup = accessGroup
    }
    
    func save(_ data: Data, forKey key: String) -> Bool {
        delete(forKey: key)
        
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: key,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
        
        if let group = accessGroup {
            query[kSecAttrAccessGroup as String] = group
        }
        
        let status = SecItemAdd(query as CFDictionary, nil)
        
        if status != errSecSuccess {
            SecureLogger.error("Keychain save failed with status: \(status)", category: .keychain)
        }
        
        return status == errSecSuccess
    }
    
    func getData(forKey key: String) -> Data? {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        if let group = accessGroup {
            query[kSecAttrAccessGroup as String] = group
        }
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        if status == errSecSuccess {
            return result as? Data
        }
        
        return nil
    }
    
    @discardableResult
    func delete(forKey key: String) -> Bool {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: key
        ]
        
        if let group = accessGroup {
            query[kSecAttrAccessGroup as String] = group
        }
        
        let status = SecItemDelete(query as CFDictionary)
        
        return status == errSecSuccess || status == errSecItemNotFound
    }
    
    func save(_ value: Double, forKey key: String) {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: key,
            kSecValueData as String: withUnsafeBytes(of: value) { Data($0) },
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
        
        if let group = accessGroup {
            query[kSecAttrAccessGroup as String] = group
        }
        
        SecItemDelete(query as CFDictionary)
        SecItemAdd(query as CFDictionary, nil)
    }
    
    func getDouble(forKey key: String) -> Double? {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        if let group = accessGroup {
            query[kSecAttrAccessGroup as String] = group
        }
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        guard status == errSecSuccess,
              let data = result as? Data,
              data.count == MemoryLayout<Double>.size else {
            return nil
        }
        
        return data.withUnsafeBytes { $0.load(as: Double.self) }
    }
    
    func deleteAll() {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName
        ]
        
        if let group = accessGroup {
            query[kSecAttrAccessGroup as String] = group
        }
        
        SecItemDelete(query as CFDictionary)
    }
    
    func secureCompare(_ lhs: Data, _ rhs: Data) -> Bool {
        guard lhs.count == rhs.count else { return false }
        
        var result: UInt8 = 0
        for i in 0..<lhs.count {
            result |= lhs[i] ^ rhs[i]
        }
        
        return result == 0
    }
}
