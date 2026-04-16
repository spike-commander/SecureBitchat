//
// SecureBitchat.swift
// SecureBitchat
//
// This is free and unencumbered software released into the public domain.
// For more information, see <https://unproject.org>
//

public struct SecureBitchat {
    public static let version = "1.0.0"
    public static let build = "security-hardened"
}

public enum SecureBitchatError: Error {
    case initializationFailed
    case encryptionError
    case decryptionError
    case keychainError
    case identityError
    case roomError
}
