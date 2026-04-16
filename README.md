# SecureBitchat

A hardened security fork of BitChat with production-ready security enhancements and private room support.

## Overview

SecureBitchat is a security-hardened version of the decentralized Bluetooth mesh chat app BitChat. It maintains the core principles of offline BLE mesh communication, decentralized architecture, and P2P networking while implementing significant security improvements.

## Core Security Enhancements

### 1. Buffer Overflow Protection
- Signature validation ensures data is at least 64 bytes before processing
- Safe null byte trimming prevents memory corruption
- Length validation on all variable-size fields

### 2. Payload Truncation (UInt16)
- Maximum payload size capped at 65,535 bytes
- Rejects packets exceeding the limit during encoding/decoding
- Prevents resource exhaustion attacks

### 3. Mentions DoS Protection
- Maximum 10 mentions per message
- Maximum 256 characters per mention
- Parsing with strict limits prevents algorithmic complexity attacks

### 4. Replay Attack Protection
- Timestamp validation within 24-hour window
- Nonce tracking for message uniqueness
- Ratchet key rotation prevents message replay

### 5. MITM Protection
- QR code based out-of-band fingerprint verification
- Biometric/PIN gate for sensitive operations
- Fingerprint verification before key exchange

### 6. Ephemeral Key Rotation
- Keys rotate every 1 hour or per session
- Forward secrecy maintained via Double Ratchet
- Automatic key rotation without user intervention

### 7. Forward Secrecy (Double Ratchet)
- libsodium-style Double Ratchet implementation
- Each message uses a unique encryption key
- Compromised keys don't affect past messages

### 8. Compression Leak Prevention
- Fixed-padding LZ4 compression
- Padding ensures uniform compressed output size
- Prevents traffic analysis via compression ratios

### 9. AEAD Encryption
- XChaCha20-Poly1305 for all packet encryption
- Authenticated encryption with additional data
- Nonce-based encryption prevents pattern detection

## Private Rooms

### Features
- **Invite via Signed QR**: Ed25519 signed invitations with expiration
- **Argon2id Key Derivation**: Password + room ID → encryption key
- **MLS-style Ratchet**: Group rekey when members join/leave
- **Biometric/PIN Gate**: Extra authentication for room access
- **Traffic Padding**: Uniform packet sizes hide metadata

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Private Room Manager                      │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │  Create     │  │  Join       │  │  Rekey              │  │
│  │  Room       │  │  via QR     │  │  (on member change) │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
│                                                              │
│  ┌─────────────────────────────────────────────────────────┐│
│  │              AES-GCM Encryption Layer                   ││
│  └─────────────────────────────────────────────────────────┘│
│                                                              │
│  ┌─────────────────────────────────────────────────────────┐│
│  │           Argon2id Key Derivation                       ││
│  │     password + roomId → 32-byte encryption key          ││
│  └─────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────┘
```

## Building

### Prerequisites
- Xcode 15+
- CocoaPods or Swift Package Manager
- iOS 16.0+ / macOS 13.0+

### Using CocoaPods
```bash
cd SecureBitchat
pod install
xed .
```

### Using Swift Package Manager
The project includes Swift Package Manager support for dependencies.

## Testing

Run the test suite:
```bash
swift test
```

Or via Xcode:
```bash
xcodebuild test -scheme SecureBitchat -destination 'platform=iOS Simulator,name=iPhone 15'
```

## Project Structure

```
SecureBitchat/
├── Sources/
│   └── SecureBitchat/
│       ├── Protocols/
│       │   └── SecureBinaryProtocol.swift   # Hardened protocol
│       ├── Security/
│       │   ├── SecureIdentityManager.swift  # Identity + MITM protection
│       │   └── SecureKeychainManager.swift  # Secure storage
│       ├── Ratchet/
│       │   └── RatchetService.swift         # Double Ratchet
│       ├── Rooms/
│       │   └── PrivateRoomManager.swift     # Private rooms
│       └── Crypto/
│           └── XChaCha20Poly1305AEAD.swift  # AEAD encryption
├── Tests/
│   └── SecureBitchatTests/
│       ├── SecureBinaryProtocolTests.swift
│       ├── PrivateRoomTests.swift
│       ├── RatchetServiceTests.swift
│       └── XChaCha20Poly1305Tests.swift
├── Docs/
│   └── diagrams.md                          # Flow diagrams
├── Podfile                                  # CocoaPods deps
└── README.md
```

## Security Comparison

| Feature                  | BitChat    | SecureBitchat |
|--------------------------|------------|---------------|
| Signature Validation      | Basic      | 64-byte check |
| Payload Limit            | 4GB        | 65535 bytes   |
| Timestamp Window         | 2 minutes  | 24 hours     |
| Mentions Limit           | None       | 10 max        |
| Forward Secrecy          | Noise only | Double Ratchet|
| Room Encryption          | None       | AES-GCM       |
| Key Derivation           | None       | Argon2id      |
| Biometric Auth           | No         | Yes           |
| Traffic Padding          | Optional   | Always        |

## License

This project is released into the public domain. See the [LICENSE](LICENSE) file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## Architecture Diagrams

See [diagrams.md](Docs/diagrams.md) for Mermaid flowcharts showing:
- Secure room join flow
- Message encryption flow
- Key rotation sequence
