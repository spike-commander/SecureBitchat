# SecureBitchat Architecture Diagrams

## Secure Room Join Flow

```mermaid
sequenceDiagram
    participant Alice
    participant QRCode
    participant RoomManager
    participant Keychain
    participant IdentityManager
    
    Alice->>RoomManager: createRoom(name, password)
    RoomManager->>IdentityManager: getCurrentFingerprint()
    IdentityManager-->>RoomManager: creatorFingerprint
    
    RoomManager->>RoomManager: generateRoomId()
    RoomManager->>RoomManager: deriveKey(password, roomId)
    Note right of RoomManager: Uses Argon2id/HKDF<br/>for key derivation
    
    RoomManager->>RoomManager: generateSigningKey()
    RoomManager->>Keychain: save(room)
    
    RoomManager-->>Alice: PrivateRoom
    
    Alice->>RoomManager: generateInviteQR(room)
    RoomManager->>IdentityManager: sign(payload)
    RoomManager->>RoomManager: create QR invite
    RoomManager-->>Alice: base64EncodedQR
    
    Note over Alice: Share QR with Bob via secure channel
    
    participant Bob
    Alice->>Bob: share QR code
    
    Bob->>RoomManager: joinRoom(inviteQR, password)
    RoomManager->>RoomManager: parseInviteQR()
    RoomManager->>RoomManager: verifySignature()
    
    alt Signature Invalid
        RoomManager-->>Bob: Error: invalidInvite
    end
    
    RoomManager->>RoomManager: deriveKey(password, roomId)
    RoomManager->>Keychain: save(room)
    RoomManager-->>Bob: PrivateRoom
```

## Message Encryption Flow

```mermaid
flowchart TD
    A[User Types Message] --> B{Has Room Key?}
    
    B -->|No| C[Error: Room Not Found]
    B -->|Yes| D[Generate Nonce]
    
    D --> E[Encrypt with AES-GCM]
    E --> F[Add Padding]
    F --> G[Send via BLE Mesh]
    
    G --> H{Relay to Peers?}
    H -->|Yes| I[Encrypt for Each Peer]
    I --> J[Send Fragmented if Needed]
    J --> K[Mesh Broadcast]
    
    H -->|No| L[Direct Send]
    
    subgraph Receiver Side
        M[Receive Packet] --> N[Decrypt Header]
        N --> O[Verify Nonce]
        O --> P[Decrypt Payload]
        P --> Q[Remove Padding]
        Q --> R[Display Message]
    end
    
    K --> M
    L --> M
```

## Double Ratchet Key Exchange

```mermaid
sequenceDiagram
    participant Alice
    participant RatchetService
    participant Bob
    participant Keychain
    
    Alice->>Bob: Exchange public keys
    
    Bob->>RatchetService: initializeSession(AlicePubKey)
    RatchetService->>RatchetService: Generate DH key pair
    RatchetService->>RatchetService: Derive root key
    
    Note right of RatchetService: DH Output + Root Key<br/>→ New Root Key + Chain Key
    
    RatchetService->>Keychain: saveSession()
    
    loop For Each Message
        Alice->>RatchetService: encrypt(message)
        RatchetService->>RatchetService: deriveMessageKey
        RatchetService->>RatchetService: updateChainKey
        RatchetService-->>Bob: encryptedMessage
        
        Bob->>RatchetService: decrypt(message)
        RatchetService->>RatchetService: deriveMessageKey
        RatchetService->>RatchetService: updateChainKey
        RatchetService-->>Bob: plaintext
    end
    
    alt Ratchet Step (Periodically)
        RatchetService->>RatchetService: Generate new DH key pair
        RatchetService->>RatchetService: DH with Bob's ratchet key
        RatchetService->>RatchetService: Derive new keys
        RatchetService->>Keychain: saveSession()
    end
```

## Key Rotation Timeline

```mermaid
gantt
    title Key Rotation Schedule
    dateFormat X
    axisFormat %s
    
    section Ephemeral Keys
    Identity Key Generation    :0, 50
    Key in Use                :50, 3500
    Rotation Check            :3500, 3600
    New Key Generation        :3600, 3650
    Key in Use                :3650, 7150
    
    section Room Keys
    Room Created              :100, 200
    Member Joins              :1500, 1600
    Rekey Triggered           :1600, 1700
    New Room Key Distributed   :1700, 1800
    
    section Ratchet
    Message 1 Key             :500, 600
    Message 2 Key             :600, 700
    Message 3 Key             :700, 800
    Ratchet Step              :800, 900
    Message 4 Key             :900, 1000
```

## Biometric Authentication Flow

```mermaid
flowchart TD
    A[Access Private Room] --> B{Can use Biometrics?}
    
    B -->|Yes| C[Request Face ID/Touch ID]
    C --> D{User Authenticated?}
    
    B -->|No| E[Request Device Passcode]
    E --> D
    
    D -->|Success| F[Unlock Room Key]
    D -->|Failure| G[Show Error]
    G --> H{Retry Count < 3?}
    H -->|Yes| C
    H -->|No| I[Lock Room Access]
    
    F --> J[Room Operations Available]
```

## Security Layer Architecture

```mermaid
flowchart TB
    subgraph Application Layer
        A[User Interface]
        B[Room Management]
        C[Message Composition]
    end
    
    subgraph Security Layer
        D[Biometric Gate]
        E[Private Room Manager]
        F[Identity Manager]
    end
    
    subgraph Crypto Layer
        G[Double Ratchet]
        H[AEAD Encryption]
        I[Key Derivation]
    end
    
    subgraph Transport Layer
        J[BLE Mesh]
        K[Binary Protocol]
    end
    
    A --> D
    B --> E
    C --> E
    
    D --> F
    E --> G
    E --> I
    F --> G
    
    G --> H
    H --> I
    I --> K
    
    K --> J
```

## Packet Format Comparison

```mermaid
classDiagram
    class BitChatPacket {
        +UInt8 version
        +UInt8 type
        +UInt8 ttl
        +UInt64 timestamp
        +UInt8 flags
        +Data senderID
        +Data payload
        +Data signature
    }
    
    class SecureBitchatPacket {
        +UInt8 version
        +UInt8 type
        +UInt8 ttl
        +UInt64 timestamp
        +UInt8 flags
        +Data senderID
        +Data payload
        +Data signature
        +UInt64 nonce
        +Data route
        +Bool isRSR
    }
    
    note for BitChatPacket "Original format\n- Basic signature\n- No nonce\n- Limited validation"
    
    note for SecureBitchatPacket "Hardened format\n- 64-byte signature check\n- Anti-replay nonce\n- Padding for traffic analysis protection"
```
