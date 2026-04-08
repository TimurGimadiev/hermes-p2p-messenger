# Hermes P2P Security Architecture (v0.3.0)

## Protocol Overview

```
┌──────────┐    Forward-Secure E2E    ┌──────────┐
│  Alice   │ ───────────────────────► │   Bob    │
│ Ed25519  │   Ephemeral X25519       │ Ed25519  │
│ X25519   │ ───────────────────────► │ X25519   │
└──────────┘   + HKDF + SecretBox    └──────────┘
     │   OR O(1) Room Key                │
     │     libp2p FloodSub               │
     │     (strict_signing)              │
└─────────────────────────────────────────┘
```

## Security Layers (7 layers)

| Layer | Mechanism | Status | Protects Against |
|-------|-----------|--------|------------------|
| 1. Transport | TCP + Noise (libp2p) | DONE | Network eavesdropping |
| 2. PubSub | strict_signing=True | DONE | Unsigned message injection |
| 3. Authentication | Ed25519 per message | DONE | Sender impersonation |
| 4. Confidentiality | Ephemeral X25519 + HKDF + SecretBox | DONE | Content exposure + Forward Secrecy |
| 5. Integrity | HMAC-SHA256 + MAC | DONE | Message tampering |
| 6. Rate Limiting | Per-peer: 10 msgs/10s | DONE | Flooding/DoS |
| 7. Replay Protection | ID dedup + 5min TTL | DONE | Replay attacks |

## Forward Secrecy (NEW in v0.3.0)

### Per-Message Ephemeral Keys
- **Every message** generates a fresh X25519 keypair
- Ephemeral private key used ONLY for this message, then **discarded**
- Even if long-term private key leaks years later, **past messages are safe**
- Each message uses unique HKDF derivation with `info = "hermes_e2e:{peer_id}:{msg_id}"`

### Envelope Structure
```json
{
    "recipient_peer_id": "12D3KooW...",
    "sender_eph_pubkey": "hex_32B",       // NEW: per-message ephemeral
    "nonce": "hex_24B",
    "ciphertext": "hex",
    "mac_tag": "hex_32B"                   // NEW: HMAC-SHA256
}
```

### O(1) Group Broadcast (NEW in v0.3.0)
- Shared room symmetric key for trusted groups
- **Single envelope** regardless of group size
- Trade-off: room key compromise = all room history readable
- Ed25519 signature still verifies sender identity

### Cryptographic Primitives

| Component | Algorithm | Library |
|-----------|-----------|---------|
| Per-ECDH | X25519 (ephemeral) | PyNaCl (libsodium) |
| Symmetric | XSalsa20-Poly1305 | nacl.secret.SecretBox |
| Key Derivation | HKDF-SHA256 | cryptography library |
| Signatures | Ed25519 | nacl.signing |
| MAC | HMAC-SHA256 | hmac (stdlib) |
| Nonces | 192-bit random | nacl.utils.random |

### Threat Model

| Threat | Mitigation | Status |
|--------|------------|--------|
| Network sniffing | Ephemeral X25519 encryption | PROTECTED |
| Message forgery | Ed25519 signatures | PROTECTED |
| Sender spoofing | strict_signing + Ed25519 | PROTECTED |
| Replay attacks | ID dedup + 5min TTL | PROTECTED |
| Flooding | Rate limiting per peer | PROTECTED |
| Key compromise (past msgs) | Ephemeral X25519 per message | PROTECTED |
| Man-in-the-middle | ECDH + signatures | PROTECTED |
| Traffic analysis | No onion routing | NOT PROTECTED |
| Denial of Service | Rate limiting | BASIC |
| Quantum attack | Classical crypto only | VULNERABLE |

### Remaining Limitations

1. **No onion routing** — libp2p pubsub is IP broadcast, traffic patterns visible
2. **No forward secrecy for group mode** — room key compromise exposes all room history
   - Future: TreeKEM (MLS protocol) for forward-secure group keys
3. **O(n) for per-recipient mode** — scales to ~100 peers (group mode is O(1))
4. **No message persistence** — lost messages not recovered
5. **PubSub is broadcast** — anyone on topic can see message exists (but not content)

### Upgrade Path (Roadmap)

- **Onion routing**: Integrate Tor/I2P for traffic analysis resistance
- **Forward-secure group keys**: TreeKEM / MLS protocol for scalable forward secrecy
- **Perfect forward secrecy**: Double Ratchet for 1:1 chats
- **Message persistence**: IPFS + encryption for message history
- **Post-quantum**: Add Dilithium/Kyber when stable

### Test Results

35/35 tests passing:
- Forward-secure encrypt/decrypt cycle
- Ephemeral key uniqueness per message
- MAC tampering detection
- Signature tampering detection
- Multi-recipient decryption
- O(1) group broadcast
- Room key isolation (wrong key blocked)
- Rate limiting enforcement
- Replay protection (duplicates + old messages)
- PubSub E2E (2 nodes, bidirectional)
- PubSub group broadcast (3 nodes)

### Files

- `hermes_p2p/crypto.py` — PeerTracker (rate limiting + replay)
- `hermes_p2p/message.py` — SecureMessage (E2E encrypt/decrypt)
- `hermes_p2p/node.py` — HermesNode (secure lifecycle + processing)
- `hermes_p2p/identity.py` — Identity (Ed25519 + libp2p PeerID)
- `test_e2e_full.py` — Full integration test suite (35 tests)
- `cli.py` — E2E encrypted CLI messenger
