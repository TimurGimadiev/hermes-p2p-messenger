# Hermes P2P Protocol Specification

> Для разработчиков приложений на macOS (Swift), iOS, Android (Kotlin).

## Обзор

Hermes P2P — децентрализованный P2P мессенджер на базе **libp2p**.  
Нет центральных серверов. Сообщения шифруются E2E через libp2p Noise protocol.

```
┌─────────────────────────────────────────────┐
│  Приложение (Swift UI / Jetpack Compose)    │
├─────────────────────────────────────────────┤
│  Hermes Protocol (идентичные на всех)       │
│  ├── identity.py  → Ed25519 keys            │
│  ├── message.py   → JSON + signature        │
│  └── node.py      → libp2p wrapper          │
├─────────────────────────────────────────────┤
│  libp2p (каждая платформа — своя реализация) │
│  ├── Transport: TCP + mDNS + WebSocket      │
│  ├── Security: Noise_IK                      │
│  ├── Multiplex: Yamux                       │
│  ├── PubSub: GossipSub v1.1                 │
│  └── DHT: Kademlia (опционально)             │
└─────────────────────────────────────────────┘
```

## 1. Идентичность (Identity)

### Ключи
- **Алгоритм:** Ed25519
- **Размер:** 32 байта seed, 64 байта приватный ключ, 32 байта публичный ключ
- **Хранение:** приватный ключ в `~/.hermes_p2p/identity.json` (chmod 600)

### Peer ID
```
peer_id = base58encode(sha256(public_key_bytes))
```

### Создание идентичности
```python
# Python
signing_key = nacl.signing.SigningKey.generate()
public_key = bytes(signing_key.verify_key)  # 32 bytes
peer_id = base58.b58encode(hashlib.sha256(public_key).digest()).decode()
```

```swift
// Swift (CryptoKit)
let privateKey = Curve25519.Signing.PrivateKey()
let publicKey = privateKey.publicKey.rawRepresentation
let sha256Hash = SHA256.hash(data: publicKey)
let peerId = Base58.encode(sha256Hash)
```

```kotlin
// Kotlin (Tink)
val keyPair = Ed25519KeyPairGenerator.generateKeyPair()
val publicKey = keyPair.public.encoded
val sha256Hash = MessageDigest.getInstance("SHA-256").digest(publicKey)
val peerId = Base58.encode(sha256Hash)
```

## 2. Формат сообщения

### JSON структура
```json
{
  "message_id": "uuid-v4-string",
  "from_peer": "base58-peer-id",
  "to_peer": "",
  "timestamp": 1712345678901,
  "content": "Hello, world!",
  "msg_type": 0,
  "signature": "hex-ed25519-signature"
}
```

### Поля
| Поле | Тип | Описание |
|------|-----|----------|
| message_id | UUID v4 | Уникальный ID сообщения |
| from_peer | string | Peer ID отправителя |
| to_peer | string | Peer ID получателя (пусто = broadcast) |
| timestamp | int64 | Unix timestamp в миллисекундах |
| content | string | Текст сообщения |
| msg_type | int | 0=TEXT, 1=SYSTEM, 2=IMAGE, 3=ACK, 4=FILE_REQUEST, 5=FILE_CHUNK |
| signature | hex string | Ed25519 подпись payload |

### Подпись
```
payload = "{message_id}:{timestamp}:{content}"
signature = Ed25519_sign(private_key, payload)
```

### Проверка подписи
```
verified = Ed25519_verify(public_key, signature, payload)
```

## 3. libp2p Конфигурация

### Транспорт
- TCP `/ip4/x.x.x.x/tcp/{port}`
- mDNS для локального discovery (включён по умолчанию)
- WebSocket (для web клиентов в будущем)

### Безопасность
- Noise_IK (стандартный libp2p Noise protocol)

### Мультиплексирование
- Yamux (по умолчанию в libp2p 0.6.0+)

### PubSub
- Протокол: GossipSub v1.1
- Topic формат: `/hermes/room/{sha256(room_name)[:16]}`
- Heartbeat: 1 секунда
- Gossip window: 60
- Gossip history: 100

### Topics
| Topic | Формат | Описание |
|-------|--------|----------|
| Room | `/hermes/room/{hash}` | Групповой чат |
| DM | `/hermes/dm/{hash}` | 1-on-1 (hash от sorted peer IDs) |
| General | `/hermes/general` | Общий канал |

### Расчёт topic hash
```python
import hashlib
room_hash = hashlib.sha256(room_name.encode()).hexdigest()[:16]
topic = f"/hermes/room/{room_hash}"
```

```swift
// Swift
let roomData = roomName.data(using: .utf8)!
let roomHash = SHA256.hash(data: roomData).prefix(8).map { String(format: "%02x", $0) }.joined()
let topic = "/hermes/room/\(roomHash)"
```

## 4. Flow подключения

### Шаг 1: Создание идентичности
```
Client → Generate Ed25519 keypair → peer_id = base58(sha256(pubkey))
```

### Шаг 2: Запуск ноды
```
Client → new_host() → listen(/ip4/0.0.0.0/tcp/{port}) → get_addrs()
```

### Шаг 3: Обмен multiaddr
```
Client A: "Подключайся: /ip4/192.168.1.100/tcp/43210/p2p/QmXyZ..."
Client B → connect("/ip4/192.168.1.100/tcp/43210/p2p/QmXyZ...")
```

### Шаг 4: Подписка на topic
```
Client A → subscribe("/hermes/room/abc123def456")
Client B → subscribe("/hermes/room/abc123def456")
```

### Шаг 5: Обмен сообщениями
```
Client A → publish("/hermes/room/...", signed_message)
Client B ← receive(signed_message) → verify_signature → display
```

## 5. Реализации libp2p по платформам

| Платформа | Библиотека | Статус | Ссылка |
|-----------|-----------|--------|--------|
| Python | py-libp2p 0.6.0 | ✅ Готово | pypi.org/project/libp2p |
| Swift | libp2p-swift | ⚠️ Экспериментально | github.com/libp2p/libp2p-swift |
| Kotlin/JVM | jvm-libp2p | ✅ Работает | github.com/libp2p/jvm-libp2p |
| Android | android-libp2p | ✅ Работает (JVM совместим) | github.com/libp2p/jvm-libp2p |
| Go | go-libp2p | ✅ Reference | github.com/libp2p/go-libp2p |
| Rust | rust-libp2p | ✅ Работает | github.com/libp2p/rust-libp2p |
| JS | js-libp2p | ✅ Работает | github.com/libp2p/js-libp2p |

## 6. Архитектура приложений

### Общие компоненты (реализуются на каждой платформе):
1. **IdentityManager** — генерация/загрузка/хранение Ed25519 ключей
2. **MessageSerializer** — JSON сериализация/десериализация
3. **SignatureVerifier** — Ed25519 подпись/проверка
4. **TopicCalculator** — sha256-based topic generation
5. **NodeWrapper** — обёртка над libp2p (connect, subscribe, publish)
6. **MessageStore** — SQLite/CoreData/Room для хранения сообщений

### Platform-specific UI:
- **macOS:** SwiftUI + Menu Bar app
- **iOS:** SwiftUI + PushKit (через relay для фоновых нотификаций)
- **Android:** Jetpack Compose + FCM (через relay)
- **Python CLI:** терминальный интерфейс через trio

## 7. Хранение (Storage)

### Схема SQLite
```sql
CREATE TABLE messages (
    message_id TEXT PRIMARY KEY,
    from_peer TEXT NOT NULL,
    to_peer TEXT NOT NULL DEFAULT '',
    timestamp INTEGER NOT NULL,
    content TEXT NOT NULL,
    msg_type INTEGER NOT NULL DEFAULT 0,
    signature TEXT NOT NULL,
    topic TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE peers (
    peer_id TEXT PRIMARY KEY,
    nickname TEXT,
    public_key_hex TEXT NOT NULL,
    last_seen INTEGER,
    multiaddr TEXT
);

CREATE INDEX idx_messages_topic ON messages(topic, timestamp);
CREATE INDEX idx_messages_from ON messages(from_peer);
```

## 8. Безопасность

- **E2E шифрование:** libp2p Noise_IK (автоматически)
- **Подлинность:** Ed25519 подпись на каждом сообщении
- **Нет central server:** peer-to-peer через GossipSub
- **NAT traversal:** libp2p relay v2 + hole punching
- **Storage encryption:** platform keychain (Keychain/Keystore)

## 9. Ограничения и TODO

- [ ] Relay nodes для оффлайн-доставки
- [ ] File transfer через libp2p streams
- [ ] DHT для глобального peer discovery
- [ ] Push notifications через relay (FCM/APNS прокси)
- [ ] Code obfuscation для мобильных бинарников
- [ ] Rate limiting + spam protection
