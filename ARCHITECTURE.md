# Hermes P2P Messenger — Архитектура

> Кроссплатформенный P2P мессенджер на базе libp2p для macOS, iOS, Android, Python CLI.

## Обзор

Hermes Messenger — децентрализованный P2P мессенджер без серверов. Каждый пир — самостоятельный узел, сообщения шифруются end-to-end, доставка идёт через pubsub gossip.

## Стек протоколов

```
┌─────────────────────────────────────────┐
│  Приложения: CLI · macOS · iOS · Android │
├─────────────────────────────────────────┤
│  Hermes Protocol                        │
│  /hermes/chat/1.0.0   — чат             │
│  /hermes/presence/1.0.0 — статус        │
├─────────────────────────────────────────┤
│  libp2p PubSub (GossipSub v1.1)         │
│  Topic: peerid-based room               │
├─────────────────────────────────────────┤
│  libp2p Core                            │
│  ├── Identify      — обмен PeerID       │
│  ├── mDNS          — локальное discovery │
│  ├── Ping          — keepalive          │
│  └── Noise         — E2E шифрование     │
├─────────────────────────────────────────┤
│  Transport                              │
│  ├── TCP           /ip4/x.x.x.x/tcp/zzz  │
│  └── WebSocket     /ip4/x.x.x.x/tcp/zzz/ws│
└─────────────────────────────────────────┘
```

## Ключевые архитектурные решения

### 1. Идентичность (Ed25519)
- Каждый пир генерирует Ed25519 пару ключей
- **Peer ID** = multihash(sha2-256, PubKey)
- Приватный ключ хранится локально и не выходит с устройства
- Один Peer ID = один пользователь (можно импортировать ключ на новое устройство)

### 2. Обнаружение пиров (Discovery)
- **mDNS** — автообнаружение в локальной сети (LAN)
- **DHT** — глобальное обнаружение через Kademlia DHT
- **Bootstrap nodes** — известные стабильные узлы сети (relay)

### 3. Маршрутизация сообщений
- **Direct**: отправка напрямую по peer ID
- **Topic-based**: подписка на канал (chat room = topic)
- **GossipSub**: сообщения распространяются через mesh сеть

### 4. Формат сообщений (Protobuf)
```protobuf
message HermesMessage {
  bytes message_id = 1;        // UUID v4
  string from_peer = 2;        // Peer ID отправителя
  string to_peer = 3;          // Peer ID получателя (empty = broadcast)
  int64 timestamp = 4;        // Unix timestamp ms
  string content = 5;          // Текст сообщения
  MessageType type = 6;
  bytes encrypted_content = 7; // Опционально: зашифровано
  bytes signature = 8;         // Ed25519 signature
  enum MessageType {
    TEXT = 0;
    SYSTEM = 1;
    FILE_REQUEST = 2;
    ACK = 3;
  }
}
```

## Структура проекта

```
p2p-messenger/
├── hermes_p2p/              # Core Python package (общий протокол)
│   ├── __init__.py
│   ├── identity.py           # Ed25519 ключи + Peer ID
│   ├── message.py            # Protobuf сериализация
│   ├── node.py               # libp2p Node (setup, connect, pubsub)
│   ├── protocol.py           # Protocol handler (/hermes/chat/1.0.0)
│   ├── storage.py            # SQLite для сообщений
│   └── crypto.py             # E2E шифрование поверх libp2p Noise
├── cli.py                    # CLI приложение
├── proto/
│   └── hermes.proto          # Protobuf определение
├── tests/
│   ├── test_identity.py
│   └── test_protocol.py
├── requirements.txt
├── Makefile
└── ARCHITECTURE.md           # Этот файл
```

## Портирование на другие платформы

| Компонент | Python | Swift | Kotlin | Go |
|-----------|--------|-------|--------|-----|
| libp2p | py-libp2p | NIO-libp2p | jvm-libp2p | go-libp2p |
| Ed25519 | PyNaCl | CryptoKit | Tink | Go crypto/ed25519 |
| Protobuf | protobuf | SwiftProtobuf | protobuf-kotlin | gogo/protobuf |
| Storage | SQLite | Core Data | Room | SQLite |

## Безопасность

- **E2E шифрование** libp2p Noise protocol (автоматически)
- **Аутентификация** через Ed25519 подписи
- **Нет серверов** — трафик идёт напрямую peer-to-peer
- **NAT traversal** через libp2p relay v2 + hole punching

## Roadmap

1. **P0**: Python CLI — базовый чат между двумя пирами
2. **P0**: PubSub комнаты — групповой чат
3. **P1**: DHT discovery — глобальное обнаружение
4. **P1**: File transfer — передача файлов через stream
5. **P2**: macOS клиент (Swift SwiftUI + swift-libp2p)
6. **P2**: Android клиент (Kotlin + jvm-libp2p)
7. **P3**: iOS клиент
8. **P3**: WebRTC transport fallback
