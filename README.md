# Hermes P2P Messenger

Децентрализованный P2P мессенджер на базе **libp2p 0.6.0**.

## Быстрый старт

### Запуск первого узла (Terminal 1)
```bash
source /tmp/p2p-venv/bin/activate
cd /home/timur/obsidian/projects/p2p-messenger
python3 cli.py --room chat --port 9100
```

После запуска узел покажет свой адрес:
```
  ─── Multiaddr для подключения ───
  /ip4/127.0.0.1/tcp/9100/p2p/12D3KooWxxxxxxxxxxxxxxxxxxxxxxxxx
  ──────────────────────────────────
```

### Подключение второго узла (Terminal 2)
```bash
source /tmp/p2p-venv/bin/activate
cd /home/timur/obsidian/projects/p2p-messenger
python3 cli.py --room chat --port 9101 --connect /ip4/127.0.0.1/tcp/9100/p2p/12D3KooWxxxxxxxxxxxxxxxxxxxxxxxxx
```

### Готово!
Пишите сообщения в любом окне — они появляются в обоих.

## Команды в чате

| Команда | Описание |
|---------|----------|
| `/help` | Справка |
| `/quit` | Выход |
| `/info` | Информация о ноде |
| `/peers` | Подключённые пиры |
| `/connect <addr>` | Подключиться к пиру |
| `/identity` | Показать peer ID |
| `<текст>` | Отправить сообщение |

## Архитектура

```
┌─────────────────────────────────┐
│  CLI (input + display)          │
├─────────────────────────────────┤
│  HermesNode (обёртка)           │
│  ├── Identity (Ed25519 keys)    │
│  ├── Message (JSON + подписи)   │
│  └── PubSub (FloodSub)          │
├─────────────────────────────────┤
│  libp2p (py-libp2p 0.6.0)       │
│  ├── TCP transport              │
│  ├── Noise encrypted streams    │
│  └── FloodSub pubsub            │
└─────────────────────────────────┘
```

## Структура проекта

```
p2p-messenger/
├── cli.py                    # CLI мессенджер
├── test_integration.py       # Интеграционный тест
├── hermes_p2p/
│   ├── __init__.py
│   ├── identity.py           # Ed25519 ключи + multihash peer ID
│   ├── message.py            # JSON + Ed25519 подписи
│   └── node.py               # libp2p node wrapper + lifecycle
├── ARCHITECTURE.md           # Полная архитектура
└── PROTOCOL_SPEC.md          # Спецификация для porting (Swift/Kotlin/Go)
```

## Для разработчиков

Identity сохраняется в `~/.hermes_p2p/identity.json`.
Комната хэшируется в topic: `/hermes/room/{sha256(room)[:16]}`.

## Status
- [x] Identity (Ed25519 + multihash peer ID)
- [x] Message (JSON + Ed25519 подписи)
- [x] Node (libp2p wrapper с FloodSub)
- [x] CLI приложение
- [x] Integration test (2 ноды, cross_peer delivery)
- [ ] GossipSub (работает только с 6+ пиров)
- [ ] mDNS peer discovery
- [ ] SQLite message storage
- [ ] Swift/macOS приложение
- [ ] Kotlin/Android приложение
