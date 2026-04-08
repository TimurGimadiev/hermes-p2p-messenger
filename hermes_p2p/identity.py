"""
Identity — Ed25519 ключи и peer ID для Hermes P2P.

Использует libp2p-совместимые ключи.
Peer ID генерируется через multihash (формат 12D3KooW...).

Cross-platform:
  Python:  libp2p.crypto.ed25519 + libp2p.peer.id
  Swift:   CryptoKit + Base58 + multihash
  Kotlin:  Tink/Ed25519 + Base58 + multihash
  Go:      go-libp2p/crypto + peer.ID
"""

import json
from pathlib import Path
from typing import Optional

from libp2p import create_new_ed25519_key_pair
from libp2p.crypto.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from libp2p.peer.id import ID


class Identity:
    """
    Управление Ed25519 ключами и peer ID.

    Формат хранения: ~/.hermes_p2p/identity.json
    """

    def __init__(self, key_pair, peer_id: ID):
        self._key_pair = key_pair
        self._peer_id = peer_id

    @classmethod
    def generate(cls) -> "Identity":
        key_pair = create_new_ed25519_key_pair()
        peer_id = ID.from_pubkey(key_pair.public_key)
        return cls(key_pair, peer_id)

    @classmethod
    def load(cls, path: str) -> "Identity":
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Identity not found: {path}")

        data = json.loads(p.read_text())
        priv_key_bytes = bytes.fromhex(data["private_key_hex"])
        priv_key = Ed25519PrivateKey.from_bytes(priv_key_bytes)
        pub_key = priv_key.get_public_key()

        key_pair = type('KeyPair', (), {
            'private_key': priv_key,
            'public_key': pub_key,
        })()

        peer_id = ID.from_pubkey(pub_key)
        return cls(key_pair, peer_id)

    @classmethod
    def load_or_create(cls, path: str = None) -> "Identity":
        if path is None:
            path = str(Path.home() / ".hermes_p2p" / "identity.json")

        p = Path(path)
        if p.exists():
            return cls.load(path)

        identity = cls.generate()
        identity.save(path)
        return identity

    def save(self, path: str):
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)

        data = {
            "peer_id": self.peer_id,
            "private_key_hex": self.private_key_hex,
        }
        p.write_text(json.dumps(data, indent=2) + "\n")
        p.chmod(0o600)

    @property
    def peer_id(self) -> str:
        return self._peer_id.to_base58()

    @property
    def peer_id_obj(self) -> ID:
        return self._peer_id

    @property
    def private_key_hex(self) -> str:
        return self.private_key_bytes.hex()

    @property
    def private_key_bytes(self) -> bytes:
        return self._key_pair.private_key.to_bytes()

    @property
    def public_key_bytes(self) -> bytes:
        return self._key_pair.public_key.to_bytes()

    # Совместимость: message.py использует .private_key и .public_key как bytes
    @property
    def private_key(self) -> bytes:
        return self.private_key_bytes

    @property
    def public_key(self) -> bytes:
        return self.public_key_bytes

    def sign(self, data: bytes) -> bytes:
        return self._key_pair.private_key.sign(data)

    def verify(self, signature: bytes, data: bytes) -> bool:
        try:
            return self._key_pair.public_key.verify(signature, data)
        except Exception:
            return False

    def __repr__(self):
        return f"Identity(peer_id={self.peer_id[:16]}...)"
