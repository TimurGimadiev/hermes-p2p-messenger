"""
Hermes P2P Crypto v0.3.0 (Forward-Secure E2E)

Per-message ephemeral X25519 + HKDF-SHA256 -> SecretBox
- Each message gets its own ephemeral X25519 keypair
- Private key discarded after encryption
- Long-term key compromise CANNOT decrypt past messages
- Ed25519 signature verification on all incoming
- Rate limiting + replay protection
"""
import hmac
import hashlib
import time
from collections import defaultdict
from typing import Dict

import nacl.public
import nacl.secret
import nacl.signing


def hkdf_expand(ikm: bytes, info: bytes, length: int = 64) -> bytes:
    """HKDF-SHA256"""
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=info,
    ).derive(ikm)


class PeerTracker:
    """Per-peer rate limiting and replay protection."""

    def __init__(self, max_per_window: int = 10,
                 window: int = 10):
        self.max_per_window = max_per_window
        self.window = window
        self._msg_times: Dict[str, list] = defaultdict(list)
        self._seen_ids: set = set()

    def check_rate(self, peer_id: str) -> bool:
        now = time.time()
        cutoff = now - self.window
        times = [t for t in self._msg_times[peer_id] if t > cutoff]
        self._msg_times[peer_id] = times
        return len(times) < self.max_per_window

    def record_message(self, peer_id: str):
        self._msg_times[peer_id].append(time.time())

    def is_replay(self, msg_id: str, timestamp_ms: int) -> bool:
        if msg_id in self._seen_ids:
            return True
        now = int(time.time() * 1000)
        if now - timestamp_ms > 300_000:  # 5 min
            return True
        self._seen_ids.add(msg_id)
        if len(self._seen_ids) > 2000:
            self._seen_ids = set(list(self._seen_ids)[-1000:])
        return False
