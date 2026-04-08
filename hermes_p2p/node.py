"""
Hermes P2P Node with Forward-Secure E2E encryption (v0.3.0).

Security features:
  - Forward Secrecy: ephemeral X25519 per message
  - O(1) group broadcast with shared room key option
  - Ed25519 signature verification on ALL incoming messages
  - HMAC-SHA256 per envelope
  - Rate limiting: 10 msgs/peer/10s default
  - Replay protection: duplicate detection + 5min max age
  - strict_signing on pubsub
"""
import hashlib
import time
import trio
from contextlib import asynccontextmanager
from typing import Optional, Dict, List

import nacl.public
import nacl.signing
from libp2p import new_host, create_new_ed25519_key_pair
from libp2p.pubsub.pubsub import Pubsub
from libp2p.peer.id import ID
from libp2p.peer.peerinfo import PeerInfo
from multiaddr import Multiaddr
from libp2p.tools.async_service import background_trio_service

from hermes_p2p.identity import Identity
from hermes_p2p.message import SecureMessage
from hermes_p2p.crypto import PeerTracker


class HermesNode:
    """Hermes P2P Node with forward-secure E2E encryption."""

    def __init__(self, identity: Identity, port: int = 0,
                 rate_limit: int = 10, rate_window: int = 10):
        self.identity = identity
        self.listen_port = port if port > 0 else 0
        self._host = None
        self._pubsub: Optional[Pubsub] = None
        self._peer_pubkeys: Dict[str, bytes] = {}
        self._peer_tracker = PeerTracker(rate_limit, rate_window)
        self._longterm_x25519: Optional[nacl.public.PrivateKey] = None
        self._room_key: Optional[bytes] = None  # O(1) group symmetric key

    def _ensure_longterm_keys(self):
        """Generate long-term X25519 keypair from Ed25519 seed.
        
        This key is ONLY used to derive the room symmetric key and for
        per-recipient ECDH. Per-message ephemeral keys provide forward secrecy.
        """
        if self._longterm_x25519 is None:
            seed = hashlib.sha256(self.identity.private_key_bytes).digest()[:32]
            self._longterm_x25519 = nacl.public.PrivateKey(seed)

    @property
    def longterm_x25519_pub(self) -> bytes:
        self._ensure_longterm_keys()
        return bytes(self._longterm_x25519.public_key)

    def set_room_key(self, key: bytes):
        """Set shared room key for O(1) broadcast encryption."""
        if key and len(key) == 32:
            self._room_key = key
            print(f"[node] Room key set ({key.hex()[:16]}...)")
        else:
            self._room_key = None
            print("[node] Room key cleared")

    async def start_host(self) -> str:
        """Create libp2p host with FloodSub and strict_signing."""
        from libp2p.pubsub.floodsub import FloodSub

        key_pair = create_new_ed25519_key_pair(
            seed=self.identity.private_key_bytes
        )
        listen_addr = Multiaddr(f"/ip4/0.0.0.0/tcp/{self.listen_port}")
        self._host = new_host(key_pair=key_pair, listen_addrs=[listen_addr])

        self._ensure_longterm_keys()

        self._pubsub = Pubsub(
            host=self._host,
            router=FloodSub(protocols=["/floodsub/1.0.0"]),
            cache_size=256,
            strict_signing=True,
        )
        return self.get_multiaddr()

    @asynccontextmanager
    async def run(self):
        """Lifecycle: swarm -> listen -> pubsub."""
        await self.start_host()

        async with background_trio_service(self._host.get_network()):
            await trio.sleep(0.3)

            listen_addr = Multiaddr(f"/ip4/0.0.0.0/tcp/{self.listen_port}")
            await self._host.get_network().listen(listen_addr)
            await trio.sleep(0.3)

            addrs = self._host.get_addrs()
            if addrs:
                port_str = addrs[0].value_for_protocol("tcp")
                self.listen_port = int(port_str) if port_str else self.listen_port

            print(f"[node] Ready: {self.get_multiaddr()}")

            async with background_trio_service(self._pubsub):
                yield self

    async def stop(self):
        if self._host:
            try:
                await self._host.close()
            except Exception:
                pass

    async def connect(self, multiaddr_str: str) -> bool:
        """Connect to peer and exchange longterm pubkey."""
        if not self._host:
            return False
        try:
            ma = Multiaddr(multiaddr_str)
            peer_id_str = ma.value_for_protocol("p2p")
            peer_id = ID.from_base58(peer_id_str)
            peer_info = PeerInfo(peer_id, [ma])
            await self._host.connect(peer_info)
            print(f"[node] Connected: {peer_id_str[:16]}...")
            return True
        except Exception as e:
            print(f"[node] Connect failed: {e}")
            return False

    def register_pubkey(self, peer_id: str, x25519_pub: bytes):
        """Register peer's longterm X25519 pubkey for per-recipient E2E."""
        self._peer_pubkeys[peer_id] = x25519_pub
        print(f"[node] Registered pubkey: {peer_id[:16]}...")

    async def subscribe(self, topic: str):
        sub = await self._pubsub.subscribe(topic)
        print(f"[node] Subscribed: {topic}")
        return sub

    async def send_message(self, topic: str, content: str,
                           msg_type: int = 0,
                           recipients: Optional[List[str]] = None):
        """Send E2E encrypted message to topic.
        
        Uses O(1) group broadcast if room_key is set,
        otherwise falls back to per-recipient (forward-secure).
        """
        if self._room_key:
            # O(1) broadcast: single envelope, all room members decrypt
            msg = SecureMessage.encrypt_for_group(
                plaintext=content,
                sender_peer_id=self.identity.peer_id,
                sender_ed25519_priv=self.identity.private_key_bytes,
                room_sym_key=self._room_key,
                msg_type=msg_type
            )
        else:
            # Per-recipient forward-secure E2E
            if recipients is None:
                recipient_pubkeys = dict(self._peer_pubkeys)
            else:
                recipient_pubkeys = {
                    r: self._peer_pubkeys[r]
                    for r in recipients if r in self._peer_pubkeys
                }
            if not recipient_pubkeys:
                print("[node] WARNING: no recipients, message NOT sent")
                return None

            msg = SecureMessage.encrypt(
                plaintext=content,
                sender_peer_id=self.identity.peer_id,
                sender_ed25519_priv=self.identity.private_key_bytes,
                recipient_pubkeys=recipient_pubkeys,
                msg_type=msg_type
            )

        try:
            await self._pubsub.publish(topic, msg.to_bytes())
            return msg
        except Exception as e:
            print(f"[node] Publish failed: {e}")
            return None

    def process_incoming(self, data: bytes) -> Optional[dict]:
        """Process incoming pubsub message: parse, verify, decrypt."""
        try:
            msg = SecureMessage.from_bytes(data)
        except Exception as e:
            print(f"[node] Parse error: {e}")
            return None

        sender = msg.sender_peer_id

        # Rate limit check
        if not self._peer_tracker.check_rate(sender):
            print(f"[node] RATE LIMITED: {sender[:16]}...]")
            return None

        # Replay protection
        if self._peer_tracker.is_replay(msg.message_id, msg.timestamp):
            print(f"[node] REPLAY BLOCKED: {msg.message_id[:8]}...")
            return None

        # Decrypt
        try:
            if self._room_key:
                self._ensure_longterm_keys()
                result = msg.decrypt_group(self._room_key)
            else:
                self._ensure_longterm_keys()
                result = msg.decrypt_for(
                    my_peer_id=self.identity.peer_id,
                    my_x25519_priv=bytes(self._longterm_x25519)
                )
        except Exception as e:
            print(f"[node] Decrypt error: {e}")
            return None

        if result is None:
            return None

        if not result.get("signature_valid"):
            print(f"[node] BAD SIG: {sender[:8]}...]")
            return None

        self._peer_tracker.record_message(sender)
        return result

    def get_multiaddr(self) -> str:
        addrs = self._host.get_addrs() if self._host else []
        if addrs:
            base = str(addrs[0])
            if "/p2p/" not in base:
                return f"{base}/p2p/{self.identity.peer_id}"
            return base
        return f"/ip4/127.0.0.1/tcp/{self.listen_port}/p2p/{self.identity.peer_id}"

    def get_connected_peers(self) -> list:
        if not self._host or not self._host._network:
            return []
        return list(self._host._network.connections.keys())

    @staticmethod
    def make_room_topic(room_name: str) -> str:
        h = hashlib.sha256(room_name.encode()).hexdigest()[:16]
        return f"/hermes/room/{h}"
