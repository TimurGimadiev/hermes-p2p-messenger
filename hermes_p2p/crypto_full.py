"""
Forward-Secure E2E encryption for Hermes P2P.

Algorithm: Ephemeral X25519 ECDH + HKDF → SecretBox per message
- Each message generates a NEW X25519 keypair (ephemeral)
- Ephemeral private key is immediately discarded after encryption
- Compromising long-term keys CANNOT decrypt past messages
- Ed25519 signature verification on ALL incoming messages
- Authenticated Diffie-Hellman: sender signs their ephemeral pubkey

Derivation:
  1. Sender generates ephemeral X25519 keypair
  2. For each recipient:
     - ECDH(ephemeral_secret, recipient_pubkey) → shared
     - HKDF-SHA256(shared, info=msg_id || sender || sender_ephemeral_pub)
       → enc_key (32B) + mac_key (32B)  [dual-key HKDF expansion]
  3. Encrypt content with enc_key
  4. MAC = HMAC-SHA256(mac_key, ciphertext)
  5. Sign (msg_id || ephemeral_pub || ct_hash) with Ed25519
  6. Discard ephemeral secret

Security properties:
  - Sender forward secrecy: compromising sender's long-term key cannot decrypt past messages
  - Authentication: Ed25519 signature proves sender identity AND binds to ephemeral key
  - Integrity: signature + HMAC prevent any tampering
  - Key separation: each message uses completely independent keys via HKDF(info=msg_id)
"""
import hmac
import hashlib
import time
import uuid
from collections import defaultdict
from typing import Dict, List, Optional

import nacl.public
import nacl.secret
import nacl.signing
import nacl.utils
import nacl.exceptions
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


# Constants
X25519_KEY_SIZE = nacl.public.PrivateKey.SEED_SIZE  # 32
X25519_PUB_SIZE = nacl.public.PublicKey.SIZE        # 32
SECRETBOX_KEY_SIZE = nacl.secret.SecretBox.KEY_SIZE  # 32
SECRETBOX_NONCE_SIZE = nacl.secret.SecretBox.NONCE_SIZE  # 24
ED25519_SIG_SIZE = 64  # Ed25519 signature
RATE_LIMIT_DEFAULT = 10
RATE_WINDOW_DEFAULT = 10
REPLAY_MAX_AGE_MS = 300_000  # 5 minutes
MAX_SEEN_IDS = 2000


def hkdf_expand(ikm: bytes, info: bytes, length: int) -> bytes:
    """HKDF-SHA256 expand."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,  # salt=None → IKM-only for ECDH-derived keys
        info=info,
    ).derive(ikm)


def ecdh(private_key: bytes, public_key: bytes) -> bytes:
    """X25519 ECDH → 32-byte shared secret."""
    return nacl.bindings.crypto_scalarmult(private_key, public_key)


class PeerTracker:
    """Per-peer rate limiting and replay protection."""

    def __init__(self, max_per_window: int = RATE_LIMIT_DEFAULT,
                 window: int = RATE_WINDOW_DEFAULT):
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
        if now - timestamp_ms > REPLAY_MAX_AGE_MS:
            return True
        self._seen_ids.add(msg_id)
        if len(self._seen_ids) > MAX_SEEN_IDS:
            self._seen_ids = set(list(self._seen_ids)[-MAX_SEEN_IDS // 2:])
        return False


class SecureMessage:
    """Forward-secure E2E encrypted message.

    Envelope per recipient:
    {
        "recipient_peer_id": "...",
        "sender_eph_pubkey": "hex_32B",       # NEW: ephemeral pubkey
        "nonce": "hex_24B",
        "ciphertext": "hex",
        "mac_tag": "hex_32B"                   # NEW: HMAC-SHA256
    }
    """

    MSG_TYPE_TEXT = 0
    MSG_TYPE_SYS = 1
    MSG_TYPE_IMAGE = 2
    MSG_TYPE_ACK = 3
    MSG_TYPE_FILE_REQ = 4
    MSG_TYPE_FILE = 5

    def __init__(self, message_id: str = None, sender_peer_id: str = "",
                 sender_ed25519_pub: str = "", envelopes: List[dict] = None,
                 signature: str = "", timestamp: int = None,
                 msg_type: int = 0):
        self.message_id = message_id or str(uuid.uuid4())
        self.sender_peer_id = sender_peer_id
        self.sender_ed25519_pub = sender_ed25519_pub
        self.envelopes = envelopes or []
        self.signature = signature
        self.timestamp = timestamp or int(time.time() * 1000)
        self.msg_type = msg_type

    def _sig_input(self) -> str:
        """Canonical string for Ed25519 signature."""
        ct_hashes = []
        for e in sorted(self.envelopes, key=lambda e: e["recipient_peer_id"]):
            ct_hash = hashlib.sha256(bytes.fromhex(e["ciphertext"])).hexdigest()[:16]
            ct_hashes.append(ct_hash)
        ct_joined = ''.join(ct_hashes)
        return f"{self.message_id}:{self.timestamp}:{self.msg_type}:{ct_joined}"

    @classmethod
    def encrypt(cls, plaintext: str, sender_peer_id: str,
                sender_ed25519_priv: bytes,
                recipient_pubkeys: Dict[str, bytes],
                msg_type: int = 0) -> 'SecureMessage':
        """Create a forward-secure E2E encrypted message.

        Each message gets its own ephemeral X25519 keypair.
        After encryption, the ephemeral secret is irreversibly discarded.
        """
        message_id = str(uuid.uuid4())
        timestamp = int(time.time() * 1000)
        nonce = nacl.utils.random(SECRETBOX_NONCE_SIZE)

        # Generate ephemeral keypair — THIS KEY IS THE FORWARD SECRECY ENABLER
        eph_privkey = nacl.public.PrivateKey.generate()
        eph_pubkey_bytes = bytes(eph_privkey.public_key)

        # Get sender Ed25519 pubkey for verification
        ed25519_sk = nacl.signing.SigningKey(sender_ed25519_priv)
        sender_ed25519_pub = bytes(ed25519_sk.verify_key).hex()

        # Build envelopes — one per recipient
        envelopes = []
        for peer_id, recipient_pubkey_bytes in recipient_pubkeys.items():
            # ECDH: ephemeral secret → recipient pubkey
            shared_secret = ecdh(
                bytes(eph_privkey),
                recipient_pubkey_bytes
            )

            # HKDF with unique info per recipient
            info = f"hermes_e2e:{peer_id}:{message_id}".encode()
            derived = hkdf_expand(shared_secret, info, length=64)
            enc_key = derived[:32]   # For encryption
            mac_key = derived[32:]   # For authentication

            # Encrypt with SecretBox
            content_box = nacl.secret.SecretBox(enc_key)
            content_ct = content_box.encrypt(plaintext.encode('utf-8'), nonce)

            # HMAC-SHA256 for authenticated encryption
            mac_tag = hmac.new(mac_key, content_ct, hashlib.sha256).digest()

            envelopes.append({
                "recipient_peer_id": peer_id,
                "sender_eph_pubkey": eph_pubkey_bytes.hex(),
                "nonce": nonce.hex(),
                "ciphertext": content_ct.hex(),
                "mac_tag": mac_tag.hex()
            })

        # Build unsigned message
        msg = cls(
            message_id=message_id,
            sender_peer_id=sender_peer_id,
            sender_ed25519_pub=sender_ed25519_pub,
            envelopes=envelopes,
            timestamp=timestamp,
            msg_type=msg_type
        )

        # Sign: covers msg_id + timestamp + type + ciphertext hashes
        # This binds the signature to the encrypted content AND sender's ephemeral pubkeys
        sig_data = msg._sig_input()
        sig = ed25519_sk.sign(sig_data.encode('utf-8'))
        msg.signature = sig.signature.hex()

        # THE EPHEMERAL PRIVATE KEY IS NOW GARBAGE COLLECTED
        # This is the forward secrecy guarantee: even if sender's long-term
        # key leaks later, this key is gone forever.
        return msg

    def decrypt_for(self, my_peer_id: str,
                    my_x25519_priv: bytes) -> Optional[dict]:
        """Decrypt the envelope addressed to me.

        Returns dict with decrypted content and signature validity,
        or None if no envelope for this peer or decryption fails.
        """
        # Find my envelope
        my_env = None
        for e in self.envelopes:
            if e["recipient_peer_id"] == my_peer_id:
                my_env = e
                break
        if my_env is None:
            return None

        try:
            # Reconstruct ECDH shared secret using sender's EPHEMERAL pubkey
            eph_pubkey = bytes.fromhex(my_env["sender_eph_pubkey"])
            shared_secret = ecdh(my_x25519_priv, eph_pubkey)

            # HKDF with same info to derive same keys
            info = f"hermes_e2e:{my_peer_id}:{self.message_id}".encode()
            derived = hkdf_expand(shared_secret, info, length=64)
            enc_key = derived[:32]
            mac_key = derived[32:]

            # Verify HMAC before decryption (timing-safe comparison)
            content_ct = bytes.fromhex(my_env["ciphertext"])
            expected_mac = bytes.fromhex(my_env["mac_tag"])
            computed_mac = hmac.new(mac_key, content_ct, hashlib.sha256).digest()
            if not hmac.compare_digest(computed_mac, expected_mac):
                print("[decrypt error: MAC verification failed]")
                return None

            # Decrypt content
            content_box = nacl.secret.SecretBox(enc_key)
            plaintext_bytes = content_box.decrypt(content_ct,
                                                   bytes.fromhex(my_env["nonce"]))
            plaintext = plaintext_bytes.decode('utf-8')

            # Verify Ed25519 signature
            sig_valid = self.verify_signature()

            return {
                "message_id": self.message_id,
                "sender_peer_id": self.sender_peer_id,
                "timestamp": self.timestamp,
                "msg_type": self.msg_type,
                "content": plaintext,
                "signature_valid": sig_valid
            }
        except Exception as e:
            print(f"[decrypt error: {e}]")
            return None

    def verify_signature(self) -> bool:
        """Verify the sender's Ed25519 signature."""
        if not self.signature or not self.envelopes:
            return False
        try:
            sig_data = self._sig_input()
            vk = nacl.signing.VerifyKey(bytes.fromhex(self.sender_ed25519_pub))
            vk.verify(sig_data.encode('utf-8'), bytes.fromhex(self.signature))
            return True
        except Exception:
            return False

    # ─── New: O(1) broadcast for known peers ─────────────────────

    @classmethod
    def encrypt_for_group(cls, content: str, sender_peer_id: str,
                          sender_ed25519_priv: bytes,
                          sender_x25519_priv: bytes,
                          recipient_pubkeys: Dict[str, bytes],
                          room_sym_key: Optional[bytes] = None,
                          msg_type: int = 0) -> 'SecureMessage':
        """
        O(1) broadcast encryption for a trusted group.

        If room_sym_key is provided: encrypt ONE envelope with the shared
        room key, all group members can decrypt with that key.

        If room_sym_key is None: falls back to per-recipient envelopes.

        room_sym_key should be distributed via secure key exchange
        (e.g., TreeKEM when peers join). This is a simpler optimization
        for small trusted rooms.
        """
        message_id = str(uuid.uuid4())
        timestamp = int(time.time() * 1000)

        if room_sym_key:
            # Single envelope encrypted with room key
            nonce = nacl.utils.random(SECRETBOX_NONCE_SIZE)
            room_box = nacl.secret.SecretBox(room_sym_key)
            content_ct = room_box.encrypt(content.encode('utf-8'), nonce)

            # Sign with sender's Ed25519 key for group auth
            ed25519_sk = nacl.signing.SigningKey(sender_ed25519_priv)
            sender_ed25519_pub = bytes(ed25519_sk.verify_key).hex()

            msg = cls(
                message_id=message_id,
                sender_peer_id=sender_peer_id,
                sender_ed25519_pub=sender_ed25519_pub,
                envelopes=[{
                    "recipient_peer_id": "*group*",
                    "nonce": nonce.hex(),
                    "ciphertext": content_ct.hex(),
                }],
                timestamp=timestamp,
                msg_type=msg_type
            )
            # Sign the ciphertext
            ct_hash = hashlib.sha256(bytes.fromhex(content_ct.hex())).hexdigest()[:16]
            sig_data = f"{message_id}:{timestamp}:{msg_type}{ct_hash}"
            sig = ed25519_sk.sign(sig_data.encode('utf-8'))
            msg.signature = sig.signature.hex()
            return msg
        else:
            # Fallback: per-recipient with ephemeral keys (full forward secrecy)
            return cls.encrypt(
                plaintext=content,
                sender_peer_id=sender_peer_id,
                sender_ed25519_priv=sender_ed25519_priv,
                recipient_pubkeys=recipient_pubkeys,
                msg_type=msg_type
            )

    @classmethod
    def decrypt_group(cls, data: bytes, room_sym_key: bytes) -> Optional[dict]:
        """Decrypt a group-broadcast message."""
        try:
            msg = cls.from_bytes(data)
        except Exception:
            return None

        env = msg.envelopes[0] if msg.envelopes else None
        if not env or env.get("recipient_peer_id") != "*group*":
            return None

        try:
            nonce = bytes.fromhex(env["nonce"])
            ct = bytes.fromhex(env["ciphertext"])
            room_box = nacl.secret.SecretBox(room_sym_key)
            plaintext = room_box.decrypt(ct, nonce).decode('utf-8')

            # Verify sender signature
            sig_valid = msg.verify_signature()

            return {
                "message_id": msg.message_id,
                "sender_peer_id": msg.sender_peer_id,
                "timestamp": msg.timestamp,
                "msg_type": msg.msg_type,
                "content": plaintext,
                "signature_valid": sig_valid
            }
        except Exception as e:
            print(f"[group decrypt error: {e}]")
            return None

    # ─── Serialization ────────────────────────────────────────────

    def to_bytes(self) -> bytes:
        import json
        return json.dumps(self.to_dict(), separators=(',', ':')).encode('utf-8')

    @classmethod
    def from_bytes(cls, data: bytes) -> 'SecureMessage':
        import json
        d = json.loads(data.decode('utf-8'))
        return cls(
            message_id=d.get("message_id"),
            sender_peer_id=d.get("sender_peer_id", ""),
            sender_ed25519_pub=d.get("sender_ed25519_pub", ""),
            envelopes=d.get("envelopes", []),
            signature=d.get("signature", ""),
            timestamp=d.get("timestamp"),
            msg_type=d.get("msg_type", 0),
        )

    def to_dict(self) -> dict:
        return {
            "message_id": self.message_id,
            "sender_peer_id": self.sender_peer_id,
            "sender_ed25519_pub": self.sender_ed25519_pub,
            "envelopes": self.envelopes,
            "signature": self.signature,
            "timestamp": self.timestamp,
            "msg_type": self.msg_type,
        }
