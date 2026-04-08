"""Forward-Secure E2E Encrypted Message for Hermes P2P v0.3.0.

Per-message ephemeral X25519 + HKDF -> SecretBox + HMAC
Group broadcast with shared room key (O(1) scaling)
Ed2519 signature on ALL messages
"""
import hmac
import hashlib
import time
import uuid
import json
from typing import Dict, List, Optional

import nacl.public
import nacl.secret
import nacl.signing
import nacl.utils


class SecureMessage:
    """Forward-secure E2E encrypted P2P message."""
    
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
        hashes = []
        for e in sorted(self.envelopes, key=lambda e: e.get("recipient_peer_id", "")):
            ct_hash = hashlib.sha256(bytes.fromhex(e["ciphertext"])).hexdigest()[:16]
            hashes.append(ct_hash)
        return f"{self.message_id}:{self.timestamp}:{self.msg_type}:" + ''.join(hashes)

    @classmethod
    def encrypt(cls, plaintext: str, sender_peer_id: str,
                sender_ed25519_priv: bytes,
                recipient_pubkeys: Dict[str, bytes],
                msg_type: int = 0) -> 'SecureMessage':
        """Forward-secure encrypt: ephemeral X25519 per message."""
        message_id = str(uuid.uuid4())
        timestamp = int(time.time() * 1000)
        nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        
        eph_privkey = nacl.public.PrivateKey.generate()
        eph_pubkey_bytes = bytes(eph_privkey.public_key)
        
        ed25519_sk = nacl.signing.SigningKey(sender_ed25519_priv)
        sender_ed25519_pub = bytes(ed25519_sk.verify_key).hex()
        
        envelopes = []
        for peer_id, recipient_pubkey_bytes in recipient_pubkeys.items():
            # ECDH
            shared = nacl.bindings.crypto_scalarmult(
                bytes(eph_privkey),
                recipient_pubkey_bytes
            )
            
            # HKDF
            from cryptography.hazmat.primitives.kdf.hkdf import HKDF
            from cryptography.hazmat.primitives import hashes
            derived = HKDF(
                algorithm=hashes.SHA256(),
                length=64,
                salt=None,
                info=f"hermes_e2e:{peer_id}:{message_id}".encode(),
            ).derive(shared)
            enc_key = derived[:32]
            mac_key = derived[32:]
            
            # Encrypt
            box = nacl.secret.SecretBox(enc_key)
            content_ct = box.encrypt(plaintext.encode('utf-8'), nonce)
            
            # HMAC
            mac_tag = hmac.new(mac_key, content_ct, hashlib.sha256).digest()
            
            envelopes.append({
                "recipient_peer_id": peer_id,
                "sender_eph_pubkey": eph_pubkey_bytes.hex(),
                "nonce": nonce.hex(),
                "ciphertext": content_ct.hex(),
                "mac_tag": mac_tag.hex()
            })
        
        msg = cls(
            message_id=message_id,
            sender_peer_id=sender_peer_id,
            sender_ed25519_pub=sender_ed25519_pub,
            envelopes=envelopes,
            timestamp=timestamp,
            msg_type=msg_type
        )
        
        sig_data = msg._sig_input()
        sig = ed25519_sk.sign(sig_data.encode('utf-8'))
        msg.signature = sig.signature.hex()
        
        return msg

    @classmethod
    def encrypt_for_group(cls, plaintext: str, sender_peer_id: str,
                          sender_ed25519_priv: bytes,
                          room_sym_key: bytes,
                          msg_type: int = 0) -> 'SecureMessage':
        """O(1) broadcast: encrypt once with room key."""
        message_id = str(uuid.uuid4())
        timestamp = int(time.time() * 1000)
        nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        
        room_box = nacl.secret.SecretBox(room_sym_key)
        content_ct = room_box.encrypt(plaintext.encode('utf-8'), nonce)
        
        ed25519_sk = nacl.signing.SigningKey(sender_ed25519_priv)
        sender_ed25519_pub = bytes(ed25519_sk.verify_key).hex()
        
        msg = cls(
            message_id=message_id,
            sender_peer_id=sender_peer_id,
            sender_ed25519_pub=sender_ed25519_pub,
            envelopes=[{
                "group": True,
                "nonce": nonce.hex(),
                "ciphertext": content_ct.hex()
            }],
            timestamp=timestamp,
            msg_type=msg_type
        )
        sig_data = msg._sig_input()
        sig = ed25519_sk.sign(sig_data.encode('utf-8'))
        msg.signature = sig.signature.hex()
        return msg

    def decrypt_for(self, my_peer_id: str,
                    my_x25519_priv: bytes) -> Optional[dict]:
        """Decrypt per-recipient envelope for me."""
        my_env = None
        for e in self.envelopes:
            if e.get("recipient_peer_id") == my_peer_id:
                my_env = e
                break
        if my_env is None:
            return None
        
        try:
            eph_pubkey = bytes.fromhex(my_env["sender_eph_pubkey"])
            shared = nacl.bindings.crypto_scalarmult(my_x25519_priv, eph_pubkey)
            
            from cryptography.hazmat.primitives.kdf.hkdf import HKDF
            from cryptography.hazmat.primitives import hashes
            derived = HKDF(
                algorithm=hashes.SHA256(),
                length=64,
                salt=None,
                info=f"hermes_e2e:{my_peer_id}:{self.message_id}".encode(),
            ).derive(shared)
            enc_key = derived[:32]
            mac_key = derived[32:]
            
            content_ct = bytes.fromhex(my_env["ciphertext"])
            expected_mac = bytes.fromhex(my_env["mac_tag"])
            computed_mac = hmac.new(mac_key, content_ct, hashlib.sha256).digest()
            if not hmac.compare_digest(computed_mac, expected_mac):
                return None
            
            box = nacl.secret.SecretBox(enc_key)
            plaintext = box.decrypt(content_ct[24:], bytes.fromhex(my_env["nonce"]))
            
            sig_valid = self.verify_signature()
            
            return {
                "message_id": self.message_id,
                "sender_peer_id": self.sender_peer_id,
                "timestamp": self.timestamp,
                "msg_type": self.msg_type,
                "content": plaintext.decode('utf-8'),
                "signature_valid": sig_valid
            }
        except Exception:
            return None

    def decrypt_group(self, room_sym_key: bytes) -> Optional[dict]:
        """Decrypt group-broadcast message."""
        env = self.envelopes[0] if self.envelopes else None
        if not env or not env.get("group"):
            return None
        
        try:
            nonce = bytes.fromhex(env["nonce"])
            ct = bytes.fromhex(env["ciphertext"])
            box = nacl.secret.SecretBox(room_sym_key)
            plaintext = box.decrypt(ct[24:], nonce).decode('utf-8')
            
            sig_valid = self.verify_signature()
            
            return {
                "message_id": self.message_id,
                "sender_peer_id": self.sender_peer_id,
                "timestamp": self.timestamp,
                "msg_type": self.msg_type,
                "content": plaintext,
                "signature_valid": sig_valid
            }
        except Exception:
            return None

    def verify_signature(self) -> bool:
        """Verify Ed25519 signature."""
        if not self.signature or not self.envelopes:
            return False
        try:
            sig_data = self._sig_input()
            vk = nacl.signing.VerifyKey(bytes.fromhex(self.sender_ed25519_pub))
            vk.verify(sig_data.encode('utf-8'), bytes.fromhex(self.signature))
            return True
        except Exception:
            return False

    def to_bytes(self) -> bytes:
        return json.dumps(self.to_dict(), separators=(',', ':')).encode('utf-8')

    @classmethod
    def from_bytes(cls, data: bytes) -> 'SecureMessage':
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
