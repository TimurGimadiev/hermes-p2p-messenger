#!/usr/bin/env python3
"""
Hermes P2P CLI — E2E encrypted P2P мессенджер.

Security:
  - X25519 ECDH + XSalsa20-Poly1305 per message (crypto_box)
  - Ed25519 signature verification on ALL incoming
  - Rate limiting: 10 msgs per peer per 10s
  - Replay: duplicate + 5min max age
  - strict_signing on pubsub
  - Auto pubkey discovery

Usage:
  python3 cli.py                      # Room: general
  python3 cli.py --room myroom        # Комната
  python3 cli.py --connect <addr>     # Подключиться + pubkey exchange
  python3 cli.py --port 9000          # Порт
  python3 cli.py --new-identity       # Новая идентичность
"""

import argparse
import sys
import time

import trio

from hermes_p2p.identity import Identity
from hermes_p2p.node import HermesNode


class ChatState:
    message_count: int = 0
    own_peer_id: str = ""
    running: bool = True


def print_msg(label: str, text: str):
    print(f"\r  {label}  {text}")
    print("> ", end="", flush=True)


async def message_poller(node: HermesNode, sub):
    """Poll pubsub subscription for messages, decrypt and display."""
    try:
        async for msg_pb in sub.receive_channel:
            result = node.process_incoming(msg_pb.data)
            if result:
                ChatState.message_count += 1
                ts = time.strftime("%H:%M:%S", time.localtime(result["timestamp"] / 1000))
                sender = result["sender_peer_id"][:16]
                is_mine = result["sender_peer_id"] == ChatState.own_peer_id
                who = "you" if is_mine else sender
                mt = ["text", "sys", "img", "ack", "f_req", "file"][result["msg_type"]]
                print(f"  [{ts}] ({mt}) [{who}]: {result['content']}")
                print("> ", end="", flush=True)
    except Exception as e:
        print(f"  [listener ended: {e}]")
        print("> ", end="", flush=True)


async def input_loop(node: HermesNode, topic: str):
    """Read stdin and send E2E encrypted messages."""
    def read_line():
        try:
            line = sys.stdin.readline()
            return line.strip() if line else None
        except Exception:
            return None

    print("> ", end="", flush=True)

    while ChatState.running:
        line = await trio.to_thread.run_sync(read_line)

        if line is None or line in ("/quit", "/exit"):
            print("\n  Goodbye!")
            ChatState.running = False
            return

        if not line:
            print("> ", end="", flush=True)
            continue

        if line == "/help":
            print("  Commands:")
            print("    /help             - this help")
            print("    /quit             - exit")
            print("    /info             - node info + security status")
            print("    /peers            - connected peers")
            print("    /connect <addr>   - connect to peer (pubkey exchange)")
            print("    /identity         - show peer identity")
            print("    <text>            - send E2E encrypted message")
            print("> ", end="", flush=True)
            continue

        if line == "/info":
            peers = node.get_connected_peers()
            pubkeys = node._peer_pubkeys
            print(f"  Peer ID:  {node.identity.peer_id}")
            print(f"  X25519:   {bytes(node.x25519_public).hex()[:20]}...")
            print(f"  Address:  {node.get_multiaddr()}")
            print(f"  Peers:    {len(peers)} connected, {len(pubkeys)} known pubkeys")
            print(f"  Security: E2E encrypt + Ed25519 sign + rate limit + replay")
            print("> ", end="", flush=True)
            continue

        if line == "/peers":
            peers = node.get_connected_peers()
            if peers:
                print(f"  Peers ({len(peers)}):")
                for p in peers:
                    print(f"    - {p[:16]}...")
            else:
                print("  No connected peers")
            print("> ", end="", flush=True)
            continue

        if line.startswith("/connect "):
            addr = line[len("/connect "):].strip()
            print(f"  Connecting to {addr[:50]}...")
            ok = await node.connect(addr)
            print(f"  {'Connected + pubkey exchanged!' if ok else 'Failed'}")
            print("> ", end="", flush=True)
            continue

        if line == "/identity":
            print(f"  Peer ID:  {node.identity.peer_id}")
            print(f"  X25519:   {bytes(node.x25519_public).hex()}")
            print(f"  Address:  {node.get_multiaddr()}")
            print("  Share this to let others connect.")
            print("> ", end="", flush=True)
            continue

        # Send encrypted message
        recipients = list(node._peer_pubkeys.keys())
        if not recipients:
            print("  No peers with pubkey! Connect to someone first.")
            print("> ", end="", flush=True)
            continue

        msg = await node.send_message(topic, line, recipients=recipients)
        if msg:
            ts = time.strftime("%H:%M:%S")
            print(f"  [{ts}] (text) [you]: {line}")
        else:
            print("  Failed to send!")
        print("> ", end="", flush=True)


async def run_with_node(node: HermesNode, topic: str):
    """Full lifecycle."""
    async with node.run():
        print(f"\n  === Hermes P2P Messenger (E2E Encrypted) ===")
        print(f"  Peer ID:   {node.identity.peer_id}")
        print(f"  Multiaddr: {node.get_multiaddr()}")
        print(f"  Room:      {topic}")
        print(f"\n  Share the multiaddr to let others connect.")
        print(f"  Type /help for commands.\n")

        sub = await node.subscribe(topic)

        async with trio.open_nursery() as nursery:
            nursery.start_soon(message_poller, node, sub)
            nursery.start_soon(input_loop, node, topic)


def main():
    parser = argparse.ArgumentParser(
        description="Hermes P2P - E2E encrypted P2P messenger",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--port", type=int, default=0, help="Listen port (0 = auto)")
    parser.add_argument("--connect", type=str, action="append", help="Peer address")
    parser.add_argument("--room", type=str, default="general", help="Room name")
    parser.add_argument("--identity", type=str, help="Identity file path")
    parser.add_argument("--new-identity", action="store_true", help="Generate new identity")
    parser.add_argument("--rate-limit", type=int, default=10, help="Max msgs per peer")
    parser.add_argument("--rate-window", type=int, default=10, help="Rate window (seconds)")
    args = parser.parse_args()

    if args.new_identity:
        path = args.identity or str(Identity._default_path())
        identity = Identity.generate()
        identity.save(path)
        print(f"New identity: {path}")
        print(f"  Peer ID: {identity.peer_id}")
        sys.exit(0)

    identity = Identity.load_or_create(args.identity)
    ChatState.own_peer_id = identity.peer_id

    node = HermesNode(
        identity, port=args.port,
        rate_limit=args.rate_limit, rate_window=args.rate_window
    )
    topic = HermesNode.make_room_topic(args.room)

    async def run():
        print(f"\n  Hermes P2P E2E")
        print(f"  Peer ID: {identity.peer_id[:16]}...")
        print(f"  Room: {topic}")
        if args.connect:
            await run_with_node(node, topic)
        await run_with_node(node, topic)

    try:
        trio.run(run)
    except KeyboardInterrupt:
        print("\n  Exiting...")


if __name__ == "__main__":
    main()
