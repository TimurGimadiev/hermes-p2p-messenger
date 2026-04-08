#!/usr/bin/env python3
"""
Integration test: 2 nodes + pubsub cross-peer delivery.
"""
import sys
sys.path.insert(0, "/home/timur/obsidian/projects/p2p-messenger")

import trio

from hermes_p2p.identity import Identity
from hermes_p2p.message import HermesMessage
from hermes_p2p.node import HermesNode


async def test():
    print("=== Test: Two nodes + pubsub ===\n")

    id1 = Identity.generate()
    id2 = Identity.generate()
    print(f"N1: {id1.peer_id}")
    print(f"N2: {id2.peer_id}")

    n1 = HermesNode(id1, port=9100)
    n2 = HermesNode(id2, port=9101)

    topic = "/hermes/room/test"
    received = []

    async def listen_and_report(sub, label):
        """Listen for messages on this subscription."""
        try:
            async for msg_pb in sub.receive_channel:
                msg = HermesMessage.from_bytes(msg_pb.data)
                received.append((label, msg))
                print(f"  [{label}] Got: '{msg.content}' (from {msg.from_peer[:16]}...)")
        except Exception as e:
            print(f"  [{label}] Listen ended: {e}")

    async def run_pair():
        # Start both nodes
        async with n1.run():
            async with n2.run():
                addr1 = n1.get_multiaddr()
                print(f"\nN1 addr: {addr1}")

                # Connect N2 -> N1
                ok = await n2.connect(addr1)
                print(f"Connect N2->N1: {ok}")
                await trio.sleep(0.5)

                # Subscribe both
                sub1 = await n1.subscribe(topic)
                sub2 = await n2.subscribe(topic)
                await trio.sleep(1)  # Let GossipSub mesh form

                # Start listeners
                async with trio.open_nursery() as nursery:
                    nursery.start_soon(listen_and_report, sub1, "N1")
                    nursery.start_soon(listen_and_report, sub2, "N2")

                    await trio.sleep(2)

                    print(f"\n  [N1] Sending: 'Hello P2P!'")
                    sent = await n1.send_message(topic, "Hello P2P!")
                    print(f"  [N1] Sent: {sent is not None}")

                    await trio.sleep(5)
                    nursery.cancel_scope.cancel()

    await run_pair()

    print(f"\n=== Result: {len(received)} messages ===")
    for label, msg in received:
        print(f"  {label}: '{msg.content}' (from {msg.from_peer[:16]}...)")

    n2_got = any(l == "N2" for l, _ in received)
    n1_got = any(l == "N1" for l, _ in received)
    print(f"\nN1 got message: {n1_got} (loopback)")
    print(f"N2 got message: {n2_got} (cross-peer)")
    
    if n2_got:
        print("\n✅ PASS — P2P messaging works!")
    elif n1_got:
        print("\n⚠️ Partial — only loopback delivery")
    else:
        print("\n❌ FAIL — no messages received")


if __name__ == "__main__":
    trio.run(test)
