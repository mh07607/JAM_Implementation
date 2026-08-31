## QUIC
import secrets

import trio

from libp2p import (
    new_host,
    get_default_muxer
)
from libp2p.crypto.secp256k1 import (
    create_new_key_pair,
)
from libp2p.utils.address_validation import (
    get_available_interfaces,
    get_optimal_binding_address,
)
from libp2p.crypto.x25519 import create_new_key_pair as create_x25519_key_pair
from libp2p.security.noise.transport import (
    PROTOCOL_ID as NOISE_PROTOCOL_ID,
    Transport as NoiseTransport,
)
from libp2p.peer.peerinfo import info_from_p2p_addr

async def main():
    # Create a key pair for the host
    secret = secrets.token_bytes(32)
    key_pair = create_new_key_pair(secret)
    noise_key_pair = create_x25519_key_pair()

    noise_transport = NoiseTransport(
        libp2p_keypair = key_pair,
        noise_privkey = noise_key_pair.private_key,
        early_data = None,
    )

    security_options = {NOISE_PROTOCOL_ID: noise_transport}

    # Create a host with the key pair
    host = new_host(key_pair=key_pair, enable_quic=True)

    # Configure the listening address using the new paradigm
    port = 8000
    listen_addrs = get_available_interfaces(port, protocol="udp")
    # Convert TCP addresses to QUIC-v1 addresses
    quic_addrs = []
    for addr in listen_addrs:
        addr_str = str(addr).replace("/tcp/", "/udp/") + "/quic-v1"
        from multiaddr import Multiaddr

        quic_addrs.append(Multiaddr(addr_str))

    optimal_addr = get_optimal_binding_address(port, protocol="udp")
    optimal_quic_str = str(optimal_addr).replace("/tcp/", "/udp/") + "/quic-v1"

    # Start the host
    async with host.run(listen_addrs=quic_addrs):
        print(get_default_muxer(), flush=True)
        print("libp2p has started with QUIC transport", flush=True)
        print("libp2p is listening on:", host.get_addrs(), flush=True)
        print(f"Optimal address: {optimal_quic_str}", flush=True)
        print(f"Share this string: /ip4/127.0.0.1/tcp/4001/p2p/{host.get_id().to_string()}")

        # Connect to bootstrap peers manually
        bootstrap_list = [
            # "/ip4/127.0.0.1/udp/8000/quic-v1/p2p/16Uiu2HAkxkLdZFSSh3rrcgSyqBLaZcvjLz5fyrUhC3oGWYL7U7eT"
        ]
        for addr in bootstrap_list:
            try:
                peer_info = info_from_p2p_addr(Multiaddr(addr))
                await host.connect(peer_info)
                print(f"Connected to bootstrap peer: {peer_info.peer_id}", flush=True)
            except Exception as e:
                print(f"Failed to connect to bootstrap peer: {addr}, Error: {e}", flush=True)
        # Keep the host running
        await trio.sleep_forever()


# Run the async function
trio.run(main)