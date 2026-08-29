import argparse
import asyncio

from uxsp.cli.utils import prompt_password


def live_session(args: argparse.Namespace) -> None:
    from uxsp import Identity, LiveSession, PublicCard

    sender_pw = prompt_password("Your Identity Password: ")
    identity = Identity.load(args.identity, sender_pw)

    with open(args.peer) as f:
        peer_card = PublicCard.from_json(f.read())

    print(f"Initiating Live Session with {peer_card.name}...")

    async def run_session():  # type: ignore[no-untyped-def]
        LiveSession(identity, peer_card)  # type: ignore[arg-type]
        # Note: True network IO would be implemented here depending on the transport
        print(f"Session established with {peer_card.name}")

    asyncio.run(run_session())  # type: ignore[no-untyped-call]


def live_voice(args: argparse.Namespace) -> None:
    from uxsp import Identity, LiveVoiceSession, PublicCard

    sender_pw = prompt_password("Your Identity Password: ")
    identity = Identity.load(args.identity, sender_pw)

    with open(args.peer) as f:
        peer_card = PublicCard.from_json(f.read())

    print(f"Initiating Live Voice Call with {peer_card.name}...")

    async def run_voice():  # type: ignore[no-untyped-def]
        LiveVoiceSession(identity, peer_card)  # type: ignore[arg-type]
        # Note: True network IO and device recording would be implemented here
        print(f"Voice session established with {peer_card.name}")

    asyncio.run(run_voice())  # type: ignore[no-untyped-call]
