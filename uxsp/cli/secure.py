import argparse

from uxsp.cli.utils import prompt_password


def secure_send(args: argparse.Namespace) -> None:
    from uxsp import Identity, PublicCard
    from uxsp.secure import Send

    sender_pw = prompt_password("Sender Identity Password: ")
    sender = Identity.load(args.sender, sender_pw)

    with open(args.receiver) as f:
        receiver_card = PublicCard.from_json(f.read())

    print(f"Sending to {receiver_card.name}...")

    if args.file:
        pkg = Send(args.file, sender=sender, receiver=receiver_card)
    elif args.text:
        pkg = Send(args.text, sender=sender, receiver=receiver_card)
    else:
        raise ValueError("Must specify either --file or --text")

    out_path = args.out or "payload.uxsp"
    with open(out_path, "wb") as f:
        f.write(pkg.serialize())  # type: ignore[attr-defined]

    print(f"Secure payload saved to {out_path}")


def secure_receive(args: argparse.Namespace) -> None:
    from uxsp import Identity
    from uxsp.secure import Receive, SecurePackage

    receiver_pw = prompt_password("Receiver Identity Password: ")
    receiver = Identity.load(args.receiver, receiver_pw)

    with open(args.payload, "rb") as f:
        pkg = SecurePackage.deserialize(f.read())  # type: ignore[attr-defined]

    print("Decrypting payload...")
    data = Receive(pkg, receiver=receiver)

    if hasattr(data, "read"):
        out_path = args.out or getattr(data, "filename", "received_file")
        with open(out_path, "wb") as f:
            f.write(data.read())
        print(f"File saved to {out_path}")
    else:
        print("Received Data:")
        print(data)
