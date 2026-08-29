import argparse
import asyncio

from uxsp.cli.utils import prompt_password


def stream_send(args: argparse.Namespace) -> None:
    from uxsp import Identity, PublicCard
    from uxsp.secure import SendStream

    sender_pw = prompt_password("Sender Identity Password: ")
    sender = Identity.load(args.sender, sender_pw)
    
    with open(args.receiver) as f:
        receiver_card = PublicCard.from_json(f.read())
        
    print(f"Streaming {args.file} to {receiver_card.name}...")
    
    out_path = args.out or f"{args.file}.uxsp"
    
    # We use a simple local write, normally stream would go over network
    with open(out_path, "wb") as f_out:
        for chunk in SendStream(args.file, sender=sender, receiver=receiver_card):
            f_out.write(chunk)
            
    print(f"Stream saved to {out_path}")


def stream_receive(args: argparse.Namespace) -> None:
    from uxsp import Identity
    from uxsp.secure import ReceiveStream

    receiver_pw = prompt_password("Receiver Identity Password: ")
    receiver = Identity.load(args.receiver, receiver_pw)
    
    out_path = args.out or "received_stream_file"
    print(f"Receiving stream from {args.payload}...")
    
    with open(args.payload, "rb") as f_in:
        with open(out_path, "wb") as f_out:
            for chunk in ReceiveStream(f_in, receiver=receiver):
                f_out.write(chunk)
                
    print(f"Stream received and saved to {out_path}")
