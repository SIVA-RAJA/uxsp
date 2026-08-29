import argparse
import contextlib
import os
import sys
from pathlib import Path

from uxsp.cli.utils import prompt_password


def anchor_create(args: argparse.Namespace) -> None:
    import tempfile

    from uxsp import TrustAnchor

    password = prompt_password("Enter password to encrypt anchor key: ", confirm=True)
    anchor = TrustAnchor.create(args.name)
    anchor.save(args.out, password)
    pub = anchor.public_anchor()
    pub_path = str(Path(args.out).parent / (Path(args.out).stem + ".pub.json"))
    Path(pub_path).parent.mkdir(parents=True, exist_ok=True)
    
    dir_ = str(Path(pub_path).parent)
    tmp_fd, tmp_path = tempfile.mkstemp(dir=dir_)
    try:
        with os.fdopen(tmp_fd, "w") as f:
            f.write(pub.to_json())
        if sys.platform != "win32":
            os.chmod(tmp_path, 0o644)
        os.replace(tmp_path, pub_path)
    except Exception:
        with contextlib.suppress(OSError):
            os.unlink(tmp_path)
        raise
    print(f"Trust anchor created: {anchor.entity_id}")
    print(f"Anchor key  : {args.out}  (keep private)")
    print(f"Anchor pubkey: {pub_path}  (distribute to all verifiers)")


def anchor_issue(args: argparse.Namespace) -> None:
    from uxsp import PublicCard, TrustAnchor

    password = prompt_password("Anchor password: ")
    anchor = TrustAnchor.load(args.anchor, password)

    with open(args.card) as f:
        card = PublicCard.from_json(f.read())

    signed = anchor.issue(card, validity_days=args.days)
    out = args.out or str(Path(args.card).parent / (Path(args.card).stem + ".signed.json"))
    
    import tempfile as _tempfile

    out_path = Path(out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_fd, tmp_path = _tempfile.mkstemp(dir=str(out_path.parent))
    try:
        with os.fdopen(tmp_fd, "w") as f:
            f.write(signed.to_json(indent=2))
        if sys.platform != "win32":
            os.chmod(tmp_path, 0o644)
        os.replace(tmp_path, out)
    except Exception:
        with contextlib.suppress(OSError):
            os.unlink(tmp_path)
        raise

    print(f"Signed card for '{card.name}' ({card.role})")
    print(f"Cert ID      : {signed.cert_id}")
    print(f"Valid days   : {args.days}")
    print(f"Saved to     : {out}")
