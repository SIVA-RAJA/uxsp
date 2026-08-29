import argparse
import contextlib
import os
import sys
from pathlib import Path

from uxsp.cli.utils import prompt_password


def keygen(args: argparse.Namespace) -> None:
    from uxsp import Identity

    password = prompt_password("Enter password to encrypt key: ", confirm=True)
    identity = Identity.create(args.name, args.role)
    identity.save(args.out, password)
    print(f"Identity created: {identity.entity_id}")
    print(f"Saved to: {args.out}")


def pubcard(args: argparse.Namespace) -> None:
    import tempfile as _tempfile

    from uxsp import Identity

    password = prompt_password("Password: ")
    identity = Identity.load(args.key, password)
    card = identity.public_card()
    key_path = Path(args.key)
    out = args.out or str(key_path.parent / (key_path.stem + ".card.json"))
    out_path = Path(out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    tmp_fd, tmp_path = _tempfile.mkstemp(dir=str(out_path.parent))
    try:
        with os.fdopen(tmp_fd, "w") as f:
            f.write(card.to_json())
        if sys.platform != "win32":
            os.chmod(tmp_path, 0o644)
        os.replace(tmp_path, out)
    except Exception:
        with contextlib.suppress(OSError):
            os.unlink(tmp_path)
        raise

    print(f"Public card for '{card.name}' ({card.role})")
    print(f"Entity ID : {card.entity_id}")
    print(f"Saved to  : {out}")


def info(args: argparse.Namespace) -> None:
    from uxsp import Identity

    password = prompt_password("Password: ")
    identity = Identity.load(args.key, password)
    print(f"Entity ID  : {identity.entity_id}")
    print(f"Name       : {identity.name}")
    print(f"Role       : {identity.role}")
    print(f"Created    : {identity.created_at}")


def rotate(args: argparse.Namespace) -> None:
    from uxsp import Identity

    password = prompt_password("Password: ")
    identity = Identity.load(args.key, password)
    identity.rotate_keys()

    new_password = prompt_password("Enter new password (or same) to encrypt key: ", confirm=True)
    identity.save(args.key, new_password)

    print(f"Keys rotated for Entity ID: {identity.entity_id}")
    print(f"Saved to: {args.key}")


def revoke(args: argparse.Namespace) -> None:
    from uxsp import Identity

    password = prompt_password("Password: ")
    identity = Identity.load(args.key, password)
    identity.revoke(reason=args.reason)  # type: ignore[attr-defined]
    identity.save(args.key, password)

    print(f"Identity revoked: {identity.entity_id}")
    print(f"Reason: {args.reason}")
    print(f"Saved to: {args.key}")
