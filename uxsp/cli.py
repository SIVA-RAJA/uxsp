"""
UXSP Command-Line Interface (CLI)

What this file does:
    Provides the 'uxsp' terminal command with sub-commands for key management
    and trust-anchor operations. Every sub-command is a thin wrapper around the
    Python API, so it is safe to invoke from shell scripts or CI pipelines.

Available commands:
    uxsp keygen       — Generate a new Identity keypair and save it encrypted to disk.
    uxsp pubcard      — Extract and export the PublicCard (shareable) from an identity file.
    uxsp anchor create — Create a new TrustAnchor (root CA) with its encrypted private key.
    uxsp anchor issue  — Sign a PublicCard with a TrustAnchor to produce a SignedCard.
    uxsp info         — Display metadata stored inside an identity file.
    uxsp version      — Print the installed uxsp version string.

Example usage:
    $ uxsp keygen --name "API Server" --role SERVER --out ./keys/server.uxsp
    $ uxsp pubcard --key ./keys/server.uxsp --out ./cards/server.json
    $ uxsp anchor create --name "Root CA" --out ./keys/root.uxsp
    $ uxsp anchor issue --anchor ./keys/root.uxsp --card ./cards/server.json
    $ uxsp info --key ./keys/server.uxsp
    $ uxsp version
"""

from __future__ import annotations

import argparse
import contextlib
import getpass
import os
import sys
from pathlib import Path


def _keygen(args: argparse.Namespace) -> None:
    """
    Handle the 'keygen' sub-command.

    Creates a new Identity (entity name + role + hybrid keypair), prompts for
    a password to encrypt the private keys, and saves the encrypted identity
    file to the path given by --out.
    """
    from uxsp import Identity

    password = _prompt_password("Enter password to encrypt key: ", confirm=True)
    identity = Identity.create(args.name, args.role)
    identity.save(args.out, password)
    print(f"Identity created: {identity.entity_id}")
    print(f"Saved to: {args.out}")


def _pubcard(args: argparse.Namespace) -> None:
    """
    Handle the 'pubcard' sub-command.

    Loads an encrypted identity file (--key), decrypts it using the provided
    password, extracts the PublicCard (which contains only public keys and
    metadata — no secrets), and writes it as a JSON file to --out.
    The output file is safe to share with anyone who needs to communicate with
    this identity.
    """
    import tempfile as _tempfile

    from uxsp import Identity

    password = _prompt_password("Password: ")
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


def _anchor_create(args: argparse.Namespace) -> None:
    """
    Handle the 'anchor create' sub-command.

    Creates a new TrustAnchor (root Certificate Authority), encrypts the
    private key with the provided password, and saves two files:
      - The encrypted anchor key file (--out), which must be kept private.
      - A companion public anchor JSON file (<out-stem>.pub.json) that should
        be distributed to all verifiers so they can trust cards issued by this anchor.
    Both files are written atomically (temp-then-replace) to prevent corruption.
    """
    import tempfile

    from uxsp import TrustAnchor

    password = _prompt_password("Enter password to encrypt anchor key: ", confirm=True)
    anchor = TrustAnchor.create(args.name)
    anchor.save(args.out, password)
    pub = anchor.public_anchor()
    pub_path = str(Path(args.out).parent / (Path(args.out).stem + ".pub.json"))
    # Ensure parent directory exists before creating temporary file
    Path(pub_path).parent.mkdir(parents=True, exist_ok=True)
    # Write atomically: temp file in the same directory then os.replace().
    # A plain open(..., "w") would leave a half-written file if the process
    # crashes or the disk fills mid-write.
    dir_ = str(Path(pub_path).parent)
    tmp_fd, tmp_path = tempfile.mkstemp(dir=dir_)
    try:
        with os.fdopen(tmp_fd, "w") as f:
            f.write(pub.to_json())
        if sys.platform != "win32":
            os.chmod(tmp_path, 0o644)  # Ensure public anchor is readable by others
        os.replace(tmp_path, pub_path)
    except Exception:
        with contextlib.suppress(OSError):
            os.unlink(tmp_path)
        raise
    print(f"Trust anchor created: {anchor.entity_id}")
    print(f"Anchor key  : {args.out}  (keep private)")
    print(f"Anchor pubkey: {pub_path}  (distribute to all verifiers)")


def _anchor_issue(args: argparse.Namespace) -> None:
    """
    Handle the 'anchor issue' sub-command.

    Loads a TrustAnchor from an encrypted key file (--anchor), reads a
    PublicCard JSON file (--card), signs that card with the anchor's private
    key to produce a SignedCard, and writes the result as a JSON file.
    The resulting SignedCard contains the original card plus the anchor's
    certificate ID, validity window, and both classical and PQC signatures.
    """
    from uxsp import PublicCard, TrustAnchor

    password = _prompt_password("Anchor password: ")
    anchor = TrustAnchor.load(args.anchor, password)

    with open(args.card) as f:
        card = PublicCard.from_json(f.read())

    signed = anchor.issue(card, validity_days=args.days)
    out = args.out or str(Path(args.card).parent / (Path(args.card).stem + ".signed.json"))
    # Write atomically: temp file in the same directory then os.replace().
    # A plain open(..., "w") would leave a half-written card if the process
    # crashes or the disk fills mid-write.
    import tempfile as _tempfile

    out_path = Path(out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_fd, tmp_path = _tempfile.mkstemp(dir=str(out_path.parent))
    try:
        with os.fdopen(tmp_fd, "w") as f:
            f.write(signed.to_json(indent=2))
        if sys.platform != "win32":
            os.chmod(tmp_path, 0o644)  # Ensure signed card is readable by others
        os.replace(tmp_path, out)
    except Exception:
        with contextlib.suppress(OSError):
            os.unlink(tmp_path)
        raise

    print(f"Signed card for '{card.name}' ({card.role})")
    print(f"Cert ID      : {signed.cert_id}")
    print(f"Valid days   : {args.days}")
    print(f"Saved to     : {out}")


def _info(args: argparse.Namespace) -> None:
    """
    Handle the 'info' sub-command.

    Loads an encrypted identity file (--key), decrypts it with the provided
    password, and prints the public metadata: entity ID, display name, role,
    and the creation timestamp. No private key material is printed.
    """
    from uxsp import Identity

    password = _prompt_password("Password: ")
    identity = Identity.load(args.key, password)
    print(f"Entity ID  : {identity.entity_id}")
    print(f"Name       : {identity.name}")
    print(f"Role       : {identity.role}")
    print(f"Created    : {identity.created_at}")


def _version(_args: argparse.Namespace) -> None:
    """
    Handle the 'version' sub-command.

    Prints the installed uxsp package version (e.g. 'uxsp 0.1.2') to stdout.
    """
    from uxsp import __version__

    print(f"uxsp {__version__}")


def _prompt_password(prompt: str, confirm: bool = False) -> str:
    """
    Prompt the user for a password securely via getpass (no echo).

    If confirm=True, asks for the password a second time and exits if the two
    entries do not match. Exits with an error if the password is empty.

    Returns the entered password string.
    """
    pw = getpass.getpass(prompt)
    if confirm:
        pw2 = getpass.getpass("Confirm password: ")
        if pw != pw2:
            print("Passwords do not match.", file=sys.stderr)
            sys.exit(1)
    if not pw:
        print("Password cannot be empty.", file=sys.stderr)
        sys.exit(1)
    return pw


def main() -> None:
    """
    Entry point for the 'uxsp' command-line tool.

    Builds the argparse parser with all sub-commands (keygen, pubcard, anchor,
    info, version), dispatches to the appropriate handler function, and prints
    any errors to stderr before exiting with code 1 on failure.
    """
    parser = argparse.ArgumentParser(
        prog="uxsp",
        description="UXSP — Universal Exchange Security Protocol CLI",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # ── keygen ──────────────────────────────
    p_kg = sub.add_parser("keygen", help="Create a new identity keypair")
    p_kg.add_argument("--name", required=True, help="Human name for this identity")
    p_kg.add_argument("--role", required=True, help="Role string (e.g. SERVER, DEVICE)")
    p_kg.add_argument("--out", required=True, help="Output .uxsp file path")
    p_kg.set_defaults(func=_keygen)

    # ── pubcard ─────────────────────────────
    p_pc = sub.add_parser("pubcard", help="Export a public card from an identity file")
    p_pc.add_argument("--key", required=True, help="Path to .uxsp identity file")
    p_pc.add_argument("--out", default=None, help="Output .json file (default: <key>.card.json)")
    p_pc.set_defaults(func=_pubcard)

    # ── anchor ──────────────────────────────
    p_an = sub.add_parser("anchor", help="Trust anchor operations")
    an_sub = p_an.add_subparsers(dest="anchor_command", required=True)

    p_ac = an_sub.add_parser("create", help="Create a new trust anchor")
    p_ac.add_argument("--name", required=True, help="Authority name")
    p_ac.add_argument("--out", required=True, help="Output .uxsp file path")
    p_ac.set_defaults(func=_anchor_create)

    p_ai = an_sub.add_parser("issue", help="Issue a signed card from an anchor")
    p_ai.add_argument("--anchor", required=True, help="Anchor .uxsp file")
    p_ai.add_argument("--card", required=True, help="PublicCard .json file to sign")
    p_ai.add_argument("--days", type=int, default=365, help="Validity days (default 365)")
    p_ai.add_argument("--out", default=None, help="Output signed card path")
    p_ai.set_defaults(func=_anchor_issue)

    # ── info ─────────────────────────────────
    p_in = sub.add_parser("info", help="Show identity info")
    p_in.add_argument("--key", required=True, help="Path to .uxsp identity file")
    p_in.set_defaults(func=_info)

    # ── version ──────────────────────────────
    p_v = sub.add_parser("version", help="Show uxsp version")
    p_v.set_defaults(func=_version)

    args: argparse.Namespace = parser.parse_args()
    try:
        args.func(args)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":  # pragma: no cover
    main()
