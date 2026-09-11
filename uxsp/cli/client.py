"""
uxsp.cli.client — Command-line HTTP utility (uxsp curl / uxsp fetch)
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from urllib.parse import urlsplit

from uxsp.cli.utils import prompt_password
from uxsp.client import UXSPClient, UXSPResponse
from uxsp.core.identity import Identity, PublicCard


def cli_fetch(args: argparse.Namespace) -> None:
    """Execute HTTP request with automatic UXSP negotiation from CLI."""
    url = args.url
    method = (args.method or "GET").upper()
    verbose = bool(args.verbose)
    include_headers = bool(args.include)

    # Parse headers
    headers: dict[str, str] = {}
    if args.header:
        for h in args.header:
            if ":" in h:
                k, v = h.split(":", 1)
                headers[k.strip()] = v.strip()

    # Parse data / payload
    data: bytes | str | None = None
    if args.data is not None:
        data = args.data
        if data.startswith("@"):
            # Load from file if prefixed with @
            file_path = Path(data[1:])
            if not file_path.exists():
                print(f"Error: Data file not found: {file_path}", file=sys.stderr)
                sys.exit(1)
            data = file_path.read_bytes()

    # Load sender identity if specified
    sender_ident: Identity | None = None
    if getattr(args, "sender", None):
        sender_path = Path(args.sender)
        if not sender_path.exists():
            print(f"Error: Sender key file not found: {sender_path}", file=sys.stderr)
            sys.exit(1)
        pwd = os.environ.get("UXSP_PASSWORD")
        if not pwd:
            pwd = prompt_password("Sender key password: ")
        sender_ident = Identity.load(sender_path, pwd)

    # Load peer card if specified
    peer: str | PublicCard | None = None
    if getattr(args, "peer", None):
        peer_val = args.peer
        peer_path = Path(peer_val)
        if peer_path.exists() and peer_path.is_file():
            try:
                peer = PublicCard.from_json(peer_path.read_text("utf-8"))
            except Exception as e:
                print(f"Error loading peer card from {peer_path}: {e}", file=sys.stderr)
                sys.exit(1)
        else:
            peer = peer_val

    # Configure client
    force_uxsp = bool(getattr(args, "uxsp_only", False))
    allow_fallback = not force_uxsp and not bool(getattr(args, "plain_only", False))

    client = UXSPClient(
        identity=sender_ident,
        allow_fallback=allow_fallback,
        force_uxsp=force_uxsp,
    )

    if verbose:
        parsed_url = urlsplit(url)
        print(f"* Connecting to {parsed_url.netloc} ({parsed_url.scheme.upper()})...", file=sys.stderr)
        if force_uxsp:
            print("* Enforcing UXSP encryption (force_uxsp=True)", file=sys.stderr)
        elif not allow_fallback:
            print("* Plain HTTP mode (UXSP negotiation disabled)", file=sys.stderr)
        else:
            print("* Negotiating UXSP (Sec-UXSP-Support: v1.2, ml-kem-768)", file=sys.stderr)
        print(f"> {method} {parsed_url.path or '/'} HTTP/1.1", file=sys.stderr)
        print(f"> Host: {parsed_url.netloc}", file=sys.stderr)
        for hk, hv in headers.items():
            print(f"> {hk}: {hv}", file=sys.stderr)
        print(">", file=sys.stderr)

    try:
        resp: UXSPResponse = client.request(
            method=method,
            url=url,
            headers=headers if headers else None,
            data=data,
            peer=peer,
        )
    except Exception as exc:
        print(f"Error: Request failed: {exc}", file=sys.stderr)
        sys.exit(1)

    if verbose:
        print(f"< HTTP/1.1 {resp.status_code}", file=sys.stderr)
        for rk, rv in resp.headers.items():
            print(f"< {rk}: {rv}", file=sys.stderr)
        if resp.is_uxsp:
            sender_id = resp.package.sender_id if resp.package else "unknown"
            print(f"* Protocol: UXSP Encrypted (verified sender: {sender_id})", file=sys.stderr)
        else:
            print("* Protocol: Plaintext HTTP fallback (unencrypted)", file=sys.stderr)
        print("<", file=sys.stderr)

    # If --include was passed, print headers to stdout
    if include_headers:
        print(f"HTTP/1.1 {resp.status_code}")
        for rk, rv in resp.headers.items():
            print(f"{rk}: {rv}")
        print()

    # Output response body
    out_path = getattr(args, "out", None)
    if out_path:
        out_file = Path(out_path)
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_bytes(resp.content)
        if verbose:
            print(f"* Saved {len(resp.content)} bytes to {out_path}", file=sys.stderr)
    else:
        try:
            # Print as decoded text if possible, else binary to buffer
            sys.stdout.write(resp.text)
            if not resp.text.endswith("\n"):
                sys.stdout.write("\n")
            sys.stdout.flush()
        except UnicodeDecodeError:
            sys.stdout.buffer.write(resp.content)
            sys.stdout.buffer.flush()
