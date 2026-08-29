"""
UXSP Command-Line Interface (CLI)

What this file does:
    Provides the 'uxsp' terminal command with sub-commands for key management,
    trust-anchor operations, and secure transmissions.

Available commands:
    uxsp keygen       — Generate a new Identity keypair and save it encrypted to disk.
    uxsp pubcard      — Extract and export the PublicCard (shareable) from an identity file.
    uxsp info         — Display metadata stored inside an identity file.
    uxsp rotate       — Rotate the keys of an identity file.
    uxsp revoke       — Revoke an identity file.

    uxsp anchor create — Create a new TrustAnchor (root CA).
    uxsp anchor issue  — Sign a PublicCard with a TrustAnchor.

    uxsp secure send     — Securely encrypt and send payloads (file, text, etc).
    uxsp secure receive  — Securely receive and decrypt payloads.

    uxsp stream send     — Stream large files securely.
    uxsp stream receive  — Receive large secure streams.

    uxsp live session    — Start a live secure session.
    uxsp live voice      — Start a live secure voice call.

    uxsp version      — Print the installed uxsp version string.
"""

from __future__ import annotations

import argparse
import sys


def _version(_args: argparse.Namespace) -> None:
    from uxsp import __version__
    print(f"uxsp {__version__}")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="uxsp",
        description="UXSP — Universal Exchange Security Protocol CLI",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # ── identity ──────────────────────────────
    from uxsp.cli import identity

    p_kg = sub.add_parser("keygen", help="Create a new identity keypair")
    p_kg.add_argument("--name", required=True, help="Human name for this identity")
    p_kg.add_argument("--role", required=True, help="Role string (e.g. SERVER, DEVICE)")
    p_kg.add_argument("--out", required=True, help="Output .uxsp file path")
    p_kg.set_defaults(func=identity.keygen)

    p_pc = sub.add_parser("pubcard", help="Export a public card from an identity file")
    p_pc.add_argument("--key", required=True, help="Path to .uxsp identity file")
    p_pc.add_argument("--out", default=None, help="Output .json file (default: <key>.card.json)")
    p_pc.set_defaults(func=identity.pubcard)

    p_in = sub.add_parser("info", help="Show identity info")
    p_in.add_argument("--key", required=True, help="Path to .uxsp identity file")
    p_in.set_defaults(func=identity.info)

    p_rot = sub.add_parser("rotate", help="Rotate identity keys")
    p_rot.add_argument("--key", required=True, help="Path to .uxsp identity file")
    p_rot.set_defaults(func=identity.rotate)

    p_rev = sub.add_parser("revoke", help="Revoke an identity")
    p_rev.add_argument("--key", required=True, help="Path to .uxsp identity file")
    p_rev.add_argument("--reason", default="Unspecified", help="Reason for revocation")
    p_rev.set_defaults(func=identity.revoke)

    # ── anchor ──────────────────────────────
    from uxsp.cli import anchor

    p_an = sub.add_parser("anchor", help="Trust anchor operations")
    an_sub = p_an.add_subparsers(dest="anchor_command", required=True)

    p_ac = an_sub.add_parser("create", help="Create a new trust anchor")
    p_ac.add_argument("--name", required=True, help="Authority name")
    p_ac.add_argument("--out", required=True, help="Output .uxsp file path")
    p_ac.set_defaults(func=anchor.anchor_create)

    p_ai = an_sub.add_parser("issue", help="Issue a signed card from an anchor")
    p_ai.add_argument("--anchor", required=True, help="Anchor .uxsp file")
    p_ai.add_argument("--card", required=True, help="PublicCard .json file to sign")
    p_ai.add_argument("--days", type=int, default=365, help="Validity days (default 365)")
    p_ai.add_argument("--out", default=None, help="Output signed card path")
    p_ai.set_defaults(func=anchor.anchor_issue)

    # ── secure ──────────────────────────────
    from uxsp.cli import secure

    p_sec = sub.add_parser("secure", help="Secure transmission operations")
    sec_sub = p_sec.add_subparsers(dest="secure_command", required=True)

    p_ss = sec_sub.add_parser("send", help="Send a secure payload")
    p_ss.add_argument("--sender", required=True, help="Path to sender .uxsp identity file")
    p_ss.add_argument("--receiver", required=True, help="Path to receiver .json public card")
    p_ss.add_argument("--file", help="File to send")
    p_ss.add_argument("--text", help="Text to send")
    p_ss.add_argument("--out", help="Output payload file path")
    p_ss.set_defaults(func=secure.secure_send)

    p_sr = sec_sub.add_parser("receive", help="Receive a secure payload")
    p_sr.add_argument("--receiver", required=True, help="Path to receiver .uxsp identity file")
    p_sr.add_argument("--payload", required=True, help="Path to payload .uxsp file")
    p_sr.add_argument("--out", help="Output decrypted file path")
    p_sr.set_defaults(func=secure.secure_receive)

    # ── stream ──────────────────────────────
    from uxsp.cli import stream

    p_str = sub.add_parser("stream", help="Secure stream operations")
    str_sub = p_str.add_subparsers(dest="stream_command", required=True)

    p_sts = str_sub.add_parser("send", help="Stream a secure payload")
    p_sts.add_argument("--sender", required=True, help="Path to sender .uxsp identity file")
    p_sts.add_argument("--receiver", required=True, help="Path to receiver .json public card")
    p_sts.add_argument("--file", required=True, help="File to stream")
    p_sts.add_argument("--out", help="Output payload file path")
    p_sts.set_defaults(func=stream.stream_send)

    p_strr = str_sub.add_parser("receive", help="Receive a secure stream")
    p_strr.add_argument("--receiver", required=True, help="Path to receiver .uxsp identity file")
    p_strr.add_argument("--payload", required=True, help="Path to stream payload file")
    p_strr.add_argument("--out", help="Output stream file path")
    p_strr.set_defaults(func=stream.stream_receive)

    # ── live ──────────────────────────────
    from uxsp.cli import live

    p_liv = sub.add_parser("live", help="Live session operations")
    liv_sub = p_liv.add_subparsers(dest="live_command", required=True)

    p_ls = liv_sub.add_parser("session", help="Start a live session")
    p_ls.add_argument("--identity", required=True, help="Path to your .uxsp identity file")
    p_ls.add_argument("--peer", required=True, help="Path to peer .json public card")
    p_ls.set_defaults(func=live.live_session)

    p_lv = liv_sub.add_parser("voice", help="Start a live voice call")
    p_lv.add_argument("--identity", required=True, help="Path to your .uxsp identity file")
    p_lv.add_argument("--peer", required=True, help="Path to peer .json public card")
    p_lv.set_defaults(func=live.live_voice)

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
