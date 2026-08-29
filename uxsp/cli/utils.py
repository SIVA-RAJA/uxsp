import getpass
import sys


def prompt_password(prompt: str, confirm: bool = False) -> str:
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
