import argparse
import json
import os
import subprocess
import sys
import threading
import time


def get_session(force_unlock: bool) -> str:
    session = None if force_unlock else os.environ.get("BW_SESSION")
    if not session:
        unlock = subprocess.run(["bw", "unlock", "--raw"], stdout=subprocess.PIPE, text=True)
        if unlock.returncode != 0:
            sys.exit(unlock.returncode)
        session = unlock.stdout.strip()
    return session


def _spin(message: str, stop: threading.Event) -> None:
    frames = r"|/-\\"
    i = 0
    while not stop.is_set():
        print(f"\r{frames[i % len(frames)]} {message}", end="", file=sys.stderr, flush=True)
        time.sleep(0.1)
        i += 1
    print(f"\r  {message} done.", file=sys.stderr)


def fetch_ssh_items(session: str) -> list:
    stop = threading.Event()
    t = threading.Thread(target=_spin, args=("Fetching vault items…", stop), daemon=True)
    t.start()
    try:
        proc = subprocess.run(
            ["bw", "list", "items", "--session", session],
            capture_output=True,
            text=True,
        )
    finally:
        stop.set()
        t.join()

    if proc.returncode != 0:
        msg = proc.stderr.strip()
        if "Session key is invalid" in msg or "not logged in" in msg.lower():
            msg += "\n  Hint: re-run with --unlock to refresh the session."
        print(msg, file=sys.stderr)
        sys.exit(proc.returncode)

    return [item for item in json.loads(proc.stdout) if "sshKey" in item]


def cmd_list(args: argparse.Namespace) -> None:
    session = get_session(args.unlock)
    items = fetch_ssh_items(session)
    if not items:
        print("No SSH key items found.", file=sys.stderr)
        return
    for item in items:
        fp = item["sshKey"].get("keyFingerprint", "(no fingerprint)")
        print(f"{item['name']}\t{fp}", file=sys.stderr)


def cmd_add(args: argparse.Namespace) -> None:
    session = get_session(args.unlock)
    items = fetch_ssh_items(session)
    if not items:
        print("No SSH key items found.", file=sys.stderr)
        return

    if args.names:
        name_set = set(args.names)
        selected = [item for item in items if item["name"] in name_set]
        for missing in name_set - {item["name"] for item in selected}:
            print(f"Not found: {missing!r}", file=sys.stderr)
    else:
        selected = items

    for item in selected:
        name = item["name"]
        key = item["sshKey"]["privateKey"]
        add = subprocess.run(["ssh-add", "-"], input=key, text=True, capture_output=True)
        if add.returncode == 0:
            print(f"Loaded: {name}", file=sys.stderr)
        else:
            print(f"Failed to load {name!r}: {add.stderr.strip()}", file=sys.stderr)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="bw-ssh",
        description="Load SSH keys from Bitwarden into ssh-agent.",
    )
    parser.add_argument(
        "--unlock",
        action="store_true",
        help="Force re-unlock even if BW_SESSION is already set.",
    )

    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list", help="List SSH key names and fingerprints.")
    add_p = sub.add_parser("add", help="Add SSH keys to the agent.")
    add_p.add_argument(
        "names",
        nargs="*",
        metavar="NAME",
        help="Key names to add (default: all).",
    )

    args = parser.parse_args()
    {"list": cmd_list, "add": cmd_add}[args.command](args)


if __name__ == "__main__":
    main()
