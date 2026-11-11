"""Convert an authorized redis-cli --json SLOWLOG GET snapshot to redis-command-json.

SLOWLOG records slow commands only. It does not identify the authenticated actor,
transaction outcome or full command traffic. Redis can truncate arguments before
export; this tool preserves only the argv supplied by Redis, without reconstructing
missing values. Source snapshots contain sensitive arguments; keep them private.
"""
import argparse
import datetime as dt
import json
from pathlib import Path
import re
import sys


def convert(entries, run_id):
    if not re.fullmatch(r"[a-f0-9]{40}", run_id):
        raise ValueError("verified INFO server run_id is required")
    if not isinstance(entries, list) or len(entries) > 10000:
        raise ValueError("invalid bounded SLOWLOG snapshot")
    output = []
    for entry in entries:
        if not isinstance(entry, list) or len(entry) < 4:
            raise ValueError("invalid SLOWLOG entry")
        identity, timestamp, micros, argv = entry[:4]
        if any(type(value) is not int or value < 0 or value > 9007199254740991 for value in (identity, timestamp, micros)):
            raise ValueError("invalid SLOWLOG numeric metadata")
        if not isinstance(argv, list) or not argv or any(not isinstance(value, str) for value in argv):
            raise ValueError("invalid SLOWLOG argv")
        command = json.dumps(argv, ensure_ascii=False, separators=(",", ":"))
        if len(command.encode("utf-8")) > 32768 or micros / 1000 > 31536000000:
            raise ValueError("command exceeds protected evidence limits")
        at = dt.datetime.fromtimestamp(timestamp, dt.timezone.utc).isoformat()
        output.append({"eventId": "redis-slowlog:" + run_id + ":" + str(identity),
                       "timestamp": at, "service": "redis", "user": "[unknown]",
                       "userKnown": False, "operation": "OTHER",
                       "execution": {"protocol": "COMMAND", "sql": command, "durationMs": micros / 1000}})
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    if args.input.stat().st_size > 32 * 1024 * 1024:
        raise ValueError("snapshot exceeds conversion limit")
    rows = convert(json.loads(args.input.read_text(encoding="utf-8")), args.run_id)
    for row in rows:
        print(json.dumps(row, ensure_ascii=False))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, OverflowError):
        print("Redis audit conversion failed; check local snapshot and verified server run_id.", file=sys.stderr)
        sys.exit(1)
