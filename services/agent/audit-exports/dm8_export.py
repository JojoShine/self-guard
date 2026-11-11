"""Strip SQL/parameters from a complete, immutable dmaudtool export before Agent ingestion.

Export exactly one closed audit file without filters, with explicit C_SEP/R_SEP.
source-sha256 identifies that closed binary audit file. Preserve its complete row
order on retries: DM's view has no unique event ID and timestamps may collide.
operation-map maps numeric codes to names verified for the source DM version.
The input contains sensitive SQL: keep it local with restricted permissions.
"""
import argparse
import datetime as dt
import json
from pathlib import Path
import re
import sys


def convert(body, source, database, offset, operations, column_separator, row_separator, include_statement=False):
    if not re.fullmatch(r"[a-f0-9]{64}", source):
        raise ValueError("source-sha256 must identify one closed original audit file")
    if not re.fullmatch(r"[+-](?:0\d|1[0-4]):[0-5]\d", offset):
        raise ValueError("supply the verified source timezone offset, e.g. +08:00")
    if not database.strip() or len(database) > 128:
        raise ValueError("invalid database identifier")
    if not column_separator or not row_separator or column_separator == row_separator:
        raise ValueError("distinct explicit separators required")
    records = body.split(row_separator)
    if records[-1].strip():
        raise ValueError("incomplete export: final record separator missing")
    output = []
    for ordinal, record in enumerate(records[:-1], 1):
        fields = record.strip("\r\n").split(column_separator)
        if len(fields) != 17:
            raise ValueError(f"record {ordinal}: unexpected column count; check separators")
        # Bind parameters and descriptions are never serialized. SQL_TEXT requires explicit opt-in.
        timestamp = dt.datetime.fromisoformat(fields[13].replace(" ", "T") + offset)
        if not fields[1].strip() or fields[10] not in ("Y", "N"):
            raise ValueError(f"record {ordinal}: invalid user or result metadata")
        output.append({"EVENT_ID": source + ":" + str(ordinal),
                       "EVENT_TIMESTAMP": timestamp.astimezone(dt.timezone.utc).isoformat(),
                       "DBNAME": database, "USERNAME": fields[1], "IP": fields[4],
                       "SCHNAME": fields[6], "OBJNAME": fields[8],
                       "OPERATION": operations.get(fields[9], "OTHER"), "SUCC_FLAG": fields[10]})
        if include_statement and fields[11]:
            if len(fields[11].encode("utf-8")) > 32768:
                raise ValueError("SQL_TEXT exceeds the protected statement limit")
            output[-1]["SQL_TEXT"] = fields[11]
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--source-sha256", required=True)
    parser.add_argument("--database", required=True)
    parser.add_argument("--timezone-offset", required=True)
    parser.add_argument("--operation-map", type=Path, required=True)
    parser.add_argument("--column-separator", required=True)
    parser.add_argument("--row-separator", required=True)
    parser.add_argument("--include-statement", action="store_true", help="explicitly retain SQL_TEXT for dm-audit-sql-json; never exports bind values")
    args = parser.parse_args()
    if args.input.stat().st_size > 32 * 1024 * 1024:
        raise ValueError("export exceeds 32 MiB conversion limit")
    operations = json.loads(args.operation_map.read_text(encoding="utf-8"))
    if not isinstance(operations, dict) or any(not isinstance(v, str) for v in operations.values()):
        raise ValueError("operation map must contain string values")
    rows = convert(args.input.read_text(encoding="utf-8"), args.source_sha256, args.database,
                   args.timezone_offset, operations, args.column_separator, args.row_separator, args.include_statement)
    for row in rows:
        print(json.dumps(row, ensure_ascii=False))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError):
        # Exception messages may contain source SQL, paths, or credentials.
        print("DM audit conversion failed; check local input, mapping and explicit timezone.", file=sys.stderr)
        sys.exit(1)
