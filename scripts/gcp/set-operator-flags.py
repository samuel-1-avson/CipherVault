#!/usr/bin/env python3
"""Set the transparency-log witnessing flags in an operator compose file.

Runs ON an operator box (DEPLOYMENT_RUNBOOK.md R5c, TRANSPARENCY_LOG.md
"Wiring a three-operator fleet"). The fleet compose keeps the operator
command as a one-line JSON array; this rewrites only that array:

  * drops every existing --witness, --witness-name, --witness-trusted-log,
    --log-witness, --log-witness-quorum and --log-witness-interval-secs flag
  * appends the flags from <flags.json> ({"flags": ["--witness", ...]})

The file is backed up next to itself first; the change is idempotent.

  sudo python3 set-operator-flags.py /opt/ciphervault/docker-compose.yml flags.json
"""
import json
import shutil
import sys
import time
from pathlib import Path

WITH_VALUE = {
    "--witness-name",
    "--witness-trusted-log",
    "--log-witness",
    "--log-witness-quorum",
    "--log-witness-interval-secs",
}
BARE = {"--witness"}


def main() -> int:
    compose = Path(sys.argv[1])
    new_flags = json.loads(Path(sys.argv[2]).read_text())["flags"]
    lines = compose.read_text().splitlines(keepends=True)
    in_operator = False
    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("operator:"):
            in_operator = True
        elif line[:2] == "  " and line[2:3].isalpha() and not stripped.startswith("operator:"):
            in_operator = False
        if in_operator and stripped.startswith("command:"):
            prefix = line[: line.index("command:") + len("command:")]
            command = json.loads(stripped[len("command:"):].strip())
            kept, skip = [], False
            for arg in command:
                if skip:
                    skip = False
                    continue
                if arg in WITH_VALUE:
                    skip = True
                    continue
                if arg in BARE:
                    continue
                kept.append(arg)
            kept.extend(new_flags)
            backup = compose.with_name(compose.name + time.strftime(".pre-witness-%Y%m%dT%H%M%SZ", time.gmtime()))
            shutil.copy2(compose, backup)
            lines[index] = prefix + " " + json.dumps(kept) + "\n"
            compose.write_text("".join(lines))
            print(f"backup {backup}")
            print(f"operator command now has {len(kept)} args ({len(new_flags)} witnessing args)")
            return 0
    print("operator command line not found", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
