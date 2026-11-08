#!/usr/bin/env python3
"""Fail if production (non-test) Rust code uses .unwrap().

Rule (matches IMPLEMENTATION_PLAN.md P2):
- Files under tests/ dirs or *tests*.rs are test code: ignored.
- For src files with an inline `#[cfg(test)]` module, only lines before the
  first `#[cfg(test)]` marker count as production.
- Files with no marker: the whole file is production.
- `.expect()` is reported as a warning count only (phased conversion to
  thiserror, e.g. crates/chain/src/error.rs pattern) -- it does not fail.

Exit 0 = no production unwrap. Exit 1 = violation (prints file:line).
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCAN_DIRS = [ROOT / "crates", ROOT / "services", ROOT / "apps"]
UNWRAP_RE = re.compile(r"\.unwrap\s*\(\s*\)")
EXPECT_RE = re.compile(r"\.expect\s*\(")
CFG_TEST_RE = re.compile(r"#\s*\[\s*cfg\s*\(.*\btest\b.*\)")


def is_test_path(p: Path) -> bool:
    parts = p.parts
    return "tests" in parts or "test_support" in p.name or p.name == "tests.rs"


def prod_lines(path: Path):
    text = path.read_text(encoding="utf-8", errors="replace").splitlines()
    for i, line in enumerate(text, start=1):
        if CFG_TEST_RE.search(line):
            return text[: i - 1], i  # prod region = before marker
    return text, None


def main() -> int:
    violations = []
    expect_count = 0
    files_scanned = 0
    for base in SCAN_DIRS:
        for path in sorted(base.rglob("*.rs")):
            if is_test_path(path):
                continue
            lines, _ = prod_lines(path)
            files_scanned += 1
            rel = path.relative_to(ROOT).as_posix()
            for offset, line in enumerate(lines, start=1):
                if UNWRAP_RE.search(line):
                    violations.append(f"{rel}:{offset}:{line.strip()}")
                if EXPECT_RE.search(line):
                    expect_count += 1
    print(f"scanned {files_scanned} non-test .rs files")
    print(f"production .expect() hits (warning only): {expect_count}")
    if violations:
        print(f"FAIL: {len(violations)} production .unwrap() hits:")
        for v in violations[:30]:
            print(f"  {v}")
        if len(violations) > 30:
            print(f"  ... and {len(violations) - 30} more")
        return 1
    print("PASS: no production .unwrap()")
    return 0


if __name__ == "__main__":
    sys.exit(main())
