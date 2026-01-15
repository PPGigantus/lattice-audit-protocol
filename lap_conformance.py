"""LAP conformance runner.

This is the entry point for standardization/conformance checks. It verifies:
- interoperability vectors (`spec/test_vectors`)
- golden audit packs (`spec/golden_packs`)

Usage:
    lap-conformance
    lap-conformance --vectors spec/test_vectors --golden spec/golden_packs
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import List, Optional

import lap_verify


def _run_verify(argv: List[str]) -> int:
    return int(lap_verify.main(argv))


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="lap-conformance")
    p.add_argument("--vectors", default="spec/test_vectors", help="Path to test vectors directory")
    p.add_argument("--golden", default="spec/golden_packs", help="Path to golden packs directory")
    args = p.parse_args(argv)

    rc = 0
    rc |= _run_verify(["vectors", args.vectors])

    golden_dir = Path(args.golden)
    if golden_dir.exists():
        for item in sorted(golden_dir.iterdir()):
            if item.suffix.lower() != ".zip":
                continue
            # Skip intentional-negative fixtures (validated via vectors.json).
            # Convention: filenames containing "spliced" represent adversarial corpus examples.
            if "spliced" in item.name:
                print(f"[INFO] Skipping negative corpus pack in golden dir: {item.name}")
                continue
            rc |= _run_verify(["audit-pack", str(item)])
    else:
        print(f"[WARN] golden directory not found: {golden_dir}")

    if rc == 0:
        print("LAP conformance: PASS")
    else:
        print("LAP conformance: FAIL")

    return 0 if rc == 0 else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
