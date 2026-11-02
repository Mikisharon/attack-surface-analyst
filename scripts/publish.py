"""Copy recorded runs into site/data/ so the static replay UI can load them.

    python scripts/publish.py

Then commit and push: GitHub Pages serves the site/ folder.
"""
from __future__ import annotations

import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RUNS, DATA = ROOT / "runs", ROOT / "site" / "data"


def main() -> None:
    DATA.mkdir(parents=True, exist_ok=True)
    files = sorted(RUNS.glob("*.json"))
    for path in files:
        shutil.copy2(path, DATA / path.name)
    print(f"Copied {len(files)} file(s) from runs/ to site/data/")


if __name__ == "__main__":
    main()
