from __future__ import annotations

import glob
from typing import List


def read_code_files(paths: List[str]) -> List[str]:
    contents: List[str] = []
    for p in paths:
        matched = glob.glob(p, recursive=True)
        if not matched:
            # try literal path
            matched = [p]
        for fp in matched:
            try:
                with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                    contents.append(f.read())
            except Exception as e:
                contents.append(f"/* Failed to read {fp}: {e} */")
    return contents
