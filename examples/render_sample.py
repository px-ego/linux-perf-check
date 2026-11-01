#!/usr/bin/env python3
"""Render a synthetic fixture with the inherited report functions; no collection."""

import argparse
import json
from pathlib import Path
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from linux_inspection import generate_batch_html, generate_batch_summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=PROJECT_ROOT / "reports" / "synthetic-demo",
        help="directory for generated text/HTML summaries",
    )
    args = parser.parse_args()
    fixture = json.loads(
        Path(__file__).with_name("inspection.synthetic.json").read_text(encoding="utf-8")
    )
    meta = fixture["meta"]
    batch_results = [{
        "host": meta["host"],
        "port": meta["port"],
        "user": meta["user"],
        "alias": "SYNTHETIC EXAMPLE - no live collection",
        "tags": ["synthetic", "illustrative values"],
        "success": True,
        "error": None,
        "json_path": None,
        "txt_path": None,
        "results": fixture["results"],
        "time": meta["time"],
    }]
    output_dir = str(args.output_dir.resolve())
    _, summary_path = generate_batch_summary(batch_results, output_dir)
    html_path = generate_batch_html(batch_results, output_dir)
    html_file = Path(html_path)
    banner = (
        '<p style="padding:16px;border:2px solid #f59e0b;color:#f8fafc">'
        "SYNTHETIC EXAMPLE: no host was contacted. All values are illustrative. "
        "The report timestamp is the render time, not a live collection time.</p>"
    )
    html_file.write_text(
        html_file.read_text(encoding="utf-8").replace("<body>", "<body>" + banner, 1),
        encoding="utf-8",
    )
    print("Synthetic example only. No SSH, database, model, or webhook calls.")
    print(f"Text summary: {summary_path}")
    print(f"HTML report: {html_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
