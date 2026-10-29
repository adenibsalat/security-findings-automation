"""Send a Prowler output file to the pipeline (the API directly, or later the n8n webhook)."""

import argparse
import json
import os
import sys
from pathlib import Path

import requests
from dotenv import load_dotenv


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", help="Prowler json-ocsf or v3 JSON file")
    parser.add_argument("--url", default="http://127.0.0.1:8000/findings")
    parser.add_argument("--min-severity", default="high")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    load_dotenv()
    text = Path(args.path).read_text(encoding="utf-8").strip()
    if text.startswith("["):
        findings = json.loads(text)
    else:
        findings = [json.loads(line) for line in text.splitlines() if line.strip()]

    resp = requests.post(
        args.url,
        json={"findings": findings, "min_severity": args.min_severity, "dry_run": args.dry_run},
        headers={"X-Api-Key": os.environ.get("PIPELINE_API_KEY", "")},
        timeout=120,
    )
    print(f"HTTP {resp.status_code}")
    try:
        print(json.dumps(resp.json(), indent=2))
    except ValueError:
        print(resp.text)
    return 0 if resp.ok else 1


if __name__ == "__main__":
    sys.exit(main())