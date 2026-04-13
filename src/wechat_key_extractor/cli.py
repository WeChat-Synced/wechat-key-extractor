from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

from .linux import KeyExtractor, default_cache_path, default_wechat_db_dir


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Extract WeChat SQLCipher keys on Linux")
    parser.add_argument("--db-dir", type=Path, default=default_wechat_db_dir())
    parser.add_argument("--cache-path", type=Path, default=default_cache_path())
    parser.add_argument("--pattern", default=r"x'([0-9a-fA-F]{64,192})'")
    parser.add_argument("--pretty", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )
    extractor = KeyExtractor(
        wechat_db_dir=args.db_dir,
        cache_path=args.cache_path,
        pattern=args.pattern,
    )
    report = extractor.probe_keys().to_dict()
    print(json.dumps(report, indent=2 if args.pretty else None, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
