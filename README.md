# wechat-key-extractor

Standalone Linux WeChat SQLCipher key extraction logic, split out from the
`wechat-sync-daemon` runtime.

This package targets the Linux `arm64` WeChat 4.1.1 flow we validated on
Ubuntu 24.04. It extracts launcher-emitted payloads shaped like:

```text
x'<64-hex-key><32-hex-salt>'
```

The extractor:

- scans relevant WeChat memory mappings for launcher payloads
- validates candidate keys against DB page-1 WCDB/SQLCipher HMACs
- falls back to a `gdb` capture on the proven launcher raw-store write site
- caches validated per-DB keys

## Scope

This repo is only the key extraction and validation surface. It does not
decrypt message content, monitor databases, or relay messages.

## Requirements

- Linux
- Python 3.11+
- access to `/proc/<pid>/mem`
- either `CAP_SYS_PTRACE` or a permissive ptrace configuration
- `gdb` installed if you want the launcher-capture fallback

## Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e '.[dev]'
```

Pinned install from GitHub:

```bash
pip install "wechat-key-extractor @ git+https://github.com/WeChat-Synced/wechat-key-extractor.git@v0.1.1"
```

## CLI

Default usage:

```bash
wechat-key-extractor --pretty
```

Explicit paths:

```bash
wechat-key-extractor \
  --db-dir /home/wechat/xwechat_files \
  --cache-path ~/.cache/wechat-key-extractor/keys.json \
  --pretty
```

Example output:

```json
{
  "pid": 42274,
  "db_files_found": 17,
  "keys": {
    "/home/wechat/xwechat_files/.../message_0.db": "fd25cc8a040bb792..."
  },
  "failure_reason": null,
  "used_cached_keys": false
}
```

## Version-specific note

The current Linux `arm64` WeChat `4.1.1` launcher raw-store offset is:

```text
base + 0x665E4E0
```

If Tencent changes the binary layout, do not guess a replacement offset from
memory alone. Use the version-update procedure in
[`OFFSET_UPDATE_PLAYBOOK.md`](OFFSET_UPDATE_PLAYBOOK.md) and only record a new
offset after the candidate key has been validated against real WCDB files.

## Postmortem

The reverse-engineering writeup lives in [`POSTMORTEM.md`](POSTMORTEM.md). It
documents:

- the working Linux `arm64` WeChat `4.1.1` extraction path
- dead ends that looked promising but failed
- the verification path used on Ubuntu 24.04
- which public references helped and where they fell short

The package boundary and Rust decision live in the umbrella repo ADR:
`wechat-sync/docs/adr/2026-04-12-extractor-boundary.md`.

## Tests

```bash
pytest
```

## Releases

Tags named `v*` run the GitHub Actions release test workflow in
`.github/workflows/release.yml`.
