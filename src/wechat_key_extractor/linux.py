"""Linux WeChat SQLCipher key extraction and validation."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import hmac
import json
import logging
import os
from pathlib import Path
import re
import shutil
import signal
import struct
import subprocess
import tempfile
import time

logger = logging.getLogger(__name__)

SQLCIPHER_PAGE_SIZE = 4096
SQLCIPHER_RESERVE = 80
SQLCIPHER_KEY_SIZE = 32
SQLCIPHER_SALT_SIZE = 16
SQLCIPHER_HMAC_SIZE = 64
SQLCIPHER_MAC_SALT_XOR = 0x3A

EXTRACTION_ATTEMPTS = 2
EXTRACTION_INTERVAL_SECONDS = 1.0
GDB_CAPTURE_TIMEOUT_SECONDS = 60.0
GDB_CAPTURE_SETTLE_SECONDS = 2.0
GDB_CAPTURE_POLL_SECONDS = 0.2
WECHAT_RAW_STORE_OFFSET = 0x665E4E0
DEFAULT_PATTERN = r"x'([0-9a-fA-F]{64,192})'"

XKEY_PAYLOAD_PATTERN = re.compile(rb"x'([0-9a-fA-F]{64,192})'")
RAW_KEY_PATTERN = re.compile(rb"(?<![0-9a-fA-F])([0-9a-fA-F]{64})(?![0-9a-fA-F])")


@dataclass(slots=True)
class KeyExtractionReport:
    pid: int | None
    db_files_found: int
    keys: dict[str, str]
    failure_reason: str | None = None
    used_cached_keys: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


def default_wechat_db_dir() -> Path:
    return Path("/home/wechat/xwechat_files")


def default_cache_path() -> Path:
    return Path.home() / ".cache" / "wechat-key-extractor" / "keys.json"


def _should_scan_region(perms: str, path: str, region_size: int) -> bool:
    if "r" not in perms:
        return False
    if region_size > 256 * 1024 * 1024 or region_size < 32:
        return False

    normalized_path = path or "[anonymous]"
    if normalized_path in {"[anonymous]", "[heap]"}:
        return True
    if normalized_path.startswith("[anon:"):
        return True
    if normalized_path.startswith("/opt/wechat"):
        return True
    return False


def find_wechat_pid() -> int | None:
    proc = Path("/proc")
    pids: list[int] = []
    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            cmdline = (entry / "cmdline").read_bytes().decode("utf-8", errors="ignore")
        except (PermissionError, FileNotFoundError, ProcessLookupError):
            continue
        if "wechat" in cmdline.lower():
            pids.append(int(entry.name))
    return min(pids) if pids else None


def _read_memory_regions(pid: int) -> list[tuple[int, int, str]]:
    regions: list[tuple[int, int, str]] = []
    maps_path = Path(f"/proc/{pid}/maps")
    try:
        for line in maps_path.read_text().splitlines():
            parts = line.split()
            if len(parts) < 2:
                continue
            perms = parts[1]
            start_s, end_s = parts[0].split("-")
            start = int(start_s, 16)
            end = int(end_s, 16)
            region_size = end - start
            path = parts[-1] if len(parts) >= 6 else ""
            if _should_scan_region(perms, path, region_size):
                regions.append((start, end, perms))
    except (PermissionError, FileNotFoundError) as exc:
        logger.error("Cannot read /proc/%d/maps: %s", pid, exc)
    return regions


def _read_db_salt(db_path: Path) -> bytes | None:
    try:
        with open(db_path, "rb") as f:
            salt = f.read(SQLCIPHER_SALT_SIZE)
            if len(salt) == SQLCIPHER_SALT_SIZE:
                return salt
    except (FileNotFoundError, PermissionError) as exc:
        logger.warning("Cannot read salt from %s: %s", db_path, exc)
    return None


def _build_db_salts(db_paths: list[Path]) -> dict[str, bytes]:
    db_salts: dict[str, bytes] = {}
    for db_path in db_paths:
        salt = _read_db_salt(db_path)
        if salt:
            db_salts[str(db_path)] = salt
    return db_salts


def _extract_key_candidates(data: bytes) -> list[tuple[str, str | None]]:
    candidates: list[tuple[str, str | None]] = []
    seen: set[tuple[str, str | None]] = set()

    def add_candidate(key_hex: str, salt_hex: str | None) -> None:
        candidate = (key_hex.lower(), salt_hex.lower() if salt_hex else None)
        if candidate not in seen:
            seen.add(candidate)
            candidates.append(candidate)

    for match in XKEY_PAYLOAD_PATTERN.finditer(data):
        inner = match.group(1).decode("ascii").lower()
        if len(inner) >= 96:
            add_candidate(inner[:64], inner[-32:])
        elif len(inner) == 64:
            add_candidate(inner, None)

    for match in RAW_KEY_PATTERN.finditer(data):
        add_candidate(match.group(1).decode("ascii"), None)

    return candidates


def _verify_page_hmac(db_path: Path, raw_key: bytes) -> bool:
    try:
        with open(db_path, "rb") as f:
            page = f.read(SQLCIPHER_PAGE_SIZE)
            if len(page) < SQLCIPHER_PAGE_SIZE:
                return False

        salt = page[:SQLCIPHER_SALT_SIZE]
        mac_salt = bytes(b ^ SQLCIPHER_MAC_SALT_XOR for b in salt)
        mac_key = hashlib.pbkdf2_hmac(
            "sha512",
            raw_key,
            mac_salt,
            2,
            dklen=SQLCIPHER_KEY_SIZE,
        )
        hmac_data_end = SQLCIPHER_PAGE_SIZE - SQLCIPHER_RESERVE + SQLCIPHER_SALT_SIZE
        hmac_data = page[SQLCIPHER_SALT_SIZE:hmac_data_end]
        stored_hmac = page[SQLCIPHER_PAGE_SIZE - SQLCIPHER_HMAC_SIZE:SQLCIPHER_PAGE_SIZE]

        computed = hmac.new(mac_key, hmac_data, hashlib.sha512)
        computed.update(struct.pack("<I", 1))
        return hmac.compare_digest(computed.digest(), stored_hmac)
    except Exception as exc:
        logger.debug("HMAC verification failed for %s: %s", db_path, exc)
        return False


def _validate_key_candidates(
    candidates: list[tuple[str, str | None]],
    db_salts: dict[str, bytes],
) -> dict[str, str]:
    db_paths_by_salt: dict[str, list[str]] = {}
    for db_path_str, salt in db_salts.items():
        db_paths_by_salt.setdefault(salt.hex(), []).append(db_path_str)

    validated: dict[str, str] = {}
    for hex_key, inline_salt_hex in candidates:
        raw_key = bytes.fromhex(hex_key)
        target_paths = (
            db_paths_by_salt.get(inline_salt_hex, [])
            if inline_salt_hex
            else list(db_salts.keys())
        )
        for db_path_str in target_paths:
            if db_path_str in validated:
                continue
            if _verify_page_hmac(Path(db_path_str), raw_key):
                validated[db_path_str] = hex_key
        if len(validated) == len(db_salts):
            break
    return validated


def _validate_cached_keys(cached_keys: dict[str, str], db_files: list[Path]) -> dict[str, str]:
    validated: dict[str, str] = {}
    db_files_by_path = {str(db_path): db_path for db_path in db_files}
    for db_path_str, hex_key in cached_keys.items():
        db_path = db_files_by_path.get(db_path_str)
        if db_path is None:
            continue
        try:
            raw_key = bytes.fromhex(hex_key)
        except ValueError:
            continue
        if _verify_page_hmac(db_path, raw_key):
            validated[db_path_str] = hex_key
    return validated


def _resolve_wechat_base(pid: int) -> int | None:
    maps_path = Path(f"/proc/{pid}/maps")
    try:
        for line in maps_path.read_text().splitlines():
            if "/opt/wechat/wechat" not in line:
                continue
            parts = line.split()
            start = int(parts[0].split("-", 1)[0], 16)
            offset = int(parts[2], 16)
            return start - offset
    except (FileNotFoundError, PermissionError, ValueError) as exc:
        logger.warning("Failed to resolve WeChat base for PID %d: %s", pid, exc)
    return None


def _resolve_wechat_executable(pid: int) -> Path | None:
    exe_link = Path(f"/proc/{pid}/exe")
    proc_root = Path(f"/proc/{pid}/root")
    try:
        target = os.readlink(exe_link)
    except OSError as exc:
        logger.warning("Failed to resolve /proc/%d/exe: %s", pid, exc)
        return None

    candidate = proc_root / target.lstrip("/")
    if candidate.exists():
        return candidate

    direct = Path(target)
    if direct.exists():
        return direct
    return None


def _render_gdb_capture_script(
    executable_path: Path,
    pid: int,
    log_path: Path,
    raw_store_addr: int,
) -> str:
    return f"""
set pagination off
set confirm off
set breakpoint pending on
set print elements 0
set print repeats 0
set print inferior-events off
file {executable_path}
attach {pid}
set logging file {log_path}
set logging overwrite on
set logging enabled on

break *0x{raw_store_addr:x}
commands
  silent
  if $x1 != 0 && ($w2 == 99 || $w2 == 67)
    if *((unsigned char *)$x1) == 0x78 && *((unsigned char *)($x1 + 1)) == 0x27
      x/s $x1
    end
  end
  continue
end

continue
"""


def _capture_gdb_key_candidates(
    pid: int,
    timeout_seconds: float = GDB_CAPTURE_TIMEOUT_SECONDS,
) -> list[tuple[str, str | None]]:
    if not shutil.which("gdb"):
        logger.warning("gdb not installed; skipping launcher payload capture")
        return []

    base = _resolve_wechat_base(pid)
    executable_path = _resolve_wechat_executable(pid)
    if base is None or executable_path is None:
        return []

    with tempfile.TemporaryDirectory(prefix="wechat-key-capture-") as tmpdir:
        tmpdir_path = Path(tmpdir)
        log_path = tmpdir_path / "capture.log"
        gdb_log_path = tmpdir_path / "gdb.log"
        script_path = tmpdir_path / "capture.gdb"
        script_path.write_text(
            _render_gdb_capture_script(
                executable_path,
                pid,
                log_path,
                base + WECHAT_RAW_STORE_OFFSET,
            )
        )

        with gdb_log_path.open("wb") as gdb_log:
            proc = subprocess.Popen(
                [
                    "gdb",
                    "-q",
                    "-iex",
                    "set debuginfod enabled off",
                    "-x",
                    str(script_path),
                ],
                stdout=gdb_log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        try:
            deadline = time.monotonic() + timeout_seconds
            first_hit_at: float | None = None
            last_candidate_count = 0
            while time.monotonic() < deadline:
                data = log_path.read_bytes() if log_path.exists() else b""
                candidates = _extract_key_candidates(data)
                candidate_count = len(candidates)
                if candidate_count:
                    if first_hit_at is None or candidate_count > last_candidate_count:
                        first_hit_at = time.monotonic()
                        last_candidate_count = candidate_count
                    elif time.monotonic() - first_hit_at >= GDB_CAPTURE_SETTLE_SECONDS:
                        return candidates
                if proc.poll() is not None:
                    break
                time.sleep(GDB_CAPTURE_POLL_SECONDS)

            data = log_path.read_bytes() if log_path.exists() else b""
            return _extract_key_candidates(data)
        finally:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                proc.wait(timeout=2)


def _scan_memory_for_keys(pid: int, db_paths: list[Path], pattern: str) -> dict[str, str]:
    regions = _read_memory_regions(pid)
    if not regions:
        return {}

    db_salts = _build_db_salts(db_paths)
    if not db_salts:
        return {}

    validated: dict[str, str] = {}
    mem_path = Path(f"/proc/{pid}/mem")
    candidate_pattern = re.compile(pattern.encode("ascii"))

    try:
        mem_fd = open(mem_path, "rb")  # noqa: SIM115
    except PermissionError:
        logger.error("Cannot open /proc/%d/mem. Ensure CAP_SYS_PTRACE or ptrace_scope=0", pid)
        return {}

    candidates: list[tuple[str, str | None]] = []
    for start, end, _perms in regions:
        try:
            mem_fd.seek(start)
            expected_size = end - start
            chunk = mem_fd.read(expected_size)
            if len(chunk) < SQLCIPHER_KEY_SIZE:
                continue
        except (OSError, OverflowError):
            continue

        scan_chunk = 1024 * 1024
        for offset in range(0, len(chunk), scan_chunk):
            sub = chunk[offset : offset + scan_chunk + 256]
            for match in candidate_pattern.finditer(sub):
                matched_bytes = match.group(0)
                candidates.extend(_extract_key_candidates(matched_bytes))
            validated = _validate_key_candidates(candidates, db_salts)
            if len(validated) == len(db_salts):
                break
        if len(validated) == len(db_salts):
            break

    mem_fd.close()
    return validated


def _find_db_files(wechat_db_dir: Path) -> list[Path]:
    db_files: list[Path] = []
    if not wechat_db_dir.exists():
        return db_files

    for glob_pattern in ("*.db", "**/*.db"):
        for db_file in wechat_db_dir.glob(glob_pattern):
            if db_file.suffix in (".db-wal", ".db-shm"):
                continue
            try:
                with open(db_file, "rb") as f:
                    header = f.read(16)
                    if not header.startswith(b"SQLite format"):
                        db_files.append(db_file)
            except (PermissionError, FileNotFoundError):
                continue

    unique = sorted({db.resolve() if db.exists() else db for db in db_files}, key=str)
    return list(unique)


class KeyExtractor:
    def __init__(
        self,
        wechat_db_dir: Path | None = None,
        cache_path: Path | None = None,
        pattern: str = DEFAULT_PATTERN,
    ) -> None:
        self.wechat_db_dir = wechat_db_dir or default_wechat_db_dir()
        self.cache_path = cache_path or default_cache_path()
        self.pattern = pattern
        self._keys: dict[str, str] = {}
        self._pid: int | None = None

    def load_cached_keys(self) -> dict[str, str]:
        if self.cache_path.exists():
            try:
                data = json.loads(self.cache_path.read_text())
                self._keys = data.get("keys", {})
                self._pid = data.get("pid")
            except (json.JSONDecodeError, KeyError):
                self._keys = {}
                self._pid = None
        return self._keys

    def _save_keys(self, pid: int) -> None:
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        self.cache_path.write_text(json.dumps({"pid": pid, "keys": self._keys}, indent=2))
        os.chmod(self.cache_path, 0o600)

    def extract_keys(self) -> dict[str, str]:
        return self.probe_keys().keys

    def probe_keys(self) -> KeyExtractionReport:
        if not self._keys and self.cache_path.exists():
            self.load_cached_keys()

        pid = find_wechat_pid()
        if pid is None:
            if self._keys:
                return KeyExtractionReport(
                    pid=None,
                    db_files_found=len(self._keys),
                    keys=self._keys,
                    failure_reason="wechat_not_running",
                    used_cached_keys=True,
                )
            return KeyExtractionReport(
                pid=None,
                db_files_found=0,
                keys={},
                failure_reason="wechat_not_running",
            )

        if pid == self._pid and self._keys:
            return KeyExtractionReport(
                pid=pid,
                db_files_found=len(self._keys),
                keys=self._keys,
                used_cached_keys=True,
            )

        db_files = _find_db_files(self.wechat_db_dir)
        if not db_files:
            return KeyExtractionReport(
                pid=pid,
                db_files_found=0,
                keys={},
                failure_reason="no_database_files",
            )

        if self._keys:
            cached_keys = _validate_cached_keys(self._keys, db_files)
            if cached_keys:
                self._keys = cached_keys
                self._pid = pid
                self._save_keys(pid)
                return KeyExtractionReport(
                    pid=pid,
                    db_files_found=len(db_files),
                    keys=self._keys,
                    used_cached_keys=True,
                )

        keys: dict[str, str] = {}
        for attempt in range(1, EXTRACTION_ATTEMPTS + 1):
            keys = _scan_memory_for_keys(pid, db_files, self.pattern)
            if keys:
                break
            if attempt < EXTRACTION_ATTEMPTS:
                time.sleep(EXTRACTION_INTERVAL_SECONDS)

        if not keys:
            db_salts = _build_db_salts(db_files)
            gdb_candidates = _capture_gdb_key_candidates(pid)
            keys = _validate_key_candidates(gdb_candidates, db_salts)

        if keys:
            self._keys = keys
            self._pid = pid
            self._save_keys(pid)
            return KeyExtractionReport(pid=pid, db_files_found=len(db_files), keys=self._keys)

        return KeyExtractionReport(
            pid=pid,
            db_files_found=len(db_files),
            keys={},
            failure_reason="no_valid_keys",
        )

    def get_key_for_db(self, db_path: Path) -> str | None:
        return self._keys.get(str(db_path))
