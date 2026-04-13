import hashlib
import hmac
from importlib.metadata import version
import json
import struct
from pathlib import Path
from unittest.mock import patch

from wechat_key_extractor.linux import (
    KeyExtractionReport,
    KeyExtractor,
    _extract_key_candidates,
    _render_gdb_capture_script,
    _scan_memory_for_keys,
    _should_scan_region,
    _validate_cached_keys,
    _validate_key_candidates,
    _verify_page_hmac,
)


def test_package_version_is_explicit() -> None:
    assert version("wechat-key-extractor") == "0.1.1"


def _build_encrypted_page(raw_key: bytes, salt: bytes) -> bytes:
    page = bytearray(4096)
    page[:16] = salt
    for i in range(16, 4096 - 80):
        page[i] = (i * 7) % 256
    mac_salt = bytes(b ^ 0x3A for b in salt)
    mac_key = hashlib.pbkdf2_hmac("sha512", raw_key, mac_salt, 2, dklen=32)
    hm = hmac.new(mac_key, page[16 : 4096 - 80 + 16], hashlib.sha512)
    hm.update(struct.pack("<I", 1))
    page[4096 - 64 : 4096] = hm.digest()
    return bytes(page)


def test_verify_page_hmac_matches_wcdb_layout(tmp_path: Path) -> None:
    raw_key = bytes.fromhex("00" * 31 + "01")
    salt = bytes(range(16))
    db_path = tmp_path / "sample.db"
    db_path.write_bytes(_build_encrypted_page(raw_key, salt))
    assert _verify_page_hmac(db_path, raw_key) is True


def test_extract_key_candidates_from_xkey_payload() -> None:
    data = (
        b"noise "
        b"x'fd25cc8a040bb79255240e4d7f1031dcd02dfb4e808ca64a5a6c6466a8bd506d64e67b3cf3cf51e45638136d0b5c1dfd'"
        b" tail"
    )
    assert _extract_key_candidates(data) == [
        (
            "fd25cc8a040bb79255240e4d7f1031dcd02dfb4e808ca64a5a6c6466a8bd506d",
            "64e67b3cf3cf51e45638136d0b5c1dfd",
        )
    ]


def test_should_scan_region_keeps_wechat_and_anon_memory_only() -> None:
    assert _should_scan_region("r--p", "/opt/wechat/wechat", 4096) is True
    assert _should_scan_region("rw-p", "[anonymous]", 4096) is True
    assert _should_scan_region("rw-p", "[anon:partition_alloc]", 4096) is True
    assert _should_scan_region("rw-p", "[heap]", 4096) is True
    assert _should_scan_region("r--p", "/usr/lib/aarch64-linux-gnu/libc.so.6", 4096) is False
    assert _should_scan_region("---p", "[anonymous]", 4096) is False


def test_validate_key_candidates_uses_inline_salt_to_match_db(tmp_path: Path) -> None:
    raw_key = bytes.fromhex("ab" * 32)
    salt = bytes(range(16))
    db_path = tmp_path / "sample.db"
    db_path.write_bytes(_build_encrypted_page(raw_key, salt))
    keys = _validate_key_candidates([("ab" * 32, salt.hex())], {str(db_path): salt})
    assert keys == {str(db_path): "ab" * 32}


def test_validate_cached_keys_keeps_only_matching_databases(tmp_path: Path) -> None:
    valid_key = bytes.fromhex("ab" * 32)
    salt = bytes(range(16))
    valid_db = tmp_path / "valid.db"
    valid_db.write_bytes(_build_encrypted_page(valid_key, salt))
    invalid_db = tmp_path / "invalid.db"
    invalid_db.write_bytes(_build_encrypted_page(bytes.fromhex("cd" * 32), bytes(range(16, 32))))
    keys = _validate_cached_keys(
        {
            str(valid_db): "ab" * 32,
            str(invalid_db): "ab" * 32,
            str(tmp_path / "missing.db"): "ab" * 32,
        },
        [valid_db, invalid_db],
    )
    assert keys == {str(valid_db): "ab" * 32}


def test_render_gdb_capture_script_targets_raw_store_and_logging(tmp_path: Path) -> None:
    log_path = tmp_path / "capture.log"
    executable_path = tmp_path / "wechat"
    script = _render_gdb_capture_script(executable_path, 42, log_path, 0x123456)
    assert f"file {executable_path}" in script
    assert "attach 42" in script
    assert str(log_path) in script
    assert "break *0x123456" in script
    assert "x/s $x1" in script


@patch("wechat_key_extractor.linux.find_wechat_pid")
def test_probe_keys_reports_missing_process(mock_pid, tmp_path: Path) -> None:
    mock_pid.return_value = None
    ke = KeyExtractor(tmp_path, tmp_path / "keys.json")
    report = ke.probe_keys()
    assert isinstance(report, KeyExtractionReport)
    assert report.keys == {}
    assert report.failure_reason == "wechat_not_running"


@patch("wechat_key_extractor.linux._find_db_files")
@patch("wechat_key_extractor.linux._scan_memory_for_keys")
@patch("wechat_key_extractor.linux.time.sleep")
@patch("wechat_key_extractor.linux.find_wechat_pid")
def test_extract_retries_until_keys_found(mock_pid, mock_sleep, mock_scan, mock_find_db_files, tmp_path: Path) -> None:
    db_path = tmp_path / "message_0.db"
    db_path.write_bytes(b"x")
    mock_pid.return_value = 4242
    mock_find_db_files.return_value = [db_path]
    mock_scan.side_effect = [{}, {str(db_path): "ab" * 32}]
    ke = KeyExtractor(tmp_path, tmp_path / "keys.json")
    keys = ke.extract_keys()
    assert keys == {str(db_path): "ab" * 32}
    assert mock_scan.call_count == 2
    assert mock_sleep.call_count == 1


@patch("wechat_key_extractor.linux._validate_key_candidates")
@patch("wechat_key_extractor.linux._capture_gdb_key_candidates")
@patch("wechat_key_extractor.linux._find_db_files")
@patch("wechat_key_extractor.linux._scan_memory_for_keys")
@patch("wechat_key_extractor.linux.time.sleep")
@patch("wechat_key_extractor.linux.find_wechat_pid")
def test_extract_falls_back_to_gdb_capture(
    mock_pid,
    mock_sleep,
    mock_scan,
    mock_find_db_files,
    mock_capture,
    mock_validate,
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "message_0.db"
    db_path.write_bytes(_build_encrypted_page(bytes.fromhex("ab" * 32), bytes(range(16))))
    mock_pid.return_value = 4242
    mock_find_db_files.return_value = [db_path]
    mock_scan.return_value = {}
    mock_capture.return_value = [("ab" * 32, bytes(range(16)).hex())]
    mock_validate.return_value = {str(db_path): "ab" * 32}
    ke = KeyExtractor(tmp_path, tmp_path / "keys.json")
    keys = ke.extract_keys()
    assert keys == {str(db_path): "ab" * 32}
    assert mock_capture.call_count == 1
    assert mock_validate.call_count == 1


@patch("wechat_key_extractor.linux._find_db_files")
@patch("wechat_key_extractor.linux.find_wechat_pid")
def test_probe_keys_reuses_valid_cache_across_pid_change(mock_pid, mock_find_db_files, tmp_path: Path) -> None:
    raw_key = bytes.fromhex("ab" * 32)
    salt = bytes(range(16))
    db_path = tmp_path / "message_0.db"
    db_path.write_bytes(_build_encrypted_page(raw_key, salt))
    mock_pid.return_value = 4242
    mock_find_db_files.return_value = [db_path]

    ke = KeyExtractor(tmp_path, tmp_path / "keys.json")
    ke._pid = 1111
    ke._keys = {str(db_path): "ab" * 32}

    with patch.object(ke, "_save_keys") as mock_save_keys:
        report = ke.probe_keys()

    assert report.used_cached_keys is True
    assert report.keys == {str(db_path): "ab" * 32}
    assert ke._pid == 4242
    mock_save_keys.assert_called_once_with(4242)


def test_scan_memory_for_keys_validates_xkey_payload(tmp_path: Path) -> None:
    raw_key_hex = "fd25cc8a040bb79255240e4d7f1031dcd02dfb4e808ca64a5a6c6466a8bd506d"
    salt_hex = "64e67b3cf3cf51e45638136d0b5c1dfd"
    db_dir = tmp_path / "db_storage"
    db_dir.mkdir()
    db_path = db_dir / "message_0.db"
    db_path.write_bytes(_build_encrypted_page(bytes.fromhex(raw_key_hex), bytes.fromhex(salt_hex)))

    mem_blob = b"prefix " + f"x'{raw_key_hex}{salt_hex}'".encode("ascii") + b" suffix"
    mem_path = Path("/proc/4242/mem")
    real_open = open

    def fake_open(path, mode="r", *args, **kwargs):
        if Path(path) == mem_path:
            return real_open(mem_file, mode, *args, **kwargs)
        return real_open(path, mode, *args, **kwargs)

    mem_file = tmp_path / "mem.bin"
    mem_file.write_bytes(mem_blob)

    with patch(
        "wechat_key_extractor.linux._read_memory_regions",
        return_value=[(0, len(mem_blob), "r--p")],
    ), patch("builtins.open", side_effect=fake_open):
        keys = _scan_memory_for_keys(4242, [db_path], r"x'([0-9a-fA-F]{64,192})'")

    assert keys == {str(db_path): raw_key_hex}
