#!/usr/bin/env python3
"""Recover TV Time watch history from a local iPhone/iPad backup.

TV Time's servers are gone, but the app kept a local cache of its last server
responses (Documents/DioCache.db, plus NSKeyedArchiver files in older app
versions). This tool finds that cache in a Finder / Apple Devices / iTunes
backup (encrypted or not), decrypts it, and turns it into a browsable page,
CSV files, a JSON library and a Simkl import file.

Standard library only (Python 3.9+). AES comes from macOS CommonCrypto, from
the OpenSSL library that ships with Python, or from a pure-Python fallback.
The backup is only read, never modified. The only network request goes to the
public TVmaze API (TVDB show IDs only) to fill in episode numbers for the Simkl
file; --offline turns it off.

    python3 tvtime_recover.py                     # find the backup automatically
    python3 tvtime_recover.py --backup PATH       # a specific backup folder
    python3 tvtime_recover.py --diocache PATH     # an already extracted DioCache.db
"""
from __future__ import annotations

import argparse
import collections
import csv
import ctypes
import ctypes.util
import getpass
import glob
import gzip
import hashlib
import json
import os
import plistlib
import re
import sqlite3
import struct
import sys
import tempfile
import time
import urllib.error
import urllib.request
import webbrowser
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path

__version__ = "1.1.0"

BUNDLE_ID = "com.tozelabs.tvshowtime"
DOMAIN_PATTERN = "%tozelabs%"
PRIMARY_DOMAIN = f"AppDomain-{BUNDLE_ID}"

# TV Time series status -> Simkl list name (https://simkl.com/apps/import/csv/)
SIMKL_STATUS = {
    "continuing": "watching",
    "up_to_date": "completed",
    "stopped": "dropped",
    "not_started_yet": "plan to watch",
}
TVMAZE_API = "https://api.tvmaze.com"


class RecoveryError(Exception):
    """A problem the user can act on; printed without a traceback."""


# --------------------------------------------------------------------------
# AES backends
# --------------------------------------------------------------------------
def _rotl8(x: int, shift: int) -> int:
    return ((x << shift) | (x >> (8 - shift))) & 0xFF


def _gf_mul(a: int, b: int) -> int:
    result = 0
    while b:
        if b & 1:
            result ^= a
        a = ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else a << 1
        b >>= 1
    return result


def _aes_tables():
    sbox = [0] * 256
    p = q = 1
    while True:
        p = (p ^ (p << 1) ^ (0x1B if p & 0x80 else 0)) & 0xFF
        q = (q ^ (q << 1)) & 0xFF
        q = (q ^ (q << 2)) & 0xFF
        q = (q ^ (q << 4)) & 0xFF
        if q & 0x80:
            q ^= 0x09
        sbox[p] = q ^ _rotl8(q, 1) ^ _rotl8(q, 2) ^ _rotl8(q, 3) ^ _rotl8(q, 4) ^ 0x63
        if p == 1:
            break
    sbox[0] = 0x63
    inv = [0] * 256
    for i, s in enumerate(sbox):
        inv[s] = i

    def ror8(table):
        return [((t >> 8) | (t << 24)) & 0xFFFFFFFF for t in table]

    te0 = [(_gf_mul(s, 2) << 24) | (s << 16) | (s << 8) | _gf_mul(s, 3) for s in sbox]
    td0 = [(_gf_mul(s, 14) << 24) | (_gf_mul(s, 9) << 16) | (_gf_mul(s, 13) << 8) | _gf_mul(s, 11)
           for s in inv]
    te1, td1 = ror8(te0), ror8(td0)
    te2, td2 = ror8(te1), ror8(td1)
    te3, td3 = ror8(te2), ror8(td2)
    return sbox, inv, (te0, te1, te2, te3), (td0, td1, td2, td3)


class PurePythonAES:
    """Table-driven AES in plain Python. Slow (~1 MB/s) but works everywhere."""

    name = "pure-python"

    def __init__(self):
        self.sbox, self.inv, self.te, self.td = _aes_tables()
        self._keys: dict[bytes, tuple[list[int], list[int]]] = {}

    def _schedule(self, key: bytes) -> tuple[list[int], list[int]]:
        cached = self._keys.get(key)
        if cached:
            return cached
        if len(key) not in (16, 24, 32):
            raise ValueError("AES key must be 16, 24 or 32 bytes")
        nk, sb = len(key) // 4, self.sbox
        rounds = nk + 6
        w = list(struct.unpack(f">{nk}I", key))
        rcon = 1
        for i in range(nk, 4 * (rounds + 1)):
            t = w[i - 1]
            if i % nk == 0:
                t = ((t << 8) | (t >> 24)) & 0xFFFFFFFF
                t = (sb[t >> 24] << 24 | sb[(t >> 16) & 255] << 16 | sb[(t >> 8) & 255] << 8
                     | sb[t & 255]) ^ (rcon << 24)
                rcon = _gf_mul(rcon, 2)
            elif nk > 6 and i % nk == 4:
                t = sb[t >> 24] << 24 | sb[(t >> 16) & 255] << 16 | sb[(t >> 8) & 255] << 8 | sb[t & 255]
            w.append(w[i - nk] ^ t)
        td0, td1, td2, td3 = self.td
        dec: list[int] = []
        for r in range(rounds, -1, -1):
            words = w[4 * r: 4 * r + 4]
            if 0 < r < rounds:
                words = [td0[sb[x >> 24]] ^ td1[sb[(x >> 16) & 255]] ^ td2[sb[(x >> 8) & 255]]
                         ^ td3[sb[x & 255]] for x in words]
            dec.extend(words)
        self._keys[key] = (w, dec)
        return w, dec

    def _decrypt_words(self, dk, rounds, s0, s1, s2, s3):
        td0, td1, td2, td3 = self.td
        si = self.inv
        s0 ^= dk[0]
        s1 ^= dk[1]
        s2 ^= dk[2]
        s3 ^= dk[3]
        k = 4
        for _ in range(rounds - 1):
            t0 = td0[s0 >> 24] ^ td1[(s3 >> 16) & 255] ^ td2[(s2 >> 8) & 255] ^ td3[s1 & 255] ^ dk[k]
            t1 = td0[s1 >> 24] ^ td1[(s0 >> 16) & 255] ^ td2[(s3 >> 8) & 255] ^ td3[s2 & 255] ^ dk[k + 1]
            t2 = td0[s2 >> 24] ^ td1[(s1 >> 16) & 255] ^ td2[(s0 >> 8) & 255] ^ td3[s3 & 255] ^ dk[k + 2]
            t3 = td0[s3 >> 24] ^ td1[(s2 >> 16) & 255] ^ td2[(s1 >> 8) & 255] ^ td3[s0 & 255] ^ dk[k + 3]
            s0, s1, s2, s3 = t0, t1, t2, t3
            k += 4
        return (
            (si[s0 >> 24] << 24 | si[(s3 >> 16) & 255] << 16 | si[(s2 >> 8) & 255] << 8 | si[s1 & 255]) ^ dk[k],
            (si[s1 >> 24] << 24 | si[(s0 >> 16) & 255] << 16 | si[(s3 >> 8) & 255] << 8 | si[s2 & 255]) ^ dk[k + 1],
            (si[s2 >> 24] << 24 | si[(s1 >> 16) & 255] << 16 | si[(s0 >> 8) & 255] << 8 | si[s3 & 255]) ^ dk[k + 2],
            (si[s3 >> 24] << 24 | si[(s2 >> 16) & 255] << 16 | si[(s1 >> 8) & 255] << 8 | si[s0 & 255]) ^ dk[k + 3],
        )

    def _encrypt_words(self, ek, rounds, s0, s1, s2, s3):
        te0, te1, te2, te3 = self.te
        sb = self.sbox
        s0 ^= ek[0]
        s1 ^= ek[1]
        s2 ^= ek[2]
        s3 ^= ek[3]
        k = 4
        for _ in range(rounds - 1):
            t0 = te0[s0 >> 24] ^ te1[(s1 >> 16) & 255] ^ te2[(s2 >> 8) & 255] ^ te3[s3 & 255] ^ ek[k]
            t1 = te0[s1 >> 24] ^ te1[(s2 >> 16) & 255] ^ te2[(s3 >> 8) & 255] ^ te3[s0 & 255] ^ ek[k + 1]
            t2 = te0[s2 >> 24] ^ te1[(s3 >> 16) & 255] ^ te2[(s0 >> 8) & 255] ^ te3[s1 & 255] ^ ek[k + 2]
            t3 = te0[s3 >> 24] ^ te1[(s0 >> 16) & 255] ^ te2[(s1 >> 8) & 255] ^ te3[s2 & 255] ^ ek[k + 3]
            s0, s1, s2, s3 = t0, t1, t2, t3
            k += 4
        return (
            (sb[s0 >> 24] << 24 | sb[(s1 >> 16) & 255] << 16 | sb[(s2 >> 8) & 255] << 8 | sb[s3 & 255]) ^ ek[k],
            (sb[s1 >> 24] << 24 | sb[(s2 >> 16) & 255] << 16 | sb[(s3 >> 8) & 255] << 8 | sb[s0 & 255]) ^ ek[k + 1],
            (sb[s2 >> 24] << 24 | sb[(s3 >> 16) & 255] << 16 | sb[(s0 >> 8) & 255] << 8 | sb[s1 & 255]) ^ ek[k + 2],
            (sb[s3 >> 24] << 24 | sb[(s0 >> 16) & 255] << 16 | sb[(s1 >> 8) & 255] << 8 | sb[s2 & 255]) ^ ek[k + 3],
        )

    def cbc_decrypt(self, key: bytes, data: bytes, iv: bytes = bytes(16)) -> bytes:
        _check_blocks(data)
        _, dk = self._schedule(key)
        rounds = len(dk) // 4 - 1
        out = bytearray(len(data))
        prev = struct.unpack(">4I", iv)
        offset = 0
        for block in struct.iter_unpack(">4I", data):
            p = self._decrypt_words(dk, rounds, *block)
            struct.pack_into(">4I", out, offset, p[0] ^ prev[0], p[1] ^ prev[1], p[2] ^ prev[2], p[3] ^ prev[3])
            prev = block
            offset += 16
        return bytes(out)

    def ecb_decrypt(self, key: bytes, data: bytes) -> bytes:
        _check_blocks(data)
        _, dk = self._schedule(key)
        rounds = len(dk) // 4 - 1
        return b"".join(struct.pack(">4I", *self._decrypt_words(dk, rounds, *block))
                        for block in struct.iter_unpack(">4I", data))

    def cbc_encrypt(self, key: bytes, data: bytes, iv: bytes = bytes(16)) -> bytes:
        _check_blocks(data)
        ek, _ = self._schedule(key)
        rounds = len(ek) // 4 - 1
        out = bytearray(len(data))
        prev = struct.unpack(">4I", iv)
        offset = 0
        for b in struct.iter_unpack(">4I", data):
            prev = self._encrypt_words(ek, rounds, b[0] ^ prev[0], b[1] ^ prev[1], b[2] ^ prev[2], b[3] ^ prev[3])
            struct.pack_into(">4I", out, offset, *prev)
            offset += 16
        return bytes(out)

    def ecb_encrypt(self, key: bytes, data: bytes) -> bytes:
        _check_blocks(data)
        ek, _ = self._schedule(key)
        rounds = len(ek) // 4 - 1
        return b"".join(struct.pack(">4I", *self._encrypt_words(ek, rounds, *block))
                        for block in struct.iter_unpack(">4I", data))


def _check_blocks(data: bytes) -> None:
    if len(data) % 16:
        raise ValueError("AES input must be a multiple of 16 bytes")


class CommonCryptoAES:
    """macOS system AES (libcommonCrypto)."""

    name = "commoncrypto"

    def __init__(self):
        lib = ctypes.CDLL("/usr/lib/system/libcommonCrypto.dylib")
        lib.CCCrypt.argtypes = [
            ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_char_p, ctypes.c_size_t,
            ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_size_t),
        ]
        lib.CCCrypt.restype = ctypes.c_int32
        self._lib = lib

    def _crypt(self, operation: int, ecb: bool, key: bytes, data: bytes, iv: bytes | None) -> bytes:
        _check_blocks(data)
        out = ctypes.create_string_buffer(max(len(data), 1))
        moved = ctypes.c_size_t(0)
        status = self._lib.CCCrypt(operation, 0, 2 if ecb else 0, key, len(key), iv, data, len(data),
                                   out, len(data), ctypes.byref(moved))
        if status != 0:
            raise RuntimeError(f"CommonCrypto error {status}")
        return out.raw[: moved.value]

    def cbc_decrypt(self, key, data, iv=bytes(16)):
        return self._crypt(1, False, key, data, iv)

    def ecb_decrypt(self, key, data):
        return self._crypt(1, True, key, data, None)


class OpenSSLAES:
    """AES from an OpenSSL libcrypto (the copy bundled with Python on Windows, the system one on Linux)."""

    name = "openssl"
    _CHUNK = 16 * 1024 * 1024

    def __init__(self, path: str):
        lib = ctypes.CDLL(path)
        lib.EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
        lib.EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]
        for bits in (128, 192, 256):
            for mode in ("cbc", "ecb"):
                getattr(lib, f"EVP_aes_{bits}_{mode}").restype = ctypes.c_void_p
        lib.EVP_DecryptInit_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                           ctypes.c_char_p, ctypes.c_char_p]
        lib.EVP_CIPHER_CTX_set_padding.argtypes = [ctypes.c_void_p, ctypes.c_int]
        lib.EVP_DecryptUpdate.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int),
                                          ctypes.c_char_p, ctypes.c_int]
        lib.EVP_DecryptFinal_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]
        self._lib = lib
        self.path = path

    def _decrypt(self, mode: str, key: bytes, data: bytes, iv: bytes | None) -> bytes:
        _check_blocks(data)
        lib = self._lib
        cipher = getattr(lib, f"EVP_aes_{len(key) * 8}_{mode}")()
        ctx = lib.EVP_CIPHER_CTX_new()
        if not ctx:
            raise RuntimeError("OpenSSL could not allocate a cipher context")
        try:
            if lib.EVP_DecryptInit_ex(ctx, cipher, None, key, iv) != 1:
                raise RuntimeError("OpenSSL decrypt init failed")
            lib.EVP_CIPHER_CTX_set_padding(ctx, 0)
            out = ctypes.create_string_buffer(len(data) + 32)
            base = ctypes.addressof(out)
            total, written = 0, ctypes.c_int(0)
            for start in range(0, len(data), self._CHUNK):
                chunk = data[start: start + self._CHUNK]
                if lib.EVP_DecryptUpdate(ctx, ctypes.c_void_p(base + total), ctypes.byref(written),
                                         chunk, len(chunk)) != 1:
                    raise RuntimeError("OpenSSL decrypt failed")
                total += written.value
            if lib.EVP_DecryptFinal_ex(ctx, ctypes.c_void_p(base + total), ctypes.byref(written)) != 1:
                raise RuntimeError("OpenSSL decrypt final failed")
            return out.raw[: total + written.value]
        finally:
            lib.EVP_CIPHER_CTX_free(ctx)

    def cbc_decrypt(self, key, data, iv=bytes(16)):
        return self._decrypt("cbc", key, data, iv)

    def ecb_decrypt(self, key, data):
        return self._decrypt("ecb", key, data, None)


def _libcrypto_candidates() -> list[str]:
    paths = []
    if os.environ.get("TVTIME_LIBCRYPTO"):
        paths.append(os.environ["TVTIME_LIBCRYPTO"])
    if sys.platform == "darwin":
        return paths  # never load the unversioned system libcrypto on macOS: it aborts the process
    if os.name == "nt":
        bases = {sys.base_prefix, sys.prefix, os.path.dirname(sys.executable)}
        for base in sorted(bases):
            for sub in ("DLLs", os.path.join("Library", "bin"), ""):
                paths.extend(sorted(glob.glob(os.path.join(base, sub, "libcrypto*.dll")), reverse=True))
    found = ctypes.util.find_library("crypto")
    if found:
        paths.append(found)
    return paths


def _self_test(backend) -> bool:
    key = bytes.fromhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
    iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    ciphertext = bytes.fromhex("f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d")
    plaintext = bytes.fromhex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51")
    block = bytes.fromhex("8ea2b7ca516745bfeafc49904b496089")
    return (backend.cbc_decrypt(key, ciphertext, iv) == plaintext
            and backend.ecb_decrypt(bytes(range(32)), block) == bytes.fromhex("00112233445566778899aabbccddeeff"))


_BACKEND = None


def aes_backend():
    """Fastest working AES implementation; each candidate must pass a known-answer test."""
    global _BACKEND
    if _BACKEND is not None:
        return _BACKEND
    forced = os.environ.get("TVTIME_AES_BACKEND", "")
    makers = []
    if sys.platform == "darwin":
        makers.append(("commoncrypto", CommonCryptoAES))
    makers.extend(("openssl", lambda p=path: OpenSSLAES(p)) for path in _libcrypto_candidates())
    makers.append(("pure-python", PurePythonAES))
    for name, make in makers:
        if forced and name != forced:
            continue
        try:
            backend = make()
            if _self_test(backend):
                _BACKEND = backend
                return backend
        except (OSError, AttributeError, RuntimeError, ValueError):
            continue
    raise RecoveryError(f"No working AES implementation found (TVTIME_AES_BACKEND={forced!r}).")


# --------------------------------------------------------------------------
# iOS backup encryption
# --------------------------------------------------------------------------
def aes_unwrap(kek: bytes, wrapped: bytes) -> bytes:
    """RFC 3394 AES key unwrap."""
    if len(wrapped) % 8 or len(wrapped) < 24:
        raise ValueError("wrapped key has an invalid length")
    backend = aes_backend()
    n = len(wrapped) // 8 - 1
    a = wrapped[:8]
    r = [wrapped[8 * (i + 1): 8 * (i + 2)] for i in range(n)]
    for j in range(5, -1, -1):
        for i in range(n, 0, -1):
            t = (n * j + i).to_bytes(8, "big")
            b = backend.ecb_decrypt(kek, bytes(x ^ y for x, y in zip(a, t)) + r[i - 1])
            a, r[i - 1] = b[:8], b[8:]
    if a != b"\xa6" * 8:
        raise ValueError("key unwrap integrity check failed")
    return b"".join(r)


_CLASS_KEY_TAGS = {b"CLAS", b"WRAP", b"WPKY", b"KTYP", b"PBKY"}


def parse_keybag(blob: bytes) -> tuple[dict, dict]:
    attrs: dict = {}
    classes: dict = {}
    current = None
    pos = 0
    while pos + 8 <= len(blob):
        tag = blob[pos: pos + 4]
        length = struct.unpack(">I", blob[pos + 4: pos + 8])[0]
        value = blob[pos + 8: pos + 8 + length]
        pos += 8 + length
        if length == 4:
            value = struct.unpack(">I", value)[0]
        if tag == b"UUID" and b"UUID" not in attrs:
            attrs[tag] = value
        elif tag == b"WRAP" and b"WRAP" not in attrs:
            attrs[tag] = value
        elif tag == b"UUID":
            if current is not None:
                classes[current[b"CLAS"]] = current
            current = {b"UUID": value}
        elif tag in _CLASS_KEY_TAGS and current is not None:
            current[tag] = value
        else:
            attrs[tag] = value
    if current is not None:
        classes[current[b"CLAS"]] = current
    return attrs, classes


def unlock_keybag(keybag: bytes, password: bytes) -> dict[int, bytes]:
    """Derive the backup's class keys. Raises ValueError for a wrong password."""
    attrs, classes = parse_keybag(keybag)
    secret = password
    if b"DPSL" in attrs:  # iOS 10.2+ adds a slow SHA-256 round
        secret = hashlib.pbkdf2_hmac("sha256", password, attrs[b"DPSL"], attrs[b"DPIC"], 32)
    passcode_key = hashlib.pbkdf2_hmac("sha1", secret, attrs[b"SALT"], attrs[b"ITER"], 32)
    keys = {}
    for clas, entry in classes.items():
        if b"WPKY" in entry and entry.get(b"WRAP", 0) & 2:
            keys[clas] = aes_unwrap(passcode_key, entry[b"WPKY"])
    return keys


def strip_pkcs7(data: bytes) -> bytes | None:
    pad = data[-1] if data else 0
    if 1 <= pad <= 16 and data.endswith(bytes([pad]) * pad):
        return data[:-pad]
    return None


# --------------------------------------------------------------------------
# Backups
# --------------------------------------------------------------------------
def default_backup_roots() -> list[Path]:
    home = Path.home()
    if sys.platform == "darwin":
        return [home / "Library" / "Application Support" / "MobileSync" / "Backup"]
    if os.name == "nt":
        roots = [home / "Apple" / "MobileSync" / "Backup"]
        if os.environ.get("APPDATA"):
            roots.append(Path(os.environ["APPDATA"]) / "Apple Computer" / "MobileSync" / "Backup")
        return roots
    return []


def backup_info(folder: Path) -> dict:
    def load(name):
        path = folder / name
        try:
            return plistlib.loads(path.read_bytes()) if path.is_file() else {}
        except (plistlib.InvalidFileException, ValueError):
            return {}

    info, manifest, status = load("Info.plist"), load("Manifest.plist"), load("Status.plist")
    apps = [str(a) for a in info.get("Installed Applications") or []]
    last = info.get("Last Backup Date")
    return {
        "path": folder,
        "device": "".join(ch for ch in str(info.get("Device Name", "")) if ch.isprintable()) or "?",
        "ios": str(info.get("Product Version", "")),
        "date": last.strftime("%Y-%m-%d %H:%M") if isinstance(last, datetime) else "",
        "encrypted": bool(manifest.get("IsEncrypted")),
        "finished": status.get("SnapshotState", "finished") == "finished",
        "has_tvtime": BUNDLE_ID in apps if apps else None,
    }


def find_backups() -> tuple[list[dict], list[Path]]:
    """Backups in the standard locations, plus roots we were not allowed to read."""
    found, denied = [], []
    for root in default_backup_roots():
        try:
            children = sorted(p for p in root.iterdir() if p.is_dir())
        except PermissionError:
            denied.append(root)
            continue
        except FileNotFoundError:
            continue
        for child in children:
            if (child / "Manifest.db").is_file() and (child / "Manifest.plist").is_file():
                found.append(backup_info(child))
    return found, denied


def _safe_relative(domain: str, relative: str) -> Path:
    """Backup paths are untrusted: drop '..', absolute parts and characters Windows rejects."""
    parts = []
    for part in [domain] + relative.replace("\\", "/").split("/"):
        if part in ("", ".", ".."):
            continue
        parts.append(re.sub(r'[<>:"|?*\x00-\x1f]', "_", part))
    return Path(*parts)


def extract_tvtime(backup: Path, raw_dir: Path, password_source, *, all_files: bool = False, log=print) -> list[dict]:
    """Copy (and decrypt) TV Time's files from the backup into raw_dir. Returns the file index."""
    info = backup_info(backup)
    if not (backup / "Manifest.db").is_file():
        raise RecoveryError(f"{backup} is not an iOS backup folder (no Manifest.db).")
    if not info["finished"]:
        log("  Warning: this backup is marked as unfinished; data may be missing.")
    manifest = plistlib.loads((backup / "Manifest.plist").read_bytes())
    class_keys: dict[int, bytes] = {}
    with tempfile.TemporaryDirectory(prefix="tvtime-manifest-") as tmp:
        manifest_db = backup / "Manifest.db"
        if info["encrypted"]:
            class_keys = _unlock_with_retries(manifest["BackupKeyBag"], password_source, log)
            wrapped = manifest["ManifestKey"]
            key = aes_unwrap(class_keys[struct.unpack("<I", wrapped[:4])[0]], wrapped[4:])
            log(f"  Decrypting the backup index ({manifest_db.stat().st_size / 1e6:.0f} MB, "
                f"AES: {aes_backend().name})...")
            plain = aes_backend().cbc_decrypt(key, manifest_db.read_bytes())
            if not plain.startswith(b"SQLite format 3\x00"):
                raise RecoveryError("The backup index did not decrypt correctly.")
            manifest_db = Path(tmp) / "Manifest.db"
            manifest_db.write_bytes(plain)
            del plain
        con = sqlite3.connect(f"file:{manifest_db.as_posix()}?mode=ro", uri=True)
        try:
            rows = con.execute(
                "SELECT fileID, domain, relativePath, flags, file FROM Files WHERE domain LIKE ? "
                "ORDER BY domain, relativePath", (DOMAIN_PATTERN,)).fetchall()
        finally:
            con.close()
    if not rows:
        raise RecoveryError("TV Time is not in this backup. Was the app installed when the backup was made?")

    index = []
    for file_id, domain, relative, flags, blob in rows:
        entry = {"domain": domain, "path": relative, "status": "", "bytes": ""}
        index.append(entry)
        if flags != 1:
            entry["status"] = "directory" if flags == 2 else "link"
            continue
        if not all_files and not (domain == PRIMARY_DOMAIN and relative.startswith("Documents/")):
            entry["status"] = "not copied"
            continue
        archive = plistlib.loads(blob)
        objects = archive["$objects"]
        root = objects[archive["$top"]["root"].data]
        source = backup / file_id[:2] / file_id
        if not source.is_file():
            entry["status"] = "missing in backup"
            continue
        data = source.read_bytes()
        key_ref = root.get("EncryptionKey")
        if info["encrypted"] and key_ref is not None:
            wrapped = objects[key_ref.data]
            wrapped = wrapped["NS.data"] if isinstance(wrapped, dict) else wrapped
            clas = root.get("ProtectionClass") or struct.unpack("<I", wrapped[:4])[0]
            data = aes_backend().cbc_decrypt(aes_unwrap(class_keys[clas], wrapped[4:]), data)
            # The manifest Size is stale for SQLite files (iOS backs up a fresh snapshot),
            # so the PKCS7 padding decides the real length.
            unpadded = strip_pkcs7(data)
            size = root.get("Size")
            if unpadded is not None:
                data = unpadded
            elif isinstance(size, int) and size <= len(data):
                data = data[:size]
        target = raw_dir / _safe_relative(domain, relative)
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        except OSError as exc:
            entry["status"] = f"write failed: {exc.strerror or exc}"
            continue
        entry["status"], entry["bytes"] = "copied", len(data)
    return index


def _unlock_with_retries(keybag: bytes, password_source, log) -> dict[int, bytes]:
    for attempt in range(3):
        password = password_source()
        if not password:
            raise RecoveryError("No password entered.")
        log("  Checking the password (takes a few seconds)...")
        try:
            return unlock_keybag(keybag, password.encode("utf-8"))
        except ValueError:
            log("  Wrong backup password.")
            if not getattr(password_source, "interactive", False) or attempt == 2:
                break
    raise RecoveryError("Wrong backup password. It is the password set for encrypted "
                        "local backups in Finder / Apple Devices / iTunes, not the Apple ID password.")


# --------------------------------------------------------------------------
# Reading the app cache
# --------------------------------------------------------------------------
def _decode_json(blob) -> object:
    if isinstance(blob, str):
        blob = blob.encode("utf-8")
    if not isinstance(blob, (bytes, bytearray)) or not blob:
        return None
    blob = bytes(blob)
    if blob[:2] == b"\x1f\x8b":
        try:
            blob = gzip.decompress(blob)
        except (OSError, EOFError):
            return None
    if blob.lstrip()[:1] not in (b"{", b"["):
        return None
    try:
        return json.loads(blob.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return None


def _walk(value):
    stack = [value]
    while stack:
        item = stack.pop()
        yield item
        if isinstance(item, dict):
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)


def read_payloads(files: list[Path]) -> tuple[list[dict], collections.Counter]:
    """JSON responses from DioCache databases and legacy NSKeyedArchiver cache files."""
    payloads, seen, sources = [], set(), collections.Counter()
    for path in files:
        try:
            with path.open("rb") as fh:
                head = fh.read(16)
        except OSError:
            continue
        if head.startswith(b"SQLite format 3"):
            for payload, fetched in _dio_rows(path):
                digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
                if digest not in seen:
                    seen.add(digest)
                    payloads.append({"json": payload, "url": "", "fetched": fetched})
                    sources["dio_cache"] += 1
        elif head.startswith(b"bplist00"):
            for payload, url in _archive_payloads(path):
                digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
                if digest not in seen:
                    seen.add(digest)
                    payloads.append({"json": payload, "url": url, "fetched": ""})
                    sources["legacy_archive"] += 1
    return payloads, sources


def _dio_rows(path: Path):
    con = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
    try:
        tables = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        for table in tables:
            columns = [r[1] for r in con.execute(f'PRAGMA table_info("{table}")')]
            if "content" not in columns:
                continue
            select = ", headers" if "headers" in columns else ", NULL"
            for content, headers in con.execute(f'SELECT content{select} FROM "{table}"'):
                payload = _decode_json(content)
                if payload is not None:
                    yield payload, _response_date(headers)
    except sqlite3.DatabaseError:
        return
    finally:
        con.close()


def _response_date(headers) -> str:
    parsed = _decode_json(headers)
    if not isinstance(parsed, dict):
        return ""
    value = parsed.get("date") or parsed.get("Date")
    if isinstance(value, list):
        value = value[0] if value else ""
    try:
        return parsedate_to_datetime(str(value)).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError):
        return ""


def _archive_payloads(path: Path):
    try:
        archive = plistlib.loads(path.read_bytes())
    except Exception:  # plistlib raises several unrelated types on garbage
        return
    if not (isinstance(archive, dict) and archive.get("$archiver") == "NSKeyedArchiver"):
        return
    urls, payloads = [], []
    for item in _walk(archive.get("$objects")):
        if isinstance(item, str) and item.startswith(("https://", "http://")):
            urls.append(item)
        elif isinstance(item, bytes):
            payload = _decode_json(item)
            if payload is not None:
                payloads.append(payload)
    url = urls[0] if len(urls) == 1 else ""
    for payload in payloads:
        yield payload, url


# --------------------------------------------------------------------------
# Building the library
# --------------------------------------------------------------------------
def iso_utc(value) -> str:
    """TV Time timestamps are UTC: ISO strings, 'YYYY-MM-DD HH:MM:SS' or epoch seconds."""
    if value in (None, "", 0):
        return ""
    if isinstance(value, (int, float)) or (isinstance(value, str) and value.isdigit()):
        seconds = float(value)
        if seconds > 1e11:  # milliseconds
            seconds /= 1000
        if seconds <= 0:
            return ""
        return datetime.fromtimestamp(seconds, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    text = str(value).strip().replace(" ", "T")
    if text.startswith("1970-01-01") or len(text) < 10:
        return ""
    if len(text) == 10:
        text += "T00:00:00"
    text = text.split(".")[0].rstrip("Z")
    if "+" in text[10:]:
        text = text[: 10 + text[10:].index("+")]
    return text + "Z"


def episode_code(season, number) -> str:
    try:
        return f"S{int(season):02d}E{int(number):02d}"
    except (TypeError, ValueError):
        return ""


def _int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _user_from_url(url: str):
    match = re.search(r"/user/(\d+)(?:/|$)", url or "")
    return int(match.group(1)) if match else None


def _sort_value(obj: dict, key: str):
    for item in obj.get("sorting") or []:
        if isinstance(item, dict) and item.get("id") == key:
            return item.get("value")
    return None


def _image_url(images, kind: str) -> tuple[str, str]:
    if isinstance(images, dict):
        images = [dict(v, type=k) for k, v in images.items() if isinstance(v, dict)]
    for img in images or []:
        if isinstance(img, dict) and img.get("type", kind) == kind and (img.get("url") or img.get("thumb_url")):
            versions = img.get("versions") if isinstance(img.get("versions"), dict) else {}
            full = img.get("url") or img.get("thumb_url")
            return versions.get("medium") or img.get("thumb_url") or full, full
    return "", ""


class LibraryBuilder:
    def __init__(self, payloads: list[dict]):
        self.payloads = payloads
        self.shows: dict[int, dict] = {}
        self.movies: dict[str, dict] = {}
        self.episodes: dict[tuple, dict] = {}
        self.show_hints: dict[int, dict] = {}
        self.kinds = collections.Counter()
        self.owner = self._find_owner()

    # -- ownership: a cache can also hold friends' profiles and lists -------
    def _find_owner(self):
        candidates = []
        for p in self.payloads:
            data = p["json"].get("data", p["json"]) if isinstance(p["json"], dict) else None
            if isinstance(data, dict) and _int(data.get("id")) and (
                    {"is_vip", "user_rights", "is_premium"} & data.keys()):
                candidates.append((len(data), _int(data["id"])))
        if candidates:
            return max(candidates)[1]
        users = collections.Counter(_user_from_url(p["url"]) for p in self.payloads if _user_from_url(p["url"]))
        return users.most_common(1)[0][0] if users else None

    def _foreign(self, payload: dict, data) -> bool:
        if self.owner is None:
            return False
        owners = {_user_from_url(payload["url"])}
        if isinstance(data, dict):
            owners.add(_int(data.get("user_id")))
        owners.discard(None)
        return bool(owners) and self.owner not in owners

    # -- shows -------------------------------------------------------------
    def _show(self, show_id: int, title: str = "") -> dict:
        show = self.shows.get(show_id)
        if show is None:
            show = self.shows[show_id] = {
                "tvdb_id": show_id, "title": title, "status": "", "filters": [],
                "followed_at": "", "last_watched_at": "", "country": "", "network": "",
                "favorite": False, "archived": False, "for_later": False,
                "poster": "", "poster_full": "", "seen_episodes": None, "aired_episodes": None,
                "next_episode": None, "last_seen_episode": None, "episodes": [],
            }
        if title and not show["title"]:
            show["title"] = title
        return show

    def _add_follow(self, obj: dict) -> None:
        meta = obj.get("meta") if isinstance(obj.get("meta"), dict) else {}
        show_id = _int(meta.get("id") or obj.get("id"))
        if not show_id:
            return
        show = self._show(show_id, meta.get("name") or obj.get("name") or "")
        filters = [str(f) for f in obj.get("filter") or [] if f != "all"]
        show["filters"] = sorted(set(show["filters"]) | set(filters))
        status = next((f for f in filters if f in SIMKL_STATUS), "")
        show["status"] = status or show["status"]
        show["favorite"] |= "favorite" in filters or bool(obj.get("is_favorite"))
        show["archived"] |= "archived" in filters
        show["for_later"] |= "for_later" in filters or "watch_later" in filters
        show["followed_at"] = iso_utc(_sort_value(obj, "follow_date")) or show["followed_at"] or iso_utc(obj.get("created_at"))
        show["last_watched_at"] = max(show["last_watched_at"], iso_utc(_sort_value(obj, "watch_date")))
        show["country"] = meta.get("country") or show["country"]
        self._set_poster(show, meta.get("images") or meta.get("all_images") or meta.get("posters"))
        watch = obj.get("watch_status") if isinstance(obj.get("watch_status"), dict) else {}
        self._set_counts(show, watch.get("watched_episode_count"), watch.get("aired_episode_count"))

    def _add_progress_show(self, item: dict) -> None:
        """Shows from the progress/profile endpoints: counts, flags, maybe full seasons."""
        show_id = _int(item.get("id"))
        if not show_id or not item.get("name"):
            return
        show = self._show(show_id, item["name"])
        self._set_counts(show, item.get("watched_episode_count", item.get("seen_episodes")),
                         item.get("aired_episode_count", item.get("aired_episodes")))
        filters = {f.get("id"): f.get("values") for f in item.get("filters") or [] if isinstance(f, dict)}
        progress = [str(v) for v in filters.get("progress") or []]
        status = next((v for v in progress if v in SIMKL_STATUS), "")
        if item.get("is_up_to_date") and not status:
            status = "up_to_date"
        show["status"] = show["status"] or status
        show["favorite"] |= bool(item.get("is_favorite"))
        show["archived"] |= bool(item.get("is_archived"))
        show["for_later"] |= bool(item.get("is_for_later"))
        show["last_watched_at"] = max(show["last_watched_at"], iso_utc(_sort_value(item, "last_watched")))
        show["country"] = show["country"] or item.get("country") or ""
        show["network"] = show["network"] or item.get("network") or ""
        for key in ("poster", "all_images", "images"):
            self._set_poster(show, item.get(key))
        for season in item.get("seasons") or []:
            if not isinstance(season, dict):
                continue
            for ep in season.get("episodes") or []:
                if isinstance(ep, dict) and {"seen", "is_watched", "seen_date"} & ep.keys():
                    number = season.get("number")
                    self._add_episode(ep, show_id, item["name"], number)

    def _set_counts(self, show: dict, seen, aired) -> None:
        if _int(seen) is not None:
            show["seen_episodes"] = _int(seen)
        if _int(aired) is not None:
            show["aired_episodes"] = _int(aired)

    def _set_poster(self, show: dict, images) -> None:
        if show["poster"] or not images:
            return
        if isinstance(images, dict) and "url" in images:
            images = [dict(images, type="poster")]
        if isinstance(images, dict) and isinstance(images.get("poster"), dict):
            poster = images["poster"]
            images = [dict(poster, type="poster", url=poster.get("url") or next(
                (v for v in poster.values() if isinstance(v, str) and v.startswith("http")), ""))]
        show["poster"], show["poster_full"] = _image_url(images, "poster")

    # -- episodes ----------------------------------------------------------
    def _add_episode(self, ep: dict, show_id=None, show_name="", season=None) -> None:
        show = ep.get("show") if isinstance(ep.get("show"), dict) else {}
        show_id = _int(show.get("id")) or show_id
        season = ep.get("season_number", season)
        if isinstance(ep.get("season"), dict):
            season = ep["season"].get("number", season)
        elif "season_number" not in ep and _int(ep.get("season")) is not None:
            season = ep["season"]
        number = _int(ep.get("number"))
        if not show_id or _int(season) is None or number is None:
            return
        if show:
            self.show_hints[show_id] = show
        key = (show_id, _int(season), number)
        record = self.episodes.setdefault(key, {
            "show_id": show_id, "show": show.get("name") or show_name, "season": _int(season),
            "number": number, "code": episode_code(season, number), "name": "", "air_date": "",
            "seen": False, "seen_at": "", "times_watched": 0, "in_up_next": False, "is_special": False,
        })
        record["name"] = record["name"] or ep.get("name") or ""
        record["air_date"] = record["air_date"] or str(ep.get("air_date") or "")[:10]
        record["seen"] |= ep.get("seen") is True or ep.get("is_watched") is True
        record["seen_at"] = max(record["seen_at"], iso_utc(ep.get("seen_date")))
        record["times_watched"] = max(record["times_watched"], _int(ep.get("nb_times_watched")) or 0)
        record["in_up_next"] |= "to_watch_category" in ep
        record["is_special"] |= bool(ep.get("is_special")) or record["season"] == 0

    # -- movies ------------------------------------------------------------
    def _add_movie(self, obj: dict, *, watch_event: bool, favorite: bool = False) -> None:
        meta = obj.get("meta") if isinstance(obj.get("meta"), dict) else {}
        uuid = obj.get("uuid") or meta.get("uuid") or meta.get("imdb_id") or meta.get("name")
        if not uuid:
            return
        movie = self.movies.setdefault(uuid, {
            "uuid": uuid, "title": "", "year": "", "imdb_id": "", "watched": False, "watched_at": "",
            "rewatch_count": 0, "watch_later": False, "favorite": False, "runtime_min": None,
            "genres": [], "overview": "", "poster": "", "poster_full": "",
        })
        filters = [str(f) for f in obj.get("filter") or []]
        extended = obj.get("extended") if isinstance(obj.get("extended"), dict) else {}
        movie["title"] = meta.get("name") or movie["title"]
        movie["year"] = str(meta.get("first_release_date") or "")[:4] or movie["year"]
        movie["imdb_id"] = meta.get("imdb_id") or movie["imdb_id"]
        movie["genres"] = meta.get("genres") or movie["genres"]
        movie["overview"] = meta.get("overview") or movie["overview"]
        if _int(meta.get("runtime")):
            movie["runtime_min"] = round(int(meta["runtime"]) / 60)
        movie["watched"] |= (watch_event or "watched" in filters or bool(extended.get("is_watched"))
                             or bool(iso_utc(obj.get("watched_at"))))
        movie["watch_later"] |= "watch_later" in filters or "for_later" in filters
        movie["favorite"] |= favorite or "favorite" in filters
        movie["watched_at"] = max(movie["watched_at"], iso_utc(obj.get("watched_at")))
        movie["rewatch_count"] = max(movie["rewatch_count"], _int(obj.get("rewatch_count")) or 0)
        if not movie["poster"]:
            movie["poster"], movie["poster_full"] = _image_url(meta.get("posters"), "poster")

    # -- main pass ---------------------------------------------------------
    def build(self) -> dict:
        for payload in self.payloads:
            raw = payload["json"]
            data = raw.get("data", raw) if isinstance(raw, dict) else raw
            if self._foreign(payload, data):
                self.kinds["skipped: another user's data"] += 1
                continue
            containers = [data] + ([raw] if raw is not data else [])
            for container in containers:
                if isinstance(container, dict) and isinstance(container.get("objects"), list):
                    watch = container.get("type") == "watch" or "/tracking/watches/" in payload["url"]
                    favorite = str(container.get("id", "")).startswith("favorite")
                    for obj in container["objects"]:
                        if not isinstance(obj, dict):
                            continue
                        if obj.get("entity_type") == "series":
                            self._add_follow(obj)
                            self.kinds["series list"] += 1
                        elif obj.get("entity_type") == "movie":
                            self._add_movie(obj, watch_event=watch, favorite=favorite)
                            self.kinds["movie list" if not watch else "watch events"] += 1
                if isinstance(container, dict) and isinstance(container.get("shows"), list):
                    for item in container["shows"]:
                        if isinstance(item, dict):
                            self._add_progress_show(item)
                            self.kinds["show progress"] += 1
            if isinstance(data, list):
                for item in data:
                    if not isinstance(item, dict):
                        continue
                    if isinstance(item.get("objects"), list) and str(item.get("id", "")).startswith("favorite"):
                        for obj in item["objects"]:
                            if isinstance(obj, dict) and obj.get("entity_type") == "movie":
                                self._add_movie(obj, watch_event=False, favorite=True)
                            elif isinstance(obj, dict) and obj.get("entity_type") == "series":
                                self._add_follow(dict(obj, filter=list(obj.get("filter") or []) + ["favorite"]))
                    elif "name" in item and "number" not in item and (
                            {"watched_episode_count", "aired_episode_count", "seen_episodes", "seasons"} & item.keys()):
                        self._add_progress_show(item)
                        self.kinds["show progress"] += 1
            for node in _walk(raw):
                if isinstance(node, dict) and "number" in node and isinstance(node.get("show"), dict) and (
                        "season_number" in node or "season" in node) and (
                        {"seen", "is_watched", "seen_date", "to_watch_category"} & node.keys()):
                    self._add_episode(node)
                    self.kinds["episodes"] += 1
        return self._finish()

    def _finish(self) -> dict:
        for (show_id, _, _), ep in self.episodes.items():
            if show_id in self.shows:
                self.shows[show_id]["episodes"].append(ep)
        for show_id, hint in self.show_hints.items():
            if show_id in self.shows:
                show = self.shows[show_id]
                self._set_counts(show, hint.get("seen_episodes"), hint.get("aired_episodes"))
                show["network"] = show["network"] or hint.get("network") or ""
                self._set_poster(show, hint.get("all_images"))
        for show in self.shows.values():
            eps = sorted(show["episodes"], key=lambda e: (e["season"], e["number"]))
            show["episodes"] = eps
            watched = [e for e in eps if e["seen"] and e["season"] > 0]
            upcoming = [e for e in eps if e["in_up_next"] and not e["seen"]]
            if upcoming:
                nxt = upcoming[0]
                show["next_episode"] = {k: nxt[k] for k in ("season", "number", "code", "name", "air_date")}
            if watched:
                show["last_seen_episode"] = watched[-1]["code"]
            elif upcoming and upcoming[0]["number"] > 1:
                show["last_seen_episode"] = episode_code(upcoming[0]["season"], upcoming[0]["number"] - 1)
            if not show["status"]:
                seen, aired = show["seen_episodes"], show["aired_episodes"]
                if seen == 0:
                    show["status"] = "not_started_yet"
                elif seen is not None and aired and seen >= aired:
                    show["status"] = "up_to_date"
                elif seen:
                    show["status"] = "continuing"
            for e in eps:
                e["show"] = e["show"] or show["title"]
            show["last_watched_at"] = show["last_watched_at"] or max((e["seen_at"] for e in eps), default="")

        shows = sorted(self.shows.values(), key=lambda s: (s["last_watched_at"], s["title"]), reverse=True)
        episodes = [e for e in self.episodes.values() if e["show_id"] in self.shows]
        history = sorted((e for e in episodes if e["seen"]), key=lambda e: e["seen_at"], reverse=True)
        others = sorted((e for e in episodes if not e["seen"]), key=lambda e: (e["show"].casefold(), e["season"], e["number"]))
        movies = sorted(self.movies.values(), key=lambda m: m["watched_at"], reverse=True)
        fetched = [p["fetched"] for p in self.payloads if p["fetched"]]
        statuses = collections.Counter(s["status"] or "unknown" for s in shows)
        return {
            "generator": f"tvtime_recover.py {__version__}",
            "snapshot_at": max(fetched) if fetched else "",
            "stats": {
                "series": len(shows),
                **{k: statuses.get(k, 0) for k in list(SIMKL_STATUS) + ["unknown"]},
                "series_with_counts": sum(1 for s in shows if s["seen_episodes"] is not None),
                "series_with_next_episode": sum(1 for s in shows if s["next_episode"]),
                "watched_episodes_with_dates": sum(1 for e in history if e["seen_at"]),
                "episodes": len(episodes),
                "movies": len(movies),
                "movies_watched": sum(1 for m in movies if m["watched"]),
            },
            "recognized": dict(self.kinds),
            "series": shows,
            "episodes": history + others,
            "movies": movies,
        }


def build_library(payloads: list[dict]) -> dict:
    return LibraryBuilder(payloads).build()


# --------------------------------------------------------------------------
# Outputs
# --------------------------------------------------------------------------
def _csv(path: Path, header: list[str], rows, *, bom: bool = True) -> None:
    # The BOM helps Excel read UTF-8; the Simkl file is written without it.
    with path.open("w", newline="", encoding="utf-8-sig" if bom else "utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(header)
        writer.writerows(rows)


def _simkl_date(iso: str) -> str:
    if not iso:
        return ""
    moment = datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ")
    return moment.strftime("%H:%M:%S %d-%m-%Y")


def _code_key(code: str):
    match = re.fullmatch(r"S(\d+)E(\d+)", code or "")
    return (int(match[1]), int(match[2])) if match else None


def _fetch_json(url: str):
    """GET a JSON document; None on 404. Waits and retries when rate-limited."""
    request = urllib.request.Request(url, headers={"User-Agent": f"tvtime-ios-recovery/{__version__}"})
    for attempt in range(5):
        try:
            with urllib.request.urlopen(request, timeout=20) as resp:
                return json.load(resp)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            if exc.code != 429 or attempt == 4:
                raise
            time.sleep(2 * (attempt + 1))
    return None


def _moment(iso: str) -> datetime:
    return datetime.fromisoformat(iso.replace("Z", "+00:00"))


def tvmaze_positions(lib: dict, fetch=None, log=print) -> dict[int, str]:
    """Last watched episode, looked up on TVmaze, for series whose position the cache doesn't give.

    Simkl marks episodes of a "completed" series only when the series has ended, so an ongoing one lands
    in "watching" at 0%. For those we send the last episode aired before the last watch date. For a
    series in progress whose next episode opens a new season, it's the last episode of the season before.
    """
    wanted = {}
    for s in lib["series"]:
        nxt = s["next_episode"]
        if not s["tvdb_id"]:
            continue
        if s["status"] == "up_to_date":
            wanted[s["tvdb_id"]] = ("aired_by", s["last_watched_at"] or lib["snapshot_at"])
        elif not s["last_seen_episode"] and nxt and nxt["number"] == 1 and nxt["season"] > 1:
            wanted[s["tvdb_id"]] = ("season_end", nxt["season"] - 1)
    if not wanted:
        return {}
    fetch = fetch or _fetch_json
    log(f"Looking up episode numbers for {len(wanted)} series on TVmaze (--offline to skip)...")
    found, errors = {}, 0
    for tvdb_id, (kind, arg) in wanted.items():
        try:
            show = fetch(f"{TVMAZE_API}/lookup/shows?thetvdb={tvdb_id}")
            episodes = (fetch(f"{TVMAZE_API}/shows/{show['id']}/episodes") or []) if show else []
        except (OSError, ValueError, KeyError, TypeError):
            errors += 1
            if errors >= 3 and not found:
                log("  TVmaze is not reachable; the Simkl file is written without these episode numbers.")
                return {}
            continue
        regular = [e for e in episodes if isinstance(e, dict) and _int(e.get("season")) and _int(e.get("number"))]
        if kind == "aired_by":
            cutoff = _moment(arg) if arg else None
            regular = [e for e in regular if e.get("airstamp") and (cutoff is None or _moment(e["airstamp"]) <= cutoff)]
        else:
            regular = [e for e in regular if _int(e["season"]) == arg]
        if regular:
            last = max(regular, key=lambda e: (_int(e["season"]), _int(e["number"])))
            found[tvdb_id] = episode_code(last["season"], last["number"])
    missing = len(wanted) - len(found)
    log(f"  found {len(found)} of {len(wanted)}" + (f"; {missing} not on TVmaze or failed" if missing else ""))
    return found


def simkl_rows(lib: dict, positions: dict | None = None) -> list[list]:
    positions = positions or {}
    rows = []
    for m in lib["movies"]:
        status = "completed" if m["watched"] else "plan to watch" if m["watch_later"] else ""
        if status:
            rows.append(["movie", m["title"], m["year"], "", m["imdb_id"], status, "",
                         _simkl_date(m["watched_at"]) if m["watched"] else ""])
    for s in lib["series"]:
        status = SIMKL_STATUS.get(s["status"]) or ("watching" if s["last_seen_episode"] else "plan to watch")
        known, looked_up = s["last_seen_episode"] or "", positions.get(s["tvdb_id"], "")
        if status == "completed":
            # Without a number Simkl marks everything aired, which is right for ended series only.
            last = max((c for c in (known, looked_up) if _code_key(c)), key=_code_key) if looked_up else ""
        elif status in ("watching", "dropped", "on hold"):
            last = known or looked_up
        else:
            last = ""
        rows.append(["tv", s["title"], "", s["tvdb_id"], "", status, last, _simkl_date(s["last_watched_at"])])
    return rows


def write_outputs(lib: dict, out: Path, positions: dict | None = None) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / "library.json").write_text(json.dumps(lib, ensure_ascii=False, indent=1), encoding="utf-8")
    _csv(out / "series.csv",
         ["title", "status", "seen_episodes", "aired_episodes", "last_seen_episode", "next_episode",
          "last_watched_at_utc", "followed_at_utc", "favorite", "archived", "tvdb_id", "country"],
         [[s["title"], s["status"], "" if s["seen_episodes"] is None else s["seen_episodes"],
           "" if s["aired_episodes"] is None else s["aired_episodes"], s["last_seen_episode"] or "",
           (s["next_episode"] or {}).get("code", ""), s["last_watched_at"], s["followed_at"],
           int(s["favorite"]), int(s["archived"]), s["tvdb_id"], s["country"]] for s in lib["series"]])
    _csv(out / "episodes.csv",
         ["show", "episode", "title", "watched", "watched_at_utc", "times_watched", "up_next", "air_date",
          "season", "number", "show_tvdb_id"],
         [[e["show"], e["code"], e["name"], int(e["seen"]), e["seen_at"], e["times_watched"],
           int(e["in_up_next"]), e["air_date"], e["season"], e["number"], e["show_id"]] for e in lib["episodes"]])
    _csv(out / "movies.csv",
         ["title", "year", "watched", "watched_at_utc", "rewatch_count", "watch_later", "favorite",
          "runtime_min", "genres", "imdb_id"],
         [[m["title"], m["year"], int(m["watched"]), m["watched_at"], m["rewatch_count"], int(m["watch_later"]),
           int(m["favorite"]), m["runtime_min"] or "", ", ".join(m["genres"]), m["imdb_id"]] for m in lib["movies"]])
    _csv(out / "simkl_import.csv",
         ["Type", "Title", "Year", "TVDB_ID", "IMDB_ID", "Watchlist", "LastEpWatched", "WatchedDate"],
         simkl_rows(lib, positions), bom=False)
    data = json.dumps(lib, ensure_ascii=False).replace("<", "\\u003c")
    (out / "TVTime.html").write_text(VIEWER_HTML.replace("__DATA__", data), encoding="utf-8")


def diagnostics(payloads: list[dict], sources: collections.Counter, lib: dict) -> str:
    """Structure only: key names, types and counts. No titles, IDs, dates or URLs."""
    def shape(value, depth=0):
        if isinstance(value, dict):
            if depth >= 2:
                return "{...}"
            return "{" + ", ".join(f"{k}: {shape(v, depth + 1)}" for k, v in sorted(value.items())[:25]) + "}"
        if isinstance(value, list):
            return f"[{len(value)} x {shape(value[0], depth + 1) if value else '-'}]"
        return type(value).__name__

    lines = [f"tvtime_recover.py {__version__}, python {sys.version.split()[0]}, {sys.platform}",
             f"sources: {dict(sources)}", f"recognized: {lib['recognized']}", f"stats: {lib['stats']}",
             "payload shapes:"]
    shapes = collections.Counter(shape(p["json"])[:400] for p in payloads)
    lines += [f"  {n} x {s}" for s, n in shapes.most_common(30)]
    return "\n".join(lines)


# --------------------------------------------------------------------------
# Command line
# --------------------------------------------------------------------------
def _choose_backup(log) -> Path:
    backups, denied = find_backups()
    candidates = [b for b in backups if b["has_tvtime"] is not False]
    if not candidates:
        if denied and sys.platform == "darwin":
            raise RecoveryError(
                "macOS does not let Terminal read the backup folder.\n"
                "Either copy the backup somewhere else in Finder (iPhone > Manage Backups > right-click > "
                "Show in Finder, then Cmd+C and Cmd+V into e.g. your Documents) and run again with\n"
                "  --backup PATH_TO_THE_COPIED_FOLDER\n"
                "or give Terminal Full Disk Access (System Settings > Privacy & Security).")
        where = ", ".join(str(r) for r in default_backup_roots()) or "(no default location on this system)"
        raise RecoveryError(f"No iPhone/iPad backup with TV Time found in {where}.\n"
                            "Make a local backup first (see README) or pass --backup PATH.")
    if len(candidates) == 1:
        return candidates[0]["path"]
    log("Several backups found:")
    for i, b in enumerate(candidates, 1):
        lock = "encrypted" if b["encrypted"] else "not encrypted"
        log(f"  {i}. {b['device']}  iOS {b['ios']}  {b['date']}  ({lock})")
    while True:
        answer = input(f"Which one? [1-{len(candidates)}]: ").strip()
        if answer.isdigit() and 1 <= int(answer) <= len(candidates):
            return candidates[int(answer) - 1]["path"]


def _password_source(from_stdin: bool):
    if from_stdin:
        def read():
            return sys.stdin.readline().rstrip("\r\n")
        return read

    def ask():
        return getpass.getpass("  Backup password: ")
    ask.interactive = True
    return ask


def main(argv=None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass
    parser = argparse.ArgumentParser(description="Recover TV Time watch history from a local iPhone/iPad backup.")
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--backup", metavar="DIR", help="backup folder (the one with Manifest.db). "
                        "Default: look in the standard Finder / iTunes location")
    source.add_argument("--diocache", metavar="PATH", help="skip the backup and read an extracted DioCache.db "
                        "(or a folder with TV Time's Documents files)")
    source.add_argument("--list-backups", action="store_true", help="show the backups found and exit")
    parser.add_argument("--output", metavar="DIR", help="new folder for the results (default: ./TVTime-Recovery-DATE)")
    parser.add_argument("--password-stdin", action="store_true", help="read the backup password from standard input")
    parser.add_argument("--all-files", action="store_true", help="copy every TV Time file from the backup into raw/, "
                        "not just Documents (includes login cookies and tokens)")
    parser.add_argument("--diagnose", action="store_true", help="print the cache structure without personal data "
                        "(for bug reports) and write nothing")
    parser.add_argument("--no-open", action="store_true", help="do not open the result page in the browser")
    parser.add_argument("--offline", action="store_true", help="don't look up episode numbers for the Simkl file "
                        "on TVmaze (the only network request)")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args(argv)
    log = print

    try:
        if args.list_backups:
            backups, denied = find_backups()
            for b in backups:
                tv = {True: "TV Time: yes", False: "TV Time: no", None: "TV Time: ?"}[b["has_tvtime"]]
                log(f"{b['path']}\n  {b['device']}, iOS {b['ios']}, {b['date']}, "
                    f"{'encrypted' if b['encrypted'] else 'not encrypted'}, {tv}")
            for root in denied:
                log(f"No permission to read {root} (see README: Full Disk Access).")
            return 0

        output = Path(args.output or f"TVTime-Recovery-{datetime.now():%Y%m%d-%H%M%S}").expanduser().resolve()
        if output.exists() and not args.diagnose:
            raise RecoveryError(f"{output} already exists; choose a new --output folder.")

        with tempfile.TemporaryDirectory(prefix="tvtime-") as scratch:
            if args.diocache:
                source_path = Path(args.diocache).expanduser()
                if not source_path.exists():
                    raise RecoveryError(f"{source_path} does not exist.")
                files = [source_path] if source_path.is_file() else sorted(p for p in source_path.rglob("*") if p.is_file())
                index = []
            else:
                backup = Path(args.backup).expanduser() if args.backup else _choose_backup(log)
                info = backup_info(backup)
                log(f"Backup: {backup}\n  {info['device']}, iOS {info['ios']}, {info['date']}, "
                    f"{'encrypted' if info['encrypted'] else 'not encrypted'}")
                if info["has_tvtime"] is False:
                    raise RecoveryError("TV Time was not installed on the device when this backup was made.")
                raw_dir = (Path(scratch) if args.diagnose else output) / "raw"
                log("Copying TV Time files from the backup...")
                index = extract_tvtime(backup, raw_dir, _password_source(args.password_stdin),
                                       all_files=args.all_files, log=log)
                files = sorted(p for p in (raw_dir / PRIMARY_DOMAIN / "Documents").rglob("*") if p.is_file()) \
                    if (raw_dir / PRIMARY_DOMAIN / "Documents").is_dir() else []
                if not files:
                    raise RecoveryError("TV Time's Documents folder is empty in this backup; the cache is gone.")

            log("Reading the app cache...")
            payloads, sources = read_payloads(files)
            lib = build_library(payloads)
            if args.diagnose:
                log(diagnostics(payloads, sources, lib))
                return 0
            if index:
                output.mkdir(parents=True, exist_ok=True)
                _csv(output / "file_index.csv", ["domain", "path", "status", "bytes"],
                     [[e["domain"], e["path"], e["status"], e["bytes"]] for e in index])
            positions = {} if args.offline else tvmaze_positions(lib, log=log)
            write_outputs(lib, output, positions)

        st = lib["stats"]
        log("")
        if not st["series"] and not st["movies"]:
            log("No TV Time library data was recognized in the cache.\n"
                "Please run again with --diagnose and report the output (it contains no personal data).")
            return 3
        log(f"Series: {st['series']}  (watching {st['continuing']}, up to date {st['up_to_date']}, "
            f"stopped {st['stopped']}, not started {st['not_started_yet']}, unknown {st['unknown']})")
        log(f"  with watched/aired counts: {st['series_with_counts']}, with next episode: "
            f"{st['series_with_next_episode']}")
        log(f"Episodes in the cache: {st['episodes']}  (with watch dates: {st['watched_episodes_with_dates']})")
        log(f"Movies: {st['movies']}  (watched {st['movies_watched']})")
        if lib["snapshot_at"]:
            log(f"Data as of {lib['snapshot_at'][:10]} (the last time the app loaded it from the server).")
        log(f"\nResults: {output}\nOpen TVTime.html to browse them.")
        if not args.no_open:
            webbrowser.open((output / "TVTime.html").as_uri())
        return 0
    except RecoveryError as exc:
        print(f"\nError: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nCancelled.", file=sys.stderr)
        return 130


# --------------------------------------------------------------------------
# Viewer page (one self-contained file; posters load from artworks.thetvdb.com)
# --------------------------------------------------------------------------
VIEWER_HTML = r"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>TV Time history</title>
<style>
:root {
  --bg: #f5f4f0; --surface: #ffffff; --text: #1c1b19; --muted: #69655d; --line: #e2dfd7;
  --watching: #1864ab; --done: #2b8a3e; --stopped: #6c737a; --notstarted: #9c6f00; --unknown: #6c737a;
  --radius: 10px;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --bg: #141413; --surface: #1e1d1b; --text: #ecebe7; --muted: #a09b92; --line: #34322e;
    --watching: #74b3f0; --done: #69c47e; --stopped: #aab1b8; --notstarted: #e3c04a; --unknown: #aab1b8;
  }
}
:root[data-theme="dark"] {
  --bg: #141413; --surface: #1e1d1b; --text: #ecebe7; --muted: #a09b92; --line: #34322e;
  --watching: #74b3f0; --done: #69c47e; --stopped: #aab1b8; --notstarted: #e3c04a; --unknown: #aab1b8;
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text);
  font: 15px/1.45 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
.wrap { max-width: 1200px; margin: 0 auto; padding: 0 16px; }
header { padding-top: 24px; }
h1 { font-size: 26px; margin: 0 0 4px; letter-spacing: -0.01em; }
.sub { color: var(--muted); margin: 0 0 16px; max-width: 70ch; }
.stats { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 16px; }
.stat { background: var(--surface); border: 1px solid var(--line); border-radius: var(--radius); padding: 8px 14px; min-width: 110px; }
.stat b { display: block; font-size: 22px; font-variant-numeric: tabular-nums; }
.stat span { color: var(--muted); font-size: 13px; }
.controls { position: sticky; top: 0; z-index: 2; background: var(--bg); border-bottom: 1px solid var(--line); }
@media (max-width: 600px) { .controls { position: static; } }
.controls .wrap { padding-top: 10px; padding-bottom: 10px; display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
.tabs { display: flex; flex-wrap: wrap; gap: 6px; }
.tab { border: 1px solid var(--line); background: var(--surface); color: var(--text); border-radius: 999px;
  padding: 5px 12px; cursor: pointer; font: inherit; font-size: 14px; }
.tab[aria-pressed="true"] { background: var(--text); color: var(--bg); border-color: var(--text); }
.tab small { opacity: .7; margin-left: 4px; font-variant-numeric: tabular-nums; }
.tools { display: flex; flex-wrap: wrap; gap: 8px; flex: 1 1 280px; min-width: 0; }
input[type=search], select { font: inherit; font-size: 14px; padding: 6px 10px; border-radius: 8px;
  border: 1px solid var(--line); background: var(--surface); color: var(--text); }
input[type=search] { flex: 1 1 180px; min-width: 0; }
select { flex: 0 1 auto; min-width: 0; max-width: 100%; }
main { padding-top: 16px; padding-bottom: 40px; }
.grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(150px, 1fr)); gap: 14px; }
@media (max-width: 420px) { .grid { grid-template-columns: repeat(2, 1fr); gap: 10px; } }
.card { background: var(--surface); border: 1px solid var(--line); border-radius: var(--radius); overflow: hidden; display: flex; flex-direction: column; }
.poster { aspect-ratio: 2 / 3; background: var(--line); position: relative; }
.poster img { position: absolute; inset: 0; width: 100%; height: 100%; object-fit: cover; display: block; }
.poster .ph { position: absolute; inset: 0; display: grid; place-items: center; padding: 10px; text-align: center; color: var(--muted); font-weight: 600; }
.body { padding: 8px 10px 10px; display: flex; flex-direction: column; gap: 5px; flex: 1; }
.title { font-weight: 600; line-height: 1.25; overflow-wrap: anywhere; }
.chips { display: flex; flex-wrap: wrap; gap: 4px; }
.badge { font-size: 12px; padding: 1px 8px; border-radius: 999px; color: var(--c); border: 1px solid currentColor; }
.meta { font-size: 13px; color: var(--muted); }
.meta b { color: var(--text); font-weight: 600; }
.bar { height: 4px; background: var(--line); border-radius: 2px; overflow: hidden; }
.bar i { display: block; height: 100%; background: var(--c); }
h2 { font-size: 18px; margin: 24px 0 8px; }
h2:first-child { margin-top: 0; }
.table { overflow-x: auto; border: 1px solid var(--line); border-radius: var(--radius); background: var(--surface); }
table { width: 100%; border-collapse: collapse; min-width: 560px; }
th, td { text-align: left; padding: 8px 12px; border-bottom: 1px solid var(--line); font-size: 14px; vertical-align: top; }
tr:last-child td { border-bottom: 0; }
th { color: var(--muted); font-weight: 600; }
td.num { font-variant-numeric: tabular-nums; white-space: nowrap; }
.note { color: var(--muted); font-size: 13px; margin: 8px 0 0; max-width: 80ch; }
.empty { color: var(--muted); padding: 40px 0; text-align: center; }
</style>
</head>
<body>
<header class="wrap">
  <h1 id="h1"></h1>
  <p class="sub" id="sub"></p>
  <div class="stats" id="stats"></div>
</header>
<div class="controls">
  <div class="wrap">
    <div class="tabs" id="tabs" role="toolbar"></div>
    <div class="tools">
      <input type="search" id="q">
      <select id="sort"></select>
    </div>
  </div>
</div>
<main class="wrap" id="main"></main>
<script id="data" type="application/json">__DATA__</script>
<script>
const DATA = JSON.parse(document.getElementById("data").textContent);
const LANG = (navigator.language || "en").toLowerCase().startsWith("ru") ? "ru" : "en";
const T = {
  en: {
    title: "TV Time history", locale: "en-GB",
    sub: "Recovered from the TV Time app cache in a local iPhone backup.",
    asOf: (d) => ` Data as of ${d}, the last time the app loaded it from the server.`,
    status: { continuing: "Watching", up_to_date: "Up to date", stopped: "Stopped", not_started_yet: "Not started", "": "Unknown" },
    statLabels: ["series", "watching", "up to date", "stopped", "not started", "movies"],
    all: "All series", movies: "Movies", episodes: "Episodes", search: "Search by title",
    sort: { watched: "Last watched", followed: "Date added", title: "Title" },
    of: (a, b) => `${a} of ${b}`, eps: () => "episodes", next: "Next", last: "Last seen",
    lastWatched: "Last watched", added: "Added", watched: "Watched", min: "min",
    favorite: "Favorite", archived: "Archived", forLater: "For later", watchLater: "Watch later",
    recent: "Watched episodes", upnext: "Up next and other cached episodes",
    cols: ["When", "Show", "Episode", "Title"], cols2: ["Show", "Episode", "Title", "Progress"],
    historyNote: "Only episodes that were in the app cache are listed; the full per-episode history was usually not cached.",
    nothing: "Nothing found",
  },
  ru: {
    title: "История TV Time", locale: "ru-RU",
    sub: "Восстановлено из кэша приложения TV Time в резервной копии iPhone.",
    asOf: (d) => ` Данные на ${d} — последний раз, когда приложение загружало их с сервера.`,
    status: { continuing: "Смотрю", up_to_date: "Всё просмотрено", stopped: "Брошено", not_started_yet: "Не начато", "": "Неизвестно" },
    statLabels: ["сериалов", "смотрю", "всё просмотрено", "брошено", "не начато", "фильмов"],
    all: "Все сериалы", movies: "Фильмы", episodes: "Серии", search: "Поиск по названию",
    sort: { watched: "По последнему просмотру", followed: "По дате добавления", title: "По названию" },
    of: (a, b) => `${a} из ${b}`, eps: (n) => (n % 10 === 1 && n % 100 !== 11 ? "серии" : "серий"),
    next: "Далее", last: "Последняя", lastWatched: "Последний просмотр", added: "Добавлен",
    watched: "Просмотрен", min: "мин", favorite: "Избранное", archived: "Архив", forLater: "На потом",
    watchLater: "Посмотреть позже",
    recent: "Просмотренные серии", upnext: "Следующие и другие серии из кэша",
    cols: ["Когда", "Сериал", "Серия", "Название"], cols2: ["Сериал", "Серия", "Название", "Прогресс"],
    historyNote: "Показаны только серии, которые были в кэше приложения; полная поэпизодная история обычно не кэшировалась.",
    nothing: "Ничего не найдено",
  },
}[LANG];
document.documentElement.lang = LANG;
document.title = T.title;
const COLORS = { continuing: "--watching", up_to_date: "--done", stopped: "--stopped", not_started_yet: "--notstarted", "": "--unknown" };
const state = { tab: "all", q: "", sort: "watched" };
try { Object.assign(state, JSON.parse(localStorage.getItem("tvtime-view") || "{}")); } catch (e) {}

function el(tag, props, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "style") node.style.cssText = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat()) if (c !== null && c !== undefined && c !== false)
    node.append(c instanceof Node ? c : String(c));
  return node;
}
const fmtDate = (iso) => iso ? new Date(iso).toLocaleDateString(T.locale) : "";
const fmtDateTime = (iso) => iso ? new Date(iso).toLocaleString(T.locale,
  { day: "2-digit", month: "2-digit", year: "numeric", hour: "2-digit", minute: "2-digit" }) : "";

function poster(src, title) {
  const box = el("div", { class: "poster" }, el("div", { class: "ph" }, title));
  if (src) {
    const img = el("img", { src, alt: "", loading: "lazy", referrerpolicy: "no-referrer" });
    img.addEventListener("error", () => img.remove());
    box.append(img);
  }
  return box;
}

function seriesCard(s) {
  const c = `--c: var(${COLORS[s.status] || "--unknown"})`;
  const chips = [el("span", { class: "badge", style: c }, T.status[s.status] || s.status)];
  if (s.favorite) chips.push(el("span", { class: "badge", style: "--c: var(--notstarted)" }, T.favorite));
  if (s.archived) chips.push(el("span", { class: "badge", style: "--c: var(--stopped)" }, T.archived));
  if (s.for_later) chips.push(el("span", { class: "badge", style: "--c: var(--stopped)" }, T.forLater));
  const lines = [];
  if (s.seen_episodes !== null && s.aired_episodes) {
    const pct = Math.min(100, Math.round(100 * s.seen_episodes / s.aired_episodes));
    lines.push(el("div", { class: "meta" }, el("b", {}, T.of(s.seen_episodes, s.aired_episodes)), ` ${T.eps(s.aired_episodes)}`));
    lines.push(el("div", { class: "bar", style: c }, el("i", { style: `width:${pct}%` })));
  }
  if (s.next_episode) lines.push(el("div", { class: "meta" }, `${T.next}: `, el("b", {}, s.next_episode.code)));
  else if (s.last_seen_episode) lines.push(el("div", { class: "meta" }, `${T.last}: `, el("b", {}, s.last_seen_episode)));
  if (s.last_watched_at) lines.push(el("div", { class: "meta" }, `${T.lastWatched}: ${fmtDate(s.last_watched_at)}`));
  if (s.followed_at) lines.push(el("div", { class: "meta" }, `${T.added}: ${fmtDate(s.followed_at)}`));
  return el("article", { class: "card" }, poster(s.poster, s.title),
    el("div", { class: "body" }, el("div", { class: "title" }, s.title), el("div", { class: "chips" }, chips), lines));
}

function movieCard(m) {
  const lines = [];
  if (m.watched_at) lines.push(el("div", { class: "meta" }, `${T.watched}: ${fmtDate(m.watched_at)}`));
  else if (m.watch_later) lines.push(el("div", { class: "meta" }, T.watchLater));
  if (m.runtime_min) lines.push(el("div", { class: "meta" }, `${m.runtime_min} ${T.min}`));
  if (m.genres && m.genres.length) lines.push(el("div", { class: "meta" }, m.genres.slice(0, 3).join(", ")));
  return el("article", { class: "card" }, poster(m.poster, m.title),
    el("div", { class: "body" }, el("div", { class: "title" }, m.year ? `${m.title} (${m.year})` : m.title), lines));
}

function sorted(items, dateKey) {
  const list = items.slice();
  if (state.sort === "title") list.sort((a, b) => a.title.localeCompare(b.title, LANG));
  else {
    const key = state.sort === "followed" && dateKey === "last_watched_at" ? "followed_at" : dateKey;
    list.sort((a, b) => (b[key] || "").localeCompare(a[key] || "") || a.title.localeCompare(b.title, LANG));
  }
  return list;
}

function episodesView(q) {
  const match = (e) => !q || e.show.toLowerCase().includes(q) || (e.name || "").toLowerCase().includes(q);
  const watched = DATA.episodes.filter((e) => e.seen && match(e));
  const others = DATA.episodes.filter((e) => !e.seen && match(e));
  const byId = Object.fromEntries(DATA.series.map((s) => [s.tvdb_id, s]));
  const table = (head, rows) => el("div", { class: "table" }, el("table", {},
    el("thead", {}, el("tr", {}, head.map((h) => el("th", {}, h)))), el("tbody", {}, rows)));
  return [
    el("h2", {}, T.recent),
    table(T.cols, watched.map((e) => el("tr", {}, el("td", { class: "num" }, fmtDateTime(e.seen_at)),
      el("td", {}, e.show), el("td", { class: "num" }, e.code), el("td", {}, e.name)))),
    el("p", { class: "note" }, T.historyNote),
    el("h2", {}, T.upnext),
    table(T.cols2, others.map((e) => {
      const s = byId[e.show_id] || {};
      const progress = s.seen_episodes !== null && s.seen_episodes !== undefined && s.aired_episodes ? T.of(s.seen_episodes, s.aired_episodes) : "";
      return el("tr", {}, el("td", {}, e.show), el("td", { class: "num" }, e.code), el("td", {}, e.name), el("td", { class: "num" }, progress));
    })),
  ];
}

function render() {
  try { localStorage.setItem("tvtime-view", JSON.stringify(state)); } catch (e) {}
  document.querySelectorAll(".tab").forEach((b) => b.setAttribute("aria-pressed", b.dataset.tab === state.tab));
  document.getElementById("sort").disabled = state.tab === "episodes";
  const q = state.q.trim().toLowerCase();
  let content;
  if (state.tab === "episodes") content = episodesView(q);
  else {
    const movies = state.tab === "movies";
    const source = movies ? DATA.movies : DATA.series.filter((s) => state.tab === "all" || s.status === state.tab);
    const list = sorted(source.filter((x) => !q || x.title.toLowerCase().includes(q)), movies ? "watched_at" : "last_watched_at");
    content = list.length ? el("div", { class: "grid" }, list.map(movies ? movieCard : seriesCard)) : el("p", { class: "empty" }, T.nothing);
  }
  document.getElementById("main").replaceChildren(...[content].flat());
}

const st = DATA.stats;
document.getElementById("h1").textContent = T.title;
document.getElementById("sub").textContent = T.sub + (DATA.snapshot_at ? T.asOf(fmtDate(DATA.snapshot_at)) : "");
document.getElementById("stats").append(...[st.series, st.continuing, st.up_to_date, st.stopped, st.not_started_yet, st.movies]
  .map((n, i) => el("div", { class: "stat" }, el("b", {}, n), el("span", {}, T.statLabels[i]))));
const tabs = [["all", T.all, st.series], ["continuing", T.status.continuing, st.continuing],
  ["up_to_date", T.status.up_to_date, st.up_to_date], ["stopped", T.status.stopped, st.stopped],
  ["not_started_yet", T.status.not_started_yet, st.not_started_yet], ["movies", T.movies, st.movies],
  ["episodes", T.episodes, DATA.episodes.length]].filter(([id, , n]) => n || id === "all");
if (!tabs.some(([id]) => id === state.tab)) state.tab = "all";
document.getElementById("tabs").append(...tabs.map(([id, label, n]) => el("button", { class: "tab", "data-tab": id,
  "aria-pressed": "false", onclick: () => { state.tab = id; render(); } }, label, el("small", {}, n))));
const qInput = document.getElementById("q");
qInput.placeholder = T.search;
qInput.setAttribute("aria-label", T.search);
qInput.value = state.q;
qInput.addEventListener("input", () => { state.q = qInput.value; render(); });
const sortSelect = document.getElementById("sort");
sortSelect.append(...Object.entries(T.sort).map(([v, label]) => el("option", { value: v }, label)));
sortSelect.value = state.sort;
sortSelect.addEventListener("change", () => { state.sort = sortSelect.value; render(); });
render();
</script>
</body>
</html>
"""

if __name__ == "__main__":
    sys.exit(main())
