"""Tests for tvtime_recover.py. Synthetic data only.

    python3 -m unittest discover -s tests -v
"""
from __future__ import annotations

import contextlib
import csv
import hashlib
import io
import json
import os
import plistlib
import sqlite3
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import tvtime_recover as tv  # noqa: E402

h = bytes.fromhex
PURE = tv.PurePythonAES()


def backends():
    found = [PURE]
    if sys.platform == "darwin":
        found.append(tv.CommonCryptoAES())
    for path in tv._libcrypto_candidates():
        try:
            found.append(tv.OpenSSLAES(path))
            break
        except (OSError, AttributeError):
            continue
    return found


class CryptoTests(unittest.TestCase):
    def test_fips197_block_vectors(self):
        plain = h("00112233445566778899aabbccddeeff")
        vectors = {16: "69c4e0d86a7b0430d8cdb78070b4c55a", 24: "dda97ca4864cdfe06eaf70a0ec0d7191",
                   32: "8ea2b7ca516745bfeafc49904b496089"}
        for size, cipher in vectors.items():
            key = bytes(range(size))
            self.assertEqual(PURE.ecb_encrypt(key, plain), h(cipher))
            for backend in backends():
                with self.subTest(backend=backend.name, size=size):
                    self.assertEqual(backend.ecb_decrypt(key, h(cipher)), plain)

    def test_sp800_38a_cbc_aes256(self):
        key = h("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
        iv = h("000102030405060708090a0b0c0d0e0f")
        plain = h("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
                  "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")
        cipher = h("f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d"
                   "39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b")
        self.assertEqual(PURE.cbc_encrypt(key, plain, iv), cipher)
        for backend in backends():
            with self.subTest(backend=backend.name):
                self.assertEqual(backend.cbc_decrypt(key, cipher, iv), plain)

    def test_backends_agree_on_random_data(self):
        key, data = os.urandom(32), os.urandom(16 * 257)
        expected = PURE.cbc_decrypt(key, data)
        for backend in backends():
            with self.subTest(backend=backend.name):
                self.assertEqual(backend.cbc_decrypt(key, data), expected)
        self.assertEqual(PURE.cbc_decrypt(key, PURE.cbc_encrypt(key, data)), data)

    def test_rfc3394_unwrap(self):
        kek = h("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
        wrapped = h("28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21")
        self.assertEqual(tv.aes_unwrap(kek, wrapped),
                         h("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F"))
        with self.assertRaises(ValueError):
            tv.aes_unwrap(bytes(32), wrapped)

    def test_backend_selection_passes_self_test(self):
        self.assertTrue(tv._self_test(tv.aes_backend()))


# ---------------------------------------------------------------- fixtures
def aes_wrap(kek, plain):
    n = len(plain) // 8
    a, r = b"\xa6" * 8, [plain[8 * i: 8 * (i + 1)] for i in range(n)]
    for j in range(6):
        for i in range(1, n + 1):
            b = PURE.ecb_encrypt(kek, a + r[i - 1])
            a = bytes(x ^ y for x, y in zip(b[:8], (n * j + i).to_bytes(8, "big")))
            r[i - 1] = b[8:]
    return a + b"".join(r)


def pad(data):
    n = 16 - len(data) % 16
    return data + bytes([n]) * n


def response(payload, date="Sun, 28 Jun 2026 07:11:59 GMT"):
    return json.dumps(payload).encode(), json.dumps({"date": [date]}).encode()


OWNER = 1001
FRIEND = 2002


def follow(show_id, name, status, follow_date="2020-01-02T03:04:05Z", watch_date="2026-05-01T10:00:00Z"):
    return {"uuid": f"u-{show_id}", "type": "follow", "entity_type": "series",
            "meta": {"id": show_id, "name": name, "country": "us", "is_ended": False,
                     "images": [{"type": "poster", "url": f"https://artworks.example/{show_id}.jpg",
                                 "versions": {"medium": f"https://artworks.example/{show_id}-m.jpg"}}]},
            "extended": {"rating": 0}, "filter": ["all", status],
            "sorting": [{"id": "follow_date", "value": follow_date}, {"id": "alphabetical", "value": name},
                        {"id": "watch_date", "value": watch_date}]}


def episode(show_id, name, season, number, *, seen, seen_date=None, up_next=False, seen_count=None, aired=None):
    ep = {"id": show_id * 1000 + season * 100 + number, "name": f"Episode {number}", "number": number,
          "season_number": season, "air_date": "2026-01-01", "seen": seen, "is_watched": seen,
          "seen_date": seen_date, "nb_times_watched": 1 if seen else 0,
          "show": {"id": show_id, "name": name, "seen_episodes": seen_count, "aired_episodes": aired,
                   "all_images": {}}}
    if up_next:
        ep["to_watch_category"] = "continue_watching"
    return ep


def modern_cache_rows():
    """Shapes seen in a real TV Time 10.x DioCache.db, with invented values."""
    movie_meta = {"uuid": "m-1", "name": "Invented Movie", "first_release_date": "2019-05-01",
                  "imdb_id": "tt0000001", "genres": ["Drama"], "runtime": 7200, "overview": "x",
                  "posters": [{"url": "https://artworks.example/m1.jpg", "thumb_url": "https://artworks.example/m1-t.jpg"}]}
    return [
        response({"status": "success", "data": {"id": OWNER, "is_vip": False, "user_rights": "user",
                                                 "allow_friend_invite_notification": True}}),
        response({"status": "success", "data": {"user_id": OWNER, "type": "list", "objects": [
            follow(1, "Alpha Show", "continuing"), follow(2, "Beta Show", "up_to_date"),
            follow(3, "Gamma Show", "stopped", watch_date="2017-01-01T00:00:00Z"),
            follow(4, "Delta <Show>, \"quoted\"", "not_started_yet", watch_date="1970-01-01T00:00:00Z")]}}),
        response({"status": "success", "data": {"user_id": OWNER, "type": "list", "objects": [
            {"uuid": "m-1", "type": "follow", "entity_type": "movie", "watched_at": "2019-12-07T19:11:02Z",
             "rewatch_count": 1, "meta": movie_meta, "extended": {"is_watched": True}, "filter": ["watched"]}]}}),
        response({"status": "success", "data": {"user_id": OWNER, "type": "watch", "objects": [
            {"uuid": "m-1", "type": "watch", "entity_type": "movie", "watched_at": "2019-12-07T19:11:02Z"}]}}),
        response([episode(1, "Alpha Show", 2, 3, seen=True, seen_date="2026-06-10 17:22:55", seen_count=12, aired=20),
                  episode(2, "Beta Show", 1, 8, seen=True, seen_date="2026-06-01 09:00:00", seen_count=8, aired=8)]),
        response([episode(1, "Alpha Show", 2, 4, seen=False, up_next=True, seen_count=12, aired=20)]),
        # a friend's list must not leak into the library
        response({"status": "success", "data": {"user_id": FRIEND, "type": "list",
                                                 "objects": [follow(99, "Friend Show", "up_to_date")]}}),
    ]


def make_dio_cache(path, rows):
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE cache_dio (key text, subKey text, max_age_date integer, max_stale_date integer, "
                "content BLOB, statusCode integer, headers BLOB, PRIMARY KEY (key, subKey))")
    for i, (content, headers) in enumerate(rows):
        con.execute("INSERT INTO cache_dio VALUES (?,?,?,?,?,?,?)",
                    (f"k{i}", "s", 1782641519000, 1782641519000, content, 200, headers))
    con.commit()
    con.close()


def legacy_archive(url, payload):
    return plistlib.dumps({
        "$version": 100000, "$archiver": "NSKeyedArchiver", "$top": {"root": plistlib.UID(1)},
        "$objects": ["$null", {"$class": plistlib.UID(4), "url": plistlib.UID(2), "data": plistlib.UID(3)},
                     url, json.dumps(payload).encode(),
                     {"$classname": "NSCachedURLResponse", "$classes": ["NSCachedURLResponse", "NSObject"]}],
    }, fmt=plistlib.FMT_BINARY)


def make_backup(folder: Path, files: dict, password: bytes | None, *, stale_sizes=()):
    """Write a synthetic Finder backup. files: {(domain, relative_path): bytes}."""
    folder.mkdir(parents=True)
    encrypted = password is not None
    class_keys = {c: os.urandom(32) for c in (1, 2, 3, 4)}
    manifest_plist = {"IsEncrypted": encrypted}
    if encrypted:
        salt, dpsl = os.urandom(20), os.urandom(20)
        passcode_key = hashlib.pbkdf2_hmac(
            "sha1", hashlib.pbkdf2_hmac("sha256", password, dpsl, 2000, 32), salt, 1000, 32)

        def tlv(tag, value):
            value = struct.pack(">I", value) if isinstance(value, int) else value
            return tag + struct.pack(">I", len(value)) + value

        keybag = b"".join([tlv(b"VERS", 4), tlv(b"TYPE", 1), tlv(b"UUID", os.urandom(16)), tlv(b"WRAP", 0),
                           tlv(b"SALT", salt), tlv(b"ITER", 1000), tlv(b"DPWT", 1), tlv(b"DPIC", 2000),
                           tlv(b"DPSL", dpsl)])
        for clas, key in class_keys.items():
            keybag += tlv(b"UUID", os.urandom(16)) + tlv(b"CLAS", clas) + tlv(b"WRAP", 2) + tlv(b"KTYP", 0)
            keybag += tlv(b"WPKY", aes_wrap(passcode_key, key))
        manifest_plist["BackupKeyBag"] = keybag

    db_path = folder / "plain-manifest.db"
    con = sqlite3.connect(db_path)
    con.execute("CREATE TABLE Files (fileID TEXT PRIMARY KEY, domain TEXT, relativePath TEXT, flags INTEGER, file BLOB)")
    for (domain, rel), content in files.items():
        file_id = hashlib.sha1(f"{domain}-{rel}".encode()).hexdigest()
        (folder / file_id[:2]).mkdir(exist_ok=True)
        root = {"$class": plistlib.UID(3), "ProtectionClass": 3,
                "Size": 4096 if rel in stale_sizes else len(content)}
        objects = ["$null", root]
        stored = content
        if encrypted:
            file_key = os.urandom(32)
            stored = PURE.cbc_encrypt(file_key, pad(content))
            root["EncryptionKey"] = plistlib.UID(2)
            objects.append({"NS.data": struct.pack("<I", 3) + aes_wrap(class_keys[3], file_key),
                            "$class": plistlib.UID(4)})
        else:
            objects.append("$placeholder")
        objects += [{"$classname": "MBFile", "$classes": ["MBFile", "NSObject"]},
                    {"$classname": "NSMutableData", "$classes": ["NSMutableData", "NSData", "NSObject"]}]
        (folder / file_id[:2] / file_id).write_bytes(stored)
        archive = {"$version": 100000, "$archiver": "NSKeyedArchiver", "$top": {"root": plistlib.UID(1)},
                   "$objects": objects}
        con.execute("INSERT INTO Files VALUES (?,?,?,?,?)",
                    (file_id, domain, rel, 1, plistlib.dumps(archive, fmt=plistlib.FMT_BINARY)))
    con.execute("INSERT INTO Files VALUES (?,?,?,?,?)", ("f" * 40, tv.PRIMARY_DOMAIN, "Documents", 2, b""))
    con.commit()
    con.close()
    manifest = db_path.read_bytes()
    db_path.unlink()
    if encrypted:
        manifest_key = os.urandom(32)
        manifest = PURE.cbc_encrypt(manifest_key, manifest + bytes(-len(manifest) % 16))
        manifest_plist["ManifestKey"] = struct.pack("<I", 4) + aes_wrap(class_keys[4], manifest_key)
    (folder / "Manifest.db").write_bytes(manifest)
    (folder / "Manifest.plist").write_bytes(plistlib.dumps(manifest_plist, fmt=plistlib.FMT_BINARY))
    (folder / "Info.plist").write_bytes(plistlib.dumps({
        "Device Name": "Test iPhone", "Product Version": "26.0", "Installed Applications": [tv.BUNDLE_ID]}))
    (folder / "Status.plist").write_bytes(plistlib.dumps({"SnapshotState": "finished"}))


def run_cli(args, stdin=""):
    out, err = io.StringIO(), io.StringIO()
    with mock.patch("sys.stdin", io.StringIO(stdin)), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = tv.main(args)
    return code, out.getvalue(), err.getvalue()


# ---------------------------------------------------------------- backups
class BackupTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmp, ignore_errors=True))
        cache = self.tmp / "cache.db"
        make_dio_cache(cache, modern_cache_rows())
        self.files = {
            (tv.PRIMARY_DOMAIN, "Documents/DioCache.db"): cache.read_bytes(),
            (tv.PRIMARY_DOMAIN, "Documents/legacy-cache"): legacy_archive(
                f"https://api.example/v2/user/{OWNER}", {"shows": [{"id": 5, "name": "Legacy Show",
                                                                     "watched_episode_count": 0,
                                                                     "aired_episode_count": 10}]}),
            (tv.PRIMARY_DOMAIN, "Library/Preferences/com.tozelabs.tvshowtime.plist"): b"secret-token",
            ("HomeDomain", "Library/unrelated"): b"not ours",
        }

    def check_outputs(self, out: Path):
        lib = json.loads((out / "library.json").read_text())
        titles = {s["title"] for s in lib["series"]}
        self.assertEqual(titles, {"Alpha Show", "Beta Show", "Gamma Show", 'Delta <Show>, "quoted"', "Legacy Show"})
        self.assertTrue((out / "raw" / tv.PRIMARY_DOMAIN / "Documents" / "DioCache.db").is_file())
        self.assertFalse((out / "raw" / tv.PRIMARY_DOMAIN / "Library").exists(), "prefs must not be copied")
        index = {r["path"]: r["status"] for r in csv.DictReader(open(out / "file_index.csv", encoding="utf-8-sig"))}
        self.assertEqual(index["Documents/DioCache.db"], "copied")
        self.assertEqual(index["Library/Preferences/com.tozelabs.tvshowtime.plist"], "not copied")
        self.assertNotIn("Library/unrelated", index)

    def test_encrypted_backup_with_stale_sqlite_size(self):
        make_backup(self.tmp / "b", self.files, b"correct horse", stale_sizes={"Documents/DioCache.db"})
        code, out, err = run_cli(["--backup", str(self.tmp / "b"), "--output", str(self.tmp / "out"),
                                  "--password-stdin", "--no-open"], stdin="correct horse\n")
        self.assertEqual(code, 0, err)
        self.check_outputs(self.tmp / "out")
        copied = (self.tmp / "out" / "raw" / tv.PRIMARY_DOMAIN / "Documents" / "DioCache.db").read_bytes()
        self.assertEqual(copied, self.files[(tv.PRIMARY_DOMAIN, "Documents/DioCache.db")])

    def test_wrong_password(self):
        make_backup(self.tmp / "b", self.files, b"correct horse")
        code, _, err = run_cli(["--backup", str(self.tmp / "b"), "--output", str(self.tmp / "out"),
                                "--password-stdin", "--no-open"], stdin="nope\n")
        self.assertEqual(code, 2)
        self.assertIn("Wrong backup password", err)
        self.assertFalse((self.tmp / "out").exists())

    def test_unencrypted_backup(self):
        make_backup(self.tmp / "b", self.files, None)
        code, _, err = run_cli(["--backup", str(self.tmp / "b"), "--output", str(self.tmp / "out"), "--no-open"])
        self.assertEqual(code, 0, err)
        self.check_outputs(self.tmp / "out")

    def test_all_files_and_diagnose(self):
        make_backup(self.tmp / "b", self.files, None)
        code, _, _ = run_cli(["--backup", str(self.tmp / "b"), "--output", str(self.tmp / "out"),
                              "--all-files", "--no-open"])
        self.assertEqual(code, 0)
        self.assertTrue((self.tmp / "out" / "raw" / tv.PRIMARY_DOMAIN / "Library" / "Preferences").is_dir())
        code, out, _ = run_cli(["--diocache", str(self.tmp / "out" / "raw"), "--diagnose"])
        self.assertEqual(code, 0)
        for secret in ("Alpha", "Invented", "tt0000001", "2026-06", "artworks.example", str(OWNER)):
            self.assertNotIn(secret, out)
        self.assertIn("series list", out)

    def test_existing_output_is_refused(self):
        (self.tmp / "out").mkdir()
        code, _, err = run_cli(["--diocache", str(self.tmp / "cache.db"), "--output", str(self.tmp / "out"), "--no-open"])
        self.assertEqual(code, 2)
        self.assertIn("already exists", err)


# ---------------------------------------------------------------- parsing
def payloads_from(rows):
    return [{"json": json.loads(c), "url": "", "fetched": ""} for c, _ in rows]


class ParseTests(unittest.TestCase):
    def test_modern_cache(self):
        lib = tv.build_library(payloads_from(modern_cache_rows()))
        shows = {s["title"]: s for s in lib["series"]}
        self.assertNotIn("Friend Show", shows)
        alpha = shows["Alpha Show"]
        self.assertEqual((alpha["status"], alpha["seen_episodes"], alpha["aired_episodes"]), ("continuing", 12, 20))
        self.assertEqual(alpha["next_episode"]["code"], "S02E04")
        self.assertEqual(alpha["last_seen_episode"], "S02E03")
        self.assertEqual(alpha["followed_at"], "2020-01-02T03:04:05Z")
        self.assertEqual(alpha["poster"], "https://artworks.example/1-m.jpg")
        self.assertEqual(shows["Beta Show"]["status"], "up_to_date")
        self.assertEqual(shows['Delta <Show>, "quoted"']["last_watched_at"], "")
        self.assertEqual(lib["stats"]["movies"], 1)
        movie = lib["movies"][0]
        self.assertEqual((movie["watched"], movie["watched_at"], movie["runtime_min"], movie["rewatch_count"]),
                         (True, "2019-12-07T19:11:02Z", 120, 1))
        history = [e for e in lib["episodes"] if e["seen"]]
        self.assertEqual([e["seen_at"] for e in history], ["2026-06-10T17:22:55Z", "2026-06-01T09:00:00Z"])

    def test_progress_endpoint_shape(self):
        payload = {"shows": [
            {"id": 7, "name": "Progress Show", "watched_episode_count": 5, "aired_episode_count": 9,
             "filters": [{"id": "progress", "values": ["stopped"]}], "sorting": [{"id": "last_watched", "value": 1700000000}],
             "is_favorite": True, "is_archived": True, "poster": {"url": "https://artworks.example/7.jpg"}},
            {"id": 8, "name": "Done Show", "watched_episode_count": 3, "aired_episode_count": 3},
            {"id": 9, "name": "Fresh Show", "watched_episode_count": 0, "aired_episode_count": 4, "is_for_later": True},
        ]}
        lib = tv.build_library([{"json": payload, "url": "", "fetched": ""}])
        shows = {s["title"]: s for s in lib["series"]}
        progress = shows["Progress Show"]
        self.assertEqual((progress["status"], progress["favorite"], progress["archived"]), ("stopped", True, True))
        self.assertEqual(progress["last_watched_at"], "2023-11-14T22:13:20Z")
        self.assertEqual(progress["poster"], "https://artworks.example/7.jpg")
        self.assertEqual(shows["Done Show"]["status"], "up_to_date")
        self.assertEqual(shows["Fresh Show"]["status"], "not_started_yet")
        rows = {r[1]: r for r in tv.simkl_rows(lib)}
        self.assertEqual(rows["Fresh Show"][5], "plan to watch")

    def test_legacy_archives_and_foreign_profiles(self):
        with tempfile.TemporaryDirectory() as tmp:
            docs = Path(tmp)
            own_show = {"id": 11, "name": "Legacy Own", "watched_episode_count": 2, "aired_episode_count": 3,
                        "seasons": [{"number": 1, "episodes": [
                            {"id": 1, "number": 1, "name": "Pilot", "seen": True, "seen_date": "2015-03-01T20:00:00Z"},
                            {"id": 2, "number": 2, "name": "Two", "seen": True, "seen_date": "2015-03-02T20:00:00Z"},
                            {"id": 3, "number": 3, "name": "Three", "seen": False}]}]}
            (docs / "a").write_bytes(legacy_archive(f"https://api.example/v2/user/{OWNER}", {"shows": [own_show]}))
            (docs / "b").write_bytes(legacy_archive(f"https://api.example/v2/user/{FRIEND}",
                                                    {"shows": [dict(own_show, id=12, name="Friend Legacy")]}))
            (docs / "c").write_bytes(legacy_archive(f"https://api.example/tracking/watches/user/{OWNER}", {"data": {
                "objects": [{"uuid": "m-9", "entity_type": "movie", "watched_at": "2016-01-01T00:00:00Z"}]}}))
            (docs / "junk").write_bytes(b"bplist00 not really")
            payloads, sources = tv.read_payloads(sorted(docs.iterdir()))
        self.assertEqual(sources["legacy_archive"], 3)
        lib = tv.build_library(payloads)
        shows = {s["title"]: s for s in lib["series"]}
        self.assertEqual(set(shows), {"Legacy Own"})
        own = shows["Legacy Own"]
        self.assertEqual((own["status"], own["last_seen_episode"]), ("continuing", "S01E02"))
        self.assertEqual(own["last_watched_at"], "2015-03-02T20:00:00Z")
        self.assertEqual(len([e for e in own["episodes"] if e["seen"]]), 2)
        self.assertEqual(lib["stats"]["movies_watched"], 1)

    def test_iso_utc(self):
        self.assertEqual(tv.iso_utc("2026-06-10 17:22:55"), "2026-06-10T17:22:55Z")
        self.assertEqual(tv.iso_utc("2019-12-07T19:11:02.123Z"), "2019-12-07T19:11:02Z")
        self.assertEqual(tv.iso_utc("2019-12-07T19:11:02+00:00"), "2019-12-07T19:11:02Z")
        self.assertEqual(tv.iso_utc("1970-01-01T00:00:00Z"), "")
        self.assertEqual(tv.iso_utc(1700000000), "2023-11-14T22:13:20Z")
        self.assertEqual(tv.iso_utc("1700000000000"), "2023-11-14T22:13:20Z")


# ---------------------------------------------------------------- outputs
class OutputTests(unittest.TestCase):
    def test_simkl_file_follows_the_documented_format(self):
        lib = tv.build_library(payloads_from(modern_cache_rows()))
        with tempfile.TemporaryDirectory() as tmp:
            tv.write_outputs(lib, Path(tmp))
            with open(Path(tmp) / "simkl_import.csv", encoding="utf-8-sig", newline="") as fh:
                rows = list(csv.DictReader(fh))
            html = (Path(tmp) / "TVTime.html").read_text(encoding="utf-8")
        self.assertEqual(list(rows[0]), ["Type", "Title", "Year", "TVDB_ID", "IMDB_ID", "Watchlist",
                                         "LastEpWatched", "WatchedDate"])
        by_title = {r["Title"]: r for r in rows}
        self.assertEqual(by_title["Alpha Show"]["Watchlist"], "watching")
        self.assertEqual(by_title["Alpha Show"]["LastEpWatched"], "S02E03")
        self.assertEqual(by_title["Alpha Show"]["TVDB_ID"], "1")
        self.assertEqual(by_title["Beta Show"]["Watchlist"], "completed")
        self.assertEqual(by_title["Beta Show"]["LastEpWatched"], "")
        self.assertEqual(by_title["Gamma Show"]["Watchlist"], "dropped")
        self.assertEqual(by_title['Delta <Show>, "quoted"']["Watchlist"], "plan to watch")
        movie = by_title["Invented Movie"]
        self.assertEqual((movie["Type"], movie["IMDB_ID"], movie["Watchlist"], movie["WatchedDate"]),
                         ("movie", "tt0000001", "completed", "19:11:02 07-12-2019"))
        self.assertTrue(all(r["Watchlist"] in {"watching", "completed", "dropped", "plan to watch", "on hold"}
                            for r in rows))
        self.assertNotIn("Delta <Show>", html, "raw '<' must be escaped inside the page")
        self.assertIn("Delta \\u003cShow>", html)


if __name__ == "__main__":
    unittest.main()
