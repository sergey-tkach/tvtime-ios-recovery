# TV Time iOS Recovery

Get your TV Time watch history back from a local iPhone or iPad backup after the TV Time shutdown.

TV Time's servers are gone, but the app kept a local cache of what it last loaded: your series with
their status, episode progress, recently watched episodes and movies. This tool finds that cache in a
Finder / Apple Devices / iTunes backup, decrypts it, and gives you:

- a page to browse everything with posters (`TVTime.html`),
- spreadsheets (`series.csv`, `episodes.csv`, `movies.csv`) and `library.json`,
- a ready-to-import file for [Simkl](https://simkl.com) (`simkl_import.csv`).

One Python file, no dependencies, works offline, never modifies the backup.
Русская версия: [README.ru.md](README.ru.md).

## Before you start

- It only works if **TV Time is still installed** on the iPhone, or if you have a local backup made
  while it was installed. If the app was deleted, its cache is gone.
- Don't delete, reinstall or log out of the app before the backup is made.
- iCloud backups can't be used. You need a backup on a computer.

## 1. Back up the iPhone to a computer

**Mac:** connect the iPhone, open Finder, select the iPhone in the sidebar. On the *General* tab choose
*Back up all of the data on your iPhone to this Mac*, then *Back Up Now*.

**Windows:** install the Apple Devices app (or iTunes), connect the iPhone, choose to back up to
*this computer*, then *Back Up Now*.

Encrypted and unencrypted backups both work. If the backup is encrypted, you'll need its password.
Wait until the backup is finished.

## 2. Get Python and the script

- Python 3.9 or newer. On a Mac, run `python3 --version` in Terminal; if it's missing, install it from
  [python.org](https://www.python.org/downloads/). On Windows, install it from python.org or the
  Microsoft Store.
- Download [`tvtime_recover.py`](tvtime_recover.py) (the *Download raw file* button on GitHub), for
  example into Downloads.

## 3. Run it

**Mac** (Terminal):

```bash
cd ~/Downloads
python3 tvtime_recover.py
```

**Windows** (Command Prompt):

```bat
cd %USERPROFILE%\Downloads
py tvtime_recover.py
```

With Python from the Microsoft Store, use `python` instead of `py`.

The script finds the backup, asks for the backup password if it's encrypted, saves the results to a new
`TVTime-Recovery-<date>` folder in the current folder, and opens the page in your browser.

### macOS: "Terminal can't read the backup folder"

macOS blocks apps from reading `~/Library/Application Support/MobileSync`. Use one of these:

1. **Copy the backup (recommended).** Finder → iPhone → *Manage Backups…* → right-click the backup →
   *Show in Finder*. Select the folder with the long name, press ⌘C, open e.g. Documents and press ⌘V.
   On the same disk the copy is instant and takes no extra space. Then run:

   ```bash
   python3 tvtime_recover.py --backup ~/Documents/PASTE_THE_FOLDER_NAME
   ```

2. Or give Terminal *Full Disk Access* (System Settings → Privacy & Security → Full Disk Access), then
   restart Terminal.

### Options

| Option | What it does |
|---|---|
| `--backup DIR` | Use this backup folder (the one with `Manifest.db`) |
| `--output DIR` | Where to write the results (must not exist yet) |
| `--list-backups` | Show the backups found and exit |
| `--diocache PATH` | Skip the backup: read an extracted `DioCache.db` or a folder of TV Time's files |
| `--all-files` | Also copy the rest of TV Time's files into `raw/` (includes login tokens) |
| `--diagnose` | Print the cache structure without personal data, for bug reports |
| `--password-stdin` | Read the backup password from standard input |
| `--no-open` | Don't open the page in the browser |

## What you get

| File | Contents |
|---|---|
| `TVTime.html` | Browse series and movies with posters, filter by status, search, see recent episodes. English or Russian, following your browser language |
| `series.csv` | Every followed series: status, watched / aired episodes, last watched and next episode, dates, TVDB ID |
| `episodes.csv` | Episodes found in the cache, with watch date and time |
| `movies.csv` | Movies: watched, date, rewatches, IMDb ID |
| `simkl_import.csv` | Import file for Simkl, see below |
| `library.json` | Everything above in one structured file |
| `raw/`, `file_index.csv` | The app files copied from the backup and a list of them |

## What can and can't be recovered

The cache holds the last server responses the app loaded, so everything is as of that date (the page
shows it). In the TV Time 10.x cache this tool was developed on, that meant:

- **every series you follow**, with status *Watching*, *Up to date*, *Stopped* or *Not started*, the
  date you added it and the date you last watched it;
- *Up to date* means you had watched every episode aired by that date, so the progress of those series
  is complete;
- watched / aired counts and the next episode for series in the "continue watching" and
  "not watched for a while" lists;
- recently watched episodes with exact times, and watched movies with dates.

What's usually **not** in the cache: the dates you watched older individual episodes, the exact position
in *Watching* series that weren't in those lists, ratings, comments and custom lists.

Older app versions cached different responses, and some of them include a full per-episode history.
The tool also reads the older formats described by tvtime-backup-extractor. They're covered by tests with
invented data but haven't been checked against a real old backup yet.

## Moving to Simkl

1. Sign in to Simkl and open [simkl.com/apps/import/csv](https://simkl.com/apps/import/csv/).
2. Choose `simkl_import.csv`, keep *Use .csv data*, click *Upload and start import*.

| TV Time | Simkl |
|---|---|
| Watching | watching, with the last watched episode when it's known |
| Up to date | completed |
| Stopped | dropped |
| Not started | plan to watch |
| Watched movie | completed, with the watch date |

Series are matched by TVDB ID (TV Time's show IDs are TheTVDB IDs), movies by IMDb ID. The file follows
Simkl's documented CSV columns. For other services, start from `library.json` or the CSV files.

## Privacy

- Everything runs on your computer and nothing is uploaded. The page loads poster images from
  artworks.thetvdb.com when you open it.
- The backup is opened read-only. The password is used only in memory.
- `raw/` contains the app's cache, which includes your TV Time login tokens. The servers are gone, but
  don't share that folder. For bug reports, share only the `--diagnose` output: it lists field names and
  counts, not titles, dates or IDs.

## Troubleshooting

| Message | What to do |
|---|---|
| No backup with TV Time found | Make a local backup (step 1) or pass `--backup` |
| Terminal can't read the backup folder (macOS) | See the macOS section above |
| Wrong backup password | It's the password for encrypted local backups, not your Apple ID password |
| TV Time is not in this backup | The app wasn't installed when the backup was made |
| No TV Time library data was recognized | Run with `--diagnose` and open an issue with the output |
| Decryption is slow | No fast AES library was found, so a pure-Python fallback (about 1 MB/s) is decrypting the backup index. It takes a few minutes |

If you forgot the backup password, Apple's documented fix is to reset *all settings* on the iPhone
(Settings → General → Transfer or Reset iPhone → Reset → Reset All Settings). That removes the backup
password without deleting apps or data, but it also resets things like Wi-Fi networks and wallpaper.
Then make a new backup.

## How it works

1. **Backup.** `Manifest.db` indexes every file in the backup. In an encrypted backup it's AES-encrypted
   with a key wrapped by a class key from `Manifest.plist`'s keybag. The class keys are unlocked with the
   password: a slow PBKDF2-SHA256 round (iOS 10.2 and later), then PBKDF2-SHA1, then RFC 3394 AES key
   unwrap. Each file has its own wrapped AES-256-CBC key. iOS stores a fresh snapshot of SQLite
   databases, so their size in the index can be wrong; PKCS#7 padding gives the real length.
2. **Cache.** TV Time is a Flutter app. `Documents/DioCache.db` is an SQLite HTTP cache: table
   `cache_dio`, one JSON server response per row. Older versions also kept NSKeyedArchiver files with a
   request URL and a JSON body.
3. **Library.** The tool merges all recognized responses: followed-series lists, show progress
   (`shows`), profile season lists, episode lists (history, up next), movie lists and watch events. It
   skips data that belongs to other accounts (friends' profiles the app happened to cache).

AES comes from macOS CommonCrypto, from the OpenSSL library bundled with Python on Windows and Linux, or
from a pure-Python fallback. Each one must pass known-answer tests before it's used.

## Development

```bash
python3 -m unittest discover -s tests -v
```

The tests use invented data only. To test the other AES implementations, set
`TVTIME_AES_BACKEND=pure-python`, or `TVTIME_AES_BACKEND=openssl` with
`TVTIME_LIBCRYPTO=/path/to/libcrypto`. Never commit a real backup, cache or recovered output.

## Credits

- [tvtime-rescue-data](https://github.com/Marak123/tvtime-rescue-data) and
  [tvtime-backup-extractor](https://github.com/amirbrooks/tvtime-backup-extractor), which first
  documented where TV Time keeps its cache and what the responses look like.
- [iphone-dataprotection](https://code.google.com/archive/p/iphone-dataprotection/) and
  [iphone_backup_decrypt](https://github.com/jsharkey13/iphone_backup_decrypt), for the iOS backup
  encryption scheme.

Not affiliated with TV Time, Apple, Simkl or TheTVDB. Use it only on your own data.

## License

[MIT](LICENSE)
