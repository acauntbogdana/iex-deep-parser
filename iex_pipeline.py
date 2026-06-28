import os
import sys
import time
import shutil
import logging
import threading
from datetime import date, timedelta
from urllib.parse import quote
from concurrent.futures import ThreadPoolExecutor, as_completed

import subprocess
import requests

# ──────────────────────────────────────────────
# CONFIGURATION
# ──────────────────────────────────────────────
BASE_DIR      = r"C:\IEX"                              # <- adjust this to your environment
DOWNLOAD_DIR  = os.path.join(BASE_DIR, "download")      # Latin-only path recommended
OUTPUT_DIR    = os.path.join(BASE_DIR, "output")

START_DATE    = date(2021, 1, 4)
END_DATE      = date(2026, 6, 23)

# Path to the compiled Rust binary.
# After `cargo build --release` it will be located relative to this script.
SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
RUST_PARSER  = os.path.join(SCRIPT_DIR, "iex_deep_parser", "target", "release", "iex-deep-parser.exe")

MAX_QUEUED_FILES  = 2
DOWNLOAD_WORKERS  = 3
MAX_RETRIES       = 5
RETRY_BACKOFF     = 2
REQUEST_DELAY_SEC = 0.5

FEED_CANDIDATES = [
    ("DEEP1.0", "DEEP_1_0"),
    ("DEEP",    "DEEP_1_0"),
]

# ──────────────────────────────────────────────
# LOGGING – terminal only
# ──────────────────────────────────────────────
log_formatter = logging.Formatter(
    "%(asctime)s  %(levelname)-8s  %(threadName)-18s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(log_formatter)
console_handler.setLevel(logging.DEBUG)

log = logging.getLogger("IEX")
log.setLevel(logging.DEBUG)
log.addHandler(console_handler)


def _fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def free_space_gb(path: str) -> float:
    return shutil.disk_usage(path).free / 1024 ** 3


# ──────────────────────────────────────────────
# HTTP session (per-thread)
# ──────────────────────────────────────────────
_tls = threading.local()

def get_session() -> requests.Session:
    if not hasattr(_tls, "session"):
        _tls.session = requests.Session()
    return _tls.session


# ──────────────────────────────────────────────
# DOWNLOAD
# ──────────────────────────────────────────────
def robust_download(url: str, dest_path: str, expected_size: int | None = None,
                    timeout: int = 120) -> None:
    tmp = dest_path + ".part"
    for attempt in range(MAX_RETRIES):
        resume = os.path.getsize(tmp) if os.path.exists(tmp) else 0
        if expected_size and resume > expected_size:
            os.remove(tmp)
            resume = 0

        headers = {"Range": f"bytes={resume}-"} if resume else {}
        try:
            with get_session().get(url, stream=True, timeout=timeout, headers=headers) as resp:
                if resume and resp.status_code == 416:
                    log.warning("Resume offset invalid, restarting")
                    os.remove(tmp)
                    raise IOError("invalid resume offset")
                if resume and resp.status_code == 200:
                    log.info("Server does not support resume, starting from scratch")
                    resume = 0
                resp.raise_for_status()

                total_so_far = resume
                last_log = time.monotonic()
                mode = "ab" if resume else "wb"
                with open(tmp, mode) as f:
                    for chunk in resp.iter_content(chunk_size=1024 * 1024):
                        if chunk:
                            f.write(chunk)
                            total_so_far += len(chunk)
                            now = time.monotonic()
                            if now - last_log >= 10:
                                pct = (
                                    f"{total_so_far / expected_size * 100:.1f}%"
                                    if expected_size else _fmt_bytes(total_so_far)
                                )
                                log.info("  → downloaded %s (%s)", _fmt_bytes(total_so_far), pct)
                                last_log = now

            actual = os.path.getsize(tmp)
            if expected_size and actual != expected_size:
                raise IOError(f"Size mismatch: expected {expected_size}, got {actual}")
            os.replace(tmp, dest_path)
            log.info("  ✓ Downloaded: %s", _fmt_bytes(actual))
            return

        except (requests.RequestException, IOError, OSError) as exc:
            if attempt == MAX_RETRIES - 1:
                raise
            wait = RETRY_BACKOFF ** attempt
            suffix = f" (resumed from {_fmt_bytes(resume)})" if resume else ""
            log.warning("Download error (attempt %d/%d): %s%s — retrying in %d s",
                        attempt + 1, MAX_RETRIES, exc, suffix, wait)
            time.sleep(wait)


def get_download_url(d: date, feed_label: str) -> tuple[str | None, int | None]:
    """
    Obtains a direct download URL via GCS metadata API.
    Returns (url, size) or (None, None) if the file is unavailable.
    """
    ds = d.strftime("%Y%m%d")
    obj = f"data/feeds/{ds}/{ds}_IEXTP1_{feed_label}.pcap.gz"
    obj_encoded = quote(obj, safe='')
    meta_url = f"https://www.googleapis.com/storage/v1/b/iex/o/{obj_encoded}"
    try:
        resp = get_session().get(meta_url, timeout=15)
        if not resp.ok:
            return None, None
        meta = resp.json()
        generation = meta.get("generation", "")
        size = int(meta.get("size", 0)) or None
        url = f"https://www.googleapis.com/download/storage/v1/b/iex/o/{obj_encoded}?generation={generation}&alt=media"
        return url, size
    except Exception as exc:
        log.debug("  Metadata request failed for %s: %s", feed_label, exc)
        return None, None


def try_download(d: date) -> tuple[str | None, str | None]:
    for feed_label, version_const in FEED_CANDIDATES:
        time.sleep(REQUEST_DELAY_SEC)
        url, expected_size = get_download_url(d, feed_label)
        if url is None:
            log.debug("  %s unavailable for %s", feed_label, d)
            continue

        size_str = _fmt_bytes(expected_size) if expected_size else "unknown size"
        filename  = f"{d.strftime('%Y%m%d')}_IEXTP1_{feed_label}.pcap.gz"
        tmp_path  = os.path.join(DOWNLOAD_DIR, filename)
        dest_path = os.path.join(DOWNLOAD_DIR, f"{d.strftime('%Y%m%d')}.pcap.gz")

        log.info("  Found %s (%s) — starting download...", feed_label, size_str)
        try:
            robust_download(url, tmp_path, expected_size=expected_size)
        except Exception as exc:
            log.error("  Failed to download %s: %s", feed_label, exc)
            continue

        for fl, _ in FEED_CANDIDATES:
            stray = os.path.join(DOWNLOAD_DIR, f"{d.strftime('%Y%m%d')}_IEXTP1_{fl}.pcap.gz.part")
            if os.path.exists(stray):
                try:
                    os.remove(stray)
                except OSError:
                    pass

        shutil.move(tmp_path, dest_path)
        return dest_path, version_const

    return None, None


# ──────────────────────────────────────────────
# PARSING & CONVERSION
# ──────────────────────────────────────────────
def process_pcap(pcap_gz_path: str, output_parquet_path: str) -> int:
    """
    Calls the Rust binary iex-deep-parser to convert pcap.gz → Parquet.
    Returns the number of rows written.
    """
    if not os.path.exists(RUST_PARSER):
        raise FileNotFoundError(
            f"Rust binary not found: {RUST_PARSER}\n"
            f"Build it with:\n"
            f"  cd iex_deep_parser && cargo build --release"
        )

    cmd = [RUST_PARSER, pcap_gz_path, output_parquet_path]
    log.debug("  Running: %s", " ".join(cmd))

    result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")

    for line in result.stderr.splitlines():
        if line.strip():
            log.info("  %s", line)

    if result.returncode != 0:
        raise RuntimeError(
            f"iex-deep-parser exited with code {result.returncode}\n"
            f"STDOUT: {result.stdout[-1000:]}\n"
            f"STDERR: {result.stderr[-1000:]}"
        )

    total = 0
    for line in result.stderr.splitlines():
        if "Rows written" in line:               # match the Rust binary's output
            nums = "".join(c for c in line if c.isdigit())
            if nums:
                total = int(nums)
            break

    return total


# ──────────────────────────────────────────────
# QUEUE & THREADS
# ──────────────────────────────────────────────
ready_files   = {}
ready_cond    = threading.Condition()
download_sema = threading.Semaphore(MAX_QUEUED_FILES)
stop_event    = threading.Event()


def mark_ready(d: date, ver: str | None) -> None:
    with ready_cond:
        ready_files[d] = ver
        ready_cond.notify_all()


def download_task(d: date) -> None:
    threading.current_thread().name = f"DL-{d.isoformat()}"
    if stop_event.is_set():
        return
    download_sema.acquire()
    if stop_event.is_set():
        download_sema.release()
        return

    dest_path = os.path.join(DOWNLOAD_DIR, f"{d.strftime('%Y%m%d')}.pcap.gz")
    if os.path.exists(dest_path):
        log.info("[%s] File already exists, skipping download", d)
        mark_ready(d, "DEEP_1_0")
        return

    log.info("[%s] ▶ Starting download  |  free: %.1f GB", d, free_space_gb(BASE_DIR))
    try:
        path, ver = try_download(d)
        if path:
            log.info("[%s] ✓ Downloaded", d)
            mark_ready(d, ver)
        else:
            log.warning("[%s] File not found in any feed variant", d)
            mark_ready(d, None)
    except Exception as exc:
        log.error("[%s] Critical download error: %s", d, exc, exc_info=True)
        mark_ready(d, None)


def processor_worker(dates: list[date]) -> None:
    threading.current_thread().name = "Processor"
    log.info("[Processor] Started, waiting for %d dates", len(dates))

    for d in dates:
        with ready_cond:
            while d not in ready_files:
                if stop_event.is_set():
                    return
                ready_cond.wait(timeout=2)
            ver = ready_files.pop(d)

        if ver is None:
            log.warning("[Processor] %s — file unavailable, skipping", d)
            download_sema.release()
            continue

        dest_path = os.path.join(DOWNLOAD_DIR, f"{d.strftime('%Y%m%d')}.pcap.gz")

        waited = 0
        while not os.path.exists(dest_path):
            if stop_event.is_set():
                return
            time.sleep(0.5)
            waited += 0.5
            if waited > 30:
                log.error("[Processor] File never appeared: %s", dest_path)
                break

        if not os.path.exists(dest_path):
            download_sema.release()
            continue

        output_path = os.path.join(OUTPUT_DIR, f"{d.isoformat()}.parquet")
        log.info("\n" + "═" * 60)
        log.info("[Processor] ▶ %s  |  free: %.1f GB", d.isoformat(), free_space_gb(BASE_DIR))
        log.info("═" * 60)

        success = False
        try:
            t_start = time.monotonic()
            total   = process_pcap(dest_path, output_path)
            elapsed = time.monotonic() - t_start
            if total > 0:
                log.info(
                    "[Processor] ✓ %s — %s rows in %.0f s  (%.0f rows/s)",
                    d.isoformat(), f"{total:,}", elapsed, total / elapsed,
                )
            else:
                log.warning("[Processor] %s — empty result", d.isoformat())
            success = True
        except Exception as exc:
            log.error(
                "[Processor] ✗ Error %s: %s\n  pcap.gz kept: %s",
                d.isoformat(), exc, dest_path, exc_info=True,
            )
        finally:
            if success and os.path.exists(dest_path):
                os.remove(dest_path)
                log.debug("[Processor] Removed pcap.gz: %s", dest_path)
            elif not success and os.path.exists(dest_path):
                log.info("[Processor] ⚠ pcap.gz kept (error): %s", dest_path)
            download_sema.release()


# ──────────────────────────────────────────────
# ENTRY POINT
# ──────────────────────────────────────────────
def main() -> None:
    for d in (DOWNLOAD_DIR, OUTPUT_DIR):
        os.makedirs(d, exist_ok=True)

    dates_to_process: list[date] = []
    current = START_DATE
    while current <= END_DATE:
        out = os.path.join(OUTPUT_DIR, f"{current.isoformat()}.parquet")
        if not os.path.exists(out):
            dates_to_process.append(current)
        current += timedelta(days=1)

    if not dates_to_process:
        log.info("All files already processed. Exiting.")
        return

    pending_set = set(dates_to_process)
    removed = 0
    for fname in os.listdir(DOWNLOAD_DIR):
        if not fname.endswith(".part"):
            continue
        try:
            fd = date(int(fname[:4]), int(fname[4:6]), int(fname[6:8]))
        except Exception:
            continue
        if fd not in pending_set:
            try:
                os.remove(os.path.join(DOWNLOAD_DIR, fname))
                removed += 1
            except OSError:
                pass
    if removed:
        log.info("Removed stale .part files: %d", removed)

    log.info("Dates to process: %d  (%s — %s)",
             len(dates_to_process), dates_to_process[0], dates_to_process[-1])
    log.info("Free disk space: %.1f GB", free_space_gb(BASE_DIR))

    proc_thread = threading.Thread(
        target=processor_worker, args=(dates_to_process,), name="Processor", daemon=True,
    )
    proc_thread.start()

    with ThreadPoolExecutor(max_workers=DOWNLOAD_WORKERS) as executor:
        futures = {executor.submit(download_task, d): d for d in dates_to_process}
        for future in as_completed(futures):
            exc = future.exception()
            if exc:
                log.error("Download thread %s finished with exception: %s", futures[future], exc)

    proc_thread.join()
    log.info("\n" + "═" * 60)
    log.info("✓ Pipeline finished.")
    log.info("═" * 60)


if __name__ == "__main__":
    main()
