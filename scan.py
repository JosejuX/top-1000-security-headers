"""
Top-N web report scanner (v2).

Runs the local Web Metadata & Contact Extractor API against the Tranco top-N
domains. Per site, records security header grades, security/seo scores,
detected technologies, bot-protection flag, inner HTTP status, and the raw
Server / X-Powered-By headers (captured directly, since the API response is
JSON and doesn't echo the target's own headers).

- Tries https://<domain>; on hard failure retries https://www.<domain>.
- One retry on timeout.
- `usable` is decided in analyze.py, not here; this script records everything.

Output: results.jsonl (one JSON object per line, including failures).
"""
import asyncio
import json
import sys
import time
import zipfile
from pathlib import Path

import httpx

HERE = Path(__file__).parent
API = "http://127.0.0.1:8899/api/v1/extract"
FIELDS = ",".join([
    "security_headers", "security_score_percentage", "security_header_grades",
    "detected_technologies", "technology_details", "seo_score_percentage",
    "bot_protection_detected", "metadata",
])
N = int(sys.argv[1]) if len(sys.argv) > 1 else 1000
CONCURRENCY = 12
API_TIMEOUT = 40.0
RAW_TIMEOUT = 15.0
OUT = HERE / "results.jsonl"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"


def load_domains(n):
    with zipfile.ZipFile(HERE / "tranco.zip") as z:
        with z.open(z.namelist()[0]) as f:
            out = []
            for line in f:
                rank, domain = line.decode().strip().split(",", 1)
                out.append((int(rank), domain))
                if len(out) >= n:
                    break
    return out


async def call_api(client, url):
    for attempt in (1, 2):
        try:
            r = await client.get(API, params={"url": url, "fields": FIELDS}, timeout=API_TIMEOUT)
            if r.status_code == 200:
                return r.json(), None
            return None, f"HTTP {r.status_code}: {r.text[:180]}"
        except (httpx.ReadTimeout, httpx.ConnectTimeout, httpx.PoolTimeout) as e:
            if attempt == 2:
                return None, f"{type(e).__name__}"
        except Exception as e:
            return None, f"{type(e).__name__}: {e}"[:180]
    return None, "timeout"


async def raw_headers(client, url):
    try:
        r = await client.get(url, timeout=RAW_TIMEOUT, follow_redirects=True,
                             headers={"User-Agent": UA})
        return {"raw_status": r.status_code, "server_header": r.headers.get("server"),
                "x_powered_by": r.headers.get("x-powered-by"), "raw_final_url": str(r.url)}
    except Exception as e:
        return {"raw_error": f"{type(e).__name__}"}


def looks_hard_fail(err):
    return err and any(x in err for x in ("DNS", "404", "SSL", "CERTIFICATE", "421", "ConnectError"))


def looks_thin(data):
    """API returned a page, but it looks like a redirect stub / edge placeholder
    rather than the real homepage (big apex sites often serve these to non-browsers)."""
    if data is None:
        return False
    md = data.get("metadata") or {}
    return (md.get("h1_count") == 0 and not md.get("description")
            and (md.get("content_length_bytes") or 0) < 1500
            and not (data.get("detected_technologies")))


async def scan_one(capi, craw, sem, rank, domain):
    rec = {"rank": rank, "domain": domain}
    async with sem:
        t0 = time.time()
        rec.update(await raw_headers(craw, f"https://{domain}"))
        data, err = await call_api(capi, f"https://{domain}")
        tried_www = False
        if not domain.startswith("www.") and ((err and looks_hard_fail(err)) or looks_thin(data)):
            tried_www = True
            data2, _ = await call_api(capi, f"https://www.{domain}")
            if data2 is not None and not looks_thin(data2):
                data, err = data2, None
                r2 = await raw_headers(craw, f"https://www.{domain}")
                if "server_header" in r2:
                    rec.update(r2)
        rec["tried_www"] = tried_www
        if data is not None:
            md = data.get("metadata") or {}
            rec.update({
                "api_ok": True,
                "status_code": data.get("status_code"),
                "final_url": data.get("final_url"),
                "bot_protection_detected": data.get("bot_protection_detected"),
                "security_headers": data.get("security_headers"),
                "security_header_grades": data.get("security_header_grades"),
                "security_score_percentage": data.get("security_score_percentage"),
                "detected_technologies": data.get("detected_technologies"),
                "technology_details": data.get("technology_details"),
                "seo_score_percentage": data.get("seo_score_percentage"),
                "title": md.get("title"),
                "has_description": bool(md.get("description")),
                "h1_count": md.get("h1_count"),
                "content_length_bytes": md.get("content_length_bytes"),
            })
        else:
            rec["api_ok"] = False
            rec["api_error"] = err
        rec["elapsed_s"] = round(time.time() - t0, 2)
    return rec


async def main():
    domains = load_domains(N)
    sem = asyncio.Semaphore(CONCURRENCY)
    total, done, t_start = len(domains), 0, time.time()
    limits = httpx.Limits(max_connections=CONCURRENCY * 3, max_keepalive_connections=CONCURRENCY)
    fh = OUT.open("w", encoding="utf-8")
    async with httpx.AsyncClient(limits=limits) as capi, \
               httpx.AsyncClient(limits=limits, verify=False) as craw:
        tasks = [scan_one(capi, craw, sem, r, d) for r, d in domains]
        for coro in asyncio.as_completed(tasks):
            rec = await coro
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
            fh.flush()
            done += 1
            if done % 50 == 0 or done == total:
                rate = done / (time.time() - t_start)
                print(f"  {done}/{total}  ({rate:.1f}/s, ETA {(total-done)/rate/60:.1f} min)", flush=True)
    fh.close()
    print(f"Done: {total} sites in {(time.time()-t_start)/60:.1f} min -> {OUT}")


if __name__ == "__main__":
    asyncio.run(main())
