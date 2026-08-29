"""Build docs/data.js (embedded summary + per-domain rows) from the scan output + summary.json."""
import gzip
import json
import re
from pathlib import Path

HERE = Path(__file__).parent


def load_results():
    for p in (HERE / "results.jsonl", HERE / "data" / "results.jsonl.gz"):
        if p.exists():
            op = gzip.open if p.suffix == ".gz" else open
            with op(p, "rt", encoding="utf-8") as f:
                return [json.loads(l) for l in f]
    raise SystemExit("need results.jsonl (run scan.py) or data/results.jsonl.gz")
CH = re.compile(r"just a moment|attention required|client challenge|checking your browser|"
                r"request has been blocked|access denied|are you a (robot|human)|"
                r"verify you are human|visitor system|ddos-guard|please wait|security check|"
                r"one more step|robot check", re.I)
PLAT = ["WordPress", "Next.js", "Nuxt.js", "Angular", "React", "Drupal", "Astro", "Vue.js",
        "Svelte", "Shopify", "Wix", "Squarespace", "Gatsby", "Webflow", "Ghost"]
G = ["strict_transport_security", "content_security_policy", "x_frame_options",
     "x_content_type_options", "referrer_policy", "permissions_policy"]
GMAP = {"missing": 0, "weak": 1, "report-only": 1, "reasonable": 2, "strong": 3}


def platform(r):
    t = set(r.get("detected_technologies") or [])
    for p in PLAT:
        if p in t:
            return p
    return "" if not t else "other"


def klass(r):
    if r.get("api_ok") and r.get("security_header_grades"):
        sc = r.get("status_code") or 0
        if r.get("bot_protection_detected") or sc in (401, 403) or CH.search(r.get("title") or ""):
            return "blocked"
        if not (200 <= sc < 300):
            return "unreachable"
        if ((r.get("content_length_bytes") or 0) < 2500 and (r.get("h1_count") or 0) <= 1
                and not r.get("has_description") and not r.get("detected_technologies")):
            return "thin"
        return "usable"
    e = (r.get("api_error") or "") + (r.get("raw_error") or "")
    if any(x in e for x in ("DNS", "SSRF", "content type", "content-type")):
        return "infra"
    return "unreachable"


recs = load_results()
summary = json.loads((HERE / "summary.json").read_text(encoding="utf-8"))
rows = []
for r in sorted(recs, key=lambda x: x["rank"]):
    c = klass(r)
    g = r.get("security_header_grades") or {}
    rows.append({
        "r": r["rank"], "d": r["domain"], "c": c,
        "sec": r.get("security_score_percentage"), "seo": r.get("seo_score_percentage"),
        "p": platform(r) if c == "usable" else "",
        "srv": (r.get("server_header") or "").split("/")[0].split(" ")[0][:24],
        "g": [GMAP.get(g.get(k, "missing"), 0) for k in G] if c == "usable" else None,
    })

out = HERE / "docs" / "data.js"
out.parent.mkdir(exist_ok=True)
out.write_text("window.REPORT=" + json.dumps({"summary": summary, "rows": rows},
               separators=(",", ":"), ensure_ascii=False) + ";\n", encoding="utf-8")
print("wrote", out, "-", sum(r["c"] == "usable" for r in rows), "usable of", len(rows))
