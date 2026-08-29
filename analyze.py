"""Analyze results.jsonl -> summary.json + top1000-web-report.csv.

Denominator discipline:
  scanned            = every domain in the Tranco slice
  not_a_website      = DNS failure / SSRF-blocked / non-HTML  (CDN & infra domains)
  unreachable        = timeout / connection refused / geo-block
  blocked_inspection = API reached it but got a bot-challenge page (403 + bot flag)
  usable             = a real homepage we could read  <-- all header stats use THIS
"""
import csv
import json
import re
import statistics as st
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).parent
recs = [json.loads(l) for l in (HERE / "results.jsonl").open(encoding="utf-8")]

HEADERS = ["strict_transport_security", "content_security_policy", "x_frame_options",
           "x_content_type_options", "referrer_policy", "permissions_policy"]
PRESENT = {"weak", "reasonable", "strong", "report-only"}
VERSION_RE = re.compile(r"/\d|\d\.\d")
PLATFORMS = ["WordPress", "Shopify", "Wix", "Squarespace", "Drupal", "Joomla",
             "Webflow", "Ghost", "HubSpot", "Next.js", "Nuxt.js", "Gatsby",
             "Angular", "Vue.js", "React", "Svelte", "Astro", "Adobe Experience Manager"]


CHALLENGE_RE = re.compile(
    r"just a moment|attention required|client challenge|checking your browser|"
    r"request has been blocked|access denied|are you a (robot|human)|"
    r"verify you are human|visitor system|ddos-guard|please wait|security check|"
    r"one more step|захист|проверка|robot check", re.I)


def classify(r):
    if r.get("api_ok") and r.get("security_header_grades"):
        sc = r.get("status_code") or 0
        if r.get("bot_protection_detected") or sc in (401, 403) or CHALLENGE_RE.search(r.get("title") or ""):
            return "blocked_inspection"
        if not (200 <= sc < 300):
            return "unreachable"
        # degraded/placeholder page (big sites serving a stub to non-browsers)
        if ((r.get("content_length_bytes") or 0) < 2500 and (r.get("h1_count") or 0) <= 1
                and not r.get("has_description") and not (r.get("detected_technologies"))):
            return "thin_page"
        return "usable"
    err = (r.get("api_error") or "") + (r.get("raw_error") or "")
    if any(x in err for x in ("DNS", "SSRF", "content type", "content-type")):
        return "not_a_website"
    if any(x in err for x in ("timeout", "Timeout", "CONNECTION", "ConnectError", "ReadError")):
        return "unreachable"
    if "40" in err or "42" in err:  # 401/403/404/421 on a real host
        return "unreachable"
    return "unreachable"


for r in recs:
    r["_class"] = classify(r)
usable = [r for r in recs if r["_class"] == "usable"]


def platform_of(rec):
    tech = set(rec.get("detected_technologies") or [])
    for p in PLATFORMS:
        if p in tech:
            return p
    return "No CMS/framework detected" if not tech else "Other (analytics/CDN only)"


def scores(vals):
    vals = [v for v in vals if v is not None]
    if not vals:
        return {}
    return {"n": len(vals), "mean": round(st.mean(vals), 1), "median": round(st.median(vals), 1),
            "p25": round(sorted(vals)[len(vals)//4], 1), "p75": round(sorted(vals)[3*len(vals)//4], 1),
            "pct_zero": round(100*sum(v == 0 for v in vals)/len(vals), 1),
            "pct_ge_70": round(100*sum(v >= 70 for v in vals)/len(vals), 1)}


S = {}
S["coverage"] = dict(Counter(r["_class"] for r in recs))
S["coverage"]["scanned"] = len(recs)

hdr = {}
for h in HEADERS:
    c = Counter(r["security_header_grades"].get(h, "missing") for r in usable)
    hdr[h] = {"pct_present": round(100*sum(c[g] for g in PRESENT)/len(usable), 1),
              "pct_missing": round(100*c["missing"]/len(usable), 1),
              "grades": dict(c)}
S["header_adoption"] = hdr
S["n_headers_present_dist"] = dict(sorted(Counter(
    sum(1 for h in HEADERS if r["security_header_grades"].get(h) in PRESENT) for r in usable).items()))
S["pct_zero_headers"] = round(100*S["n_headers_present_dist"].get(0, 0)/len(usable), 1)

S["security_score"] = scores([r["security_score_percentage"] for r in usable])
S["seo_score"] = scores([r["seo_score_percentage"] for r in usable])
S["seo_vs_security_pearson"] = None
try:
    a = [r["seo_score_percentage"] for r in usable]
    b = [r["security_score_percentage"] for r in usable]
    S["seo_vs_security_pearson"] = round(st.correlation(a, b), 3)
except Exception:
    pass

byp = defaultdict(list)
for r in usable:
    byp[platform_of(r)].append(r)
S["by_platform"] = {p: {"n": len(rs),
                        "median_security": round(st.median([x["security_score_percentage"] for x in rs]), 1),
                        "median_seo": round(st.median([x["seo_score_percentage"] for x in rs]), 1),
                        "pct_no_csp": round(100*sum(1 for x in rs if x["security_header_grades"].get("content_security_policy") == "missing")/len(rs), 1),
                        "pct_has_hsts": round(100*sum(1 for x in rs if x["security_header_grades"].get("strict_transport_security") in PRESENT)/len(rs), 1)}
                    for p, rs in sorted(byp.items(), key=lambda kv: -len(kv[1])) if len(rs) >= 8}

tc = Counter()
for r in usable:
    tc.update(r.get("detected_technologies") or [])
S["top_technologies"] = tc.most_common(20)

srv, leak, tot = Counter(), 0, 0
for r in usable:
    s = r.get("server_header")
    if s:
        tot += 1
        srv[s.split("/")[0].split(" ")[0].strip()[:24] or "(blank)"] += 1
        if VERSION_RE.search(s):
            leak += 1
S["server_header"] = {"n_with_header": tot, "n_usable": len(usable),
                      "pct_leaking_version": round(100*leak/tot, 1) if tot else 0,
                      "top": srv.most_common(12)}
S["x_powered_by"] = {"pct_present": round(100*sum(1 for r in usable if r.get("x_powered_by"))/len(usable), 1),
                     "top": Counter(r["x_powered_by"] for r in usable if r.get("x_powered_by")).most_common(10)}

(HERE / "summary.json").write_text(json.dumps(S, indent=2, ensure_ascii=False), encoding="utf-8")

with (HERE / "top1000-web-report.csv").open("w", newline="", encoding="utf-8") as fh:
    w = csv.writer(fh)
    w.writerow(["rank", "domain", "class", "final_url", "security_score", "seo_score", "platform",
                "detected_technologies", "server", "x_powered_by", *[f"grade_{h}" for h in HEADERS]])
    for r in sorted(recs, key=lambda x: x["rank"]):
        g = r.get("security_header_grades") or {}
        fu = (r.get("final_url") or "").split("?")[0].split("#")[0]
        w.writerow([r["rank"], r["domain"], r["_class"], fu,
                    r.get("security_score_percentage", ""), r.get("seo_score_percentage", ""),
                    platform_of(r) if r["_class"] == "usable" else "",
                    "|".join(r.get("detected_technologies") or []),
                    r.get("server_header") or "", r.get("x_powered_by") or "",
                    *[g.get(h, "") for h in HEADERS]])

print(json.dumps(S, indent=2, ensure_ascii=False))
