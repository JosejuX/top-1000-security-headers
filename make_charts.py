"""Render the 5 report charts as PNGs (light surface, readable on any bg)."""
import json
import re
import statistics as st
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.font_manager as fm
import matplotlib.pyplot as plt
import numpy as np

HERE = Path(__file__).parent
OUT = HERE / "charts"
OUT.mkdir(exist_ok=True)

SURFACE = "#fcfcfb"; INK = "#0b0b0b"; INK2 = "#52514e"; MUTED = "#898781"
GRID = "#e1e0d9"; BASE = "#c3c2b7"; BLUE = "#2a78d6"; RED = "#d03b3b"

for cand in ("Segoe UI", "Inter", "DejaVu Sans"):
    if any(f.name == cand for f in fm.fontManager.ttflist):
        plt.rcParams["font.family"] = cand
        break
plt.rcParams.update({
    "figure.facecolor": SURFACE, "axes.facecolor": SURFACE, "savefig.facecolor": SURFACE,
    "text.color": INK, "axes.labelcolor": INK2, "xtick.color": MUTED, "ytick.color": INK2,
    "axes.edgecolor": BASE, "axes.linewidth": 0.8, "font.size": 11,
})

recs = [json.loads(l) for l in (HERE / "results.jsonl").open(encoding="utf-8")]
S = json.load((HERE / "summary.json").open(encoding="utf-8"))

PLATFORMS = ["WordPress", "Next.js", "Nuxt.js", "Angular", "React", "Drupal", "Astro"]
def platform_of(r):
    tech = set(r.get("detected_technologies") or [])
    for p in PLATFORMS:
        if p in tech:
            return p
    return "No framework detected" if not tech else "Other"

_CHALLENGE = re.compile(r"just a moment|attention required|client challenge|checking your browser|"
                        r"request has been blocked|access denied|are you a (robot|human)|"
                        r"verify you are human|visitor system|ddos-guard|please wait|security check|"
                        r"one more step|захист|проверка|robot check", re.I)


def is_usable(r):
    if not (r.get("api_ok") and r.get("security_header_grades")):
        return False
    sc = r.get("status_code") or 0
    if r.get("bot_protection_detected") or sc in (401, 403) or not (200 <= sc < 300):
        return False
    if _CHALLENGE.search(r.get("title") or ""):
        return False
    if ((r.get("content_length_bytes") or 0) < 2500 and (r.get("h1_count") or 0) <= 1
            and not r.get("has_description") and not r.get("detected_technologies")):
        return False
    return True

U = [r for r in recs if is_usable(r)]
N = len(U)
SRC = f"Web Metadata & Contact Extractor API  ·  Tranco top 1,000  ·  {N} reachable homepages  ·  Aug 2026"


def canvas(title, h=4.6, sub=None, left=0.32):
    fig, ax = plt.subplots(figsize=(8.6, h))
    fig.subplots_adjust(top=0.72, left=left, right=0.965, bottom=0.20)
    fig.text(0.022, 0.955, title, fontsize=13.5, fontweight="bold", color=INK, va="top")
    if sub:
        fig.text(0.022, 0.875, sub, fontsize=10.5, color=INK2, va="top")
    fig.text(0.022, 0.045, SRC, fontsize=8.5, color=MUTED, va="top")
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    ax.set_axisbelow(True)
    ax.xaxis.labelpad = 8
    return fig, ax

def save(fig, name):
    fig.savefig(OUT / name, dpi=170)
    plt.close(fig)
    print("wrote", name)


# 1 --- header adoption --------------------------------------------------
labels = {"strict_transport_security": "Strict-Transport-Security", "x_frame_options": "X-Frame-Options",
          "x_content_type_options": "X-Content-Type-Options", "content_security_policy": "Content-Security-Policy",
          "referrer_policy": "Referrer-Policy", "permissions_policy": "Permissions-Policy"}
ha = sorted(S["header_adoption"].items(), key=lambda kv: kv[1]["pct_present"])
fig, ax = canvas("Security-header adoption across the web's top 1,000 sites",
                 sub="Share of sites that send each header. Only HSTS has crossed 50%.", left=0.30)
ys = range(len(ha))
ax.barh(list(ys), [v["pct_present"] for _, v in ha], color=BLUE, height=0.6)
ax.set_yticks(list(ys), [labels[k] for k, _ in ha])
ax.set_xlim(0, 100); ax.set_xlabel("% of sites sending the header")
ax.xaxis.grid(True, color=GRID, linewidth=0.8)
for i, (_, v) in enumerate(ha):
    ax.text(v["pct_present"] + 1.5, i, f'{v["pct_present"]:.0f}%', va="center", fontsize=10, color=INK)
save(fig, "01-header-adoption.png")

# 2 --- score distribution ---------------------------------------------
scores = [r["security_score_percentage"] for r in U]
med = st.median(scores)
fig, ax = canvas("Security-header score across the top 1,000 sites",
                 sub=f"0-100, graded on header presence and strength. Median {med:.0f}. Only {S['security_score']['pct_ge_70']:.0f}% score 70 or above.", left=0.12)
ax.hist(scores, bins=[i * 10 for i in range(11)], color=BLUE, edgecolor=SURFACE, linewidth=1.5)
ax.axvline(med, color=RED, linewidth=2)
ax.text(med + 2, ax.get_ylim()[1] * 0.92, f"median {med:.0f}", color=RED, fontsize=10, fontweight="bold")
ax.set_xlabel("Security-header score"); ax.set_ylabel("Number of sites")
ax.yaxis.grid(True, color=GRID, linewidth=0.8)
save(fig, "02-score-distribution.png")

# 3 --- median security score by platform ----------------------------
bp = {p: v for p, v in S["by_platform"].items() if v["n"] >= 15}
order = sorted(bp.items(), key=lambda kv: -kv[1]["median_security"])
fig, ax = canvas("WordPress sites are the security-header laggards of the top 1,000", h=4.2,
                 sub="Median security-header score by detected platform (groups with n≥15).", left=0.34)
ys = range(len(order))
ax.barh(list(ys), [v["median_security"] for _, v in order],
        color=[RED if p == "WordPress" else BLUE for p, _ in order], height=0.58)
ax.set_yticks(list(ys), [f'{p}  (n={v["n"]})' for p, v in order])
ax.invert_yaxis()
ax.axvline(med, color=MUTED, linewidth=1.3, linestyle=(0, (4, 3)))
ax.set_xlim(0, 46); ax.set_xlabel("Median security-header score")
ax.xaxis.grid(True, color=GRID, linewidth=0.8)
for i, (_, v) in enumerate(order):
    ax.text(v["median_security"] + 0.8, i, f'{v["median_security"]:.0f}', va="center", fontsize=10, color=INK)
ax.text(med + 0.6, -0.75, f"all-sites median {med:.0f}", color=INK2, fontsize=9)
save(fig, "03-security-by-platform.png")

# 4 --- SEO vs security ---------------------------------------------
xs = [r["seo_score_percentage"] for r in U]
ysc = [r["security_score_percentage"] for r in U]
r_pear = S["seo_vs_security_pearson"]
fig, ax = canvas("Teams that invest in SEO mostly don't invest in security headers", h=5.2,
                 sub=f"One dot per site, {N} sites. Pearson r = {r_pear:.2f} (SEO median 75, security median {med:.0f}).", left=0.12)
ax.scatter(xs, ysc, s=20, color=BLUE, alpha=0.30, edgecolors="none")
m, b = np.polyfit(xs, ysc, 1)
xr = np.array([min(xs), max(xs)])
ax.plot(xr, m * xr + b, color=RED, linewidth=2)
ax.set_xlabel("SEO score"); ax.set_ylabel("Security-header score")
ax.set_xlim(0, 104); ax.set_ylim(-4, 95)
ax.grid(True, color=GRID, linewidth=0.8)
save(fig, "04-seo-vs-security.png")
print("done")
