"""Render docs/social-card.png (1200x630 OG image) from summary.json."""
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.font_manager as fm
import matplotlib.pyplot as plt

HERE = Path(__file__).parent
S = json.loads((HERE / "summary.json").read_text(encoding="utf-8"))

SURFACE = "#fcfcfb"; INK = "#0b0b0b"; INK2 = "#52514e"; MUTED = "#898781"
GRID = "#e1e0d9"; BLUE = "#2a78d6"; RED = "#d03b3b"

for cand in ("Segoe UI", "Inter", "DejaVu Sans"):
    if any(f.name == cand for f in fm.fontManager.ttflist):
        plt.rcParams["font.family"] = cand
        break

fig = plt.figure(figsize=(12, 6.3), dpi=100)
fig.patch.set_facecolor(SURFACE)

fig.text(0.055, 0.88, "DATA STUDY  ·  AUGUST 2026", fontsize=13, color=MUTED,
         fontweight="bold", va="top")
fig.text(0.055, 0.80, "Security headers of the\ntop 1,000 websites", fontsize=42,
         color=INK, fontweight="bold", va="top", linespacing=1.1)

# two headline stat blocks
stats = [
    (str(round(S["security_score"]["median"])) + " / 100", "median security-\nheader score"),
    ("~82%", "no browser-enforced\nCSP that stops an XSS"),
]
x0 = 0.055
for val, lab in stats:
    fig.text(x0, 0.44, val, fontsize=40, color=RED, fontweight="bold", va="top")
    fig.text(x0, 0.27, lab, fontsize=14, color=INK2, va="top", linespacing=1.35)
    x0 += 0.30

# mini header-adoption bar chart, right side
ax = fig.add_axes([0.74, 0.24, 0.22, 0.54])
ax.set_facecolor(SURFACE)
labels = {"strict_transport_security": "HSTS", "content_security_policy": "CSP",
          "x_frame_options": "XFO", "x_content_type_options": "nosniff",
          "referrer_policy": "Referrer", "permissions_policy": "Permissions"}
ha = sorted(S["header_adoption"].items(), key=lambda kv: kv[1]["pct_present"])
ys = range(len(ha))
ax.barh(list(ys), [v["pct_present"] for _, v in ha], color=BLUE, height=0.62)
ax.set_yticks(list(ys), [labels[k] for k, _ in ha], fontsize=11, color=INK2)
ax.set_xlim(0, 100)
ax.set_xticks([0, 50, 100])
ax.tick_params(axis="x", labelsize=9, colors=MUTED, length=0)
ax.xaxis.grid(True, color=GRID, linewidth=0.8)
for s in ax.spines.values():
    s.set_visible(False)
for i, (_, v) in enumerate(ha):
    ax.text(v["pct_present"] + 3, i, f'{v["pct_present"]:.0f}%', va="center",
            fontsize=10, color=INK)
ax.set_title("% of top sites\nsending each header", fontsize=11, color=INK2, pad=10)

fig.text(0.055, 0.10, "webmetadataextractor.com   ·   open dataset + scripts on GitHub   ·   489 real homepages analyzed",
         fontsize=12, color=MUTED, va="top")

fig.savefig(HERE / "docs" / "social-card.png", facecolor=SURFACE)
print("wrote docs/social-card.png")
