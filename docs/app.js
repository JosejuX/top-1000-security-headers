/* Security headers of the top 1,000 websites - interactive report */
(function () {
"use strict";

var REPO = "https://github.com/JosejuX/top-1000-security-headers";
var CSV  = REPO + "/raw/main/data/top1000-web-report.csv";
var API  = "https://webmetadataextractor.com";

var S = window.REPORT.summary;
var ROWS = window.REPORT.rows;
var SVGNS = "http://www.w3.org/2000/svg";
var tip = document.getElementById("tip");

// ---- links -----------------------------------------------------------
setHref("repo", REPO); setHref("csv", CSV); setHref("api", API); setHref("api2", API);
function setHref(id, url) { var a = document.getElementById(id); if (a) a.href = url; }

// ---- theme ----------------------------------------------------------
var root = document.documentElement;
try {
  var saved = localStorage.getItem("report-theme");
  if (saved) root.setAttribute("data-theme", saved);
} catch (e) {}
document.getElementById("theme").addEventListener("click", function () {
  var cur = root.getAttribute("data-theme");
  var isDark = cur ? cur === "dark"
    : window.matchMedia("(prefers-color-scheme: dark)").matches;
  var next = isDark ? "light" : "dark";
  root.setAttribute("data-theme", next);
  try { localStorage.setItem("report-theme", next); } catch (e) {}
  drawAll();
});

// ---- tiny SVG helpers --------------------------------------------
function E(name, attrs) {
  var n = document.createElementNS(SVGNS, name);
  for (var k in attrs) n.setAttribute(k, attrs[k]);
  return n;
}
function T(x, y, str, cls, anchor) {
  var t = E("text", { x: x, y: y, "text-anchor": anchor || "start" });
  if (cls) t.setAttribute("class", cls);
  t.textContent = str;
  return t;
}
function clear(svg) { while (svg.firstChild) svg.removeChild(svg.firstChild); }
function css(v) { return getComputedStyle(document.body).getPropertyValue(v).trim(); }

function showTip(evt, html) {
  tip.innerHTML = html;
  tip.classList.add("show");
  moveTip(evt);
}
function moveTip(evt) {
  var x = evt.clientX + 14, y = evt.clientY + 14;
  if (x + tip.offsetWidth > window.innerWidth - 8) x = evt.clientX - tip.offsetWidth - 14;
  if (y + tip.offsetHeight > window.innerHeight - 8) y = evt.clientY - tip.offsetHeight - 14;
  tip.style.left = x + "px"; tip.style.top = y + "px";
}
function hideTip() { tip.classList.remove("show"); }
window.addEventListener("scroll", hideTip, { passive: true });

function hover(node, html) {
  node.addEventListener("mousemove", function (e) { showTip(e, html); });
  node.addEventListener("mouseleave", hideTip);
}

// ---- stat tiles ------------------------------------------------
(function tiles() {
  var wrap = document.getElementById("tiles");
  var data = [
    { n: Math.round(S.security_score.median), k: "median security-header score (of 100)", bad: true },
    { n: "82%", k: "have no browser-enforced CSP worth the name", bad: true },
    { n: S.pct_zero_headers + "%", k: "send no security headers at all", bad: true },
    { n: S.security_score.pct_ge_70 + "%", k: "score 70 or above" }
  ];
  data.forEach(function (d) {
    var el = document.createElement("div");
    el.className = "tile";
    el.innerHTML = '<div class="n ' + (d.bad ? "bad" : "") + '">' + d.n + '</div><div class="k">' + d.k + '</div>';
    wrap.appendChild(el);
  });
})();

// ---- chart 1: header adoption --------------------------------
var HLABEL = {
  strict_transport_security: "Strict-Transport-Security",
  content_security_policy: "Content-Security-Policy",
  x_frame_options: "X-Frame-Options",
  x_content_type_options: "X-Content-Type-Options",
  referrer_policy: "Referrer-Policy",
  permissions_policy: "Permissions-Policy"
};
function drawAdoption() {
  var svg = document.getElementById("c-adoption");
  clear(svg);
  var W = 700, H = 300, L = 190, R = 655, T0 = 14, BOT = 268;
  var items = Object.keys(S.header_adoption).map(function (k) {
    return { k: k, v: S.header_adoption[k] };
  }).sort(function (a, b) { return a.v.pct_present - b.v.pct_present; });
  var n = items.length, band = (BOT - T0) / n;
  var x = function (p) { return L + (R - L) * p / 100; };
  [0, 25, 50, 75, 100].forEach(function (g) {
    svg.appendChild(E("line", { class: "grid", x1: x(g), x2: x(g), y1: T0, y2: BOT }));
    svg.appendChild(T(x(g), BOT + 16, g + "%", null, "middle"));
  });
  items.forEach(function (it, i) {
    var cy = T0 + band * i + band / 2, bh = Math.min(26, band * 0.62);
    svg.appendChild(T(L - 10, cy + 4, HLABEL[it.k], null, "end"));
    var bar = E("rect", { class: "bar", x: L, y: cy - bh / 2, width: x(it.v.pct_present) - L, height: bh, rx: 3 });
    svg.appendChild(bar);
    svg.appendChild(T(x(it.v.pct_present) + 6, cy + 4, Math.round(it.v.pct_present) + "%", "val"));
    var g = it.v.grades;
    var lines = ["strong", "reasonable", "weak", "report-only", "missing"].filter(function (q) { return g[q]; })
      .map(function (q) { return q + ": " + g[q]; }).join("<br>");
    hover(bar, "<b>" + HLABEL[it.k] + "</b><br>" + Math.round(it.v.pct_present) + "% send it<br>" + lines);
  });
}

// ---- chart 2: score distribution ---------------------------
function drawDist() {
  var svg = document.getElementById("c-dist");
  clear(svg);
  var W = 700, H = 300, L = 46, R = 682, T0 = 14, BOT = 262;
  var bins = new Array(10).fill(0);
  ROWS.forEach(function (r) {
    if (r.c !== "usable" || r.sec == null) return;
    var b = Math.min(9, Math.floor(r.sec / 10));
    bins[b]++;
  });
  var max = Math.max.apply(null, bins);
  var x = function (v) { return L + (R - L) * v / 100; };
  var y = function (c) { return BOT - (BOT - T0) * c / (Math.ceil(max / 10) * 10); };
  for (var g = 0; g <= Math.ceil(max / 10) * 10; g += 20) {
    svg.appendChild(E("line", { class: "grid", x1: L, x2: R, y1: y(g), y2: y(g) }));
    svg.appendChild(T(L - 8, y(g) + 4, String(g), null, "end"));
  }
  bins.forEach(function (c, i) {
    var bx = x(i * 10), bw = x(10) - x(0);
    var bar = E("rect", { class: "bar", x: bx + 1.5, y: y(c), width: bw - 3, height: BOT - y(c) });
    svg.appendChild(bar);
    hover(bar, "<b>score " + (i * 10) + "-" + (i * 10 + 10) + "</b><br>" + c + " sites");
  });
  [0, 20, 40, 60, 80, 100].forEach(function (v) {
    svg.appendChild(T(x(v), BOT + 16, String(v), null, "middle"));
  });
  var m = S.security_score.median;
  svg.appendChild(E("line", { class: "med", x1: x(m), x2: x(m), y1: T0, y2: BOT }));
  svg.appendChild(T(x(m) + 6, T0 + 12, "median " + Math.round(m), "val"));
  svg.appendChild(E("line", { class: "axis", x1: L, x2: R, y1: BOT, y2: BOT }));
}

// ---- chart 3: by platform -------------------------------
function drawPlatform() {
  var svg = document.getElementById("c-plat");
  clear(svg);
  var W = 700, H = 260, L = 210, R = 650, T0 = 14, BOT = 228;
  var items = Object.keys(S.by_platform).map(function (k) {
    return { k: k, v: S.by_platform[k] };
  }).filter(function (o) { return o.v.n >= 15; })
    .sort(function (a, b) { return b.v.median_security - a.v.median_security; });
  var n = items.length, band = (BOT - T0) / n;
  var maxX = 46;
  var x = function (p) { return L + (R - L) * p / maxX; };
  for (var g = 0; g <= maxX; g += 10) {
    svg.appendChild(E("line", { class: "grid", x1: x(g), x2: x(g), y1: T0, y2: BOT }));
    svg.appendChild(T(x(g), BOT + 16, String(g), null, "middle"));
  }
  var med = S.security_score.median;
  svg.appendChild(E("line", { class: "refline", x1: x(med), x2: x(med), y1: T0 - 4, y2: BOT }));
  svg.appendChild(T(x(med), T0 - 8, "all-sites median " + Math.round(med), null, "middle"));
  items.forEach(function (it, i) {
    var cy = T0 + band * i + band / 2, bh = Math.min(24, band * 0.6);
    svg.appendChild(T(L - 10, cy + 4, it.k + "  (n=" + it.v.n + ")", null, "end"));
    var hl = it.k === "WordPress" ? " hl" : "";
    var bar = E("rect", { class: "bar" + hl, x: L, y: cy - bh / 2, width: x(it.v.median_security) - L, height: bh, rx: 3 });
    svg.appendChild(bar);
    svg.appendChild(T(x(it.v.median_security) + 6, cy + 4, Math.round(it.v.median_security), "val"));
    hover(bar, "<b>" + it.k + "</b> (n=" + it.v.n + ")<br>median security " + it.v.median_security +
      "<br>no CSP: " + it.v.pct_no_csp + "%<br>has HSTS: " + it.v.pct_has_hsts + "%<br>median SEO " + it.v.median_seo);
  });
}

// ---- chart 4: SEO vs security scatter ------------------
function drawScatter() {
  var svg = document.getElementById("c-scatter");
  clear(svg);
  var W = 700, H = 380, L = 46, R = 682, T0 = 14, BOT = 340;
  var pts = ROWS.filter(function (r) { return r.c === "usable" && r.sec != null && r.seo != null; });
  var x = function (v) { return L + (R - L) * v / 100; };
  var y = function (v) { return BOT - (BOT - T0) * v / 95; };
  [0, 20, 40, 60, 80, 100].forEach(function (v) {
    svg.appendChild(E("line", { class: "grid", x1: x(v), x2: x(v), y1: T0, y2: BOT }));
    svg.appendChild(T(x(v), BOT + 16, String(v), null, "middle"));
  });
  [0, 20, 40, 60, 80].forEach(function (v) {
    svg.appendChild(E("line", { class: "grid", x1: L, x2: R, y1: y(v), y2: y(v) }));
    svg.appendChild(T(L - 8, y(v) + 4, String(v), null, "end"));
  });
  svg.appendChild(T((L + R) / 2, BOT + 34, "SEO score", null, "middle"));
  // least-squares line
  var n = pts.length, sx = 0, sy = 0, sxy = 0, sxx = 0;
  pts.forEach(function (p) { sx += p.seo; sy += p.sec; sxy += p.seo * p.sec; sxx += p.seo * p.seo; });
  var m = (n * sxy - sx * sy) / (n * sxx - sx * sx), b = (sy - m * sx) / n;
  pts.forEach(function (p) {
    var c = E("circle", { class: "dot", cx: x(p.seo), cy: y(p.sec), r: 4 });
    hover(c, "<b>" + p.d + "</b><br>SEO " + p.seo + " &middot; security " + p.sec);
    svg.appendChild(c);
  });
  svg.appendChild(E("line", { class: "trend", x1: x(10), y1: y(m * 10 + b), x2: x(100), y2: y(m * 100 + b) }));
  svg.appendChild(T(L, T0 - 2, "Security-header score", null, "start"));
}

function drawAll() { drawAdoption(); drawDist(); drawPlatform(); drawScatter(); }
drawAll();
window.addEventListener("resize", function () { /* viewBox scales; tooltip only */ });

// ---- explorer table ---------------------------------
var CLASSES = [
  ["all", "All 1,000"], ["usable", "Analyzed (489)"], ["blocked", "Bot-blocked (43)"],
  ["unreachable", "Unreachable (209)"], ["infra", "Not a website (225)"], ["thin", "Placeholder (34)"]
];
var CLABEL = { usable: "analyzed", blocked: "bot-blocked", unreachable: "unreachable", infra: "not a website", thin: "placeholder" };
var state = { cls: "all", q: "", sort: "r", dir: 1 };

var chipsWrap = document.getElementById("chips");
CLASSES.forEach(function (c) {
  var b = document.createElement("button");
  b.className = "chip" + (c[0] === "all" ? " on" : "");
  b.textContent = c[1]; b.dataset.c = c[0];
  b.addEventListener("click", function () {
    state.cls = c[0];
    [].forEach.call(chipsWrap.children, function (x) { x.classList.toggle("on", x.dataset.c === c[0]); });
    render();
  });
  chipsWrap.appendChild(b);
});
document.getElementById("search").addEventListener("input", function (e) {
  state.q = e.target.value.toLowerCase().trim(); render();
});
[].forEach.call(document.querySelectorAll("thead th[data-k]"), function (th) {
  th.addEventListener("click", function () {
    var k = th.dataset.k;
    if (state.sort === k) state.dir *= -1; else { state.sort = k; state.dir = (k === "d" || k === "p" || k === "srv" || k === "c") ? 1 : -1; }
    render();
  });
});

var GNAMES = ["HSTS", "CSP", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy"];
var GTXT = ["missing", "weak / report-only", "reasonable", "strong"];
function dots(g) {
  if (!g) return '<span class="pill">n/a</span>';
  return '<span class="dots">' + g.map(function (v, i) {
    return '<i class="d d' + v + '" title="' + GNAMES[i] + ': ' + GTXT[v] + '"></i>';
  }).join("") + '</span>';
}
function render() {
  var rows = ROWS.filter(function (r) {
    if (state.cls !== "all" && r.c !== state.cls) return false;
    if (state.q && r.d.toLowerCase().indexOf(state.q) === -1) return false;
    return true;
  });
  var k = state.sort, d = state.dir;
  rows.sort(function (a, b) {
    var va = a[k], vb = b[k];
    if (va == null) va = -1; if (vb == null) vb = -1;
    if (va < vb) return -d; if (va > vb) return d; return a.r - b.r;
  });
  var tb = document.getElementById("tbody");
  tb.innerHTML = rows.slice(0, 1000).map(function (r) {
    return "<tr><td class='num'>" + r.r + "</td><td>" + esc(r.d) + "</td>" +
      "<td><span class='pill'>" + (CLABEL[r.c] || r.c) + "</span></td>" +
      "<td class='num'>" + (r.sec == null ? "" : Math.round(r.sec)) + "</td>" +
      "<td class='num'>" + (r.seo == null ? "" : Math.round(r.seo)) + "</td>" +
      "<td>" + esc(r.p || "") + "</td><td>" + esc(r.srv || "") + "</td>" +
      "<td>" + dots(r.g) + "</td></tr>";
  }).join("");
  document.getElementById("count").textContent = rows.length + " domains";
}
function esc(s) { return String(s).replace(/[&<>"]/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]; }); }
render();

})();
