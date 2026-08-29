---
title: "I scanned the top 1,000 websites for security headers. The median score is 37/100."
published: false
tags: security, webdev, http, data
canonical_url:
---

Security-header advice has been the same for a decade: set HSTS, set a CSP, add
`X-Frame-Options` and `nosniff`, done. I wanted to know how many sites that
actually reach the biggest audiences on the web bother. So I took the
[Tranco](https://tranco-list.eu/) top 1,000, fetched every homepage once, and
graded six response headers.

Short version: **the median security-header score is 37 out of 100. Fewer than 1
in 10 of the top sites score 70 or higher, and 13% send no security headers at
all.** The full dataset and scripts are [on GitHub](https://github.com/JosejuX/top-1000-security-headers); this post is the
walk-through.

## How the scan works

One `GET https://<domain>` per site, redirects followed, then six headers each
graded `missing` / `weak` / `reasonable` / `strong`:

- `Strict-Transport-Security`
- `Content-Security-Policy`
- `X-Frame-Options`
- `X-Content-Type-Options`
- `Referrer-Policy`
- `Permissions-Policy`

The score is the mean of the six grades as a percentage. The one nuance worth
stating: a CSP containing `unsafe-inline`, `unsafe-eval` or a wildcard source is
graded `weak`, not `strong`. It parses, but it does not stop injected script
from running.

I did the fetching and grading with an open-source API I maintain (the
[Web Metadata & Contact Extractor](https://webmetadataextractor.com)), because one call to its
`/api/v1/extract` endpoint returns the header grades, an overall security score,
an SEO score and a detected tech stack for a URL. That last part matters for the
third finding below.

### About the denominator

Of the 1,000 domains, only 489 are real, reachable homepages. 225 are
infrastructure (DNS-only CDN and cloud domains that serve no site), 209 were
unreachable from where I ran the scan (timeouts, geo-blocks, paywalls, apex
redirect quirks), 43 returned a bot-challenge or WAF page, and 34 served a
placeholder. Every number below is over those 489. The sites I could not read
lean toward the heavily bot-protected, which are on average the more
security-conscious ones, so the real picture is probably a little worse than
this.

## Finding 1: most of the top sites are missing most of the headers

![Security-header adoption across the top 1,000 sites](https://raw.githubusercontent.com/JosejuX/top-1000-security-headers/main/charts/01-header-adoption.png)

`Strict-Transport-Security` is the only header on a majority of sites (71%).
`X-Frame-Options` and `X-Content-Type-Options` - each a single static line with
no downside - are missing on roughly 45%. `Referrer-Policy` is on 29%.
`Permissions-Policy` is on 16%.

## Finding 2: the score distribution is bottom-heavy

![Security-header score distribution](https://raw.githubusercontent.com/JosejuX/top-1000-security-headers/main/charts/02-score-distribution.png)

Median 37, mean 36, and a long tail into the low scores rather than the high
ones. A quarter of the top 1,000 score 17 or below.

Content-Security-Policy is where it breaks down hardest. 46% of sites have no CSP
at all. Of the 54% that do, all but 90 sites carry `unsafe-inline` or a
wildcard. Put together, **about 82% of the top 1,000 have no browser-enforced
CSP that would actually stop an XSS.** Three sites in the whole set have a CSP I
would call strong.

That is not all negligence. A strict CSP on a large existing site is genuinely
hard - third-party tags, inline handlers, A/B tools all fight it, and a bad
rollout breaks the page. But "hard" is the explanation for the weak-CSP half,
not for the 46% with nothing and the 84% with no `Permissions-Policy`.

## Finding 3: the tech stack predicts the posture

![Median security score by platform](https://raw.githubusercontent.com/JosejuX/top-1000-security-headers/main/charts/03-security-by-platform.png)

Bucketing the 489 sites by detected platform, WordPress (n=44) sits about 10
points below the field: median score 27, and 61% ship no CSP versus 46%
overall. Next.js and similar framework/edge stacks land near or just above the
median, mostly because their hosting (Vercel, Netlify, Cloudflare Pages) sets a
decent HSTS by default. The only groups with a median above 42 were Astro (n=8,
too small to lean on) and Drupal (n=10).

The interesting part is what happens inside the WordPress bucket. Those 44 sites
have a median *SEO* score of 83, well above the overall 75. They are not
neglected sites. They are sites where SEO got attention and headers did not.

## Finding 4: SEO effort and security effort barely correlate

![SEO score vs security score](https://raw.githubusercontent.com/JosejuX/top-1000-security-headers/main/charts/04-seo-vs-security.png)

Across all 489 sites, Pearson r between the SEO score and the security-header
score is 0.17. The top of the web has largely solved SEO (median 75) and largely
skipped security headers (median 37), and knowing how much a team invested in
one tells you almost nothing about the other.

My read: SEO has a tight, visible feedback loop (rankings, traffic, revenue).
Security headers have none until an incident. So on a busy roadmap the headers
lose, every sprint, at almost every company - including ones with the resources
to know better.

## Try it on your own site

```bash
pip install httpx matplotlib
curl -sL -o tranco.zip https://tranco-list.eu/top-1m.csv.zip
python scan.py 1000    # -> results.jsonl
python analyze.py      # -> summary.json + top1000-web-report.csv
python make_charts.py
```

Everything - the scan script, the analysis, the raw JSONL, the flattened CSV -
is in the [repo](https://github.com/JosejuX/top-1000-security-headers) under MIT. If you just want your own site graded, the
[API](https://webmetadataextractor.com) has a free tier and `curl "…/api/v1/security?url=https://yoursite.com"`
gives you the same per-header grades used here.

If you find a bug in the grading or want a rank band or a platform I did not
break out, open an issue with the dataset row and I will take a look.
