# Testing against real sites

A test suite that only talks to servers you wrote finds only the problems you thought of. This page records what was run against real
sites, what broke, and what was changed because of it. Only sites that are yours, or that exist to be crawled, are used.

## What was run

| Target | Why it is a fair target | What it exercised |
| --- | --- | --- |
| The author's own site (matchelminski.com) | owned by the author | a real CDN (Cloudflare), a real sitemap, HTTP/2 front end, quick scan and browser crawl, DNS and certificate-log checks |
| `books.toscrape.com`, `quotes.toscrape.com` | built for scraper practice | hundreds of pages, pagination, a JavaScript-rendered variant of the quotes site |
| `httpbin.org` | an HTTP testing service | redirect chains, status codes, gzip and deflate, slow and drip-fed responses, `Retry-After` |
| `*.badssl.com` | a certificate and TLS test bed run for exactly this | expired, self-signed, wrong-host and untrusted-root certificates, TLS 1.0 only, an 8192-bit key |
| `testfire.net`, `the-internet.herokuapp.com` | deliberately flawed practice sites | login pages, forms, odd markup, error pages |

`python tools/realworld.py` repeats the quick scans of these (politely: a delay between requests and a small page limit), and
`WEBCRAWLER_LIVE=1 python -m unittest tests.test_live` turns the important expectations into tests. They depend on other people's
servers, so they are opt-in and may fail when those servers are down or slow (`rsa8192.badssl.com` often times out).

## What the real sites broke, and the fix

- **A 50,000-URL sitemap vanished without a word.** A 256 KB read limit cut the file and the XML then failed to parse. Sitemaps now have
  their own, larger limit, and a file that is still too big is reported as "too large" instead of "invalid XML".
- **Connections were not reused.** `urllib` opens a connection per request; against a TLS site that dominates the time. The tool now has
  its own HTTP client with a keep-alive pool: eight requests used three connections, and a page that was 13 KB decoded travelled as 3 KB
  because it asks for gzip/deflate (with a cap on the decompressed size so a "zip bomb" cannot fill memory).
- **A slow server could hold a scan forever.** A response drip-fed one byte at a time ignored the timeout. Reads are now chunked and
  checked against an overall deadline.
- **Pages behind a login were reported as broken.** A 401 or 403 is not a broken link: it is part of the attack surface. They are now
  "restricted" (informational) and are not counted as broken, in the map, the report or comparisons.
- **A script-built page looked empty.** A quick scan of a single-page app saw no links. The quick scanner now judges each page
  (little visible text plus script tags) and renders only those in a headless browser; images, fonts and media are blocked while rendering.
- **TLS reporting was wrong in four ways.** An incomplete chain was labelled "self-signed"; a server that only speaks TLS 1.0 was not
  reported at all; expired certificates lost their dates; the same expiry was reported twice. All four came from the badssl matrix, and the
  public certificates of four of its hosts are kept in `tests/fixtures/certs/` so the parser is tested without the network.
- **A cookie called `secure_id` passed the "Secure flag" check.** The check searched the whole line for the word. Cookie attributes are
  now parsed properly.
- **A `;jsessionid=` in the path was not recognised as a secret in the URL.** `urlparse` splits path parameters off; the check now looks
  at both parts.
- **Crawler traps.** Calendars and faceted search can generate endless `?query` variants of one page. At most 20 variants per path are
  followed (configurable), and the first page counts.
- **Redirects.** Cross-host redirects drop credentials; the redirect hop is recorded as a node of its own and folded away in the map.
- **Non-ASCII link text crashed a scan whose output was redirected on Windows.** The legacy code page could not print an arrow in a link's
  text, and the error ended the crawl. Output now replaces what the console cannot show; the saved data keeps the real characters.
- **WebKit refuses a hand-made redirect.** The way logins send headers to the crawled site (and never to another one after a redirect)
  hangs in WebKit. In WebKit and Firefox a redirecting page load is replayed as a page that goes on to the next address.

## What is not verified

- **Firefox.** The Playwright build of Firefox 157 would not start on the Windows machine used for development (the loader reports a missing
  `mozglue` side-by-side assembly, which usually means a damaged Visual C++ runtime on that machine), so the Firefox code path has not been
  run. Chromium, Chrome, Edge and WebKit have.
- **macOS and Linux desktops.** CI runs the suite on Ubuntu (with a virtual display) and Windows, but the GUI has only been looked at on Windows.
- **Sites that actively block crawlers** (bot protection, CAPTCHAs). The tool does not try to get around them; it reports what it is told
  (403, 429, a challenge page) and slows down.
