# Phishing Email Analyzer

A static phishing-indicator scanner for raw `.eml` files. Parses a message,
runs it through a set of independent heuristics used in real SOC/email
triage, and produces a weighted risk score with a plain-language explanation
of every finding.

No live DNS lookups, no fetching of linked URLs, no external services — it's
pure static analysis of the message as given, so it's safe to point at a real
suspicious email without touching the network.

## What it checks

| Category | Signal |
|---|---|
| **Authentication** | SPF / DKIM / DMARC results parsed from the `Authentication-Results` header |
| **Sender spoofing** | From vs Reply-To domain mismatch; display name impersonating a known brand (e.g. "PayPal Security") on a domain that isn't actually PayPal's |
| **Urgency language** | Pressure/urgency phrases in subject and body ("act now", "account suspended", "verify immediately", etc.) |
| **Suspicious links** | IP-address URLs, URL shorteners, punycode/homograph domains, anchor text that shows one domain but links to another |
| **Attachments** | Dangerous executable extensions, double extensions used to disguise an executable (`invoice.pdf.exe`) |

Each finding carries a weight; they sum to a score, which maps to **Low**
(< 20), **Medium** (20–49), or **High** (≥ 50).

## Usage

```bash
python -m phishing_analyzer.cli path/to/email.eml
python -m phishing_analyzer.cli --json path/to/email.eml   # machine-readable output
python -m phishing_analyzer.cli samples/*.eml               # analyze several at once
```

## Real output (run against the sample emails in this repo)

```
=== benign_newsletter.eml ===
Risk: Low  (score: 0)
  No indicators found.

=== phishing_invoice_malware.eml ===
Risk: High  (score: 60)
  [+35] (attachments) Attachment 'Invoice_48213.pdf.exe' uses a double extension to disguise an executable
  [+10] (authentication) No Authentication-Results header present (SPF/DKIM/DMARC not evaluated by receiving server, or header stripped)
  [+10] (suspicious_links) Link uses a URL shortener (bit.ly), which hides the real destination
  [+ 5] (urgency_language) Urgency/pressure language detected (immediately)

=== phishing_paypal.eml ===
Risk: High  (score: 150)
  [+25] (authentication) SPF check failed
  [+20] (authentication) DKIM check failed
  [+20] (sender_spoofing) Display name references 'paypal' but sending domain is 'paypa1-support.net', not an official paypal domain
  [+20] (suspicious_links) Link points directly to an IP address (185.220.101.47)
  [+20] (suspicious_links) Link text shows 'www.paypal.com' but actually points to '185.220.101.47'
  [+15] (authentication) DMARC check failed
  [+15] (sender_spoofing) Reply-To domain (account-verify-center.net) differs from From domain (paypa1-support.net)
  [+15] (urgency_language) Urgency/pressure language detected (act now, final notice, immediately, ...)
```

## Sample emails

`samples/` contains three synthetic `.eml` fixtures written for this project
(not real captured phishing mail — no real people, real malicious infrastructure,
or live URLs are involved; the "phishing" IP/domains are non-routable examples):

- `benign_newsletter.eml` — a clean email with matching domains and no red flags
- `phishing_paypal.eml` — brand impersonation: spoofed display name, failed
  SPF/DKIM/DMARC, mismatched Reply-To, and a link whose visible text claims
  `paypal.com` but actually points to a raw IP
- `phishing_invoice_malware.eml` — a business-email-compromise-style invoice
  lure with a double-extension attachment and a shortened link

## Running the tests

```bash
pip install pytest
pytest tests/ -v
```

9 tests cover: correct low-risk scoring on the benign sample, correct
high-risk scoring and specific-finding detection on both phishing samples,
and the score → risk-level threshold boundaries directly.

## Design notes / limitations

- HTML bodies are parsed with Python's built-in `html.parser` (not regex) to
  extract anchor text/href pairs reliably.
- Brand-impersonation detection uses a small hardcoded list of commonly
  spoofed brands and their legitimate domains (`BRAND_DOMAINS` in
  `analyzer.py`) — trivial to extend.
- This is static/offline analysis by design. A production version would add:
  live SPF/DKIM DNS verification when `Authentication-Results` is absent or
  untrusted, WHOIS/domain-age lookups for newly registered sending domains,
  and sandboxed detonation of attachments/links rather than extension-based
  heuristics alone.

## Skills demonstrated

- Email protocol internals (RFC 5322, MIME, SPF/DKIM/DMARC)
- Python: `email`, `html.parser`, dataclasses, regex
- Threat-informed heuristic design (mapping real phishing tradecraft to
  detectable signals)
- Test-driven development — every detection is backed by an assertion
  against real (synthetic) sample data, not just eyeballed output
