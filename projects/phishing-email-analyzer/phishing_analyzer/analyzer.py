"""Static phishing-indicator analysis for raw email (.eml) files.

Parses a raw RFC 5322 message and scores it against a set of independent
heuristics commonly used in phishing triage: authentication results
(SPF/DKIM/DMARC), sender/display-name spoofing, urgency language, suspicious
links, and dangerous attachments. Everything here is offline/static analysis
against the message as given -- no live DNS lookups, no fetching of linked
URLs, so it's safe to run against a real suspicious email.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from email import policy
from email.message import Message
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser

# --- Reference data -----------------------------------------------------

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at",
}

URGENCY_KEYWORDS = {
    "urgent", "immediately", "verify your account", "suspended", "act now",
    "final notice", "your account will be", "click here", "confirm your",
    "unauthorized access", "unusual activity", "limited time", "expire",
    "password will expire", "security alert", "restricted",
}

# Brands frequently impersonated. If the display name mentions one but the
# sending domain doesn't match any of its known domains, that's a strong
# spoofing signal.
BRAND_DOMAINS = {
    "paypal": {"paypal.com"},
    "microsoft": {"microsoft.com", "outlook.com", "office.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.co.uk"},
    "netflix": {"netflix.com"},
    "google": {"google.com", "gmail.com"},
    "bank of america": {"bankofamerica.com"},
    "hmrc": {"hmrc.gov.uk", "gov.uk"},
    "dhl": {"dhl.com"},
}

DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".ps1", ".jar", ".msi",
    ".hta", ".wsf", ".lnk",
}

DOUBLE_EXTENSION_RE = re.compile(
    r"\.(pdf|doc|docx|xls|xlsx|jpg|png|txt)\.(exe|scr|js|vbs|bat|hta)$",
    re.IGNORECASE,
)

IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


# --- Data model -----------------------------------------------------------

@dataclass
class Finding:
    category: str
    description: str
    weight: int


@dataclass
class AnalysisResult:
    findings: list[Finding] = field(default_factory=list)

    @property
    def score(self) -> int:
        return sum(f.weight for f in self.findings)

    @property
    def risk_level(self) -> str:
        s = self.score
        if s >= 50:
            return "High"
        if s >= 20:
            return "Medium"
        return "Low"

    def add(self, category: str, description: str, weight: int) -> None:
        self.findings.append(Finding(category, description, weight))


class _LinkExtractor(HTMLParser):
    """Pulls (anchor_text, href) pairs out of an HTML body."""

    def __init__(self) -> None:
        super().__init__()
        self.links: list[tuple[str, str]] = []
        self._current_href: str | None = None
        self._current_text: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            href = dict(attrs).get("href")
            if href:
                self._current_href = href
                self._current_text = []

    def handle_data(self, data):
        if self._current_href is not None:
            self._current_text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._current_href is not None:
            self.links.append((" ".join(self._current_text).strip(), self._current_href))
            self._current_href = None
            self._current_text = []


def _extract_domain(url_or_addr: str) -> str:
    match = re.search(r"@([\w.-]+)", url_or_addr)
    if match:
        return match.group(1).lower()
    match = re.search(r"^[a-z]+://([^/]+)", url_or_addr, re.IGNORECASE)
    if match:
        host = match.group(1).lower()
        return host.split("@")[-1].split(":")[0]
    return ""


def _check_auth_results(msg: Message, result: AnalysisResult) -> None:
    header = msg.get("Authentication-Results", "")
    if not header:
        result.add("authentication", "No Authentication-Results header present (SPF/DKIM/DMARC not evaluated by receiving server, or header stripped)", 10)
        return

    header_lower = header.lower()
    for mechanism, fail_weight, none_weight in (("spf", 25, 10), ("dkim", 20, 10), ("dmarc", 15, 8)):
        m = re.search(rf"{mechanism}=(\w+)", header_lower)
        if not m:
            continue
        outcome = m.group(1)
        if outcome == "fail":
            result.add("authentication", f"{mechanism.upper()} check failed", fail_weight)
        elif outcome in ("none", "neutral", "softfail"):
            result.add("authentication", f"{mechanism.upper()} result: {outcome}", none_weight)


def _check_sender_spoofing(msg: Message, result: AnalysisResult) -> None:
    from_name, from_addr = parseaddr(msg.get("From", ""))
    from_domain = from_addr.split("@")[-1].lower() if "@" in from_addr else ""

    reply_to = msg.get("Reply-To")
    if reply_to:
        _, reply_addr = parseaddr(reply_to)
        reply_domain = reply_addr.split("@")[-1].lower() if "@" in reply_addr else ""
        if reply_domain and from_domain and reply_domain != from_domain:
            result.add(
                "sender_spoofing",
                f"Reply-To domain ({reply_domain}) differs from From domain ({from_domain})",
                15,
            )

    name_lower = from_name.lower()
    for brand, domains in BRAND_DOMAINS.items():
        if brand in name_lower and not any(from_domain.endswith(d) for d in domains):
            result.add(
                "sender_spoofing",
                f"Display name references '{brand}' but sending domain is '{from_domain}', not an official {brand} domain",
                20,
            )
            break


def _check_urgency_language(subject: str, body_text: str, result: AnalysisResult) -> None:
    haystack = f"{subject}\n{body_text}".lower()
    matched = {kw for kw in URGENCY_KEYWORDS if kw in haystack}
    if matched:
        weight = min(5 * len(matched), 15)
        sample = ", ".join(sorted(matched)[:3])
        result.add("urgency_language", f"Urgency/pressure language detected ({sample}{', ...' if len(matched) > 3 else ''})", weight)


def _check_links(body_html: str, body_text: str, result: AnalysisResult) -> None:
    extractor = _LinkExtractor()
    if body_html:
        try:
            extractor.feed(body_html)
        except Exception:
            pass

    plain_urls = re.findall(r"https?://[^\s\"'<>]+", body_text)
    all_hrefs = [href for _, href in extractor.links] + plain_urls

    seen_ip = False
    seen_shortener = False
    seen_punycode = False
    for href in all_hrefs:
        domain = _extract_domain(href)
        if not domain:
            continue
        if IPV4_RE.match(domain) and not seen_ip:
            result.add("suspicious_links", f"Link points directly to an IP address ({domain})", 20)
            seen_ip = True
        if domain in URL_SHORTENERS and not seen_shortener:
            result.add("suspicious_links", f"Link uses a URL shortener ({domain}), which hides the real destination", 10)
            seen_shortener = True
        if "xn--" in domain and not seen_punycode:
            result.add("suspicious_links", f"Link domain uses punycode encoding ({domain}), often used for homograph/lookalike domains", 25)
            seen_punycode = True

    for text, href in extractor.links:
        text_domain = _extract_domain(text) if ("." in text and " " not in text.strip()) else ""
        href_domain = _extract_domain(href)
        if text_domain and href_domain and text_domain != href_domain:
            result.add(
                "suspicious_links",
                f"Link text shows '{text_domain}' but actually points to '{href_domain}'",
                20,
            )
            break


def _check_attachments(msg: Message, result: AnalysisResult) -> None:
    for part in msg.walk():
        filename = part.get_filename()
        if not filename:
            continue
        lower = filename.lower()
        if DOUBLE_EXTENSION_RE.search(lower):
            result.add("attachments", f"Attachment '{filename}' uses a double extension to disguise an executable", 35)
            continue
        for ext in DANGEROUS_EXTENSIONS:
            if lower.endswith(ext):
                result.add("attachments", f"Attachment '{filename}' has a dangerous executable extension ({ext})", 30)
                break


def _get_bodies(msg: Message) -> tuple[str, str]:
    """Return (text_body, html_body)."""
    text_body, html_body = "", ""
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if part.get_content_disposition() == "attachment":
                continue
            try:
                content = part.get_content()
            except Exception:
                continue
            if ctype == "text/plain" and not text_body:
                text_body = content
            elif ctype == "text/html" and not html_body:
                html_body = content
    else:
        try:
            content = msg.get_content()
        except Exception:
            content = ""
        if msg.get_content_type() == "text/html":
            html_body = content
        else:
            text_body = content
    return text_body, html_body


def analyze_email(raw_bytes: bytes) -> AnalysisResult:
    """Run all static checks against a raw .eml message and return the result."""
    msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
    result = AnalysisResult()

    text_body, html_body = _get_bodies(msg)
    subject = msg.get("Subject", "")

    _check_auth_results(msg, result)
    _check_sender_spoofing(msg, result)
    _check_urgency_language(subject, text_body + " " + re.sub("<[^>]+>", " ", html_body), result)
    _check_links(html_body, text_body, result)
    _check_attachments(msg, result)

    return result
