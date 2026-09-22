import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from phishing_analyzer.analyzer import analyze_email

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def _load(name: str) -> bytes:
    return (SAMPLES / name).read_bytes()


def test_benign_newsletter_scores_low():
    result = analyze_email(_load("benign_newsletter.eml"))
    assert result.risk_level == "Low"
    assert result.score < 20


def test_paypal_phish_scores_high():
    result = analyze_email(_load("phishing_paypal.eml"))
    assert result.risk_level == "High"
    categories = {f.category for f in result.findings}
    assert "authentication" in categories
    assert "sender_spoofing" in categories
    assert "urgency_language" in categories
    assert "suspicious_links" in categories


def test_paypal_phish_detects_spf_dkim_dmarc_fail():
    result = analyze_email(_load("phishing_paypal.eml"))
    descriptions = " ".join(f.description for f in result.findings)
    assert "SPF check failed" in descriptions
    assert "DKIM check failed" in descriptions
    assert "DMARC check failed" in descriptions


def test_paypal_phish_detects_ip_link_and_link_mismatch():
    result = analyze_email(_load("phishing_paypal.eml"))
    descriptions = " ".join(f.description for f in result.findings)
    assert "IP address" in descriptions
    assert "paypal.com" in descriptions  # flagged as the displayed-but-fake text domain


def test_paypal_phish_detects_reply_to_mismatch_and_brand_spoof():
    result = analyze_email(_load("phishing_paypal.eml"))
    descriptions = " ".join(f.description for f in result.findings)
    assert "Reply-To domain" in descriptions
    assert "'paypal'" in descriptions


def test_invoice_malware_scores_high():
    result = analyze_email(_load("phishing_invoice_malware.eml"))
    assert result.risk_level == "High"


def test_invoice_malware_detects_double_extension_attachment():
    result = analyze_email(_load("phishing_invoice_malware.eml"))
    descriptions = " ".join(f.description for f in result.findings)
    assert "double extension" in descriptions
    assert "Invoice_48213.pdf.exe" in descriptions


def test_invoice_malware_detects_url_shortener():
    result = analyze_email(_load("phishing_invoice_malware.eml"))
    descriptions = " ".join(f.description for f in result.findings)
    assert "bit.ly" in descriptions


def test_risk_level_thresholds():
    from phishing_analyzer.analyzer import AnalysisResult

    result = AnalysisResult()
    assert result.risk_level == "Low"
    result.add("test", "low weight finding", 19)
    assert result.risk_level == "Low"
    result.add("test", "pushes into medium", 1)
    assert result.risk_level == "Medium"
    result.add("test", "pushes into high", 30)
    assert result.risk_level == "High"
