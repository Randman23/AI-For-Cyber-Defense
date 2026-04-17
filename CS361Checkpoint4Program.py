"""
Email Scam & Phishing Scanner
Reads emails from a .txt file and rates each one from 1 (trustworthy) to 10 (untrustworthy).
"""

import re
import json
from dataclasses import dataclass, field
from typing import List, Tuple
from urllib.parse import urlparse


#  DATA STRUCTURES


@dataclass
class Email:
    sender: str = ""
    subject: str = ""
    body: str = ""

@dataclass
class Flag:
    category: str
    description: str
    severity: int  # 1-3: low=1, medium=2, high=3

@dataclass
class ScanResult:
    email: Email
    flags: List[Flag] = field(default_factory=list)
    risk_score: float = 0.0
    risk_rating: int = 0
    verdict: str = ""
    urls_found: List[str] = field(default_factory=list)



#  DETECTION RULES

# Suspicious TLDs often used in phishing
SUSPICIOUS_TLDS = {".xyz", ".tk", ".ru", ".cn", ".ml", ".ga", ".cf", ".gq", ".pw", ".top", ".click", ".loan"}

# Domain whitelist
TRUSTED_DOMAINS = {
    "google.com", "gmail.com", "microsoft.com", "outlook.com", "apple.com",
    "amazon.com", "paypal.com", "github.com", "linkedin.com", "twitter.com",
    "facebook.com", "instagram.com", "shopify.com", "medium.com", "stripe.com",
    "dropbox.com", "netflix.com", "spotify.com", "zoom.us", "slack.com",
}

# URL shorteners can hide malicious destinations
URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "rb.gy", "cutt.ly", "is.gd"}

# Urgency / pressure phrases
URGENCY_PHRASES = [
    r"act now", r"expires? (soon|in \d+ hours?)", r"immediate(ly)?",
    r"urgent(ly)?", r"don.t delay", r"within \d+ hours?", r"respond immediately",
    r"failure to (act|comply|respond)", r"will be (suspended|frozen|deleted|terminated)",
    r"last (chance|warning|notice)", r"account (will be )?(limited|suspended|frozen)",
]

# Requests for sensitive information
SENSITIVE_INFO_REQUESTS = [
    r"(social security|ssn)", r"bank account (number)?", r"credit card (number)?",
    r"password", r"passport (scan|copy|number)?", r"date of birth",
    r"mother.s maiden name", r"pin (number)?", r"full name.{0,20}address.{0,20}phone",
]

# Classic scam phrases
SCAM_PHRASES = [
    r"you (have )?won", r"congratulations.{0,30}(winner|selected|chosen)",
    r"lucky winner", r"claim your (prize|reward|gift|winnings)",
    r"processing fee", r"western union", r"wire transfer",
    r"nigerian? (prince|official|minister|lottery)",
    r"million (dollar|usd|gbp|euros?)",
    r"(free|complimentary) (gift|prize|iphone|ipad|laptop)",
    r"100% (free|guaranteed|risk.?free)",
    r"selected (at )?random",
]

# Malware / dangerous file indicators
MALWARE_INDICATORS = [
    r"\.(exe|bat|scr|vbs|js|cmd|ps1|jar|apk|dmg)\b",
    r"download.{0,20}(tool|software|update|patch|security)",
    r"run.{0,20}attached",
    r"enable macro",
]

# Suspicious sender patterns
SUSPICIOUS_SENDER_PATTERNS = [
    r"@.*-.*\.(com|net|org)",   # dashes in domain
    r"noreply@.*support.*\.",   # noreply at support-sounding domain
    r"\d{4,}@",                 # lots of numbers in address
]


#  HELPER FUNCTIONS

def extract_urls(text: str) -> List[str]:
    """Extract all URLs from a block of text, stripping trailing punctuation."""
    pattern = r'https?://[^\s<>"\')\]}]+'
    raw = re.findall(pattern, text, re.IGNORECASE)
    # Strip trailing punctuation that may be sentence-ending punctuation, not part of URL
    return [re.sub(r'[.,;:!?]+$', '', url) for url in raw]


def get_domain(url: str) -> str:
    """Extract root domain from a URL."""
    try:
        parsed = urlparse(url)
        netloc = parsed.netloc.lower()
        # Strip www.
        if netloc.startswith("www."):
            netloc = netloc[4:]
        return netloc
    except Exception:
        return ""


def is_domain_spoofed(domain: str, trusted: set) -> Tuple[bool, str]:
    """
    Check if a domain is trying to impersonate a trusted brand.
    e.g., 'paypal-secure-login.xyz' → spoofing PayPal
    Ignores legitimate subdomains like 'help.shopify.com'.
    """
    for trusted_domain in trusted:
        brand = trusted_domain.split(".")[0]  # e.g. "paypal"
        if brand in domain and domain != trusted_domain:
            # Allow legitimate subdomains: domain must END with .trusted_domain
            if domain.endswith("." + trusted_domain):
                continue  # e.g. help.shopify.com is fine
            return True, trusted_domain
    return False, ""


def match_patterns(text: str, patterns: List[str]) -> List[str]:
    """Return list of matched pattern descriptions."""
    matches = []
    text_lower = text.lower()
    for pattern in patterns:
        if re.search(pattern, text_lower, re.IGNORECASE):
            matches.append(pattern)
    return matches


#  SCANNER

def scan_email(email: Email) -> ScanResult:
    result = ScanResult(email=email)
    full_text = f"{email.sender} {email.subject} {email.body}"

    # 1. Extract all URLs
    result.urls_found = extract_urls(full_text)

    # 2. Check URLs
    for url in result.urls_found:
        domain = get_domain(url)

        # Suspicious TLD
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                result.flags.append(Flag(
                    category="Suspicious URL",
                    description=f"URL uses suspicious TLD '{tld}': {url}",
                    severity=3
                ))
                break

        # URL shortener
        if domain in URL_SHORTENERS:
            result.flags.append(Flag(
                category="Hidden URL",
                description=f"URL shortener hides true destination: {url}",
                severity=2
            ))

        # Brand spoofing
        spoofed, impersonated = is_domain_spoofed(domain, TRUSTED_DOMAINS)
        if spoofed:
            result.flags.append(Flag(
                category="Phishing / Spoofed Domain",
                description=f"Domain '{domain}' appears to spoof '{impersonated}': {url}",
                severity=3
            ))

    # 3. Sender analysis
    sender_lower = email.sender.lower()

    # Check if sender claims to be trusted but domain doesn't match
    for trusted in TRUSTED_DOMAINS:
        brand = trusted.split(".")[0]
        if brand in sender_lower:
            sender_domain = re.search(r'@([^\s>]+)', sender_lower)
            if sender_domain:
                actual_domain = sender_domain.group(1)
                root = get_domain("http://" + actual_domain)
                if root not in TRUSTED_DOMAINS and brand in root and root != trusted:
                    result.flags.append(Flag(
                        category="Sender Spoofing",
                        description=f"Sender claims to be '{brand}' but uses suspicious domain '{actual_domain}'",
                        severity=3
                    ))

    for pattern in SUSPICIOUS_SENDER_PATTERNS:
        if re.search(pattern, sender_lower):
            result.flags.append(Flag(
                category="Suspicious Sender",
                description=f"Sender address matches suspicious pattern",
                severity=1
            ))
            break

    # 4. Subject line analysis
    subject_lower = email.subject.lower()
    urgency_hits = match_patterns(subject_lower, URGENCY_PHRASES)
    if urgency_hits:
        result.flags.append(Flag(
            category="Urgency in Subject",
            description=f"Subject uses pressure/urgency language",
            severity=2
        ))
    if re.search(r'[!]{2,}|[A-Z]{5,}', email.subject):
        result.flags.append(Flag(
            category="Aggressive Formatting",
            description="Subject contains excessive caps or exclamation marks",
            severity=1
        ))

    # 5. Body analysis
    body_lower = email.body.lower()

    # Urgency phrases in body
    urgency_body = match_patterns(body_lower, URGENCY_PHRASES)
    if len(urgency_body) >= 1:
        result.flags.append(Flag(
            category="Urgency / Pressure Tactics",
            description=f"Body uses {len(urgency_body)} urgency/threat phrases",
            severity=2
        ))

    # Sensitive data requests
    sensitive_hits = match_patterns(body_lower, SENSITIVE_INFO_REQUESTS)
    if sensitive_hits:
        result.flags.append(Flag(
            category="Sensitive Info Request",
            description=f"Requests sensitive personal/financial data ({len(sensitive_hits)} indicators)",
            severity=3
        ))

    # Classic scam language
    scam_hits = match_patterns(body_lower, SCAM_PHRASES)
    if len(scam_hits) >= 1:
        result.flags.append(Flag(
            category="Scam Language",
            description=f"Body contains {len(scam_hits)} classic scam phrase(s)",
            severity=3
        ))

    # Malware indicators
    malware_hits = match_patterns(body_lower, MALWARE_INDICATORS)
    if malware_hits:
        result.flags.append(Flag(
            category="Malware / Dangerous Attachment",
            description=f"References to executable files or dangerous downloads detected",
            severity=3
        ))

    # 6. Calculate risk score
    severity_weights = {1: 1.0, 2: 3.0, 3: 5.5}
    raw_score = sum(severity_weights[f.severity] for f in result.flags)

    # Cap and normalize to 1–10
    capped = min(raw_score, 20.0)
    normalized = 1 + (capped / 20.0) * 9  # maps [0,20] → [1,10]
    result.risk_rating = round(normalized)

    # If no flags at all, clamp to 1
    if not result.flags:
        result.risk_rating = 1
        result.risk_score = 0.0
    else:
        result.risk_score = round(capped, 2)

    # 7. Verdict
    if result.risk_rating <= 2:
        result.verdict = "TRUSTWORTHY"
    elif result.risk_rating <= 4:
        result.verdict = "LOW RISK"
    elif result.risk_rating <= 6:
        result.verdict = "SUSPICIOUS"
    elif result.risk_rating <= 8:
        result.verdict = "HIGH RISK"
    else:
        result.verdict = "DANGEROUS – LIKELY SCAM/PHISHING"

    return result


# ─────────────────────────────────────────────
#  FILE PARSER
# ─────────────────────────────────────────────

def parse_emails_from_file(filepath: str) -> List[Email]:
    """
    Parse emails from a plain text file.
    Each email is delimited by EMAIL_START / EMAIL_END.
    Fields: From:, Subject:, Body:
    """
    emails = []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
    except FileNotFoundError:
        print(f"[ERROR] File not found: {filepath}")
        return []

    blocks = re.findall(r'EMAIL_START(.*?)EMAIL_END', content, re.DOTALL)
    for block in blocks:
        email = Email()
        from_match = re.search(r'^From:\s*(.+)$', block, re.MULTILINE)
        subj_match = re.search(r'^Subject:\s*(.+)$', block, re.MULTILINE)

        if from_match:
            email.sender = from_match.group(1).strip()
        if subj_match:
            email.subject = subj_match.group(1).strip()
        body_match = re.search(r'Body:\s*(.*)', block)
        if body_match:
            email.body = body_match.group(1).strip()

        if email.sender or email.subject or email.body:
            emails.append(email)

    return emails


# ─────────────────────────────────────────────
#  REPORT PRINTER
# ─────────────────────────────────────────────

COLORS = {
    "reset":  "\033[0m",
    "bold":   "\033[1m",
    "red":    "\033[91m",
    "yellow": "\033[93m",
    "green":  "\033[92m",
    "cyan":   "\033[96m",
    "white":  "\033[97m",
    "gray":   "\033[90m",
    "orange": "\033[38;5;208m",
}

SEVERITY_COLORS = {1: "yellow", 2: "orange", 3: "red"}

def rating_bar(rating: int) -> str:
    """Visual risk bar."""
    filled = "█" * rating
    empty  = "░" * (10 - rating)
    if rating <= 2:
        color = COLORS["green"]
    elif rating <= 5:
        color = COLORS["yellow"]
    elif rating <= 7:
        color = COLORS["orange"]
    else:
        color = COLORS["red"]
    return f"{color}{filled}{empty}{COLORS['reset']} {rating}/10"


def verdict_color(verdict: str) -> str:
    if "TRUSTWORTHY" in verdict:
        return COLORS["green"]
    elif "LOW" in verdict:
        return COLORS["cyan"]
    elif "SUSPICIOUS" in verdict:
        return COLORS["yellow"]
    elif "HIGH" in verdict:
        return COLORS["orange"]
    else:
        return COLORS["red"]


def print_result(idx: int, result: ScanResult):
    b = COLORS["bold"]
    r = COLORS["reset"]
    g = COLORS["gray"]
    c = COLORS["cyan"]
    w = COLORS["white"]

    print(f"\n{'─'*65}")
    print(f"{b}{c}EMAIL #{idx}{r}  {g}{result.email.sender}{r}")
    print(f"{b}{w}Subject:{r} {result.email.subject}")
    print()

    # Risk bar
    print(f"  {b}Risk Rating:{r}  {rating_bar(result.risk_rating)}")
    vc = verdict_color(result.verdict)
    print(f"  {b}Verdict:    {r}  {vc}{b}{result.verdict}{r}")
    print()

    # URLs
    if result.urls_found:
        print(f"  {b}{g}URLs found ({len(result.urls_found)}):{r}")
        for url in result.urls_found[:5]:
            print(f"    {g}↳ {url}{r}")
        if len(result.urls_found) > 5:
            print(f"    {g}... and {len(result.urls_found)-5} more{r}")
        print()

    # Flags
    if result.flags:
        print(f"  {b}Flags ({len(result.flags)}):{r}")
        for flag in result.flags:
            sev_color = COLORS[SEVERITY_COLORS[flag.severity]]
            sev_label = ["", "LOW", "MED", "HIGH"][flag.severity]
            print(f"    {sev_color}[{sev_label}]{r} {b}{flag.category}:{r} {flag.description}")
    else:
        print(f"  {COLORS['green']}✓ No suspicious indicators detected.{r}")


def print_summary(results: List[ScanResult]):
    b = COLORS["bold"]
    r = COLORS["reset"]
    print(f"\n{'═'*65}")
    print(f"{b}  SCAN SUMMARY  —  {len(results)} emails analyzed{r}")
    print(f"{'═'*65}")
    for i, res in enumerate(results, 1):
        vc = verdict_color(res.verdict)
        bar = rating_bar(res.risk_rating)
        sender_short = res.email.sender[:35].ljust(35)
        print(f"  #{i}  {bar}  {vc}{res.verdict}{r}")
        print(f"       {COLORS['gray']}{sender_short}{r}")
    print(f"{'═'*65}\n")


#  JSON EXPORT

def export_json(results: List[ScanResult], output_path: str):
    data = []
    for i, res in enumerate(results, 1):
        data.append({
            "email_number": i,
            "sender": res.email.sender,
            "subject": res.email.subject,
            "risk_rating": res.risk_rating,
            "verdict": res.verdict,
            "urls_found": res.urls_found,
            "flags": [
                {"category": f.category, "description": f.description, "severity": f.severity}
                for f in res.flags
            ]
        })
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    print(f"  JSON report saved → {output_path}\n")


#  MAIN

def main():
    import sys

    filepath = sys.argv[1] if len(sys.argv) > 1 else "test_emails.txt" ##If using other .txt file change this to new name
    export_path = sys.argv[2] if len(sys.argv) > 2 else None

    print(f"\n{COLORS['bold']}{COLORS['cyan']}")
    print("  ╔══════════════════════════════════════════════╗")
    print("  ║        EMAIL SCAM & PHISHING SCANNER         ║")
    print("  ╚══════════════════════════════════════════════╝")
    print(f"{COLORS['reset']}")
    print(f"  Scanning: {COLORS['white']}{filepath}{COLORS['reset']}\n")

    emails = parse_emails_from_file(filepath)
    if not emails:
        print(f"{COLORS['red']}No emails found or file could not be read.{COLORS['reset']}")
        return

    print(f"  Found {len(emails)} email(s) to scan...")

    results = []
    for i, email in enumerate(emails, 1):
        result = scan_email(email)
        results.append(result)
        print_result(i, result)

    print_summary(results)

    if export_path:
        export_json(results, export_path)
    else:
        export_json(results, "scan_results.json")


if __name__ == "__main__":
    main()
