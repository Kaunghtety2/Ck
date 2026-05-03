"""
network_interceptor_bot_v3.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Internal Telegram Bot — Advanced Network Interceptor  (v3)
Stack : aiogram 3.x  |  playwright async  |  playwright-stealth

v3 IMPROVEMENTS over v2:
  ⑪ Form structure detection — fields, types, labels → JSON block (no submit)
  ⑫ Payment form fake-fill — card/CVV/expiry auto-filled → XHR captured
  ⑬ JS event triggers — scroll + hover + timer wait → lazy XHR capture
  ⑭ Payment field detection output — /payload-style JSON block in Telegram
  ⑮ Cookie/session extraction — HttpOnly, Secure, auth cookies shown
  ⑯ Improved auth/token detection — JWT, Bearer in responses, API keys
  ⑰ Improved secrets detection — 20+ patterns, response body scanning
  ⑱ Multi-phase scan engine — 5 phases, best result auto-selected

Install:
    pip install aiogram playwright playwright-stealth
    playwright install chromium

Run:
    export BOT_TOKEN="123:ABC..."
    python network_interceptor_bot_v3.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse

from aiogram import Bot, Dispatcher, F
from aiogram.filters import Command
from aiogram.types import (
    BufferedInputFile,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    Message,
    CallbackQuery,
)

from playwright.async_api import (
    Browser,
    BrowserContext,
    Page,
    Request,
    Response,
    Route,
    WebSocket,
    async_playwright,
)

try:
    from playwright_stealth import stealth_async
    STEALTH_AVAILABLE = True
except ImportError:
    STEALTH_AVAILABLE = False

# ════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ════════════════════════════════════════════════════════════════════════════

BOT_TOKEN: str = os.getenv("BOT_TOKEN", "8598285940:AAHkqNe2jIr7Jw5X70u_Tv6rw8r2UTKiWCE")

# Timeouts
NAVIGATE_TIMEOUT_MS: int  = 25_000
NETWORKIDLE_TIMEOUT_MS: int = 20_000
EXTRA_WAIT_S: float       = 3.0     # extra wait after networkidle for lazy XHR
RESPONSE_TIMEOUT_S: float = 8.0     # max wait for a matching response

# Limits
MAX_REQUESTS: int         = 300
MAX_WS_FRAMES: int        = 100
MAX_BODY_BYTES: int       = 8_192   # truncate response/request bodies
MAX_SCAN_CACHE: int       = 20      # how many scans to keep in memory per user
MAX_PARALLEL_SCANS: int   = 3       # global concurrent playwright sessions

# Noise filter
CAPTURED_RESOURCE_TYPES: set[str] = {"fetch", "xhr"}

NOISE_PATTERNS: list[re.Pattern] = [re.compile(p, re.I) for p in [
    r"google-analytics\.com", r"googletagmanager\.com",
    r"doubleclick\.net",      r"facebook\.com/tr",
    r"hotjar\.com",           r"segment\.io",
    r"mixpanel\.com",         r"amplitude\.com",
    r"fullstory\.com",        r"intercom\.io",
    r"sentry\.io",            r"bugsnag\.com",
    r"datadog-browser",       r"newrelic\.com",
    r"tealiumiq\.com",        r"quantserve\.com",
    r"chartbeat\.com",        r"crazyegg\.com",
]]

STRIP_REQUEST_HEADERS: set[str] = {
    "accept-encoding", "accept-language", "cache-control", "connection",
    "dnt", "pragma", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
    "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "sec-fetch-user",
    "upgrade-insecure-requests",
}

# ① Secrets in GET params — flag these to the user
SECRET_PARAM_PATTERNS: list[re.Pattern] = [re.compile(p, re.I) for p in [
    r"(api[_-]?key|apikey|access[_-]?token|auth[_-]?token|secret|password|passwd|pwd)=([^&]{4,})",
    r"(bearer|token)=([^&]{8,})",
    r"(private[_-]?key|client[_-]?secret|app[_-]?secret)=([^&]{4,})",
    r"(jwt|id[_-]?token|refresh[_-]?token)=([^&]{8,})",
]]

# ⑰ Secrets in response bodies
SECRET_BODY_PATTERNS: list[re.Pattern] = [re.compile(p, re.I) for p in [
    r'"(access_token|accessToken|auth_token|authToken|id_token|idToken)"\s*:\s*"([^"]{10,})"',
    r'"(api_key|apiKey|api_secret|apiSecret|client_secret|clientSecret)"\s*:\s*"([^"]{8,})"',
    r'"(password|passwd|pwd|secret)"\s*:\s*"([^"]{4,})"',
    r'(sk_live|pk_live|sk_test|pk_test)_[A-Za-z0-9]{20,}',  # Stripe keys
    r'ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',  # JWT
]]

# ⑫ Fake card data for payment form fill
FAKE_CARD_DATA = {
    "number":  "4111111111111111",   # Visa test number
    "expiry_month": "12",
    "expiry_year":  "2028",
    "expiry_mmyy":  "12/28",
    "cvv":     "123",
    "name":    "John Doe",
    "email":   "test@example.com",
    "phone":   "5555555555",
    "zip":     "10001",
    "address": "123 Test St",
    "city":    "New York",
    "state":   "NY",
    "country": "US",
}

# ⑪ Field name → category mapping for form structure detection
_CARD_FIELD_RE = re.compile(
    r"card.?num|cardnumber|cc.?num|pan$|account.?num|acctnum|number$|"
    r"cvv|cvc|csc|security.?code|card.?code|cvv2|"
    r"exp.?date|expiry|exp.?month|exp.?year|expirationdate|"
    r"card.?holder|cardholder|name.?on.?card|"
    r"routing.?num|routingnumber",
    re.I
)
_BILLING_FIELD_RE = re.compile(
    r"bill|address|city|state|zip|postal|country|province", re.I
)
_AUTH_FIELD_RE = re.compile(
    r"email|phone|username|user.?name|login|password|passwd", re.I
)

# ════════════════════════════════════════════════════════════════════════════
# DATA MODELS
# ════════════════════════════════════════════════════════════════════════════

@dataclass
class WsFrame:
    direction: str     # "sent" | "received"
    payload: str
    timestamp: float


@dataclass
class CapturedRequest:
    # Identity
    uid: int = 0          # sequential index within scan
    url: str = ""
    method: str = ""
    resource_type: str = ""

    # Request
    req_headers: Dict[str, str] = field(default_factory=dict)
    post_data: Optional[str] = None

    # ① Response
    status: Optional[int] = None
    status_text: Optional[str] = None
    resp_headers: Dict[str, str] = field(default_factory=dict)
    resp_body: Optional[str] = None        # decoded text / truncated
    resp_content_type: str = ""

    # ⑧ Timing
    req_start: float = 0.0
    resp_end: float = 0.0

    # ③ Auth flags (detected automatically)
    has_bearer: bool = False
    has_api_key: bool = False
    has_csrf: bool = False
    has_cookie_auth: bool = False

    # ⑩ Secrets in URL
    url_secrets: list[str] = field(default_factory=list)

    @property
    def latency_ms(self) -> Optional[float]:
        if self.req_start and self.resp_end:
            return round((self.resp_end - self.req_start) * 1000, 1)
        return None

    def as_text_block(self) -> str:
        lines: list[str] = []
        lat  = f"  {self.latency_ms}ms" if self.latency_ms else ""
        stat = f"  HTTP {self.status}" if self.status else ""
        ts   = datetime.fromtimestamp(self.req_start, tz=timezone.utc).strftime("%H:%M:%S.%f")[:-3]

        lines.append(f"{'─'*70}")
        lines.append(
            f"[{self.uid:03d}]  {self.method}  ({self.resource_type.upper()}){stat}{lat}  {ts} UTC"
        )

        # Secrets warning
        if self.url_secrets:
            lines.append(f"⚠️  SECRETS IN URL: {', '.join(self.url_secrets)}")

        lines.append(f"URL: {self.url}")
        lines.append("")

        # Auth summary line
        flags = []
        if self.has_bearer:    flags.append("🔑 Bearer")
        if self.has_api_key:   flags.append("🗝 API-Key")
        if self.has_csrf:      flags.append("🛡 CSRF")
        if self.has_cookie_auth: flags.append("🍪 Cookie-Auth")
        if flags:
            lines.append("Auth: " + "  ".join(flags))
            lines.append("")

        # Request headers
        priority, other = _split_headers(self.req_headers, direction="req")
        if priority:
            lines.append("── Key Request Headers ──")
            for k, v in priority.items():
                lines.append(f"  {k}: {_mask(k, v)}")
            lines.append("")
        if other:
            lines.append("── Other Request Headers ──")
            for k, v in sorted(other.items()):
                lines.append(f"  {k}: {v}")
            lines.append("")

        # POST body
        if self.post_data:
            lines.append("── Request Payload ──")
            lines.append(_fmt_body(self.post_data))
            lines.append("")

        # ① Response
        if self.status is not None:
            lines.append(f"── Response  HTTP {self.status}  {self.resp_content_type} ──")
            if self.resp_body:
                lines.append(_fmt_body(self.resp_body))
            lines.append("")

        return "\n".join(lines)

    def as_har_entry(self) -> dict:
        """HAR 1.2 entry object."""
        started_ms = int(self.req_start * 1000)
        return {
            "startedDateTime": datetime.fromtimestamp(
                self.req_start, tz=timezone.utc
            ).isoformat(),
            "time": self.latency_ms or -1,
            "request": {
                "method": self.method,
                "url": self.url,
                "httpVersion": "HTTP/1.1",
                "headers": [{"name": k, "value": v} for k, v in self.req_headers.items()],
                "queryString": [],
                "cookies": [],
                "headersSize": -1,
                "bodySize": len(self.post_data.encode()) if self.post_data else 0,
                "postData": (
                    {"mimeType": self.req_headers.get("content-type", ""),
                     "text": self.post_data}
                    if self.post_data else None
                ),
            },
            "response": {
                "status": self.status or 0,
                "statusText": self.status_text or "",
                "httpVersion": "HTTP/1.1",
                "headers": [{"name": k, "value": v} for k, v in self.resp_headers.items()],
                "cookies": [],
                "content": {
                    "size": len(self.resp_body.encode()) if self.resp_body else 0,
                    "mimeType": self.resp_content_type,
                    "text": self.resp_body or "",
                },
                "redirectURL": self.resp_headers.get("location", ""),
                "headersSize": -1,
                "bodySize": -1,
            },
            "cache": {},
            "timings": {
                "send": 0,
                "wait": self.latency_ms or -1,
                "receive": 0,
            },
        }


@dataclass
class ScanResult:
    """Everything produced by one /scan invocation."""
    target_url: str
    scan_id: str                                    # short ID for /diff
    started_at: float
    finished_at: float = 0.0
    requests: List[CapturedRequest] = field(default_factory=list)
    ws_frames: List[WsFrame] = field(default_factory=list)
    page_title: str = ""
    console_errors: List[str] = field(default_factory=list)
    auth_tokens: Dict[str, str] = field(default_factory=dict)   # ③ extracted tokens
    # ⑪ Form structure detection
    forms_detected: List[dict] = field(default_factory=list)
    # ⑮ Cookie/session info
    session_cookies: List[dict] = field(default_factory=list)
    # ⑰ Secrets found in response bodies
    body_secrets: List[dict] = field(default_factory=list)


# ════════════════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ════════════════════════════════════════════════════════════════════════════

PRIORITY_HEADERS_REQ = {
    "authorization", "x-api-key", "x-auth-token", "x-csrf-token",
    "x-xsrf-token", "content-type", "cookie", "x-requested-with",
}
PRIORITY_HEADERS_RESP = {
    "content-type", "set-cookie", "x-request-id", "x-correlation-id",
    "www-authenticate", "location", "x-ratelimit-limit", "x-ratelimit-remaining",
}


def _split_headers(
    headers: Dict[str, str],
    direction: str = "req",
) -> Tuple[Dict[str, str], Dict[str, str]]:
    priority_set = PRIORITY_HEADERS_REQ if direction == "req" else PRIORITY_HEADERS_RESP
    priority: Dict[str, str] = {}
    other: Dict[str, str] = {}
    for k, v in headers.items():
        kl = k.lower()
        if kl in STRIP_REQUEST_HEADERS and direction == "req":
            continue
        if kl in priority_set or kl.startswith("x-"):
            priority[k] = v
        else:
            other[k] = v
    return priority, other


def _mask(header_name: str, value: str) -> str:
    hn = header_name.lower()
    if hn in ("authorization", "x-api-key", "x-auth-token", "cookie"):
        if len(value) > 20:
            return value[:10] + "…" + value[-4:]
    return value


def _fmt_body(raw: str, limit: int = MAX_BODY_BYTES) -> str:
    raw = (raw or "").strip()
    if not raw:
        return "(empty)"
    # JSON
    try:
        parsed = json.loads(raw)
        out = json.dumps(parsed, indent=2, ensure_ascii=False)
        if len(out) > limit:
            out = out[:limit] + "\n…[TRUNCATED]"
        return out
    except Exception:
        pass
    # URL-encoded
    if "&" in raw and "=" in raw:
        try:
            pairs = parse_qsl(raw, keep_blank_values=True)
            if pairs:
                out = "\n".join(f"  {k} = {v}" for k, v in pairs)
                if len(out) > limit:
                    out = out[:limit] + "\n…[TRUNCATED]"
                return out
        except Exception:
            pass
    # Raw
    if len(raw) > limit:
        raw = raw[:limit] + "\n…[TRUNCATED]"
    return raw


def _is_noise(url: str) -> bool:
    return any(p.search(url) for p in NOISE_PATTERNS)


def _validate_url(raw: str) -> Optional[str]:
    raw = raw.strip()
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    try:
        p = urlparse(raw)
        if p.scheme in ("http", "https") and p.netloc:
            return raw
    except Exception:
        pass
    return None


def _detect_secrets_in_url(url: str) -> list[str]:
    """⑩ Return list of suspicious param names found in the URL."""
    found = []
    for pat in SECRET_PARAM_PATTERNS:
        for m in pat.finditer(url):
            found.append(m.group(1))
    return found


def _extract_auth_tokens(requests: List[CapturedRequest]) -> Dict[str, str]:
    """⑯ Walk all requests AND responses — pull out unique auth tokens / keys."""
    tokens: Dict[str, str] = {}
    for req in requests:
        # Request headers
        for k, v in req.req_headers.items():
            kl = k.lower()
            if kl == "authorization":
                tokens["Authorization"] = _mask(k, v)
            elif kl in ("x-api-key", "x-auth-token", "x-access-token",
                        "x-client-token", "x-session-token"):
                tokens[k] = _mask(k, v)
            elif kl in ("x-csrf-token", "x-xsrf-token", "x-request-token"):
                tokens[k] = v[:40] + ("…" if len(v) > 40 else "")
        # Response headers — auth challenges / token issuance
        for k, v in req.resp_headers.items():
            kl = k.lower()
            if kl in ("www-authenticate", "x-auth-token", "x-access-token"):
                tokens[f"resp:{k}"] = v[:60]
        # Response body — JWT / token fields
        if req.resp_body:
            for pat in SECRET_BODY_PATTERNS:
                for m in pat.finditer(req.resp_body):
                    key = m.group(1) if m.lastindex and m.lastindex >= 1 else "token"
                    val = m.group(0)[:60]
                    tokens[f"body:{key}"] = val
    return tokens


def _scan_body_secrets(requests: List[CapturedRequest]) -> List[dict]:
    """⑰ Scan response bodies for leaked secrets / credentials."""
    found = []
    for req in requests:
        if not req.resp_body:
            continue
        for pat in SECRET_BODY_PATTERNS:
            for m in pat.finditer(req.resp_body):
                found.append({
                    "url":     req.url[:80],
                    "pattern": pat.pattern[:40],
                    "match":   m.group(0)[:80],
                })
    return found


def _categorize_field(name: str, ftype: str, label: str) -> str:
    """⑪ Categorize a form field for structure map."""
    combined = f"{name} {label}".strip()
    if _CARD_FIELD_RE.search(combined) or ftype in ("tel", "credit-card"):
        return "card"
    if _BILLING_FIELD_RE.search(combined):
        return "billing"
    if _AUTH_FIELD_RE.search(combined) or ftype in ("email", "password", "tel"):
        return "user"
    if ftype == "hidden":
        return "hidden"
    return "other"


def _short_id(url: str, ts: float) -> str:
    import hashlib
    return hashlib.md5(f"{url}{ts}".encode()).hexdigest()[:6].upper()


# ════════════════════════════════════════════════════════════════════════════
# ⑪ FORM STRUCTURE DETECTION
# ════════════════════════════════════════════════════════════════════════════

async def _detect_forms(page) -> List[dict]:
    """Extract all forms from the page DOM — structure only, no submission."""
    try:
        forms = await page.evaluate("""() => {
            const results = [];
            document.querySelectorAll('form').forEach((form, fi) => {
                const fields = [];
                form.querySelectorAll('input, select, textarea').forEach(el => {
                    const label = (() => {
                        if (el.labels && el.labels.length)
                            return el.labels[0].innerText.trim();
                        const lbl = document.querySelector(`label[for="${el.id}"]`);
                        return lbl ? lbl.innerText.trim() : (el.placeholder || '');
                    })();
                    fields.push({
                        name:        el.name || el.id || '',
                        type:        el.type || el.tagName.toLowerCase(),
                        label:       label.slice(0, 60),
                        required:    el.required,
                        value:       (el.type === 'hidden') ? (el.value || '') : '',
                        autocomplete: el.autocomplete || '',
                    });
                });
                const btns = [];
                form.querySelectorAll('button, input[type=submit], input[type=button]')
                    .forEach(b => btns.push(b.innerText?.trim() || b.value || 'Submit'));
                results.push({
                    form_idx: fi + 1,
                    action:   form.action || '',
                    method:   (form.method || 'GET').toUpperCase(),
                    id:       form.id || '',
                    fields:   fields,
                    buttons:  btns.slice(0, 3),
                });
            });
            return results;
        }""")
        return forms or []
    except Exception:
        return []


# ════════════════════════════════════════════════════════════════════════════
# ⑬ JS EVENT TRIGGERS  (scroll + hover + timer flush)
# ════════════════════════════════════════════════════════════════════════════

async def _trigger_js_events(page) -> None:
    """Trigger scroll, hover, and wait for deferred timers to fire lazy XHR."""
    try:
        # Scroll down incrementally — triggers infinite scroll / lazy load XHR
        await page.evaluate("""async () => {
            const step = Math.floor(window.innerHeight * 0.8);
            const max  = Math.min(document.body.scrollHeight, step * 8);
            for (let y = 0; y < max; y += step) {
                window.scrollTo(0, y);
                await new Promise(r => setTimeout(r, 300));
            }
            window.scrollTo(0, 0);
        }""")
        # Hover over common interactive elements
        for sel in ("button", "a.nav-link", ".menu-item", "[data-trigger]"):
            try:
                el = await page.query_selector(sel)
                if el:
                    await el.hover()
                    await asyncio.sleep(0.2)
            except Exception:
                pass
        # Extra wait for setTimeout / setInterval callbacks
        await asyncio.sleep(2.5)
    except Exception:
        pass


# ════════════════════════════════════════════════════════════════════════════
# ⑫ PAYMENT FORM FAKE-FILL ENGINE
# ════════════════════════════════════════════════════════════════════════════

_CARD_SELECTORS = [
    # Card number
    ("card_number", [
        "input[name*=cardNum]", "input[name*=cardNumber]", "input[name*=number]",
        "input[name*=cc_num]",  "input[name*=ccnum]",      "input[name*=pan]",
        "input[autocomplete=cc-number]", "input[id*=card-number]",
        "input[id*=cardNumber]", "input[placeholder*=card]",
    ]),
    ("expiry_month", [
        "select[name*=expirationDateMonth]", "select[name*=expMonth]",
        "input[name*=exp_month]", "input[name*=expMonth]",
        "input[autocomplete=cc-exp-month]",
    ]),
    ("expiry_year", [
        "select[name*=expirationDateYear]", "select[name*=expYear]",
        "input[name*=exp_year]",  "input[name*=expYear]",
        "input[autocomplete=cc-exp-year]",
    ]),
    ("expiry_mmyy", [
        "input[name*=expiry]", "input[name*=expDate]", "input[name*=exp_date]",
        "input[autocomplete=cc-exp]", "input[placeholder*=MM/YY]",
        "input[placeholder*=MM/YYYY]",
    ]),
    ("cvv", [
        "input[name*=cvv]",  "input[name*=cvc]",  "input[name*=csc]",
        "input[name*=CVV2]", "input[name*=cvv2]", "input[name*=securityCode]",
        "input[autocomplete=cc-csc]", "input[placeholder*=CVV]",
        "input[placeholder*=CVC]",
    ]),
    ("name", [
        "input[name*=cardHolder]", "input[name*=card_holder]",
        "input[name*=nameOnCard]", "input[autocomplete=cc-name]",
    ]),
    ("email", [
        "input[type=email]", "input[name*=email]", "input[id*=email]",
    ]),
    ("zip", [
        "input[name*=billZip]", "input[name*=billing_zip]", "input[name*=zipCode]",
        "input[name*=postalCode]", "input[autocomplete=postal-code]",
    ]),
]


async def _fill_payment_form(page) -> dict:
    """
    ⑫ Detect and fill payment form fields with fake card data.
    Returns a report of which fields were filled.
    Does NOT click submit.
    """
    filled = {}
    for field_key, selectors in _CARD_SELECTORS:
        value = FAKE_CARD_DATA.get(field_key, "")
        for sel in selectors:
            try:
                el = await page.query_selector(sel)
                if not el:
                    continue
                tag  = await el.evaluate("e => e.tagName.toLowerCase()")
                typ  = await el.evaluate("e => (e.type || '').toLowerCase()")
                name = await el.evaluate("e => e.name || e.id || ''")
                if tag == "select":
                    # Pick the option whose value/text best matches
                    await el.evaluate(f"""
                        e => {{
                            const v = '{value}';
                            const opt = Array.from(e.options).find(
                                o => o.value === v || o.text.includes(v)
                            );
                            if (opt) e.value = opt.value;
                        }}
                    """)
                else:
                    await el.triple_click()
                    await el.type(value, delay=30)
                filled[name or sel] = {"field": field_key, "selector": sel, "value_preview": value[:6] + "***"}
                break   # found + filled for this field_key — move on
            except Exception:
                continue
    return filled


# ════════════════════════════════════════════════════════════════════════════
# ⑮ COOKIE / SESSION EXTRACTION
# ════════════════════════════════════════════════════════════════════════════

async def _extract_session_cookies(context) -> List[dict]:
    """⑮ Get all cookies from the browser context, flag auth-relevant ones."""
    _AUTH_COOKIE_RE = re.compile(
        r"(session|sess|auth|jwt|token|sid|login|user|account|remember)", re.I
    )
    try:
        raw_cookies = await context.cookies()
    except Exception:
        return []
    result = []
    for ck in raw_cookies:
        name  = ck.get("name", "")
        value = ck.get("value", "")
        is_auth = bool(_AUTH_COOKIE_RE.search(name))
        result.append({
            "name":      name,
            "value":     (value[:12] + "…") if len(value) > 12 else value,
            "domain":    ck.get("domain", ""),
            "httpOnly":  ck.get("httpOnly", False),
            "secure":    ck.get("secure",   False),
            "sameSite":  ck.get("sameSite", ""),
            "is_auth":   is_auth,
        })
    # Sort: auth cookies first
    result.sort(key=lambda c: (not c["is_auth"], c["name"]))
    return result


# ════════════════════════════════════════════════════════════════════════════
# CORE SCAN ENGINE
# ════════════════════════════════════════════════════════════════════════════

_scan_semaphore: asyncio.Semaphore   # initialised in main()


async def scan_url(
    target_url: str,
    interact_selector: Optional[str] = None,    # ⑥ click this before capture
    filter_domain: Optional[str]     = None,    # capture only this (sub)domain
    capture_responses: bool          = True,    # ① toggle
    capture_ws: bool                 = True,    # ② toggle
) -> Tuple[ScanResult, Optional[str]]:
    """
    Full scan. Returns (ScanResult, error_string_or_None).
    Uses a semaphore to limit concurrent Playwright sessions.
    """
    scan_id   = _short_id(target_url, time.time())
    result    = ScanResult(target_url=target_url, scan_id=scan_id,
                           started_at=time.time())
    lock      = asyncio.Lock()
    pending: Dict[str, CapturedRequest] = {}   # url → in-flight request

    async with _scan_semaphore:
        async with async_playwright() as pw:

            # ── Browser & context ─────────────────────────────────────
            browser: Browser = await pw.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-setuid-sandbox",
                      "--disable-dev-shm-usage",
                      "--disable-blink-features=AutomationControlled"],
            )
            context: BrowserContext = await browser.new_context(
                viewport={"width": 1366, "height": 768},
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/124.0.0.0 Safari/537.36"
                ),
                java_script_enabled=True,
                ignore_https_errors=True,
                extra_http_headers={"Accept-Language": "en-US,en;q=0.9"},
            )
            page: Page = await context.new_page()

            if STEALTH_AVAILABLE:
                await stealth_async(page)

            # ── Console error collector ────────────────────────────────
            page.on("console", lambda msg: (
                result.console_errors.append(
                    f"[{msg.type.upper()}] {msg.text[:200]}"
                )
                if msg.type in ("error", "warning") else None
            ))

            # ── ② WebSocket capture ────────────────────────────────────
            if capture_ws:
                async def on_websocket(ws: WebSocket) -> None:
                    async def on_frame_sent(payload: str) -> None:
                        async with lock:
                            if len(result.ws_frames) < MAX_WS_FRAMES:
                                result.ws_frames.append(
                                    WsFrame("sent", payload[:1024], time.time())
                                )
                    async def on_frame_received(payload: str) -> None:
                        async with lock:
                            if len(result.ws_frames) < MAX_WS_FRAMES:
                                result.ws_frames.append(
                                    WsFrame("received", payload[:1024], time.time())
                                )
                    ws.on("framesent",     on_frame_sent)
                    ws.on("framereceived", on_frame_received)

                page.on("websocket", on_websocket)

            # ── Request listener ──────────────────────────────────────
            async def on_request(request: Request) -> None:
                if request.resource_type not in CAPTURED_RESOURCE_TYPES:
                    return
                url = request.url
                if _is_noise(url):
                    return
                if filter_domain and filter_domain.lower() not in urlparse(url).netloc.lower():
                    return
                async with lock:
                    if len(result.requests) + len(pending) >= MAX_REQUESTS:
                        return

                secrets = _detect_secrets_in_url(url)
                hdrs    = dict(request.headers)

                req_obj = CapturedRequest(
                    uid           = 0,           # assigned on finalise
                    url           = url,
                    method        = request.method.upper(),
                    resource_type = request.resource_type,
                    req_headers   = hdrs,
                    post_data     = request.post_data,
                    req_start     = time.time(),
                    url_secrets   = secrets,
                    # ③ Auth flag detection
                    has_bearer    = "authorization" in {k.lower() for k in hdrs}
                                    and any(
                                        v.lower().startswith("bearer ")
                                        for k, v in hdrs.items()
                                        if k.lower() == "authorization"
                                    ),
                    has_api_key   = any(
                        k.lower() in ("x-api-key", "x-auth-token", "api-key")
                        for k in hdrs
                    ),
                    has_csrf      = any(
                        k.lower() in ("x-csrf-token", "x-xsrf-token")
                        for k in hdrs
                    ),
                    has_cookie_auth = (
                        "cookie" in {k.lower() for k in hdrs}
                        and re.search(
                            r"(session|auth|jwt|token|sid)=",
                            hdrs.get("cookie", ""), re.I
                        ) is not None
                    ),
                )
                async with lock:
                    pending[url] = req_obj

            page.on("request", on_request)

            # ── ① Response listener ───────────────────────────────────
            if capture_responses:
                async def on_response(response: Response) -> None:
                    url = response.url
                    async with lock:
                        req_obj = pending.pop(url, None)
                    if req_obj is None:
                        return

                    req_obj.resp_end      = time.time()
                    req_obj.status        = response.status
                    req_obj.status_text   = response.status_text
                    req_obj.resp_headers  = dict(response.headers)
                    req_obj.resp_content_type = response.headers.get(
                        "content-type", ""
                    )

                    # Decode response body (best-effort)
                    ct = req_obj.resp_content_type.lower()
                    if any(t in ct for t in ("json", "text", "xml", "javascript")):
                        try:
                            body_bytes = await asyncio.wait_for(
                                response.body(), timeout=RESPONSE_TIMEOUT_S
                            )
                            text = body_bytes.decode("utf-8", errors="replace")
                            req_obj.resp_body = (
                                text[:MAX_BODY_BYTES] + "…[TRUNCATED]"
                                if len(text) > MAX_BODY_BYTES else text
                            )
                        except Exception:
                            req_obj.resp_body = None

                    async with lock:
                        result.requests.append(req_obj)

                page.on("response", on_response)
            else:
                # No response capture — move pending → result on request only
                async def on_response_noop(response: Response) -> None:
                    url = response.url
                    async with lock:
                        req_obj = pending.pop(url, None)
                        if req_obj:
                            req_obj.resp_end = time.time()
                            req_obj.status   = response.status
                            result.requests.append(req_obj)
                page.on("response", on_response_noop)

            # ── Navigate ──────────────────────────────────────────────
            try:
                await page.goto(
                    target_url,
                    timeout    = NAVIGATE_TIMEOUT_MS,
                    wait_until = "domcontentloaded",
                )
            except Exception as exc:
                await browser.close()
                return result, f"Navigation failed: {exc}"

            # ── ⑥ Interaction — click selector if given ───────────────
            if interact_selector:
                try:
                    await page.wait_for_selector(interact_selector, timeout=5_000)
                    await page.click(interact_selector)
                    log.info("Clicked selector: %s", interact_selector)
                    await asyncio.sleep(1.5)
                except Exception as exc:
                    log.warning("Interaction failed (%s): %s", interact_selector, exc)

            # ── ⑬ JS event triggers — scroll + hover + lazy XHR ─────────
            await _trigger_js_events(page)

            # ── Wait for network quiet ────────────────────────────────
            try:
                await page.wait_for_load_state("networkidle",
                                               timeout=NETWORKIDLE_TIMEOUT_MS)
            except Exception:
                pass    # partial capture is fine

            # ── Extra dwell — catch lazy deferred calls ───────────────
            await asyncio.sleep(EXTRA_WAIT_S)

            # ── ⑪ Form structure detection ───────────────────────────
            result.forms_detected = await _detect_forms(page)

            # ── ⑫ Payment form fake-fill (if payment form detected) ──
            has_payment_form = any(
                any(_CARD_FIELD_RE.search(f.get("name","") + f.get("label",""))
                    for f in frm.get("fields", []))
                for frm in result.forms_detected
            )
            if has_payment_form:
                fill_report = await _fill_payment_form(page)
                result.forms_detected.append({
                    "_payment_fill": fill_report,
                    "note": "Fake card data filled — XHR captured after fill"
                })
                # Wait for any XHR triggered by autofill / validation
                await asyncio.sleep(2.0)
                try:
                    await page.wait_for_load_state("networkidle", timeout=8_000)
                except Exception:
                    pass

            # ── ⑮ Cookie/session extraction ──────────────────────────
            result.session_cookies = await _extract_session_cookies(context)

            # Flush any still-pending requests (no response matched)
            async with lock:
                for req_obj in pending.values():
                    req_obj.resp_end = time.time()
                    result.requests.append(req_obj)
                pending.clear()

            # Page metadata
            try:
                result.page_title = await page.title()
            except Exception:
                pass

            await browser.close()

    # ── Post-process ──────────────────────────────────────────────────────
    # Assign sequential UIDs and sort by request start time
    result.requests.sort(key=lambda r: r.req_start)
    for i, req in enumerate(result.requests, start=1):
        req.uid = i

    # ⑯ Extract auth tokens (requests + response bodies)
    result.auth_tokens  = _extract_auth_tokens(result.requests)
    # ⑰ Scan response bodies for leaked secrets
    result.body_secrets = _scan_body_secrets(result.requests)

    result.finished_at = time.time()
    return result, None


# ════════════════════════════════════════════════════════════════════════════
# OUTPUT BUILDERS
# ════════════════════════════════════════════════════════════════════════════

def _build_text_log(result: ScanResult) -> bytes:
    """Human-readable .txt report."""
    elapsed = result.finished_at - result.started_at
    lines: list[str] = [
        "━" * 70,
        "NETWORK INTERCEPTOR — SCAN REPORT  v2",
        "━" * 70,
        f"Target       : {result.target_url}",
        f"Page title   : {result.page_title or '(unknown)'}",
        f"Scan ID      : {result.scan_id}",
        f"Scanned at   : {datetime.fromtimestamp(result.started_at, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC",
        f"Duration     : {elapsed:.1f}s",
        f"API requests : {len(result.requests)}",
        f"WS frames    : {len(result.ws_frames)}",
        "",
    ]

    # ③ Auth tokens summary
    if result.auth_tokens:
        lines.append("── Auth Tokens Detected ──")
        for k, v in result.auth_tokens.items():
            lines.append(f"  {k}: {v}")
        lines.append("")

    # ⑩ Secrets warnings
    secrets_reqs = [r for r in result.requests if r.url_secrets]
    if secrets_reqs:
        lines.append("⚠️  SECRETS DETECTED IN URLS:")
        for r in secrets_reqs:
            lines.append(f"  [{r.uid:03d}] {r.url[:80]}  →  params: {r.url_secrets}")
        lines.append("")

    # Console errors
    if result.console_errors:
        lines.append("── Console Errors / Warnings ──")
        for e in result.console_errors[:20]:
            lines.append(f"  {e}")
        lines.append("")

    lines.append("━" * 70)
    lines.append("API REQUESTS")
    lines.append("━" * 70)
    lines.append("")

    for req in result.requests:
        lines.append(req.as_text_block())

    # ② WebSocket frames
    if result.ws_frames:
        lines.append("━" * 70)
        lines.append(f"WEBSOCKET FRAMES  ({len(result.ws_frames)})")
        lines.append("━" * 70)
        lines.append("")
        for i, fr in enumerate(result.ws_frames, 1):
            ts = datetime.fromtimestamp(fr.timestamp, tz=timezone.utc).strftime("%H:%M:%S.%f")[:-3]
            arrow = "→" if fr.direction == "sent" else "←"
            lines.append(f"[{i:03d}] {arrow} {ts} UTC")
            lines.append(fr.payload[:512])
            lines.append("")

    lines += ["", "━" * 70, "END OF REPORT", "━" * 70]
    return "\n".join(lines).encode("utf-8")


def _build_har(result: ScanResult) -> bytes:
    """⑨ Standard HAR 1.2 export — importable into Chrome DevTools / Insomnia."""
    har = {
        "log": {
            "version": "1.2",
            "creator": {"name": "NetworkInterceptorBot", "version": "2.0"},
            "pages": [{
                "startedDateTime": datetime.fromtimestamp(
                    result.started_at, tz=timezone.utc
                ).isoformat(),
                "id": "page_1",
                "title": result.page_title or result.target_url,
                "pageTimings": {},
            }],
            "entries": [r.as_har_entry() for r in result.requests],
        }
    }
    return json.dumps(har, indent=2, ensure_ascii=False).encode("utf-8")


def _esc(text: str) -> str:
    """Escape Markdown v1 special chars in user-controlled content.
    Escapes: _ * ` [ ]  (the chars that break Telegram Markdown v1 entities)
    """
    if not isinstance(text, str):
        text = str(text)
    for ch in ('\\', '_', '*', '`', '[', ']'):
        text = text.replace(ch, '\\' + ch)
    return text


def _build_summary_text(result: ScanResult) -> str:
    """Short Telegram message — under 4096 chars."""
    elapsed   = result.finished_at - result.started_at
    methods   = defaultdict(int)
    statuses  = defaultdict(int)
    with_body = 0
    secrets   = 0
    for r in result.requests:
        methods[r.method] += 1
        if r.status:
            statuses[r.status] += 1
        if r.post_data:
            with_body += 1
        if r.url_secrets:
            secrets += 1

    method_str = "  ".join(f"{m}: {c}" for m, c in sorted(methods.items()))
    status_str = "  ".join(f"HTTP{s}: {c}" for s, c in sorted(statuses.items()))

    auth_flags = []
    if any(r.has_bearer      for r in result.requests): auth_flags.append("🔑 Bearer")
    if any(r.has_api_key     for r in result.requests): auth_flags.append("🗝 API-Key")
    if any(r.has_csrf        for r in result.requests): auth_flags.append("🛡 CSRF")
    if any(r.has_cookie_auth for r in result.requests): auth_flags.append("🍪 Cookie-Auth")

    lines = [
        f"✅ *Scan complete*  `[{_esc(result.scan_id)}]`  {elapsed:.1f}s",
        f"📡 `{_esc(result.target_url)}`",
        f"📄 _{_esc(result.page_title)}_" if result.page_title else "",
        "",
        f"*Captured:* {len(result.requests)} API call(s)  |  WS frames: {len(result.ws_frames)}",
        f"Methods : {_esc(method_str) or 'none'}",
        f"Status  : {_esc(status_str) or 'none'}",
        f"POST/payload: {with_body}",
    ]

    # ── ⑯ Auth tokens ─────────────────────────────────────────────────────
    if auth_flags:
        lines.append("")
        lines.append("*🔐 Auth detected:*  " + "  ".join(auth_flags))
    if result.auth_tokens:
        for k, v in list(result.auth_tokens.items())[:5]:
            lines.append(f"  `{_esc(k)}`: `{_esc(str(v)[:60])}`")

    # ── ⑰ Body secrets ────────────────────────────────────────────────────
    if result.body_secrets:
        lines.append("")
        lines.append(f"⚠️ *{len(result.body_secrets)} secret(s) found in response bodies:*")
        for s in result.body_secrets[:4]:
            lines.append(f"  `{_esc(s['url'][:50])}` → `{_esc(s['match'][:50])}`")

    if secrets:
        lines.append(f"⚠️ *{secrets} request(s) with secrets in URL\\!*")

    # ── ⑮ Session cookies ─────────────────────────────────────────────────
    auth_cookies = [c for c in result.session_cookies if c.get("is_auth")]
    if auth_cookies:
        lines.append("")
        lines.append(f"🍪 *Session Cookies* ({len(result.session_cookies)} total, "
                     f"{len(auth_cookies)} auth-related):")
        lines.append("```")
        for ck in auth_cookies[:6]:
            flags = ""
            if ck["httpOnly"]: flags += " HttpOnly"
            if ck["secure"]:   flags += " Secure"
            if ck["sameSite"]: flags += f" SameSite={ck['sameSite']}"
            lines.append(f'  "{ck["name"]}": "{ck["value"]}"{flags}')
        lines.append("```")

    # ── ⑪ Form structure map ──────────────────────────────────────────────
    real_forms = [f for f in result.forms_detected if "form_idx" in f]
    fill_report = next((f.get("_payment_fill") for f in result.forms_detected
                        if "_payment_fill" in f), None)
    if real_forms:
        lines.append("")
        lines.append(f"📋 *Form Structure* ({len(real_forms)} form(s) detected):")
        for frm in real_forms[:4]:
            lines.append(f"\n*Form {frm['form_idx']}* — `{_esc(frm['action'][:60] or '(no action)')}` "
                         f"[{frm['method']}]")
            # Categorize fields
            card_f    = [f for f in frm["fields"] if _categorize_field(f["name"], f["type"], f["label"]) == "card"]
            billing_f = [f for f in frm["fields"] if _categorize_field(f["name"], f["type"], f["label"]) == "billing"]
            user_f    = [f for f in frm["fields"] if _categorize_field(f["name"], f["type"], f["label"]) == "user"]
            hidden_f  = [f for f in frm["fields"] if f["type"] == "hidden"]
            other_f   = [f for f in frm["fields"]
                         if _categorize_field(f["name"], f["type"], f["label"])
                         not in ("card", "billing", "user", "hidden")]

            def _jblock(fields, max_f=10):
                if not fields:
                    return None
                rows = ["{"]
                for f in fields[:max_f]:
                    label = f.get("label") or f["name"]
                    req   = " // required" if f.get("required") else ""
                    rows.append(f'  "{_esc_raw(f["name"])}": "{_esc_raw(label)}",{req}')
                rows.append("}")
                return "```\n" + "\n".join(rows) + "\n```"

            if card_f:
                lines.append(f"💳 *Card Fields* ({len(card_f)}):")
                lines.append(_jblock(card_f))
            if billing_f:
                lines.append(f"💰 *Billing Fields* ({len(billing_f)}):")
                lines.append(_jblock(billing_f))
            if user_f:
                lines.append(f"✏️ *User Fields* ({len(user_f)}):")
                lines.append(_jblock(user_f))
            if hidden_f:
                hnames = ", ".join(f"`{_esc(f['name'][:22])}`" for f in hidden_f[:8])
                extra  = f" +{len(hidden_f)-8}" if len(hidden_f) > 8 else ""
                lines.append(f"📌 *Hidden* ({len(hidden_f)}): {hnames}{_esc(extra)}")
            if other_f:
                lines.append(f"📝 *Other* ({len(other_f)}): "
                             + ", ".join(f"`{_esc(f['name'][:20])}`" for f in other_f[:5]))
            if frm.get("buttons"):
                btns = " · ".join(f"`{_esc(b[:30])}`" for b in frm["buttons"])
                lines.append(f"🟢 *Submit*: {btns}")

    # ── ⑫ Payment fill report ─────────────────────────────────────────────
    if fill_report:
        lines.append("")
        lines.append(f"⚡ *Payment Form Auto-Fill:* {len(fill_report)} field(s) filled with fake card data")
        lines.append("```")
        for fname, info in list(fill_report.items())[:8]:
            lines.append(f'  "{_esc_raw(fname)}": "{_esc_raw(info["value_preview"])}"')
        lines.append("```")

    if result.console_errors:
        lines.append(f"\n⚠️ {len(result.console_errors)} console error(s)")

    lines += ["", "📎 Files attached below"]
    return "\n".join(l for l in lines if l is not None)


def _esc_raw(s: str) -> str:
    """Escape for use inside code block (no Markdown escaping needed, just truncate)."""
    return str(s)[:60].replace('"', "'")


# ════════════════════════════════════════════════════════════════════════════
# ④ DIFF ENGINE
# ════════════════════════════════════════════════════════════════════════════

def _diff_scans(a: ScanResult, b: ScanResult) -> str:
    """④ Side-by-side diff of two scan results."""
    urls_a = {r.url for r in a.requests}
    urls_b = {r.url for r in b.requests}

    only_a  = urls_a - urls_b
    only_b  = urls_b - urls_a
    common  = urls_a & urls_b

    # For common URLs: compare status codes
    status_a = {r.url: r.status for r in a.requests if r.url in common}
    status_b = {r.url: r.status for r in b.requests if r.url in common}
    changed_status = {
        url for url in common
        if status_a.get(url) != status_b.get(url)
    }

    lines = [
        "━" * 60,
        f"DIFF  [{_esc(a.scan_id)}]  vs  [{_esc(b.scan_id)}]",
        f"A: {_esc(a.target_url)}",
        f"B: {_esc(b.target_url)}",
        "━" * 60,
        "",
        f"Common requests  : {len(common)}",
        f"Only in A [{_esc(a.scan_id)}] : {len(only_a)}",
        f"Only in B [{_esc(b.scan_id)}] : {len(only_b)}",
        f"Status changed   : {len(changed_status)}",
        "",
    ]
    if only_a:
        lines.append(f"── Only in A ──")
        for url in sorted(only_a):
            lines.append(f"  - {url}")
        lines.append("")
    if only_b:
        lines.append(f"── Only in B ──")
        for url in sorted(only_b):
            lines.append(f"  + {url}")
        lines.append("")
    if changed_status:
        lines.append("── Status Code Changes ──")
        for url in sorted(changed_status):
            lines.append(f"  {status_a.get(url)} → {status_b.get(url)}  {url}")
        lines.append("")
    return "\n".join(lines)


# ════════════════════════════════════════════════════════════════════════════
# SCAN CACHE  (per-user, last N scans)
# ════════════════════════════════════════════════════════════════════════════

# user_id → list[ScanResult]  (most recent last)
_scan_cache: Dict[int, List[ScanResult]] = defaultdict(list)


def _cache_result(user_id: int, result: ScanResult) -> None:
    cache = _scan_cache[user_id]
    cache.append(result)
    if len(cache) > MAX_SCAN_CACHE:
        cache.pop(0)


def _find_scan(user_id: int, scan_id: str) -> Optional[ScanResult]:
    for r in _scan_cache[user_id]:
        if r.scan_id == scan_id:
            return r
    return None


# ════════════════════════════════════════════════════════════════════════════
# BOT SETUP
# ════════════════════════════════════════════════════════════════════════════

logging.basicConfig(
    level   = logging.INFO,
    format  = "%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    datefmt = "%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("interceptor")

dp = Dispatcher()

# ── Active scan tracking ────────────────────────────────────────────────────
_active: set[int] = set()


# ════════════════════════════════════════════════════════════════════════════
# COMMAND HANDLERS
# ════════════════════════════════════════════════════════════════════════════

@dp.message(Command("start", "help"))
async def cmd_help(msg: Message) -> None:
    text = (
        "🔬 *Network Interceptor Bot v2*\n\n"
        "*Commands*\n"
        "`/scan <url>` — Full auto scan \\(all modes\\)\n"
        "`/scan <url> #selector` — \\+ custom click selector\n"
        "`/scan <url> filter:domain` — \\+ domain filter\n"
        "`/diff <id1> <id2>` — Diff two scans\n"
        "`/scans` — List your recent scans\n"
        "`/help` — This message\n\n"
        "*What /scan does automatically:*\n"
        "① Base XHR/Fetch \\+ response capture\n"
        "② WebSocket frame capture\n"
        "③ Auth token extraction\n"
        "④ Auto\\-click 15\\+ common selectors\n"
        "⑤ Secrets detector in URLs\n"
        "⑥ HAR export \\(Chrome DevTools / Insomnia\\)\n"
        "⑦ Diff \\(base vs click\\) if new traffic found\n\n"
        "*Output per scan:*\n"
        "• Summary message\n"
        "• `.txt` human\\-readable log\n"
        "• `.har` file\n"
        "• `.txt` diff \\(if auto\\-click found new requests\\)\n\n"
        "*Examples*\n"
        "`/scan https://app\\.internal/checkout`\n"
        "`/scan https://app\\.internal #pay\\-button`\n"
        "`/scan https://app\\.internal filter:api\\.internal`"
    )
    await msg.answer(text, parse_mode="MarkdownV2")


# ── Auto-click selectors tried on every scan ────────────────────────────────
AUTO_CLICK_SELECTORS: list[str] = [
    # Payment / checkout buttons
    "button[type=submit]", "input[type=submit]",
    "#pay-button", "#submit-btn", "#checkout-btn", ".pay-now",
    ".checkout-button", ".submit-payment", ".place-order",
    "[data-testid*=pay]", "[data-testid*=submit]", "[data-testid*=checkout]",
    # Login / auth
    "#login-btn", ".login-button", "[type=submit]",
    # Generic
    "button.primary", "button.btn-primary", ".cta-button",
]


async def _run_full_scan(
    msg: Message,
    target_url: str,
    extra_selector: Optional[str] = None,
    filter_domain: Optional[str]  = None,
) -> None:
    """
    Runs ALL scan phases automatically:
      Phase 1 — Base XHR/Fetch + JS event triggers (scroll/hover/timers)
      Phase 2 — Form structure detection + payment fake-fill (built into scan_url)
      Phase 3 — Cookie/session extraction (built into scan_url)
      Phase 4 — Auto-click 15+ common selectors (stops on first new traffic)
      Phase 5 — User-supplied selector (if given)
    Sends: summary + .txt log + .har + diff (if click found new requests)
    """
    user_id = msg.from_user.id

    url = _validate_url(target_url)
    if not url:
        await msg.reply("❌ Invalid URL.")
        return

    if user_id in _active:
        await msg.reply("⏳ You already have an active scan. Please wait.")
        return

    _active.add(user_id)
    domain = urlparse(url).netloc.replace(":", "_") or "scan"
    ts_str = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S")

    status_msg = await msg.reply(
        f"🔬 *Full Scan v3* — `{_esc(url)}`\n"
        f"_Phase 1/5: Base XHR/Fetch + JS event triggers …_",
        parse_mode="Markdown",
    )

    try:
        # ── Phase 1: Base scan ────────────────────────────────────────────
        result_base, err = await scan_url(url, filter_domain=filter_domain)
        if err:
            await status_msg.edit_text(f"❌ Navigation failed: `{_esc(err)}`",
                                       parse_mode="Markdown")
            return

        _cache_result(user_id, result_base)
        base_urls = {r.url for r in result_base.requests}

        # ── Phase 2-3: Form detection + payment fill (done inside scan_url) ─
        forms_found = len([f for f in result_base.forms_detected if "form_idx" in f])
        pay_filled  = any("_payment_fill" in f for f in result_base.forms_detected)
        cookies_found = len(result_base.session_cookies)

        await status_msg.edit_text(
            f"🔬 *Full Scan v3* — `{_esc(url)}`\n"
            f"_Phase 2-3 done: {forms_found} form(s) detected"
            f"{', payment filled' if pay_filled else ''}"
            f", {cookies_found} cookie(s)_\n"
            f"_Phase 4/5: Auto-click {len(AUTO_CLICK_SELECTORS)} selectors …_",
            parse_mode="Markdown",
        )

        # ── Phase 4: Auto-click scan ──────────────────────────────────────

        result_click: Optional[ScanResult] = None
        clicked_selector: Optional[str]    = None

        for sel in AUTO_CLICK_SELECTORS:
            r, e = await scan_url(url, interact_selector=sel, filter_domain=filter_domain)
            if e:
                continue
            new_urls = {req.url for req in r.requests} - base_urls
            if new_urls:
                result_click    = r
                clicked_selector = sel
                _cache_result(user_id, r)
                log.info("Auto-click hit: %s → %d new request(s)", sel, len(new_urls))
                break

        # ── Phase 5: User-supplied selector ──────────────────────────────
        result_user: Optional[ScanResult] = None
        if extra_selector:
            await status_msg.edit_text(
                f"🔬 *Full Scan v3* — `{_esc(url)}`\n"
                f"_Phase 5/5: Custom click `{_esc(extra_selector)}` …_",
                parse_mode="Markdown",
            )
            r3, e3 = await scan_url(url, interact_selector=extra_selector,
                                    filter_domain=filter_domain)
            if not e3:
                result_user = r3
                _cache_result(user_id, r3)

        # ── Pick best result for primary report ───────────────────────────
        # Priority: user selector > auto-click > base
        primary = result_user or result_click or result_base

        # ── Build files ───────────────────────────────────────────────────
        txt_bytes = _build_text_log(primary)
        har_bytes = _build_har(primary)
        txt_name  = f"scan_{domain}_{primary.scan_id}_{ts_str}.txt"
        har_name  = f"scan_{domain}_{primary.scan_id}_{ts_str}.har"

        # ── Build summary ─────────────────────────────────────────────────
        elapsed_total = time.time() - result_base.started_at
        extra_lines = []
        if clicked_selector:
            new_count = len({r.url for r in result_click.requests} - base_urls)
            extra_lines.append(
                f"🖱 Auto-click `{_esc(clicked_selector)}` → *+{new_count} new request(s)*"
            )
        if result_user:
            extra_lines.append(
                f"🖱 Custom `{_esc(extra_selector)}` → "
                f"*{len(result_user.requests)} request(s)*"
            )
        if not clicked_selector and not result_user:
            extra_lines.append("🖱 No interaction triggered new requests")

        base_summary = _build_summary_text(primary)
        full_summary = (
            base_summary.replace(
                "📎 Files attached below",
                "\n".join(extra_lines) + "\n\n"
                f"⏱ Total scan time: {elapsed_total:.1f}s\n"
                "📎 Files attached below"
            )
        )
        await status_msg.edit_text(full_summary, parse_mode="Markdown")

        # ── Send files ────────────────────────────────────────────────────
        await msg.answer_document(
            BufferedInputFile(txt_bytes, filename=txt_name),
            caption="📄 Scan log (best result)",
        )
        await msg.answer_document(
            BufferedInputFile(har_bytes, filename=har_name),
            caption="📦 HAR — Chrome DevTools / Insomnia",
        )

        # ── Send diff if click phase found new traffic ─────────────────────
        if result_click and result_click is not primary:
            diff_text  = _diff_scans(result_base, result_click)
            diff_bytes = diff_text.encode("utf-8")
            await msg.answer_document(
                BufferedInputFile(diff_bytes,
                                  filename=f"diff_base_vs_click_{ts_str}.txt"),
                caption=f"④ Diff: base vs auto-click `{_esc(clicked_selector)}`",
            )

        # Edge case: nothing captured at all
        if not primary.requests and not primary.ws_frames:
            await status_msg.edit_text(
                f"✅ Scan done `[{_esc(primary.scan_id)}]` — no XHR/Fetch captured.\n"
                f"_The page may need JavaScript interaction or login._",
                parse_mode="Markdown",
            )

    except Exception as exc:
        log.exception("Full scan error")
        await status_msg.edit_text(
            f"❌ Unexpected error: `{_esc(str(exc))}`", parse_mode="Markdown"
        )
    finally:
        _active.discard(user_id)


@dp.message(Command("scan", "scan_har", "scan_click", "scan_filter"))
async def cmd_scan(msg: Message) -> None:
    """
    /scan <url> [css_selector] [filter:domain]
    Runs ALL phases automatically:
      • Base XHR/Fetch capture
      • Auto-click 15+ common selectors
      • Custom selector if provided
    Returns: summary + .txt log + .har + diff (if click found new traffic)
    """
    parts = (msg.text or "").split(maxsplit=3)
    if len(parts) < 2:
        await msg.reply(
            "📌 *Usage:* `/scan <url> [#selector] [filter:domain]`\n\n"
            "*Examples:*\n"
            "`/scan https://app.com`  — full auto scan\n"
            "`/scan https://app.com #pay-btn`  — + click selector\n"
            "`/scan https://app.com filter:api.app.com`  — domain filter\n\n"
            "_Runs all scan modes automatically and returns all results._",
            parse_mode="Markdown",
        )
        return

    raw_url        = parts[1].strip()
    extra_selector: Optional[str] = None
    filter_domain:  Optional[str] = None

    # Parse optional args: #selector and filter:domain (any order)
    for arg in parts[2:]:
        arg = arg.strip()
        if arg.startswith("filter:"):
            filter_domain = arg[7:]
        elif arg.startswith("#") or arg.startswith(".") or arg.startswith("["):
            extra_selector = arg
        else:
            # Could be a bare domain filter or a selector — heuristic
            if "." in arg and "/" not in arg and not arg.startswith(("button", "input")):
                filter_domain = arg
            else:
                extra_selector = arg

    await _run_full_scan(
        msg,
        target_url     = raw_url,
        extra_selector = extra_selector,
        filter_domain  = filter_domain,
    )


@dp.message(Command("scans"))
async def cmd_scans(msg: Message) -> None:
    """List recent scans for this user."""
    user_id = msg.from_user.id
    cache   = _scan_cache.get(user_id, [])
    if not cache:
        await msg.reply("No scans yet. Use `/scan <url>` to start.", parse_mode="Markdown")
        return
    lines = ["*Your recent scans:*", ""]
    for r in reversed(cache):
        ts  = datetime.fromtimestamp(r.started_at, tz=timezone.utc).strftime("%H:%M:%S")
        lines.append(
            f"`[{_esc(r.scan_id)}]`  {ts} UTC  —  {len(r.requests)} req(s)  "
            f"→  `{_esc(r.target_url[:50])}`"
        )
    await msg.reply("\n".join(lines), parse_mode="Markdown")


@dp.message(Command("diff"))
async def cmd_diff(msg: Message) -> None:
    """④ /diff <scan_id_A> <scan_id_B>"""
    user_id = msg.from_user.id
    parts   = (msg.text or "").split()
    if len(parts) < 3:
        cache   = _scan_cache.get(user_id, [])
        ids_str = "  ".join(f"`{_esc(r.scan_id)}`" for r in cache[-4:]) or "_none_"
        await msg.reply(
            f"Usage: `/diff <id1> <id2>`\n\nYour recent scan IDs: {ids_str}",
            parse_mode="Markdown",
        )
        return

    id_a, id_b = parts[1].upper(), parts[2].upper()
    scan_a = _find_scan(user_id, id_a)
    scan_b = _find_scan(user_id, id_b)

    missing = []
    if not scan_a: missing.append(id_a)
    if not scan_b: missing.append(id_b)
    if missing:
        await msg.reply(f"❌ Scan ID(s) not found: {', '.join(missing)}")
        return

    diff_text = _diff_scans(scan_a, scan_b)
    diff_bytes = diff_text.encode("utf-8")
    ts = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S")
    await msg.answer_document(
        BufferedInputFile(diff_bytes, filename=f"diff_{id_a}_vs_{id_b}_{ts}.txt"),
        caption=f"④ Diff: [{id_a}] vs [{id_b}]",
    )


@dp.message(F.text.startswith("/"))
async def cmd_unknown(msg: Message) -> None:
    await msg.reply("Unknown command. Send /help.")


# ════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ════════════════════════════════════════════════════════════════════════════

async def main() -> None:
    global _scan_semaphore
    _scan_semaphore = asyncio.Semaphore(MAX_PARALLEL_SCANS)

    if not BOT_TOKEN:
        raise RuntimeError("BOT_TOKEN not set. export BOT_TOKEN='123:ABC...'")

    bot = Bot(token=BOT_TOKEN)
    log.info("Network Interceptor Bot v2 — starting")
    try:
        await dp.start_polling(bot, allowed_updates=["message", "callback_query"])
    finally:
        await bot.session.close()


if __name__ == "__main__":
    asyncio.run(main())
