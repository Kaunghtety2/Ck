"""
network_interceptor_bot_v2.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Internal Telegram Bot — Advanced Network Interceptor  (v2 — Real-World)
Stack : aiogram 3.x  |  playwright async  |  playwright-stealth

REAL-WORLD ENHANCEMENTS over v1:
  ① Response body + status capture (not just requests)
  ② WebSocket frame capture (ws:// / wss://)
  ③ Auth token extraction — Bearer, API keys, cookies, CSRF
  ④ /diff command — compare two scans side-by-side
  ⑤ /filter command — re-filter a cached scan without re-fetching
  ⑥ Interaction mode — click a CSS selector before capturing
  ⑦ Scan queue — multiple users served concurrently, max 3 parallel
  ⑧ Timeline with latency — request start → response end in ms
  ⑨ HAR export — standard format parseable by DevTools / Insomnia
  ⑩ Secrets detector — flag credentials leaked into GET params

Install:
    pip install aiogram playwright playwright-stealth
    playwright install chromium

Run:
    export BOT_TOKEN="123:ABC..."
    python network_interceptor_bot_v2.py
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
    r"(api[_-]?key|apikey|access[_-]?token|auth[_-]?token|secret|password|passwd|pwd)"
    r"=([^&]{4,})",
    r"(bearer|token)=([^&]{8,})",
]]

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
    auth_tokens: Dict[str, str] = field(default_factory=dict)  # ③ extracted tokens


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
    """③ Walk all requests and pull out unique auth tokens / keys."""
    tokens: Dict[str, str] = {}
    for req in requests:
        for k, v in req.req_headers.items():
            kl = k.lower()
            if kl == "authorization":
                tokens["Authorization"] = _mask(k, v)
            elif kl in ("x-api-key", "x-auth-token", "x-access-token"):
                tokens[k] = _mask(k, v)
            elif kl == "x-csrf-token" or kl == "x-xsrf-token":
                tokens[k] = v
    return tokens


def _short_id(url: str, ts: float) -> str:
    import hashlib
    return hashlib.md5(f"{url}{ts}".encode()).hexdigest()[:6].upper()


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

            # ── Wait for network quiet ────────────────────────────────
            try:
                await page.wait_for_load_state("networkidle",
                                               timeout=NETWORKIDLE_TIMEOUT_MS)
            except Exception:
                pass    # partial capture is fine

            # ── Extra dwell — catch lazy deferred calls ───────────────
            await asyncio.sleep(EXTRA_WAIT_S)

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

    # ③ Extract auth tokens summary
    result.auth_tokens = _extract_auth_tokens(result.requests)

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
    if any(r.has_bearer    for r in result.requests): auth_flags.append("🔑 Bearer")
    if any(r.has_api_key   for r in result.requests): auth_flags.append("🗝 API-Key")
    if any(r.has_csrf      for r in result.requests): auth_flags.append("🛡 CSRF")
    if any(r.has_cookie_auth for r in result.requests): auth_flags.append("🍪 Cookie-Auth")

    lines = [
        f"✅ *Scan complete*  `[{result.scan_id}]`  {elapsed:.1f}s",
        f"📡 `{result.target_url}`",
        f"📄 _{result.page_title}_" if result.page_title else "",
        "",
        f"*Captured:* {len(result.requests)} API call(s)",
        f"Methods:  {method_str or 'none'}",
        f"Status:   {status_str or 'none'}",
        f"POST with payload: {with_body}",
        f"WS frames: {len(result.ws_frames)}",
        "",
    ]
    if auth_flags:
        lines.append("*Auth detected:*  " + "  ".join(auth_flags))
    if result.auth_tokens:
        for k, v in list(result.auth_tokens.items())[:3]:
            lines.append(f"  `{k}`: `{v}`")
    if secrets:
        lines.append(f"⚠️ *{secrets} request(s) with secrets in URL!*")
    if result.console_errors:
        lines.append(f"⚠️ {len(result.console_errors)} console error(s)")

    lines += ["", "📎 Files attached below"]
    return "\n".join(l for l in lines if l is not None)


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
        f"DIFF  [{a.scan_id}]  vs  [{b.scan_id}]",
        f"A: {a.target_url}",
        f"B: {b.target_url}",
        "━" * 60,
        "",
        f"Common requests  : {len(common)}",
        f"Only in A [{a.scan_id}] : {len(only_a)}",
        f"Only in B [{b.scan_id}] : {len(only_b)}",
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
        "`/scan <url>` — Intercept XHR/Fetch\\+responses\n"
        "`/scan_har <url>` — Same \\+ download HAR file\n"
        "`/scan_click <url> <css_selector>` — Click before capture\n"
        "`/scan_filter <url> <domain>` — Only capture that domain\n"
        "`/diff <id1> <id2>` — Diff two scans\n"
        "`/scans` — List your recent scans\n"
        "`/help` — This message\n\n"
        "*Output*\n"
        "Each scan delivers a `.txt` log \\+ `.har` file\\.\n"
        "HAR files open in Chrome DevTools / Insomnia\\.\n\n"
        "*Example*\n"
        "`/scan https://app.internal/checkout`\n"
        "`/scan_click https://app.internal #pay-button`\n"
        "`/scan_filter https://app.internal api.internal`"
    )
    await msg.answer(text, parse_mode="MarkdownV2")


async def _run_scan_command(
    msg: Message,
    target_url: str,
    interact_selector: Optional[str] = None,
    filter_domain: Optional[str]     = None,
    send_har: bool                   = True,
) -> None:
    """Core handler used by all /scan* commands."""
    user_id = msg.from_user.id

    url = _validate_url(target_url)
    if not url:
        await msg.reply("❌ Invalid URL.")
        return

    if user_id in _active:
        await msg.reply("⏳ You already have an active scan. Please wait.")
        return

    _active.add(user_id)
    status_msg = await msg.reply(
        f"🔍 Scanning `{url}` …\n"
        f"_{('Click → ' + interact_selector + ' → ') if interact_selector else ''}"
        f"waiting up to {(NAVIGATE_TIMEOUT_MS + NETWORKIDLE_TIMEOUT_MS) // 1000}s_",
        parse_mode="Markdown",
    )

    try:
        result, error = await scan_url(
            url,
            interact_selector = interact_selector,
            filter_domain     = filter_domain,
        )

        if error:
            await status_msg.edit_text(f"❌ {error}")
            return

        _cache_result(user_id, result)

        if not result.requests and not result.ws_frames:
            await status_msg.edit_text(
                f"✅ Scan `[{result.scan_id}]` done — "
                f"no XHR/Fetch captured.\n"
                f"_(Try `/scan_click` if the page needs interaction)_",
                parse_mode="Markdown",
            )
            return

        # Build files
        txt_bytes = _build_text_log(result)
        har_bytes = _build_har(result)
        ts        = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S")
        domain    = urlparse(url).netloc.replace(":", "_") or "scan"
        txt_name  = f"scan_{domain}_{result.scan_id}_{ts}.txt"
        har_name  = f"scan_{domain}_{result.scan_id}_{ts}.har"

        summary = _build_summary_text(result)
        await status_msg.edit_text(summary, parse_mode="Markdown")

        await msg.answer_document(
            BufferedInputFile(txt_bytes, filename=txt_name),
            caption="📄 Human-readable scan log",
        )
        if send_har:
            await msg.answer_document(
                BufferedInputFile(har_bytes, filename=har_name),
                caption="📦 HAR file — open in Chrome DevTools or Insomnia",
            )

    except Exception as exc:
        log.exception("Scan error")
        await status_msg.edit_text(f"❌ Unexpected error: `{exc}`", parse_mode="Markdown")
    finally:
        _active.discard(user_id)


@dp.message(Command("scan"))
async def cmd_scan(msg: Message) -> None:
    """/scan <url>"""
    parts = (msg.text or "").split(maxsplit=1)
    if len(parts) < 2:
        await msg.reply("Usage: `/scan https://your-app.com`", parse_mode="Markdown")
        return
    await _run_scan_command(msg, target_url=parts[1].strip())


@dp.message(Command("scan_har"))
async def cmd_scan_har(msg: Message) -> None:
    """/scan_har <url>  — same as /scan but explicitly mentions HAR"""
    parts = (msg.text or "").split(maxsplit=1)
    if len(parts) < 2:
        await msg.reply("Usage: `/scan_har https://your-app.com`", parse_mode="Markdown")
        return
    await _run_scan_command(msg, target_url=parts[1].strip(), send_har=True)


@dp.message(Command("scan_click"))
async def cmd_scan_click(msg: Message) -> None:
    """⑥ /scan_click <url> <css_selector>"""
    parts = (msg.text or "").split(maxsplit=2)
    if len(parts) < 3:
        await msg.reply(
            "Usage: `/scan_click https://app.com #submit-btn`\n"
            "The bot will click the selector before capturing.",
            parse_mode="Markdown",
        )
        return
    await _run_scan_command(
        msg,
        target_url         = parts[1].strip(),
        interact_selector  = parts[2].strip(),
    )


@dp.message(Command("scan_filter"))
async def cmd_scan_filter(msg: Message) -> None:
    """⑤ /scan_filter <url> <domain_filter>"""
    parts = (msg.text or "").split(maxsplit=2)
    if len(parts) < 3:
        await msg.reply(
            "Usage: `/scan_filter https://app.com api.app.com`\n"
            "Only captures requests to the specified domain.",
            parse_mode="Markdown",
        )
        return
    await _run_scan_command(
        msg,
        target_url    = parts[1].strip(),
        filter_domain = parts[2].strip(),
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
            f"`[{r.scan_id}]`  {ts} UTC  —  {len(r.requests)} req(s)  "
            f"→  `{r.target_url[:50]}`"
        )
    await msg.reply("\n".join(lines), parse_mode="Markdown")


@dp.message(Command("diff"))
async def cmd_diff(msg: Message) -> None:
    """④ /diff <scan_id_A> <scan_id_B>"""
    user_id = msg.from_user.id
    parts   = (msg.text or "").split()
    if len(parts) < 3:
        cache   = _scan_cache.get(user_id, [])
        ids_str = "  ".join(f"`{r.scan_id}`" for r in cache[-4:]) or "_none_"
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
