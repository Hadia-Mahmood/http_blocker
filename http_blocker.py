import ipaddress
import re
import time
import logging
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Optional, Callable

log = logging.getLogger("http_blocker")


@dataclass
class Decision:
    allow: bool
    reason: str = ""
    rule: str = ""
    status: int = 403


@dataclass
class BlockRule:
    name: str
    action: str = "BLOCK"                 # "BLOCK" | "ALLOW" | "LOG"
    methods: Optional[set] = None         # {"POST", "PUT"}
    path_regex: Optional[re.Pattern] = None
    ip_cidrs: Optional[list] = None       # match only if client IS in one of these
    ip_cidrs_exclude: Optional[list] = None  # match only if client is NOT in one of these
    user_agent_regex: Optional[re.Pattern] = None
    headers_contain: Optional[dict] = None
    body_regex: Optional[re.Pattern] = None
    status: int = 403

    def matches(self, method, path, client_ip, headers, body) -> bool:
        if self.methods and method.upper() not in self.methods:
            return False
        if self.path_regex and not self.path_regex.search(path):
            return False

        if self.ip_cidrs or self.ip_cidrs_exclude:
            try:
                ip = ipaddress.ip_address(client_ip)
            except ValueError:
                return False
            if self.ip_cidrs and not any(ip in n for n in self.ip_cidrs):
                return False
            if self.ip_cidrs_exclude and any(ip in n for n in self.ip_cidrs_exclude):
                return False

        ua = headers.get("User-Agent", "") or headers.get("user-agent", "")
        if self.user_agent_regex and not self.user_agent_regex.search(ua):
            return False

        if self.headers_contain:
            for k, v in self.headers_contain.items():
                if k not in headers or v not in headers[k]:
                    return False

        if self.body_regex and body:
            try:
                txt = body.decode("utf-8", "ignore")
            except Exception:
                txt = ""
            if not self.body_regex.search(txt):
                return False

        return True


class SlidingWindowLimiter:
    def __init__(self, max_reqs: int, window: float = 60.0):
        self.max = max_reqs
        self.window = window
        self._hits = defaultdict(deque)

    def allow(self, key: str) -> bool:
        if self.max <= 0:
            return True
        now = time.monotonic()
        dq = self._hits[key]
        while dq and dq[0] < now - self.window:
            dq.popleft()
        if len(dq) >= self.max:
            return False
        dq.append(now)
        return True


class HTTPBlocker:
    def __init__(self, default_allow: bool = True, log_only: bool = False):
        self.rules: list[BlockRule] = []
        self.default_allow = default_allow
        self.log_only = log_only
        self.limiter = SlidingWindowLimiter(0)
        self.on_block: Optional[Callable] = None

    def add_rule(self, rule: BlockRule) -> "HTTPBlocker":
        self.rules.append(rule)
        return self

    def set_rate_limit(self, max_reqs: int, window: float = 60.0) -> "HTTPBlocker":
        self.limiter = SlidingWindowLimiter(max_reqs, window)
        return self

    def inspect(self, method, path, client_ip, headers, body: bytes = b"") -> Decision:
        # 1) Global per-IP rate limit
        if not self.limiter.allow(client_ip):
            log.warning("rate limit exceeded for %s", client_ip)
            return Decision(False, "rate limit exceeded", "global-rate", 429)

        # 2) Rules evaluated in order — first match wins
        for rule in self.rules:
            if rule.matches(method, path, client_ip, headers, body):
                if rule.action == "ALLOW":
                    return Decision(True, "allowed by rule", rule.name)
                if rule.action == "LOG":
                    log.info("LOG rule=%s %s %s from %s",
                             rule.name, method, path, client_ip)
                    continue
                if self.log_only:
                    log.warning("would BLOCK rule=%s %s %s from %s",
                                rule.name, method, path, client_ip)
                    continue
                return Decision(False, f"blocked by {rule.name}",
                                rule.name, rule.status)

        # 3) Default policy
        return Decision(self.default_allow, "default policy", "default")


# ---------------------------------------------------------------------------
# Ready-made rule factories for common attack signatures
# ---------------------------------------------------------------------------
def make_default_rules() -> list[BlockRule]:
    return [
        BlockRule(
            name="path-traversal",
            path_regex=re.compile(r"\.\./|\.\.%2f|%2e%2e", re.I),
            status=400,
        ),
        BlockRule(
            name="sqli-probe",
            path_regex=re.compile(r"('|%27)|(\-\-)|(%23)|(#\s)", re.I),
            status=400,
        ),
        BlockRule(
            name="scanner-user-agent",
            user_agent_regex=re.compile(
                r"(sqlmap|nikto|nmap|masscan|dirbuster|gobuster|wfuzz|zap)",
                re.I),
            status=403,
        ),
        BlockRule(
            name="null-byte",
            path_regex=re.compile(r"%00"),
            status=400,
        ),
        BlockRule(
            name="dotfile-access",
            path_regex=re.compile(r"/\.(git|env|htaccess|htpasswd|ssh)/", re.I),
            status=404,
        ),
    ]
