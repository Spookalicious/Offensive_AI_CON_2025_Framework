from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Dict

from .policy import Policy, PolicyToken, KeyManager


class RateLimiter:
    """Simple token-bucket per host."""

    def __init__(self, max_rps: int = 3) -> None:
        self.max_rps = max_rps
        self.allowance: Dict[str, float] = {}
        self.last_check: Dict[str, float] = {}
        self.lock = threading.Lock()

    def allow(self, host: str) -> bool:
        with self.lock:
            now = time.time()
            self.allowance.setdefault(host, self.max_rps)
            self.last_check.setdefault(host, now)
            delta = now - self.last_check[host]
            self.last_check[host] = now
            self.allowance[host] += delta * self.max_rps
            if self.allowance[host] > self.max_rps:
                self.allowance[host] = self.max_rps
            if self.allowance[host] < 1.0:
                return False
            self.allowance[host] -= 1.0
            return True


class ScopeEngine:
    """Enforces host allowlist, method allowlist, and token expiry."""

    def __init__(self, policy: Policy, token: PolicyToken, keys: KeyManager) -> None:
        self.policy = policy
        self.token = token
        self.keys = keys
        if not token.verify(keys):
            raise ValueError("Invalid policy token signature")

    def check_host(self, host: str) -> None:
        if host not in self.token.allow_hosts:
            raise PermissionError(f"Host not allowed by policy: {host}")
        if time.time() > self.token.expiry_epoch:
            raise PermissionError("Policy token expired")

    def check_method(self, method: str) -> None:
        if method.upper() not in self.policy.allowed_methods:
            raise PermissionError(f"Method not allowed by policy: {method}")

    @property
    def verify_only(self) -> bool:
        return self.policy.verify_only

    @property
    def require_manual_approval(self) -> bool:
        return self.policy.require_manual_approval


class AuditLogger:
    """Immutable JSONL audit logs with hash chaining."""

    def __init__(self, path: str | Path = "artifacts/audit/audit.jsonl") -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._last_hash_path = self.path.with_suffix(".last")

    def _hash(self, text: str) -> str:
        import hashlib
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    def _read_last(self) -> str:
        if self._last_hash_path.exists():
            return self._last_hash_path.read_text(encoding="utf-8").strip()
        return ""

    def _write_last(self, h: str) -> None:
        self._last_hash_path.write_text(h, encoding="utf-8")

    def log(self, event: Dict) -> str:
        prev = self._read_last()
        record = {"prev": prev, "event": event, "ts": time.time()}
        line = json.dumps(record, sort_keys=True)
        h = self._hash(line)
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps({"hash": h, **record}) + "\n")
        self._write_last(h)
        return h


class KillSwitch:
    """Filesystem kill switch. If the file exists and contains '1', abort operations."""

    def __init__(self, path: str | Path = "configs/killswitch.flag") -> None:
        self.path = Path(path)

    def active(self) -> bool:
        if not self.path.exists():
            return False
        try:
            return self.path.read_text(encoding="utf-8").strip() == "1"
        except Exception:
            return True
