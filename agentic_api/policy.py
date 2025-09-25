from __future__ import annotations

import base64
import json
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization


@dataclass
class Policy:
    policy_id: str
    allow_hosts: List[str]
    max_rps: int
    max_requests: int
    verify_only: bool
    require_manual_approval: bool
    allowed_methods: List[str]

    @staticmethod
    def default_lab() -> "Policy":
        return Policy(
            policy_id="lab-default",
            allow_hosts=["127.0.0.1", "localhost"],
            max_rps=3,
            max_requests=500,
            verify_only=True,
            require_manual_approval=True,
            allowed_methods=["GET", "HEAD", "POST"],
        )


class PolicyParser:
    """Minimal DSL parser for policy files.

    Grammar:
      policy <id> {
        allow_hosts = ["host1", "host2"]
        max_rps = 3
        max_requests = 500
        verify_only = true|false
        require_manual_approval = true|false
        allowed_methods = ["GET", "POST"]
      }
    """

    _bool = re.compile(r"^(true|false)$", re.I)
    _list = re.compile(r"^\[(.*)\]$")

    def parse(self, text: str) -> Policy:
        lines = [l.strip() for l in text.splitlines() if l.strip() and not l.strip().startswith("#")]
        if not lines or not lines[0].startswith("policy "):
            raise ValueError("Policy must start with 'policy <id> {'")
        m = re.match(r"policy\s+([a-zA-Z0-9_-]+)\s*\{", lines[0])
        if not m:
            raise ValueError("Invalid policy header")
        policy_id = m.group(1)

        fields: Dict[str, Any] = {}
        for l in lines[1:]:
            if l == "}":
                break
            if "=" not in l:
                continue
            k, v = [x.strip() for x in l.split("=", 1)]
            if self._list.match(v):
                inner = self._list.match(v).group(1)
                items = [x.strip().strip('\"\'') for x in inner.split(",") if x.strip()]
                fields[k] = items
            elif self._bool.match(v):
                fields[k] = v.lower() == "true"
            else:
                try:
                    fields[k] = int(v)
                except ValueError:
                    fields[k] = v.strip('\"\'')

        return Policy(
            policy_id=policy_id,
            allow_hosts=list(fields.get("allow_hosts", ["127.0.0.1", "localhost"])),
            max_rps=int(fields.get("max_rps", 3)),
            max_requests=int(fields.get("max_requests", 500)),
            verify_only=bool(fields.get("verify_only", True)),
            require_manual_approval=bool(fields.get("require_manual_approval", True)),
            allowed_methods=list(fields.get("allowed_methods", ["GET", "HEAD", "POST"])),
        )


@dataclass
class PolicyToken:
    policy_id: str
    allow_hosts: List[str]
    expiry_epoch: int
    signature_b64: str

    @staticmethod
    def from_policy(policy: Policy, keys: "KeyManager", ttl_seconds: int = 3600) -> "PolicyToken":
        payload = {
            "policy_id": policy.policy_id,
            "allow_hosts": policy.allow_hosts,
            "expiry_epoch": int(time.time()) + ttl_seconds,
        }
        payload_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
        sig = keys.sign(payload_bytes)
        return PolicyToken(
            policy_id=policy.policy_id,
            allow_hosts=policy.allow_hosts,
            expiry_epoch=payload["expiry_epoch"],
            signature_b64=base64.b64encode(sig).decode("ascii"),
        )

    def verify(self, keys: "KeyManager") -> bool:
        payload = {
            "policy_id": self.policy_id,
            "allow_hosts": self.allow_hosts,
            "expiry_epoch": self.expiry_epoch,
        }
        payload_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
        sig = base64.b64decode(self.signature_b64.encode("ascii"))
        return keys.verify(payload_bytes, sig)


class KeyManager:
    """Ed25519 signing keys for tokens and audit events."""

    def __init__(self, key_dir: str | Path = "configs/keys") -> None:
        self.key_dir = Path(key_dir)
        self.private_path = self.key_dir / "ed25519_private.pem"
        self.public_path = self.key_dir / "ed25519_public.pem"

    def keypair_exists(self) -> bool:
        return self.private_path.exists() and self.public_path.exists()

    def generate(self) -> None:
        self.key_dir.mkdir(parents=True, exist_ok=True)
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        with open(self.private_path, "wb") as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
        with open(self.public_path, "wb") as f:
            f.write(
                public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )

    def _load_private(self) -> Ed25519PrivateKey:
        with open(self.private_path, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)

    def _load_public(self) -> Ed25519PublicKey:
        with open(self.public_path, "rb") as f:
            return serialization.load_pem_public_key(f.read())

    def sign(self, data: bytes) -> bytes:
        return self._load_private().sign(data)

    def verify(self, data: bytes, signature: bytes) -> bool:
        try:
            self._load_public().verify(signature, data)
            return True
        except Exception:
            return False
