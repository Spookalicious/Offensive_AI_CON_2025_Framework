from __future__ import annotations

import hashlib
import json
import queue
import time
import socket
import ssl
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

import networkx as nx
import requests
from bs4 import BeautifulSoup

from .evidence import EvidenceStore
from .safety import RateLimiter, ScopeEngine


@dataclass
class EndpointSample:
    url: str
    method: str
    status: int
    content_type: str
    headers: Dict[str, str]
    body_len: int
    latency_ms: float
    fingerprint: List[float]
    timestamp: float
    parent: Optional[str] = None


class PEG:
    """Probabilistic Endpoint Graph."""

    def __init__(self) -> None:
        self.graph = nx.DiGraph()

    def add_sample(self, sample: EndpointSample) -> None:
        node_id = sample.url
        self.graph.add_node(
            node_id,
            fingerprint=sample.fingerprint,
            last_status=sample.status,
            content_type=sample.content_type,
        )
        if sample.parent:
            self.graph.add_edge(sample.parent, node_id, relation="discovered", confidence=0.6)

    def to_dict(self) -> Dict:
        return {
            "nodes": [
                {"id": n, **self.graph.nodes[n]} for n in self.graph.nodes()
            ],
            "edges": [
                {"src": u, "dst": v, **d} for u, v, d in self.graph.edges(data=True)
            ],
        }

    @staticmethod
    def from_dict(d: Dict) -> "PEG":
        peg = PEG()
        for n in d.get("nodes", []):
            peg.graph.add_node(n["id"], **{k: v for k, v in n.items() if k != "id"})
        for e in d.get("edges", []):
            peg.graph.add_edge(e["src"], e["dst"], **{k: v for k, v in e.items() if k not in {"src", "dst"}})
        return peg


class DiscoveryAgent:
    def __init__(self, scope: ScopeEngine, rate_limiter: RateLimiter, evidence_store: EvidenceStore) -> None:
        self.scope = scope
        self.rate_limiter = rate_limiter
        self.store = evidence_store

    @staticmethod
    def _tls_features(url: str) -> List[float]:
        parsed = urlparse(url)
        if parsed.scheme != "https" or not parsed.hostname:
            return [0.0, 0.0, 0.0, 0.0, 0.0]
        host = parsed.hostname
        port = parsed.port or 443
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=3) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cipher = ssock.cipher()  # (name, proto, bits)
                    version = ssock.version() or ""
                    # Hash cipher name + version into a compact vector
                    h = hashlib.sha256((cipher[0] + ":" + version).encode("utf-8")).digest()
                    v0, v1, v2, v3 = [b / 255.0 for b in h[:4]]
                    # encode TLS version as a small numeric
                    vver = float(len(version)) / 10.0
                    return [v0, v1, v2, v3, vver]
        except Exception:
            return [0.0, 0.0, 0.0, 0.0, 0.0]

    def _fingerprint(self, resp: requests.Response, latency_ms: float) -> List[float]:
        headers = "|".join(sorted([f"{k}:{v}" for k, v in resp.headers.items() if k and v]))
        ct = resp.headers.get("Content-Type", "")
        size = float(len(resp.content) if resp.content is not None else 0)
        latency = float(latency_ms)
        h = hashlib.sha256((headers + ct).encode("utf-8")).digest()
        v0, v1, v2, v3 = [b / 255.0 for b in h[:4]]
        tls_vec = self._tls_features(resp.url)
        return [v0, v1, v2, v3, size / 1e6, latency / 10.0] + tls_vec

    def _safe_request(self, method: str, url: str, parent: Optional[str]) -> Optional[EndpointSample]:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        self.scope.check_host(host)
        self.scope.check_method(method)
        if not self.rate_limiter.allow(host):
            time.sleep(0.333)
        start = time.time()
        try:
            if method == "HEAD":
                resp = requests.head(url, timeout=5)
            else:
                resp = requests.get(url, timeout=5)
        except Exception:
            return None
        latency_ms = (time.time() - start) * 1000.0
        fp = self._fingerprint(resp, latency_ms)
        sample = EndpointSample(
            url=url,
            method=method,
            status=resp.status_code,
            content_type=resp.headers.get("Content-Type", ""),
            headers={k: v for k, v in resp.headers.items()},
            body_len=len(resp.content or b"") if hasattr(resp, "content") else 0,
            latency_ms=latency_ms,
            fingerprint=fp,
            timestamp=time.time(),
            parent=parent,
        )
        return sample

    def discover(self, base_url: str, max_depth: int = 2) -> PEG:
        visited: Set[str] = set()
        q: queue.Queue[Tuple[str, int, Optional[str]]] = queue.Queue()
        q.put((base_url, 0, None))
        peg = PEG()

        while not q.empty():
            url, depth, parent = q.get()
            if url in visited or depth > max_depth:
                continue
            visited.add(url)
            for method in ("HEAD", "GET"):
                sample = self._safe_request(method, url, parent)
                if not sample:
                    continue
                peg.add_sample(sample)
                self.store.write_structured(
                    name=f"sample_{hashlib.sha1(url.encode('utf-8')).hexdigest()}_{method.lower()}",
                    content={
                        "url": url,
                        "method": method,
                        "status": sample.status,
                        "content_type": sample.content_type,
                        "headers": self.store.redact_headers(sample.headers),
                        "body_len": sample.body_len,
                        "latency_ms": sample.latency_ms,
                        "fingerprint": sample.fingerprint,
                        "timestamp": sample.timestamp,
                        "parent": parent,
                    },
                )
                if method == "GET" and sample.status < 400 and sample.content_type.startswith("text/html"):
                    try:
                        soup = BeautifulSoup(requests.get(url, timeout=5).text, "html.parser")
                        for a in soup.find_all("a"):
                            href = a.get("href")
                            if not href:
                                continue
                            child = urljoin(url, href)
                            if child.startswith(base_url):
                                q.put((child, depth + 1, url))
                    except Exception:
                        pass
        return peg
