import os
import socket

import pytest

from agentic_api.discovery import DiscoveryAgent
from agentic_api.evidence import EvidenceStore
from agentic_api.policy import Policy, PolicyToken, KeyManager
from agentic_api.safety import RateLimiter, ScopeEngine


def _port_open(host: str, port: int) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.2)
    try:
        s.connect((host, port))
        s.close()
        return True
    except Exception:
        return False


@pytest.mark.skipif(not _port_open("127.0.0.1", 5000), reason="lab app not running")
def test_discovery_smoke(tmp_path):
    policy = Policy.default_lab()
    km = KeyManager(tmp_path)
    km.generate()
    token = PolicyToken.from_policy(policy, km, ttl_seconds=60)
    scope = ScopeEngine(policy, token, km)
    rl = RateLimiter(max_rps=5)
    store = EvidenceStore(tmp_path)

    agent = DiscoveryAgent(scope, rl, store)
    peg = agent.discover("http://127.0.0.1:5000", max_depth=1)
    assert len(list(peg.graph.nodes())) >= 1
