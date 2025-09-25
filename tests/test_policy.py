from agentic_api.policy import PolicyParser, PolicyToken, KeyManager


def test_policy_parse_and_token(tmp_path):
    p = tmp_path / "p.dsl"
    p.write_text("""
policy demo {
  allow_hosts = ["127.0.0.1"]
  max_rps = 2
  max_requests = 10
  verify_only = true
  require_manual_approval = true
  allowed_methods = ["GET", "HEAD"]
}
""", encoding="utf-8")
    parser = PolicyParser()
    policy = parser.parse(p.read_text(encoding="utf-8"))
    km = KeyManager(tmp_path)
    km.generate()
    tok = PolicyToken.from_policy(policy, km, ttl_seconds=60)
    assert tok.verify(km)
