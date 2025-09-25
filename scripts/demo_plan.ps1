param(
  [string]$BaseUrl = "http://127.0.0.1:5000"
)

# Start lab app if not running
Start-Process -WindowStyle Hidden -FilePath "python" -ArgumentList "-m","lab_app.app"
Start-Sleep -Seconds 2

# Reset emulator
Invoke-RestMethod -Method Post -Uri "$BaseUrl/admin/emulator" -ContentType 'application/json' -Body '{"emulate_5xx": false, "latency_ms": 0, "waf_block": false}' | Out-Null

# Baseline discovery
python -m agentic_api.cli discover --base-url $BaseUrl --policy ./configs/policy.dsl
Copy-Item artifacts\peg.json artifacts\peg_old.json -Force

# Introduce drift
Invoke-RestMethod -Method Post -Uri "$BaseUrl/admin/drift" -ContentType 'application/json' -Body '{"version": 2}' | Out-Null

# Rediscover after drift
python -m agentic_api.cli discover --base-url $BaseUrl --policy ./configs/policy.dsl

# Drift compare
python -m agentic_api.cli drift --old artifacts/peg_old.json --new artifacts/peg.json --threshold 0.9

# End-to-end run
python -m agentic_api.cli run --base-url $BaseUrl --policy ./configs/policy.dsl
