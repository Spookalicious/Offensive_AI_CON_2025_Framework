param(
  [string]$BaseUrl = "http://127.0.0.1:5000"
)

# Start lab app
Start-Process -WindowStyle Hidden -FilePath "python" -ArgumentList "-m","lab_app.app"
Start-Sleep -Seconds 2

# Run discovery
python -m agentic_api.cli discover --base-url $BaseUrl --policy ./configs/policy.dsl

# Run inference
python -m agentic_api.cli infer

# Plan
python -m agentic_api.cli plan --policy ./configs/policy.dsl --verify-only

# End-to-end (read-only)
python -m agentic_api.cli run --base-url $BaseUrl --policy ./configs/policy.dsl
