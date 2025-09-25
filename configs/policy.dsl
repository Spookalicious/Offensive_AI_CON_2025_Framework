policy lab-default {
  allow_hosts = ["127.0.0.1", "localhost"]
  max_rps = 3
  max_requests = 500
  verify_only = true
  require_manual_approval = true
  allowed_methods = ["GET", "HEAD", "POST"]
}
