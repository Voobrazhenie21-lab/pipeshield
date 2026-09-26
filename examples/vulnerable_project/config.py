# VULNERABLE CONFIGURATION (For PipeShield Testing)
# Violations:
# 1. Exposed AWS Access Key ID [PS-SEC-001]
# 2. Hardcoded Database credentials in connection URI [PS-SEC-008]
# 3. Slack Incoming Webhook URL exposed [PS-SEC-004]

AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"

DATABASE_URL = "postgres://pg_admin:SuperSecurePass12345!@db-prod.internal:5432/corp_data"

SLACK_ALERT_WEBHOOK = "https://hooks.slack.com/services/T12345678/B12345678/abcdefghijklmnopqrstuvwx"
