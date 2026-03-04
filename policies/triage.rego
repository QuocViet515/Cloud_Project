# OPA Triage Policy
# Evaluates cloud security findings and determines remediation action.
#
# Usage: opa eval -d triage.rego -i finding.json "data.triage.decision"

package triage

default decision = {"action": "create_ticket", "reason": "default policy"}

# CRITICAL findings → quarantine
decision = {"action": "quarantine", "reason": "CRITICAL severity"} {
    input.severity == "CRITICAL"
}

# IaC scanner findings → create PR
decision = {"action": "create_pr", "reason": "IaC finding from scanner"} {
    input.scanner == "checkov"
}
decision = {"action": "create_pr", "reason": "IaC finding from scanner"} {
    input.scanner == "tfsec"
}

# Container findings → ticket
decision = {"action": "create_ticket", "reason": "container finding needs review"} {
    input.scanner == "trivy"
}

# LOW severity in non-prod → auto-remediate
decision = {"action": "auto_remediate", "reason": "low severity in non-prod"} {
    input.severity == "LOW"
    input.environment != "prod"
}

# MEDIUM severity in non-prod → auto-remediate
decision = {"action": "auto_remediate", "reason": "medium severity in non-prod"} {
    input.severity == "MEDIUM"
    input.environment != "prod"
}

# HIGH severity in non-prod for safe rules → auto-remediate
decision = {"action": "auto_remediate", "reason": "safe rule in non-prod"} {
    input.severity == "HIGH"
    input.environment != "prod"
    safe_rules[input.finding_code]
}

# HIGH severity in prod → ticket
decision = {"action": "create_ticket", "reason": "HIGH in production"} {
    input.severity == "HIGH"
    input.environment == "prod"
}

# MEDIUM in prod → ticket
decision = {"action": "create_ticket", "reason": "MEDIUM in production"} {
    input.severity == "MEDIUM"
    input.environment == "prod"
}

# Sensitive resources always need ticket
decision = {"action": "create_ticket", "reason": "sensitive resource"} {
    input.is_sensitive == true
    input.severity != "LOW"
}

# Safe rules that can be auto-remediated
safe_rules = {
    "AZ-RES-TAGS-001",
    "AZ-Storage-PublicBlob-001",
    "AZST001",
    "AZ-Storage-Encryption-001",
    "AZ-VM-BOOTDIAG-001",
}
