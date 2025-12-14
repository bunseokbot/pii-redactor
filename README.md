# PII Redactor

<p align="center">
  <a href="./README.md">English</a> |
  <a href="./docs/ko/README.md">한국어</a>
</p>

A Cloud Native solution for detecting, alerting, and redacting PII (Personally Identifiable Information) from Kubernetes logs.

[![Go Version](https://img.shields.io/badge/Go-1.22+-blue.svg)](https://golang.org)
[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](LICENSE)
[![CI](https://github.com/bunseokbot/pii-redactor/actions/workflows/ci.yaml/badge.svg)](https://github.com/bunseokbot/pii-redactor/actions/workflows/ci.yaml)
[![Release](https://github.com/bunseokbot/pii-redactor/actions/workflows/release.yaml/badge.svg)](https://github.com/bunseokbot/pii-redactor/actions/workflows/release.yaml)

## Overview

PII Redactor is a Kubernetes Operator that detects and masks PII in real-time from logs generated within your Kubernetes cluster.

### Key Features

- **Real-time PII Detection**: Detect PII patterns in log streams in real-time
- **20+ Built-in Patterns**: Email, phone numbers, SSN, credit cards, AWS keys, and more
- **Custom Patterns**: Add user-defined patterns via CRD
- **Community Rules**: Subscribe and use patterns shared by the community
- **Multiple Masking Strategies**: Support for partial, full, hash, and tokenize strategies
- **Alert Integration**: Slack, PagerDuty, Webhook, and more
- **Audit Logging**: Record PII detection history for compliance

## Quick Start

### Local Testing (CLI)

```bash
# Build CLI
make build-cli

# Scan text
./bin/pii-redactor -t "Email: test@example.com Phone: 010-1234-5678"

# Scan file
./bin/pii-redactor -f /var/log/app.log

# JSON output
./bin/pii-redactor -t "Card: 4111-1111-1111-1111" -o json

# Use specific patterns only
./bin/pii-redactor -t "test@example.com" -p "email,phone-kr"

# List available patterns
./bin/pii-redactor -list
```

### Deploy to Kubernetes

```bash
# Install CRDs
make install

# Deploy controller
make deploy

# Apply sample CRs
make sample
```

### Deploy with Helm

```bash
# Install from OCI registry (recommended)
helm install pii-redactor oci://ghcr.io/bunseokbot/charts/pii-redactor \
  --namespace pii-system \
  --create-namespace

# Or install from local source
helm install pii-redactor ./deploy/helm/pii-redactor \
  --namespace pii-system \
  --create-namespace

# Install with custom values
helm install pii-redactor oci://ghcr.io/bunseokbot/charts/pii-redactor \
  --namespace pii-system \
  --create-namespace \
  --set controller.logLevel=debug \
  --set monitoring.serviceMonitor.enabled=true

# Upgrade
helm upgrade pii-redactor oci://ghcr.io/bunseokbot/charts/pii-redactor \
  --namespace pii-system

# Uninstall
helm uninstall pii-redactor --namespace pii-system
```

#### Helm Values

| Parameter | Description | Default |
|-----------|-------------|---------|
| `replicaCount` | Number of controller replicas | `1` |
| `image.repository` | Controller image repository | `ghcr.io/bunseokbot/pii-redactor` |
| `image.tag` | Controller image tag | `appVersion` |
| `controller.logLevel` | Log level (debug, info, warn, error) | `info` |
| `builtInPatterns.enabled` | Enable built-in PII patterns | `true` |
| `builtInPatterns.categories` | Pattern categories to enable | `[global, usa, korea, secrets]` |
| `communityRules.enabled` | Enable community rules support | `false` |
| `monitoring.serviceMonitor.enabled` | Enable Prometheus ServiceMonitor | `false` |
| `resources.limits.cpu` | CPU limit | `500m` |
| `resources.limits.memory` | Memory limit | `128Mi` |

## Custom Resource Definitions

### PIIPattern - Define PII Patterns

```yaml
apiVersion: pii.namjun.kim/v1alpha1
kind: PIIPattern
metadata:
  name: custom-employee-id
spec:
  displayName: "Employee ID"
  description: "Company employee ID pattern"
  patterns:
    - regex: 'EMP-[A-Z]{2}\d{6}'
      confidence: high
  maskingStrategy:
    type: partial
    showFirst: 4
    maskChar: "*"
  severity: medium
  testCases:
    shouldMatch:
      - "EMP-AB123456"
    shouldNotMatch:
      - "EMP-123456"
```

### PIIPolicy - Define Policies

```yaml
apiVersion: pii.namjun.kim/v1alpha1
kind: PIIPolicy
metadata:
  name: production-policy
spec:
  selector:
    namespaces: [production, staging]
    excludeNamespaces: [kube-system]
  patterns:
    builtIn: [email, phone-kr, korean-rrn, credit-card]
    custom:
      - name: custom-employee-id
  actions:
    redact:
      enabled: true
    alert:
      enabled: true
      channels: [slack-security]
    audit:
      enabled: true
```

### PIICommunitySource - Community Rule Source

```yaml
apiVersion: pii.namjun.kim/v1alpha1
kind: PIICommunitySource
metadata:
  name: official-community
spec:
  type: git
  git:
    url: https://github.com/bunseokbot/pii-redactor-community-rules
    ref: main
    path: rules
  sync:
    interval: "1h"
  trust:
    verification:
      enabled: true
```

### PIIRuleSubscription - Subscribe to Rules

```yaml
apiVersion: pii.namjun.kim/v1alpha1
kind: PIIRuleSubscription
metadata:
  name: korea-finance-rules
spec:
  sourceRef:
    name: official-community
  subscribe:
    - category: korea
      patterns: ["*"]
    - category: finance
      patterns: ["credit-card", "bank-account"]
  updatePolicy:
    automatic: true
    requireApproval: [majorVersion]
```

## Built-in Patterns

| Pattern Name | Description | Severity |
|-------------|-------------|----------|
| `email` | Email addresses | medium |
| `korean-rrn` | Korean Resident Registration Number | critical |
| `phone-kr` | Korean phone numbers | high |
| `credit-card` | Credit card numbers (Visa, MC, Amex) | critical |
| `ip-address` | IPv4 addresses | low |
| `ipv6-address` | IPv6 addresses | low |
| `passport-kr` | Korean passport numbers | critical |
| `driver-license-kr` | Korean driver license numbers | critical |
| `business-number-kr` | Korean business registration numbers | high |
| `bank-account-kr` | Korean bank account numbers | critical |
| `ssn-us` | US Social Security Numbers | critical |
| `phone-us` | US phone numbers | high |
| `aws-access-key` | AWS Access Key ID | critical |
| `aws-secret-key` | AWS Secret Access Key | critical |
| `github-token` | GitHub Personal Access Tokens | critical |
| `api-key` | Generic API keys | high |
| `jwt` | JSON Web Tokens | high |
| `private-key` | Private keys (RSA, DSA, EC) | critical |
| `password-in-url` | Passwords embedded in URLs | critical |
| `iban` | International Bank Account Numbers | critical |
| `mac-address` | MAC addresses | low |

## Community Rules

See [pii-redactor-community-rules](https://github.com/bunseokbot/pii-redactor-community-rules) repository for community-contributed PII patterns.

### Contributing Patterns

1. Fork the community-rules repository
2. Add your pattern to the appropriate category
3. Include test cases
4. Submit a pull request

## License

Apache License 2.0

## Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) for details.
