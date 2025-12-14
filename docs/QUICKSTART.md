# Quick Start Guide

This guide helps you get started with PII Redactor for both local testing and cluster deployment.

## Table of Contents

- [Local Testing (CLI)](#local-testing-cli)
- [Deployment Methods](#deployment-methods)
  - [Helm](#option-1-helm-recommended)
  - [Kustomize](#option-2-kustomize)
  - [kubectl](#option-3-kubectl)
- [Basic Usage](#basic-usage)
- [Community Rules](#community-rules)

---

## Local Testing (CLI)

Test PII detection locally without deploying to a cluster.

### Install CLI

```bash
# Option 1: Go install
go install github.com/bunseokbot/pii-redactor/cmd/cli@latest

# Option 2: Build from source
git clone https://github.com/bunseokbot/pii-redactor.git
cd pii-redactor
make build-cli
sudo mv bin/pii-redactor /usr/local/bin/
```

### CLI Usage

```bash
# Scan text
pii-redactor -t "My email is test@example.com and SSN is 123-45-6789"

# Scan file
pii-redactor -f /var/log/app.log

# JSON output
pii-redactor -t "Card: 4111-1111-1111-1111" -o json

# Use specific patterns only
pii-redactor -t "Call 010-1234-5678" -p "phone-kr,email"

# List available patterns
pii-redactor -list

# Read from stdin
cat app.log | pii-redactor
```

### Local Testing with Make

```bash
# Run quick tests
make test-local

# Output:
# Test 1: Korean RRN
# Detected 1 PII instance(s)
# [critical] korean-rrn (1 found)
#   - Original: 920101-1234567
#     Redacted: 920101-*******
```

---

## Deployment Methods

### Prerequisites

- Kubernetes cluster (v1.24+)
- kubectl configured
- Helm 3.x (for Helm installation)

### Option 1: Helm (Recommended)

```bash
# Add repository
helm repo add pii-redactor https://bunseokbot.github.io/pii-redactor
helm repo update

# Install
helm install pii-redactor pii-redactor/pii-redactor \
  --namespace pii-system \
  --create-namespace

# Or install from local chart
helm install pii-redactor ./deploy/helm/pii-redactor \
  --namespace pii-system \
  --create-namespace

# Custom values
helm install pii-redactor pii-redactor/pii-redactor \
  --namespace pii-system \
  --create-namespace \
  --set replicaCount=2 \
  --set controller.logLevel=debug
```

### Option 2: Kustomize

```bash
# Development
kubectl apply -k deploy/kustomize/overlays/dev

# Production
kubectl apply -k deploy/kustomize/overlays/prod

# Or base installation
kubectl apply -k deploy/kustomize/base
```

### Option 3: kubectl

```bash
# Install CRDs
kubectl apply -f config/crd/bases/

# Create namespace
kubectl create namespace pii-system

# Deploy controller
kubectl apply -f config/manager/ -n pii-system

# Apply sample CRs
kubectl apply -f config/samples/
```

---

## Basic Usage

### 1. Create a PIIPolicy

```yaml
apiVersion: pii.namjun.kim/v1alpha1
kind: PIIPolicy
metadata:
  name: default-policy
  namespace: pii-system
spec:
  targetNamespaces:
    matchNames:
      - default
      - production
  builtInPatterns:
    enabled: true
    categories:
      - global    # email, credit-card, iban
      - usa       # ssn, phone, itin
      - korea     # rrn, phone
      - secrets   # aws, github, stripe keys
  action:
    onDetection: redact
```

```bash
kubectl apply -f policy.yaml
```

### 2. Create Custom Pattern

```yaml
apiVersion: pii.namjun.kim/v1alpha1
kind: PIIPattern
metadata:
  name: employee-id
spec:
  displayName: "Employee ID"
  description: "Company employee IDs"
  patterns:
    - regex: 'EMP-[0-9]{6}'
      confidence: high
  maskingStrategy:
    type: partial
    showFirst: 4
    showLast: 0
    maskChar: "*"
  severity: medium
  testCases:
    shouldMatch:
      - "EMP-123456"
    shouldNotMatch:
      - "EMP-12345"
```

```bash
kubectl apply -f employee-pattern.yaml
```

### 3. Set Up Alerts (Optional)

```yaml
apiVersion: pii.namjun.kim/v1alpha1
kind: PIIAlertChannel
metadata:
  name: slack-alerts
  namespace: pii-system
spec:
  type: slack
  slack:
    webhookURLSecretRef:
      name: slack-webhook
      key: url
    channel: "#security-alerts"
```

```bash
# Create secret first
kubectl create secret generic slack-webhook \
  --from-literal=url=https://hooks.slack.com/services/xxx \
  -n pii-system

# Apply alert channel
kubectl apply -f alert-channel.yaml
```

---

## Community Rules

### Subscribe to Community Rules

```yaml
# 1. Add community source
apiVersion: pii.namjun.kim/v1alpha1
kind: PIICommunitySource
metadata:
  name: community
  namespace: pii-system
spec:
  type: git
  git:
    url: https://github.com/bunseokbot/pii-redactor-community-rules
    ref: main
  sync:
    interval: "1h"
---
# 2. Subscribe to rules
apiVersion: pii.namjun.kim/v1alpha1
kind: PIIRuleSubscription
metadata:
  name: my-subscription
  namespace: pii-system
spec:
  sourceRef:
    name: community
  maturityLevels:
    - stable           # Production only
  subscribe:
    - category: usa
      patterns: ["*"]
    - category: secrets
      patterns: ["aws-*", "github-*"]
```

### Maturity Levels

| Level | Description | Use Case |
|-------|-------------|----------|
| `stable` | Production-ready | Production clusters |
| `incubating` | Under development | Staging/QA |
| `sandbox` | Experimental | Development |
| `deprecated` | Being removed | Migration only |

---

## Verify Installation

```bash
# Check CRDs
kubectl get crds | grep pii

# Check controller
kubectl get pods -n pii-system

# Check policies
kubectl get piipolicies -A

# Check patterns
kubectl get piipatterns -A

# View logs
kubectl logs -n pii-system -l app.kubernetes.io/name=pii-redactor -f
```

---

## Uninstall

### Helm

```bash
helm uninstall pii-redactor -n pii-system
kubectl delete namespace pii-system
```

### Kustomize

```bash
kubectl delete -k deploy/kustomize/base
```

### kubectl

```bash
kubectl delete -f config/manager/ -n pii-system
kubectl delete -f config/crd/bases/
kubectl delete namespace pii-system
```

---

## Next Steps

- Read the [full documentation](./README.md)
- Explore [built-in patterns](../internal/detector/patterns/builtin.go)
- Contribute [community rules](../community-rules-template/README.md)
