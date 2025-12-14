# PII Redactor

<p align="center">
  <a href="../../README.md">English</a> |
  <a href="./README.md">한국어</a>
</p>

Kubernetes 로그에서 PII(개인식별정보)를 탐지, 알림, 마스킹하는 Cloud Native 솔루션입니다.

[![Go Version](https://img.shields.io/badge/Go-1.22+-blue.svg)](https://golang.org)
[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](LICENSE)
[![CI](https://github.com/bunseokbot/pii-redactor/actions/workflows/ci.yaml/badge.svg)](https://github.com/bunseokbot/pii-redactor/actions/workflows/ci.yaml)
[![Release](https://github.com/bunseokbot/pii-redactor/actions/workflows/release.yaml/badge.svg)](https://github.com/bunseokbot/pii-redactor/actions/workflows/release.yaml)

## 개요

PII Redactor는 Kubernetes 클러스터 내에서 발생하는 로그에서 PII를 실시간으로 탐지하고 마스킹하는 Kubernetes Operator입니다.

### 주요 기능

- **실시간 PII 탐지**: 로그 스트림에서 PII 패턴을 실시간으로 탐지
- **20개 이상의 내장 패턴**: 이메일, 전화번호, 주민등록번호, 신용카드, AWS 키 등
- **사용자 정의 패턴**: CRD를 통한 커스텀 패턴 추가 지원
- **커뮤니티 룰**: 커뮤니티에서 공유하는 패턴 구독 및 사용
- **다양한 마스킹 전략**: partial, full, hash, tokenize 전략 지원
- **알림 연동**: Slack, PagerDuty, Webhook 등 지원
- **감사 로깅**: 컴플라이언스를 위한 PII 탐지 이력 기록

## 빠른 시작

### 로컬 테스트 (CLI)

```bash
# CLI 빌드
make build-cli

# 텍스트 스캔
./bin/pii-redactor -t "이메일: test@example.com 전화번호: 010-1234-5678"

# 파일 스캔
./bin/pii-redactor -f /var/log/app.log

# JSON 형식 출력
./bin/pii-redactor -t "카드번호: 4111-1111-1111-1111" -o json

# 특정 패턴만 사용
./bin/pii-redactor -t "test@example.com" -p "email,phone-kr"

# 사용 가능한 패턴 목록 조회
./bin/pii-redactor -list
```

### Kubernetes 배포

```bash
# CRD 설치
make install

# 컨트롤러 배포
make deploy

# 샘플 CR 적용
make sample
```

### Helm으로 배포

```bash
# OCI 레지스트리에서 설치 (권장)
helm install pii-redactor oci://ghcr.io/bunseokbot/charts/pii-redactor \
  --namespace pii-system \
  --create-namespace

# 또는 로컬 소스에서 설치
helm install pii-redactor ./deploy/helm/pii-redactor \
  --namespace pii-system \
  --create-namespace

# 커스텀 values로 설치
helm install pii-redactor oci://ghcr.io/bunseokbot/charts/pii-redactor \
  --namespace pii-system \
  --create-namespace \
  --set controller.logLevel=debug \
  --set monitoring.serviceMonitor.enabled=true

# 업그레이드
helm upgrade pii-redactor oci://ghcr.io/bunseokbot/charts/pii-redactor \
  --namespace pii-system

# 삭제
helm uninstall pii-redactor --namespace pii-system
```

#### Helm Values

| 파라미터 | 설명 | 기본값 |
|----------|------|--------|
| `replicaCount` | 컨트롤러 레플리카 수 | `1` |
| `image.repository` | 컨트롤러 이미지 저장소 | `ghcr.io/bunseokbot/pii-redactor` |
| `image.tag` | 컨트롤러 이미지 태그 | `appVersion` |
| `controller.logLevel` | 로그 레벨 (debug, info, warn, error) | `info` |
| `builtInPatterns.enabled` | 내장 PII 패턴 활성화 | `true` |
| `builtInPatterns.categories` | 활성화할 패턴 카테고리 | `[global, usa, korea, secrets]` |
| `communityRules.enabled` | 커뮤니티 룰 지원 활성화 | `false` |
| `monitoring.serviceMonitor.enabled` | Prometheus ServiceMonitor 활성화 | `false` |
| `resources.limits.cpu` | CPU 제한 | `500m` |
| `resources.limits.memory` | 메모리 제한 | `128Mi` |

## Custom Resource Definitions

### PIIPattern - PII 패턴 정의

```yaml
apiVersion: pii.namjun.kim/v1alpha1
kind: PIIPattern
metadata:
  name: custom-employee-id
spec:
  displayName: "사원번호"
  description: "회사 사원번호 패턴"
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

### PIIPolicy - 정책 정의

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

### PIICommunitySource - 커뮤니티 룰 소스

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

### PIIRuleSubscription - 룰 구독

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

## 내장 패턴

| 패턴명 | 설명 | 심각도 |
|--------|------|--------|
| `email` | 이메일 주소 | medium |
| `korean-rrn` | 주민등록번호 | critical |
| `phone-kr` | 한국 전화번호 | high |
| `credit-card` | 신용카드 번호 (Visa, MC, Amex) | critical |
| `ip-address` | IPv4 주소 | low |
| `ipv6-address` | IPv6 주소 | low |
| `passport-kr` | 한국 여권번호 | critical |
| `driver-license-kr` | 한국 운전면허번호 | critical |
| `business-number-kr` | 사업자등록번호 | high |
| `bank-account-kr` | 한국 은행 계좌번호 | critical |
| `ssn-us` | 미국 사회보장번호 | critical |
| `phone-us` | 미국 전화번호 | high |
| `aws-access-key` | AWS Access Key ID | critical |
| `aws-secret-key` | AWS Secret Access Key | critical |
| `github-token` | GitHub Personal Access Token | critical |
| `api-key` | 일반 API 키 | high |
| `jwt` | JSON Web Token | high |
| `private-key` | 개인키 (RSA, DSA, EC) | critical |
| `password-in-url` | URL에 포함된 비밀번호 | critical |
| `iban` | 국제은행계좌번호 | critical |
| `mac-address` | MAC 주소 | low |

## 커뮤니티 룰

커뮤니티에서 기여한 PII 패턴은 [pii-redactor-community-rules](https://github.com/bunseokbot/pii-redactor-community-rules) 저장소를 참고하세요.

### 패턴 기여 방법

1. community-rules 저장소 Fork
2. 적절한 카테고리에 패턴 추가
3. 테스트 케이스 포함
4. Pull Request 제출

## 라이선스

Apache License 2.0

## 기여

기여를 환영합니다! 자세한 내용은 [Contributing Guide](../../CONTRIBUTING.md)를 참고하세요.
