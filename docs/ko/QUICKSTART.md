# 빠른 시작 가이드

이 가이드는 PII Redactor를 로컬 테스트 및 클러스터 배포에 사용하는 방법을 안내합니다.

## 목차

- [로컬 테스트 (CLI)](#로컬-테스트-cli)
- [배포 방법](#배포-방법)
  - [Helm](#방법-1-helm-권장)
  - [Kustomize](#방법-2-kustomize)
  - [kubectl](#방법-3-kubectl)
- [기본 사용법](#기본-사용법)
- [커뮤니티 룰](#커뮤니티-룰)

---

## 로컬 테스트 (CLI)

클러스터에 배포하지 않고 로컬에서 PII 탐지를 테스트할 수 있습니다.

### CLI 설치

```bash
# 방법 1: Go install
go install github.com/bunseokbot/pii-redactor/cmd/cli@latest

# 방법 2: 소스에서 빌드
git clone https://github.com/bunseokbot/pii-redactor.git
cd pii-redactor
make build-cli
sudo mv bin/pii-redactor /usr/local/bin/
```

### CLI 사용법

```bash
# 텍스트 스캔
pii-redactor -t "제 이메일은 test@example.com이고 주민번호는 920101-1234567입니다"

# 파일 스캔
pii-redactor -f /var/log/app.log

# JSON 형식 출력
pii-redactor -t "카드번호: 4111-1111-1111-1111" -o json

# 특정 패턴만 사용
pii-redactor -t "전화번호 010-1234-5678" -p "phone-kr,email"

# 사용 가능한 패턴 목록 조회
pii-redactor -list

# 표준 입력으로 읽기
cat app.log | pii-redactor
```

### Make를 사용한 로컬 테스트

```bash
# 빠른 테스트 실행
make test-local

# 출력 예시:
# Test 1: Korean RRN
# Detected 1 PII instance(s)
# [critical] korean-rrn (1 found)
#   - Original: 920101-1234567
#     Redacted: 920101-*******
```

---

## 배포 방법

### 사전 요구사항

- Kubernetes 클러스터 (v1.24+)
- kubectl 설정 완료
- Helm 3.x (Helm 설치 시)

### 방법 1: Helm (권장)

```bash
# 저장소 추가
helm repo add pii-redactor https://bunseokbot.github.io/pii-redactor
helm repo update

# 설치
helm install pii-redactor pii-redactor/pii-redactor \
  --namespace pii-system \
  --create-namespace

# 또는 로컬 차트로 설치
helm install pii-redactor ./deploy/helm/pii-redactor \
  --namespace pii-system \
  --create-namespace

# 사용자 정의 values
helm install pii-redactor pii-redactor/pii-redactor \
  --namespace pii-system \
  --create-namespace \
  --set replicaCount=2 \
  --set controller.logLevel=debug
```

### 방법 2: Kustomize

```bash
# 개발 환경
kubectl apply -k deploy/kustomize/overlays/dev

# 프로덕션 환경
kubectl apply -k deploy/kustomize/overlays/prod

# 또는 기본 설치
kubectl apply -k deploy/kustomize/base
```

### 방법 3: kubectl

```bash
# CRD 설치
kubectl apply -f config/crd/bases/

# 네임스페이스 생성
kubectl create namespace pii-system

# 컨트롤러 배포
kubectl apply -f config/manager/ -n pii-system

# 샘플 CR 적용
kubectl apply -f config/samples/
```

---

## 기본 사용법

### 1. PIIPolicy 생성

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
      - secrets   # aws, github, stripe 키
  action:
    onDetection: redact
```

```bash
kubectl apply -f policy.yaml
```

### 2. 사용자 정의 패턴 생성

```yaml
apiVersion: pii.namjun.kim/v1alpha1
kind: PIIPattern
metadata:
  name: employee-id
spec:
  displayName: "사원번호"
  description: "회사 사원번호"
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

### 3. 알림 설정 (선택사항)

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
# Secret 먼저 생성
kubectl create secret generic slack-webhook \
  --from-literal=url=https://hooks.slack.com/services/xxx \
  -n pii-system

# 알림 채널 적용
kubectl apply -f alert-channel.yaml
```

---

## 커뮤니티 룰

### 커뮤니티 룰 구독

```yaml
# 1. 커뮤니티 소스 추가
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
# 2. 룰 구독
apiVersion: pii.namjun.kim/v1alpha1
kind: PIIRuleSubscription
metadata:
  name: my-subscription
  namespace: pii-system
spec:
  sourceRef:
    name: community
  maturityLevels:
    - stable           # 프로덕션 전용
  subscribe:
    - category: usa
      patterns: ["*"]
    - category: secrets
      patterns: ["aws-*", "github-*"]
```

### 성숙도 레벨

| 레벨 | 설명 | 사용 사례 |
|------|------|----------|
| `stable` | 프로덕션 준비 완료 | 프로덕션 클러스터 |
| `incubating` | 개발 중 | 스테이징/QA |
| `sandbox` | 실험적 | 개발 환경 |
| `deprecated` | 제거 예정 | 마이그레이션 전용 |

---

## 설치 확인

```bash
# CRD 확인
kubectl get crds | grep pii

# 컨트롤러 확인
kubectl get pods -n pii-system

# 정책 확인
kubectl get piipolicies -A

# 패턴 확인
kubectl get piipatterns -A

# 로그 확인
kubectl logs -n pii-system -l app.kubernetes.io/name=pii-redactor -f
```

---

## 제거

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

## 다음 단계

- [전체 문서](./README.md) 읽기
- [내장 패턴](../../internal/detector/patterns/builtin.go) 살펴보기
- [커뮤니티 룰](https://github.com/bunseokbot/pii-redactor-community-rules) 기여하기
