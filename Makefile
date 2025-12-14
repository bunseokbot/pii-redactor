# Image URL to use all building/pushing image targets
IMG ?= ghcr.io/bunseokbot/pii-redactor:latest

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

# Setting SHELL to bash allows bash commands to be executed by recipes.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

.PHONY: all
all: build

##@ General

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: fmt
fmt: ## Run go fmt against code.
	go fmt ./...

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

.PHONY: test
test: fmt vet ## Run tests.
	go test ./... -coverprofile cover.out

.PHONY: test-local
test-local: build-cli ## Run local PII detection test
	@echo "Testing PII detection..."
	@echo "Test 1: Korean RRN"
	@./bin/pii-redactor -t "주민번호: 920101-1234567"
	@echo ""
	@echo "Test 2: Email"
	@./bin/pii-redactor -t "Contact: test@example.com"
	@echo ""
	@echo "Test 3: Credit Card"
	@./bin/pii-redactor -t "Card: 4111-1111-1111-1111"
	@echo ""
	@echo "Test 4: Multiple PII"
	@./bin/pii-redactor -t "User email test@example.com called from 010-1234-5678 with SSN 920101-1234567"

##@ Build

.PHONY: build
build: fmt vet ## Build controller binary.
	go build -o bin/controller ./cmd/controller

.PHONY: build-cli
build-cli: fmt vet ## Build CLI binary.
	go build -o bin/pii-redactor ./cmd/cli

.PHONY: run
run: fmt vet ## Run controller from your host.
	go run ./cmd/controller

.PHONY: docker-build
docker-build: ## Build docker image.
	docker build -t ${IMG} .

.PHONY: docker-push
docker-push: ## Push docker image.
	docker push ${IMG}

##@ Deployment

.PHONY: install
install: ## Install CRDs into the K8s cluster.
	kubectl apply -f config/crd/bases/

.PHONY: uninstall
uninstall: ## Uninstall CRDs from the K8s cluster.
	kubectl delete -f config/crd/bases/

.PHONY: deploy
deploy: ## Deploy controller to the K8s cluster.
	kubectl apply -f config/manager/

.PHONY: undeploy
undeploy: ## Undeploy controller from the K8s cluster.
	kubectl delete -f config/manager/

.PHONY: sample
sample: ## Apply sample CRs.
	kubectl apply -f config/samples/

##@ CLI

.PHONY: cli-install
cli-install: build-cli ## Install CLI to /usr/local/bin
	sudo cp bin/pii-redactor /usr/local/bin/

.PHONY: cli-test
cli-test: build-cli ## Interactive CLI test
	@echo "PII Redactor CLI ready. Run: ./bin/pii-redactor -h"

##@ Local Kubernetes Testing

.PHONY: kind-create
kind-create: ## Create kind cluster for local testing
	@if ! command -v kind &> /dev/null; then \
		echo "kind not installed. Install: go install sigs.k8s.io/kind@latest"; \
		exit 1; \
	fi
	kind create cluster --name pii-redactor-test
	@echo "Kind cluster created. Run 'make kind-deploy' to deploy"

.PHONY: kind-delete
kind-delete: ## Delete kind cluster
	kind delete cluster --name pii-redactor-test

.PHONY: kind-deploy
kind-deploy: docker-build install ## Build and deploy to kind cluster
	kind load docker-image ${IMG} --name pii-redactor-test
	kubectl apply -k deploy/kustomize/base
	@echo "Deployed to kind cluster"

.PHONY: kind-logs
kind-logs: ## View controller logs in kind cluster
	kubectl logs -n pii-system -l app.kubernetes.io/name=pii-redactor -f

##@ Helm

.PHONY: helm-package
helm-package: ## Package Helm chart
	helm package deploy/helm/pii-redactor -d deploy/helm/

.PHONY: helm-install
helm-install: ## Install Helm chart to current cluster
	helm install pii-redactor deploy/helm/pii-redactor \
		--namespace pii-system --create-namespace

.PHONY: helm-upgrade
helm-upgrade: ## Upgrade Helm release
	helm upgrade pii-redactor deploy/helm/pii-redactor \
		--namespace pii-system

.PHONY: helm-uninstall
helm-uninstall: ## Uninstall Helm release
	helm uninstall pii-redactor --namespace pii-system

##@ Kustomize

.PHONY: kustomize-dev
kustomize-dev: ## Deploy using kustomize (dev)
	kubectl apply -k deploy/kustomize/overlays/dev

.PHONY: kustomize-prod
kustomize-prod: ## Deploy using kustomize (prod)
	kubectl apply -k deploy/kustomize/overlays/prod

.PHONY: kustomize-delete
kustomize-delete: ## Delete kustomize deployment
	kubectl delete -k deploy/kustomize/base

##@ Helm OCI Registry

.PHONY: helm-login
helm-login: ## Login to GHCR for Helm OCI
	@echo "Login to ghcr.io..."
	@helm registry login ghcr.io -u $(shell git config user.name)

.PHONY: helm-push
helm-push: helm-package ## Push Helm chart to GHCR
	helm push deploy/helm/pii-redactor-*.tgz oci://ghcr.io/bunseokbot/charts
	@echo ""
	@echo "Chart pushed! Install with:"
	@echo "  helm install pii-redactor oci://ghcr.io/bunseokbot/charts/pii-redactor --namespace pii-system --create-namespace"
