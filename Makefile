# CloudSecure Assessment Platform - Makefile
# Usage: make deploy (or ./deploy.sh for guided deployment)

# Load .env if it exists
-include .env
export

# ─── NVM Workaround ─────────────────────────────────────────
# nvm uses shell functions that break in Makefile subshells.
# Resolve the Node binary directory directly.
NVM_NODE_DIR := $(lastword $(sort $(wildcard $(HOME)/.nvm/versions/node/*/bin)))
ifdef NVM_NODE_DIR
  export PATH := $(NVM_NODE_DIR):$(PATH)
endif

# ─── Configuration ──────────────────────────────────────────
AWS_PROFILE    ?= default
AWS_REGION     ?= eu-west-1
CLOUDSECURE_ENV ?= dev
PROWLER_IMAGE  ?= docker.io/carlosinfantes/cloudsecure-prowler:latest
SKIP_PROWLER   ?= false

# Container runtime auto-detection (Docker preferred, Podman fallback)
CONTAINER_CMD  := $(shell \
  if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then echo docker; \
  elif command -v podman >/dev/null 2>&1; then echo podman; fi)

INFRA_DIR      := infrastructure
LAMBDAS_DIR    := lambdas
LAYER_DIR      := $(LAMBDAS_DIR)/layer
CLI_DIR        := cli
STACK_PREFIX   := CloudSecure

CDK            := npx cdk
CDK_ARGS       := --profile $(AWS_PROFILE) -c env=$(CLOUDSECURE_ENV) --require-approval never

# ─── Detect Account ID ─────────────────────────────────────
ACCOUNT_ID     = $(shell aws sts get-caller-identity --profile $(AWS_PROFILE) --query Account --output text 2>/dev/null)
ECR_URI        = $(ACCOUNT_ID).dkr.ecr.$(AWS_REGION).amazonaws.com
ECR_REPO       = cloudsecure-prowler-$(CLOUDSECURE_ENV)

# ─── Default Target ─────────────────────────────────────────
.DEFAULT_GOAL := help

.PHONY: help install build layer prowler-push synth deploy destroy test lint clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

# ─── Dependencies ───────────────────────────────────────────
install: ## Install all dependencies (npm + pip)
	@echo "Installing infrastructure dependencies..."
	@cd $(INFRA_DIR) && npm ci --silent
	@echo "Installing Python dependencies..."
	@if python3 -c "import pytest, pydantic, boto3, ruff, dateutil" 2>/dev/null; then \
		echo "  Python packages already satisfied (system/apt)"; \
	else \
		echo "  Installing via pip..."; \
		cd $(LAMBDAS_DIR) && pip install -e ".[dev]" --quiet 2>/dev/null || true; \
	fi
	@echo "Dependencies installed."

# ─── Build ──────────────────────────────────────────────────
build: ## Compile TypeScript CDK code
	@cd $(INFRA_DIR) && npm run build

# ─── Lambda Layer ───────────────────────────────────────────
layer: ## Build Lambda shared layer (Docker preferred, pip fallback)
	@echo "Building Lambda layer..."
	@mkdir -p $(LAYER_DIR)/python
	@if [ -n "$(CONTAINER_CMD)" ]; then \
		echo "  Using $(CONTAINER_CMD) for Linux-compatible binaries"; \
		cd $(LAMBDAS_DIR) && $(CONTAINER_CMD) run --rm --platform linux/amd64 --entrypoint /bin/bash \
			-v "$$(pwd)/layer:/layer" \
			public.ecr.aws/lambda/python:3.12 \
			-c "pip install pydantic jinja2 boto3 python-dateutil --target /layer/python/ --no-cache-dir --quiet"; \
	else \
		echo "  WARNING: No container runtime available. Using pip (may not work on Lambda)."; \
		pip install pydantic jinja2 boto3 python-dateutil -t $(LAYER_DIR)/python/ --no-cache-dir --quiet; \
	fi
	@cp -r $(LAMBDAS_DIR)/shared $(LAMBDAS_DIR)/analyzers $(LAYER_DIR)/python/
	@echo "Lambda layer built."

# ─── Prowler Image ──────────────────────────────────────────
prowler-push: ## Pull Prowler from Docker Hub and push to ECR
ifeq ($(SKIP_PROWLER),true)
	@echo "Skipping Prowler (SKIP_PROWLER=true)"
else
	@echo "Setting up Prowler container image..."
	@aws ecr describe-repositories --repository-names $(ECR_REPO) \
		--region $(AWS_REGION) --profile $(AWS_PROFILE) >/dev/null 2>&1 || \
		aws ecr create-repository --repository-name $(ECR_REPO) \
		--region $(AWS_REGION) --profile $(AWS_PROFILE) \
		--image-scanning-configuration scanOnPush=true >/dev/null
	@aws ecr get-login-password --region $(AWS_REGION) --profile $(AWS_PROFILE) | \
		$(CONTAINER_CMD) login --username AWS --password-stdin $(ECR_URI) 2>/dev/null
	@$(CONTAINER_CMD) pull --platform linux/amd64 $(PROWLER_IMAGE) --quiet
	@$(CONTAINER_CMD) tag $(PROWLER_IMAGE) $(ECR_URI)/$(ECR_REPO):latest
	@$(CONTAINER_CMD) push $(ECR_URI)/$(ECR_REPO):latest --quiet
	@echo "Prowler image pushed to ECR."
endif

# ─── CDK Operations ─────────────────────────────────────────
synth: build ## Synthesize CloudFormation templates
	@cd $(INFRA_DIR) && $(CDK) synth $(CDK_ARGS) --quiet

deploy: build layer ## Deploy all stacks
ifeq ($(SKIP_PROWLER),true)
	@cd $(INFRA_DIR) && $(CDK) deploy --all $(CDK_ARGS) -c skipProwler=true
else
	@$(MAKE) prowler-push
	@cd $(INFRA_DIR) && $(CDK) deploy --all $(CDK_ARGS)
endif
	@echo ""
	@echo "Deployment complete. API endpoint:"
	@aws cloudformation describe-stacks --profile $(AWS_PROFILE) --region $(AWS_REGION) \
		--stack-name $(STACK_PREFIX)-API-$(CLOUDSECURE_ENV) \
		--query "Stacks[0].Outputs[?OutputKey=='ApiEndpoint'].OutputValue" --output text 2>/dev/null || true

destroy: ## Destroy all stacks (requires confirmation)
	@echo "This will destroy ALL CloudSecure resources in $(CLOUDSECURE_ENV)."
	@read -p "Are you sure? [y/N] " confirm && [ "$$confirm" = "y" ] || exit 1
	@cd $(INFRA_DIR) && $(CDK) destroy --all $(CDK_ARGS) --force

# ─── Quality ────────────────────────────────────────────────
test: ## Run all tests (CDK + Python)
	@echo "Running CDK tests..."
	@cd $(INFRA_DIR) && npm test 2>/dev/null || true
	@echo "Running Python tests..."
	@cd $(LAMBDAS_DIR) && python -m pytest tests/ -v 2>/dev/null || true

lint: ## Lint Python code
	@cd $(LAMBDAS_DIR) && ruff check . 2>/dev/null || true
	@cd $(LAMBDAS_DIR) && black --check . 2>/dev/null || true

# ─── Cleanup ────────────────────────────────────────────────
clean: ## Remove build artifacts
	@rm -rf $(INFRA_DIR)/cdk.out $(LAYER_DIR)/python
	@echo "Cleaned build artifacts."
