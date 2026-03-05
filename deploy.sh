#!/usr/bin/env bash
# CloudSecure Assessment Platform - Infrastructure Deployment
# Usage: ./deploy.sh                    # First-time interactive deployment
#        ./deploy.sh --upgrade [COMP]   # Non-interactive upgrade (all|infra|prowler|cli)
#        ./deploy.sh --setup-role       # Create assessment role for self-testing
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ─── Colors & Helpers ──────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

info()  { echo -e "${CYAN}▸${NC} $*"; }
ok()    { echo -e "${GREEN}✓${NC} $*"; }
warn()  { echo -e "${YELLOW}⚠${NC} $*"; }
fail()  { echo -e "${RED}✗${NC} $*"; exit 1; }
section() { echo -e "${BOLD}── $* ──────────────────────────────────${NC}"; echo ""; }

# ─── Upgrade Functions ────────────────────────────────────────

load_env() {
  local env_file="${SCRIPT_DIR}/.env"
  if [[ ! -f "$env_file" ]]; then
    fail ".env not found. Run './deploy.sh' first for initial setup."
  fi
  set -a
  # shellcheck source=/dev/null
  source "$env_file"
  set +a
  ok "Loaded configuration from .env"
}

validate_env() {
  local missing=()
  [[ -z "${AWS_PROFILE:-}" ]] && missing+=("AWS_PROFILE")
  [[ -z "${AWS_REGION:-}" ]] && missing+=("AWS_REGION")
  [[ -z "${CLOUDSECURE_ENV:-}" ]] && missing+=("CLOUDSECURE_ENV")

  if [[ ${#missing[@]} -gt 0 ]]; then
    fail "Missing .env variables: ${missing[*]}"
  fi

  info "Validating AWS credentials (profile: ${AWS_PROFILE})..."
  CALLER_IDENTITY=$(aws sts get-caller-identity --profile "$AWS_PROFILE" --output json 2>/dev/null) || \
    fail "Cannot authenticate with profile '${AWS_PROFILE}'. Check credentials."

  ACCOUNT_ID=$(echo "$CALLER_IDENTITY" | python3 -c "import sys,json; print(json.load(sys.stdin)['Account'])")
  ok "Profile: ${BOLD}${AWS_PROFILE}${NC} | Region: ${BOLD}${AWS_REGION}${NC} | Env: ${BOLD}${CLOUDSECURE_ENV}${NC}"

  # Set up ECR vars for prowler
  ECR_REPO="cloudsecure-prowler-${CLOUDSECURE_ENV}"
}

get_cli_versions() {
  CLI_INSTALLED=$(cloudsecure --version 2>/dev/null | awk '{print $NF}' || echo "not installed")
  CLI_LATEST=$(curl -sfm5 https://pypi.org/pypi/cloudsecure/json 2>/dev/null | \
    python3 -c "import sys,json; print(json.load(sys.stdin)['info']['version'])" 2>/dev/null || echo "unknown")
}

get_prowler_versions() {
  PROWLER_ECR_DATE=$(aws ecr describe-images --repository-name "$ECR_REPO" \
    --profile "$AWS_PROFILE" --region "$AWS_REGION" \
    --query "sort_by(imageDetails, &imagePushedAt)[-1].imagePushedAt" \
    --output text 2>/dev/null | cut -dT -f1 || echo "never")
  PROWLER_LATEST=$(curl -sfm5 "https://hub.docker.com/v2/repositories/carlosinfantes/cloudsecure-prowler/tags?page_size=5&ordering=last_updated" 2>/dev/null | \
    python3 -c "import sys,json; tags=[t['name'] for t in json.load(sys.stdin).get('results',[]) if t['name']!='latest']; print(tags[0] if tags else 'latest')" 2>/dev/null || echo "unknown")
}

get_infra_version() {
  INFRA_LAST_DEPLOY=$(aws cloudformation describe-stacks --profile "$AWS_PROFILE" --region "$AWS_REGION" \
    --stack-name "CloudSecure-API-${CLOUDSECURE_ENV}" \
    --query "Stacks[0].LastUpdatedTime // Stacks[0].CreationTime" \
    --output text 2>/dev/null | cut -dT -f1 || echo "never")
}

show_version_table() {
  section "Version Check"

  get_cli_versions
  get_prowler_versions
  get_infra_version

  printf "  ${BOLD}%-14s %-16s %-16s %s${NC}\n" "Component" "Installed" "Latest" "Status"
  printf "  %-14s %-16s %-16s %s\n" "─────────" "─────────" "──────" "──────"

  # CLI row
  if [[ "$CLI_INSTALLED" == "$CLI_LATEST" && "$CLI_LATEST" != "unknown" ]]; then
    printf "  %-14s %-16s %-16s " "CLI" "$CLI_INSTALLED" "$CLI_LATEST"
    echo -e "${GREEN}✓ Up to date${NC}"
  elif [[ "$CLI_LATEST" == "unknown" ]]; then
    printf "  %-14s %-16s %-16s " "CLI" "$CLI_INSTALLED" "?"
    echo -e "${YELLOW}? Cannot check PyPI${NC}"
  else
    printf "  %-14s %-16s %-16s " "CLI" "$CLI_INSTALLED" "$CLI_LATEST"
    echo -e "${YELLOW}⬆ Update available${NC}"
  fi

  # Prowler row
  if [[ "${SKIP_PROWLER:-false}" == "true" ]]; then
    printf "  %-14s %-16s %-16s " "Prowler" "disabled" "—"
    echo -e "${DIM}skipped${NC}"
  else
    printf "  %-14s %-16s %-16s " "Prowler" "$PROWLER_ECR_DATE" "$PROWLER_LATEST"
    echo -e "${CYAN}Docker Hub${NC}"
  fi

  # Infra row
  printf "  %-14s %-16s %-16s " "Infra" "$INFRA_LAST_DEPLOY" "(deployed)"
  echo -e "${GREEN}✓${NC}"

  echo ""
}

upgrade_cli() {
  section "Upgrading CLI"

  get_cli_versions

  if [[ "$CLI_INSTALLED" == "not installed" ]]; then
    echo -e "  Status:     ${RED}not installed${NC}"
    echo -e "  Latest:     ${GREEN}${CLI_LATEST}${NC}"
    echo ""
    info "Installing cloudsecure from PyPI..."
    if command -v pipx >/dev/null 2>&1; then
      pipx install cloudsecure
    else
      python3 -m pip install --user cloudsecure
    fi
    local new_ver
    new_ver=$(cloudsecure --version 2>/dev/null | awk '{print $NF}' || echo "unknown")
    ok "CLI installed: ${GREEN}${new_ver}${NC}"
    return 0
  fi

  if [[ "$CLI_INSTALLED" == "$CLI_LATEST" && "$CLI_LATEST" != "unknown" ]]; then
    echo -e "  Installed:  ${GREEN}${CLI_INSTALLED}${NC}"
    echo -e "  Latest:     ${GREEN}${CLI_LATEST}${NC}  ✓ Up to date"
    echo ""
    ok "CLI is already at the latest version"
    return 0
  fi

  echo -e "  Installed:  ${YELLOW}${CLI_INSTALLED}${NC}"
  echo -e "  Latest:     ${GREEN}${CLI_LATEST}${NC}  ⬆ Update available"
  echo ""
  info "Upgrading cloudsecure from PyPI..."

  if command -v pipx >/dev/null 2>&1; then
    pipx upgrade cloudsecure 2>/dev/null || pipx install cloudsecure
  else
    python3 -m pip install --upgrade cloudsecure
  fi

  local new_ver
  new_ver=$(cloudsecure --version 2>/dev/null | awk '{print $NF}' || echo "unknown")
  ok "CLI upgraded: ${CLI_INSTALLED} → ${GREEN}${new_ver}${NC}"
  echo ""
}

upgrade_prowler() {
  section "Upgrading Prowler"

  if [[ "${SKIP_PROWLER:-false}" == "true" ]]; then
    warn "Prowler is disabled (SKIP_PROWLER=true in .env). Skipping."
    echo ""
    return 0
  fi

  if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
    fail "Docker is required for Prowler upgrade but is not available."
  fi

  get_prowler_versions

  echo -e "  ECR image:    ${YELLOW}${PROWLER_ECR_DATE}${NC}"
  echo -e "  Docker Hub:   ${GREEN}${PROWLER_LATEST}${NC}"
  echo ""

  info "Pulling ${PROWLER_IMAGE:-carlosinfantes/cloudsecure-prowler:latest} from Docker Hub..."
  make -C "$SCRIPT_DIR" prowler-push
  ok "Prowler image pushed to ECR"
  echo ""

  info "Updating Prowler Lambda to use new image..."
  local ecr_uri
  ecr_uri="${ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${ECR_REPO}:latest"
  aws lambda update-function-code \
    --function-name "cloudsecure-prowler-scanner-${CLOUDSECURE_ENV}" \
    --image-uri "$ecr_uri" \
    --profile "$AWS_PROFILE" --region "$AWS_REGION" >/dev/null
  ok "Prowler Lambda updated (${GREEN}${ecr_uri}${NC})"
  echo ""
}

upgrade_infra() {
  section "Upgrading Infrastructure"

  get_infra_version
  echo -e "  Last deploy:  ${YELLOW}${INFRA_LAST_DEPLOY}${NC}"
  echo ""

  info "Installing dependencies..."
  make -C "$SCRIPT_DIR" install

  info "Building Lambda layer..."
  make -C "$SCRIPT_DIR" layer

  info "Deploying CDK stacks..."
  make -C "$SCRIPT_DIR" deploy

  get_infra_version
  ok "Infrastructure upgraded (${GREEN}${INFRA_LAST_DEPLOY}${NC})"
  echo ""
}

show_upgrade_summary() {
  echo -e "${BOLD}════════════════════════════════════════════════${NC}"
  echo -e "${BOLD}  Upgrade complete!${NC}"
  echo -e "${BOLD}════════════════════════════════════════════════${NC}"
  echo ""

  # CLI version
  local cli_ver
  cli_ver=$(cloudsecure --version 2>/dev/null | awk '{print $NF}' || echo "n/a")
  echo -e "  CLI:          ${GREEN}${cli_ver}${NC}"

  # Prowler status
  if [[ "${SKIP_PROWLER:-false}" != "true" ]]; then
    local prowler_date
    prowler_date=$(aws ecr describe-images --repository-name "$ECR_REPO" \
      --profile "$AWS_PROFILE" --region "$AWS_REGION" \
      --query "sort_by(imageDetails, &imagePushedAt)[-1].imagePushedAt" \
      --output text 2>/dev/null | cut -dT -f1 || echo "n/a")
    echo -e "  Prowler:      ${GREEN}${prowler_date}${NC} (ECR)"
  else
    echo -e "  Prowler:      ${DIM}disabled${NC}"
  fi

  # API endpoint
  local api_endpoint
  api_endpoint=$(aws cloudformation describe-stacks \
    --profile "$AWS_PROFILE" --region "$AWS_REGION" \
    --stack-name "CloudSecure-API-${CLOUDSECURE_ENV}" \
    --query "Stacks[0].Outputs[?OutputKey=='ApiEndpoint'].OutputValue" \
    --output text 2>/dev/null || echo "")
  if [ -n "$api_endpoint" ]; then
    echo -e "  API:          ${CYAN}${api_endpoint}${NC}"
  fi

  echo -e "  Environment:  ${CLOUDSECURE_ENV}"
  echo ""
}

run_upgrade() {
  local component="${1:-all}"

  load_env
  validate_env
  echo ""

  show_version_table

  case "$component" in
    all)
      upgrade_cli
      upgrade_prowler
      upgrade_infra
      ;;
    cli)
      upgrade_cli
      ;;
    prowler)
      upgrade_prowler
      ;;
    infra)
      upgrade_infra
      ;;
  esac

  show_upgrade_summary
}

# ─── Setup Role Function ─────────────────────────────────────

setup_role() {
  load_env
  validate_env
  echo ""

  local EXTERNAL_ID="cloudsecure-${ACCOUNT_ID}"
  local ROLE_STACK="CloudSecure-AssessmentRole"
  local TEMPLATE="${SCRIPT_DIR}/onboarding/cloudformation/cloudsecure-role.yaml"

  # Check if stack already exists
  local stack_status
  stack_status=$(aws cloudformation describe-stacks \
    --stack-name "$ROLE_STACK" \
    --profile "$AWS_PROFILE" --region "$AWS_REGION" \
    --query "Stacks[0].StackStatus" --output text 2>/dev/null || echo "DOES_NOT_EXIST")

  if [[ "$stack_status" == *"COMPLETE"* && "$stack_status" != "DELETE_COMPLETE" ]]; then
    ok "Assessment role already exists (${ROLE_STACK})"
    local role_arn
    role_arn=$(aws cloudformation describe-stacks \
      --stack-name "$ROLE_STACK" \
      --profile "$AWS_PROFILE" --region "$AWS_REGION" \
      --query "Stacks[0].Outputs[?OutputKey=='RoleArn'].OutputValue" \
      --output text 2>/dev/null)
    echo ""
    echo -e "  Role ARN:     ${CYAN}${role_arn}${NC}"
    echo -e "  External ID:  ${CYAN}${EXTERNAL_ID}${NC}"
    echo ""
    echo -e "${BOLD}Run your first assessment:${NC}"
    echo -e "  cloudsecure --profile ${AWS_PROFILE} assess \\"
    echo -e "    --account-id ${ACCOUNT_ID} \\"
    echo -e "    --role-arn ${role_arn} \\"
    echo -e "    --external-id ${EXTERNAL_ID}"
    echo ""
    return 0
  fi

  section "Creating Assessment Role"

  info "Deploying ${ROLE_STACK} stack..."
  aws cloudformation deploy \
    --template-file "$TEMPLATE" \
    --stack-name "$ROLE_STACK" \
    --capabilities CAPABILITY_NAMED_IAM \
    --parameter-overrides \
      "CloudSecureAccountId=${ACCOUNT_ID}" \
      "ExternalId=${EXTERNAL_ID}" \
    --profile "$AWS_PROFILE" --region "$AWS_REGION"

  ok "Assessment role created"
  echo ""

  local role_arn
  role_arn=$(aws cloudformation describe-stacks \
    --stack-name "$ROLE_STACK" \
    --profile "$AWS_PROFILE" --region "$AWS_REGION" \
    --query "Stacks[0].Outputs[?OutputKey=='RoleArn'].OutputValue" \
    --output text 2>/dev/null)

  echo -e "${BOLD}════════════════════════════════════════════════${NC}"
  echo -e "${BOLD}  Assessment role ready!${NC}"
  echo -e "${BOLD}════════════════════════════════════════════════${NC}"
  echo ""
  echo -e "  Role ARN:     ${CYAN}${role_arn}${NC}"
  echo -e "  External ID:  ${CYAN}${EXTERNAL_ID}${NC}"
  echo -e "  Account:      ${ACCOUNT_ID}"
  echo ""
  echo -e "${BOLD}Run your first assessment:${NC}"
  echo -e "  cloudsecure --profile ${AWS_PROFILE} assess \\"
  echo -e "    --account-id ${ACCOUNT_ID} \\"
  echo -e "    --role-arn ${role_arn} \\"
  echo -e "    --external-id ${EXTERNAL_ID}"
  echo ""
  echo -e "${BOLD}Then download the report:${NC}"
  echo -e "  cloudsecure --profile ${AWS_PROFILE} report <ASSESSMENT_ID> --format html --open"
  echo ""
}

# ─── Argument Parsing ─────────────────────────────────────────
if [[ "${1:-}" == "--setup-role" ]]; then
  echo ""
  echo -e "${BOLD}╔══════════════════════════════════════════════╗${NC}"
  echo -e "${BOLD}║       CloudSecure Assessment Platform        ║${NC}"
  echo -e "${BOLD}║         Assessment Role Setup                ║${NC}"
  echo -e "${BOLD}╚══════════════════════════════════════════════╝${NC}"
  echo ""

  setup_role
  exit 0
fi

if [[ "${1:-}" == "--upgrade" ]]; then
  UPGRADE_COMPONENT="${2:-all}"
  case "$UPGRADE_COMPONENT" in
    all|infra|prowler|cli) ;;
    *) fail "Unknown component: '${UPGRADE_COMPONENT}'. Use: all, infra, prowler, cli" ;;
  esac

  # Banner for upgrade mode
  echo ""
  echo -e "${BOLD}╔══════════════════════════════════════════════╗${NC}"
  echo -e "${BOLD}║       CloudSecure Assessment Platform        ║${NC}"
  echo -e "${BOLD}║            Component Upgrade                 ║${NC}"
  echo -e "${BOLD}╚══════════════════════════════════════════════╝${NC}"
  echo ""

  run_upgrade "$UPGRADE_COMPONENT"
  exit 0
fi

# ─── Banner ────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║       CloudSecure Assessment Platform        ║${NC}"
echo -e "${BOLD}║        Infrastructure Deployment             ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════╝${NC}"
echo ""

# ─── Phase 1: Check Prerequisites ─────────────────────────────
echo -e "${BOLD}Phase 1: Checking prerequisites${NC}"
echo ""

# AWS CLI
if command -v aws >/dev/null 2>&1; then
  ok "AWS CLI $(aws --version 2>&1 | awk '{print $1}' | cut -d/ -f2)"
else
  fail "AWS CLI not found. Install: https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html"
fi

# Node.js
NODE_BIN=""
if command -v node >/dev/null 2>&1; then
  NODE_BIN="node"
elif [ -d "${HOME}/.nvm/versions/node" ]; then
  # Find latest nvm-managed Node
  NODE_DIR=$(find "${HOME}/.nvm/versions/node" -maxdepth 1 -type d | sort -V | tail -1)
  if [ -x "${NODE_DIR}/bin/node" ]; then
    export PATH="${NODE_DIR}/bin:${PATH}"
    NODE_BIN="${NODE_DIR}/bin/node"
  fi
fi

if [ -n "$NODE_BIN" ]; then
  ok "Node.js $($NODE_BIN --version)"
else
  fail "Node.js not found. Install: https://nodejs.org/ (v18+ required)"
fi

# npm/npx
NPX_BIN=""
if command -v npx >/dev/null 2>&1; then
  NPX_BIN="npx"
elif [ -n "$NODE_BIN" ]; then
  NPX_DIR=$(dirname "$NODE_BIN")
  if [ -x "${NPX_DIR}/npx" ]; then
    NPX_BIN="${NPX_DIR}/npx"
  fi
fi
[ -n "$NPX_BIN" ] && ok "npx available" || fail "npx not found"

# Python
if command -v python3 >/dev/null 2>&1; then
  ok "Python $(python3 --version 2>&1 | awk '{print $2}')"
else
  fail "Python 3 not found. Install: https://www.python.org/downloads/"
fi

# pip
if python3 -m pip --version >/dev/null 2>&1; then
  ok "pip available"
else
  fail "pip not found. Install: python3 -m ensurepip"
fi

# Docker (optional)
HAS_DOCKER=false
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  ok "Docker $(docker --version | awk '{print $3}' | tr -d ',')"
  HAS_DOCKER=true
else
  warn "Docker not available — Prowler scanner will be skipped"
fi

echo ""

# ─── Phase 2: Configuration ───────────────────────────────────
echo -e "${BOLD}Phase 2: Configuration${NC}"
echo ""

# List available AWS profiles
PROFILES=$(aws configure list-profiles 2>/dev/null || echo "default")
info "Available AWS profiles:"
echo "$PROFILES" | while read -r p; do echo "    $p"; done
echo ""

# AWS Profile
read -rp "AWS profile to use [default]: " AWS_PROFILE
AWS_PROFILE=${AWS_PROFILE:-default}

# Validate credentials
info "Validating AWS credentials for profile '${AWS_PROFILE}'..."
CALLER_IDENTITY=$(aws sts get-caller-identity --profile "$AWS_PROFILE" --output json 2>/dev/null) || \
  fail "Cannot authenticate with profile '${AWS_PROFILE}'. Run: aws configure --profile ${AWS_PROFILE}"

ACCOUNT_ID=$(echo "$CALLER_IDENTITY" | python3 -c "import sys,json; print(json.load(sys.stdin)['Account'])")
CALLER_ARN=$(echo "$CALLER_IDENTITY" | python3 -c "import sys,json; print(json.load(sys.stdin)['Arn'])")
ok "Authenticated: account ${ACCOUNT_ID} (${CALLER_ARN})"

# Region
read -rp "AWS region [eu-west-1]: " AWS_REGION
AWS_REGION=${AWS_REGION:-eu-west-1}

# Environment
read -rp "Environment name (dev/test/prod) [dev]: " CLOUDSECURE_ENV
CLOUDSECURE_ENV=${CLOUDSECURE_ENV:-dev}

# Prowler
SKIP_PROWLER=false
PROWLER_IMAGE="carlosinfantes/cloudsecure-prowler:latest"
if [ "$HAS_DOCKER" = false ]; then
  SKIP_PROWLER=true
else
  echo ""
  read -rp "Include Prowler CIS scanner? (requires Docker) [Y/n]: " INCLUDE_PROWLER
  INCLUDE_PROWLER=$(echo "$INCLUDE_PROWLER" | tr '[:upper:]' '[:lower:]')
  if [[ "$INCLUDE_PROWLER" == "n" ]]; then
    SKIP_PROWLER=true
  fi
fi

# Save .env
cat > .env << EOF
# CloudSecure - Generated by deploy.sh on $(date +%Y-%m-%d)
AWS_PROFILE=${AWS_PROFILE}
AWS_REGION=${AWS_REGION}
CLOUDSECURE_ENV=${CLOUDSECURE_ENV}
PROWLER_IMAGE=${PROWLER_IMAGE}
SKIP_PROWLER=${SKIP_PROWLER}
EOF

ok "Configuration saved to .env"
echo ""

# ─── Phase 3: API Gateway CloudWatch Role ─────────────────────
echo -e "${BOLD}Phase 3: Setting up API Gateway logging${NC}"
echo ""

# Check if API Gateway account already has a CloudWatch role
APIGW_ROLE=$(aws apigateway get-account --profile "$AWS_PROFILE" --region "$AWS_REGION" \
  --query 'cloudwatchRoleArn' --output text 2>/dev/null || echo "None")

if [ "$APIGW_ROLE" = "None" ] || [ -z "$APIGW_ROLE" ]; then
  info "Creating CloudWatch role for API Gateway..."
  TRUST_POLICY='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"apigateway.amazonaws.com"},"Action":"sts:AssumeRole"}]}'

  ROLE_ARN=$(aws iam create-role \
    --role-name APIGatewayCloudWatchRole \
    --assume-role-policy-document "$TRUST_POLICY" \
    --profile "$AWS_PROFILE" \
    --query 'Role.Arn' --output text 2>/dev/null) || \
    ROLE_ARN=$(aws iam get-role \
      --role-name APIGatewayCloudWatchRole \
      --profile "$AWS_PROFILE" \
      --query 'Role.Arn' --output text 2>/dev/null)

  aws iam attach-role-policy \
    --role-name APIGatewayCloudWatchRole \
    --policy-arn "arn:aws:iam::aws:policy/service-role/AmazonAPIGatewayPushToCloudWatchLogs" \
    --profile "$AWS_PROFILE" 2>/dev/null || true

  # Wait for IAM propagation
  info "Waiting for IAM role propagation..."
  sleep 10

  aws apigateway update-account \
    --patch-operations op=replace,path=/cloudwatchRoleArn,value="$ROLE_ARN" \
    --profile "$AWS_PROFILE" --region "$AWS_REGION" >/dev/null

  ok "API Gateway CloudWatch logging configured"
else
  ok "API Gateway CloudWatch role already configured"
fi

echo ""

# ─── Phase 4: CDK Bootstrap ───────────────────────────────────
echo -e "${BOLD}Phase 4: Bootstrapping CDK${NC}"
echo ""

info "Running CDK bootstrap (idempotent)..."
cd infrastructure
npm ci --silent 2>/dev/null
$NPX_BIN cdk bootstrap "aws://${ACCOUNT_ID}/${AWS_REGION}" \
  --profile "$AWS_PROFILE" 2>&1 | tail -3
cd ..
ok "CDK bootstrapped"
echo ""

# ─── Phase 5: Build & Deploy ──────────────────────────────────
echo -e "${BOLD}Phase 5: Building and deploying${NC}"
echo ""

info "Installing dependencies..."
make install

info "Building Lambda layer..."
make layer

if [ "$SKIP_PROWLER" = false ]; then
  info "Setting up Prowler container image..."
  make prowler-push
else
  warn "Skipping Prowler setup (SKIP_PROWLER=true)"
fi

info "Deploying CloudSecure stacks..."
make deploy

echo ""
ok "Deployment complete!"
echo ""

# ─── Summary ──────────────────────────────────────────────────
echo -e "${BOLD}════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  CloudSecure deployed successfully!${NC}"
echo -e "${BOLD}════════════════════════════════════════════════${NC}"
echo ""

# Retrieve API endpoint
API_ENDPOINT=$(aws cloudformation describe-stacks \
  --profile "$AWS_PROFILE" --region "$AWS_REGION" \
  --stack-name "CloudSecure-API-${CLOUDSECURE_ENV}" \
  --query "Stacks[0].Outputs[?OutputKey=='ApiEndpoint'].OutputValue" \
  --output text 2>/dev/null || echo "")

if [ -n "$API_ENDPOINT" ]; then
  echo -e "  API Endpoint:  ${CYAN}${API_ENDPOINT}${NC}"
  echo -e "  Health Check:  ${CYAN}${API_ENDPOINT}health${NC}"
fi

echo -e "  Account:       ${ACCOUNT_ID}"
echo -e "  Region:        ${AWS_REGION}"
echo -e "  Environment:   ${CLOUDSECURE_ENV}"
echo -e "  Prowler:       $([ "$SKIP_PROWLER" = true ] && echo 'skipped' || echo 'enabled')"
echo ""
echo -e "${BOLD}Next steps:${NC}"
echo ""
echo -e "  1. ${BOLD}Install the CLI:${NC}"
echo "     pip install cloudsecure"
echo ""
echo -e "  2. ${BOLD}Create an assessment role (quick setup):${NC}"
echo "     ./deploy.sh --setup-role"
echo ""
echo -e "     ${DIM}Or manually:${NC}"
echo -e "     ${DIM}aws cloudformation deploy --template-file onboarding/cloudformation/cloudsecure-role.yaml ${NC}\\"
echo -e "     ${DIM}  --stack-name CloudSecure-AssessmentRole --capabilities CAPABILITY_NAMED_IAM ${NC}\\"
echo -e "     ${DIM}  --parameter-overrides CloudSecureAccountId=${ACCOUNT_ID} ExternalId=cloudsecure-${ACCOUNT_ID} ${NC}\\"
echo -e "     ${DIM}  --profile ${AWS_PROFILE} --region ${AWS_REGION}${NC}"
echo ""
echo -e "  3. ${BOLD}Run your first assessment:${NC}"
echo "     cloudsecure --profile ${AWS_PROFILE} assess \\"
echo "       --account-id ${ACCOUNT_ID} \\"
echo "       --role-arn arn:aws:iam::${ACCOUNT_ID}:role/CloudSecureAssessmentRole \\"
echo "       --external-id cloudsecure-${ACCOUNT_ID}"
echo ""
echo -e "  4. ${BOLD}Download the report:${NC}"
echo "     cloudsecure --profile ${AWS_PROFILE} report <ASSESSMENT_ID> --format html --open"
echo ""
echo -e "  ${DIM}To teardown: ./destroy.sh${NC}"
echo ""
