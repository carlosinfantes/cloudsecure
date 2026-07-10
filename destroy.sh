#!/usr/bin/env bash
# CloudSecure Assessment Platform - Infrastructure Teardown
# Usage: ./destroy.sh
# This script removes all CloudSecure infrastructure from your AWS account.
set -euo pipefail

# ─── Colors & Helpers ──────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

info()  { echo -e "${CYAN}▸${NC} $*"; }
ok()    { echo -e "${GREEN}✓${NC} $*"; }
warn()  { echo -e "${YELLOW}⚠${NC} $*"; }
fail()  { echo -e "${RED}✗${NC} $*"; exit 1; }

# ─── Banner ────────────────────────────────────────────────────
echo ""
echo -e "${RED}${BOLD}╔══════════════════════════════════════════════╗${NC}"
echo -e "${RED}${BOLD}║       CloudSecure Assessment Platform        ║${NC}"
echo -e "${RED}${BOLD}║          Infrastructure Teardown              ║${NC}"
echo -e "${RED}${BOLD}╚══════════════════════════════════════════════╝${NC}"
echo ""

# ─── Phase 1: Configuration ───────────────────────────────────
echo -e "${BOLD}Phase 1: Configuration${NC}"
echo ""

# Try to load defaults from .env
if [ -f .env ]; then
  info "Loading defaults from .env"
  # shellcheck disable=SC1091
  source .env 2>/dev/null || true
fi

# AWS Profile
DEFAULT_PROFILE="${AWS_PROFILE:-default}"
read -rp "AWS profile to use [${DEFAULT_PROFILE}]: " INPUT_PROFILE
AWS_PROFILE=${INPUT_PROFILE:-$DEFAULT_PROFILE}

# Validate credentials
info "Validating AWS credentials for profile '${AWS_PROFILE}'..."
CALLER_IDENTITY=$(aws sts get-caller-identity --profile "$AWS_PROFILE" --output json 2>/dev/null) || \
  fail "Cannot authenticate with profile '${AWS_PROFILE}'. Run: aws configure --profile ${AWS_PROFILE}"

ACCOUNT_ID=$(echo "$CALLER_IDENTITY" | python3 -c "import sys,json; print(json.load(sys.stdin)['Account'])")
ok "Authenticated: account ${ACCOUNT_ID}"

# Region
DEFAULT_REGION="${AWS_REGION:-eu-west-1}"
read -rp "AWS region [${DEFAULT_REGION}]: " INPUT_REGION
AWS_REGION=${INPUT_REGION:-$DEFAULT_REGION}

# Environment
DEFAULT_ENV="${CLOUDSECURE_ENV:-dev}"
read -rp "Environment name (dev/test/prod) [${DEFAULT_ENV}]: " INPUT_ENV
CLOUDSECURE_ENV=${INPUT_ENV:-$DEFAULT_ENV}

echo ""

# ─── Phase 2: Discover Stacks ─────────────────────────────────
echo -e "${BOLD}Phase 2: Discovering deployed stacks${NC}"
echo ""

STACK_PREFIX="CloudSecure"
# CDK stacks in dependency order (destroyed in reverse)
CDK_STACKS=(
  "${STACK_PREFIX}-API-${CLOUDSECURE_ENV}"
  "${STACK_PREFIX}-Orchestration-${CLOUDSECURE_ENV}"
  "${STACK_PREFIX}-Lambda-${CLOUDSECURE_ENV}"
  "${STACK_PREFIX}-Storage-${CLOUDSECURE_ENV}"
)

FOUND_STACKS=()
for STACK in "${CDK_STACKS[@]}"; do
  STATUS=$(aws cloudformation describe-stacks \
    --stack-name "$STACK" \
    --profile "$AWS_PROFILE" --region "$AWS_REGION" \
    --query "Stacks[0].StackStatus" --output text 2>/dev/null || echo "NOT_FOUND")
  if [ "$STATUS" != "NOT_FOUND" ]; then
    FOUND_STACKS+=("$STACK")
    echo -e "  ${GREEN}Found${NC}  $STACK  ${DIM}($STATUS)${NC}"
  else
    echo -e "  ${DIM}Skip${NC}   $STACK  ${DIM}(not deployed)${NC}"
  fi
done

# Check AssessmentRole stack
ROLE_STACK="${STACK_PREFIX}-AssessmentRole"
ROLE_STATUS=$(aws cloudformation describe-stacks \
  --stack-name "$ROLE_STACK" \
  --profile "$AWS_PROFILE" --region "$AWS_REGION" \
  --query "Stacks[0].StackStatus" --output text 2>/dev/null || echo "NOT_FOUND")
HAS_ROLE_STACK=false
if [ "$ROLE_STATUS" != "NOT_FOUND" ]; then
  HAS_ROLE_STACK=true
  echo -e "  ${GREEN}Found${NC}  $ROLE_STACK  ${DIM}($ROLE_STATUS)${NC}"
fi

echo ""

if [ ${#FOUND_STACKS[@]} -eq 0 ] && [ "$HAS_ROLE_STACK" = false ]; then
  ok "No CloudSecure stacks found in ${CLOUDSECURE_ENV}. Nothing to destroy."
  exit 0
fi

# ─── Phase 3: Confirmation ────────────────────────────────────
echo -e "${BOLD}Phase 3: Confirmation${NC}"
echo ""
echo -e "${RED}${BOLD}WARNING: This will permanently delete the following resources:${NC}"
echo ""
for STACK in "${FOUND_STACKS[@]}"; do
  echo -e "  ${RED}×${NC}  $STACK"
done
if [ "$HAS_ROLE_STACK" = true ]; then
  echo ""
  read -rp "Also delete the AssessmentRole stack? [y/N]: " DELETE_ROLE
  DELETE_ROLE=$(echo "$DELETE_ROLE" | tr '[:upper:]' '[:lower:]')
  if [ "$DELETE_ROLE" = "y" ]; then
    echo -e "  ${RED}×${NC}  $ROLE_STACK"
  fi
fi
echo ""
echo -e "  Account:     ${ACCOUNT_ID}"
echo -e "  Region:      ${AWS_REGION}"
echo -e "  Environment: ${CLOUDSECURE_ENV}"
echo ""
echo -e "${RED}${BOLD}This action cannot be undone.${NC}"
read -rp "Type 'destroy' to confirm: " CONFIRM
if [ "$CONFIRM" != "destroy" ]; then
  echo ""
  warn "Aborted. No resources were deleted."
  exit 0
fi

echo ""

# ─── Phase 4: Empty S3 Bucket ─────────────────────────────────
echo -e "${BOLD}Phase 4: Cleaning up resources${NC}"
echo ""

BUCKET_NAME="cloudsecure-reports-${ACCOUNT_ID}-${CLOUDSECURE_ENV}"
if aws s3api head-bucket --bucket "$BUCKET_NAME" --profile "$AWS_PROFILE" --region "$AWS_REGION" 2>/dev/null; then
  info "Emptying S3 bucket: ${BUCKET_NAME}..."
  aws s3 rm "s3://${BUCKET_NAME}" --recursive --profile "$AWS_PROFILE" --region "$AWS_REGION" 2>/dev/null || true
  # Also remove any versioned objects/delete markers
  VERSIONS=$(aws s3api list-object-versions \
    --bucket "$BUCKET_NAME" \
    --profile "$AWS_PROFILE" --region "$AWS_REGION" \
    --query '{Objects: Versions[].{Key:Key,VersionId:VersionId}}' \
    --output json 2>/dev/null || echo '{"Objects": null}')
  if echo "$VERSIONS" | python3 -c "import sys,json; d=json.load(sys.stdin); exit(0 if d.get('Objects') else 1)" 2>/dev/null; then
    echo "$VERSIONS" | python3 -c "
import sys, json
data = json.load(sys.stdin)
objects = data.get('Objects', [])
if objects:
    delete = {'Objects': [{'Key': o['Key'], 'VersionId': o['VersionId']} for o in objects], 'Quiet': True}
    json.dump(delete, sys.stdout)
" | aws s3api delete-objects \
      --bucket "$BUCKET_NAME" \
      --delete "file:///dev/stdin" \
      --profile "$AWS_PROFILE" --region "$AWS_REGION" >/dev/null 2>&1 || true
  fi
  MARKERS=$(aws s3api list-object-versions \
    --bucket "$BUCKET_NAME" \
    --profile "$AWS_PROFILE" --region "$AWS_REGION" \
    --query '{Objects: DeleteMarkers[].{Key:Key,VersionId:VersionId}}' \
    --output json 2>/dev/null || echo '{"Objects": null}')
  if echo "$MARKERS" | python3 -c "import sys,json; d=json.load(sys.stdin); exit(0 if d.get('Objects') else 1)" 2>/dev/null; then
    echo "$MARKERS" | python3 -c "
import sys, json
data = json.load(sys.stdin)
objects = data.get('Objects', [])
if objects:
    delete = {'Objects': [{'Key': o['Key'], 'VersionId': o['VersionId']} for o in objects], 'Quiet': True}
    json.dump(delete, sys.stdout)
" | aws s3api delete-objects \
      --bucket "$BUCKET_NAME" \
      --delete "file:///dev/stdin" \
      --profile "$AWS_PROFILE" --region "$AWS_REGION" >/dev/null 2>&1 || true
  fi
  ok "S3 bucket emptied"
else
  info "S3 bucket not found (may already be deleted)"
fi

echo ""

# ─── Phase 5: Destroy Stacks ──────────────────────────────────
echo -e "${BOLD}Phase 5: Destroying CloudSecure stacks${NC}"
echo ""

# Check for Node.js/npx (needed for CDK destroy)
NODE_BIN=""
if command -v node >/dev/null 2>&1; then
  NODE_BIN="node"
elif [ -d "${HOME}/.nvm/versions/node" ]; then
  NODE_DIR=$(find "${HOME}/.nvm/versions/node" -maxdepth 1 -type d | sort -V | tail -1)
  if [ -x "${NODE_DIR}/bin/node" ]; then
    export PATH="${NODE_DIR}/bin:${PATH}"
    NODE_BIN="${NODE_DIR}/bin/node"
  fi
fi

NPX_BIN=""
if command -v npx >/dev/null 2>&1; then
  NPX_BIN="npx"
elif [ -n "$NODE_BIN" ]; then
  NPX_DIR=$(dirname "$NODE_BIN")
  [ -x "${NPX_DIR}/npx" ] && NPX_BIN="${NPX_DIR}/npx"
fi

CDK_ARGS="--profile ${AWS_PROFILE} -c env=${CLOUDSECURE_ENV} --force"

if [ -n "$NPX_BIN" ] && [ -d "infrastructure" ]; then
  # Use CDK destroy for proper resource cleanup
  cd infrastructure
  npm ci --silent 2>/dev/null

  for STACK in "${FOUND_STACKS[@]}"; do
    info "Destroying ${STACK}..."
    if $NPX_BIN cdk destroy "$STACK" $CDK_ARGS 2>&1 | tail -3; then
      ok "${STACK} destroyed"
    else
      warn "Failed to destroy ${STACK} via CDK, falling back to CloudFormation..."
      aws cloudformation delete-stack \
        --stack-name "$STACK" \
        --profile "$AWS_PROFILE" --region "$AWS_REGION"
      info "Waiting for ${STACK} deletion..."
      aws cloudformation wait stack-delete-complete \
        --stack-name "$STACK" \
        --profile "$AWS_PROFILE" --region "$AWS_REGION" 2>/dev/null && \
        ok "${STACK} destroyed" || warn "${STACK} deletion may still be in progress"
    fi
    echo ""
  done

  cd ..
else
  # Fallback: use CloudFormation directly
  warn "CDK not available, using CloudFormation delete-stack"
  for STACK in "${FOUND_STACKS[@]}"; do
    info "Deleting ${STACK}..."
    aws cloudformation delete-stack \
      --stack-name "$STACK" \
      --profile "$AWS_PROFILE" --region "$AWS_REGION"
    info "Waiting for ${STACK} deletion..."
    aws cloudformation wait stack-delete-complete \
      --stack-name "$STACK" \
      --profile "$AWS_PROFILE" --region "$AWS_REGION" 2>/dev/null && \
      ok "${STACK} deleted" || warn "${STACK} deletion may still be in progress"
    echo ""
  done
fi

# Delete AssessmentRole stack if requested
if [ "$HAS_ROLE_STACK" = true ] && [ "${DELETE_ROLE:-n}" = "y" ]; then
  info "Deleting ${ROLE_STACK}..."
  aws cloudformation delete-stack \
    --stack-name "$ROLE_STACK" \
    --profile "$AWS_PROFILE" --region "$AWS_REGION"
  info "Waiting for ${ROLE_STACK} deletion..."
  aws cloudformation wait stack-delete-complete \
    --stack-name "$ROLE_STACK" \
    --profile "$AWS_PROFILE" --region "$AWS_REGION" 2>/dev/null && \
    ok "${ROLE_STACK} deleted" || warn "${ROLE_STACK} deletion may still be in progress"
  echo ""
fi

# ─── Summary ──────────────────────────────────────────────────
echo ""
echo -e "${BOLD}════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  CloudSecure teardown complete${NC}"
echo -e "${BOLD}════════════════════════════════════════════════${NC}"
echo ""
echo -e "  Account:     ${ACCOUNT_ID}"
echo -e "  Region:      ${AWS_REGION}"
echo -e "  Environment: ${CLOUDSECURE_ENV}"
echo ""
echo -e "${DIM}To also uninstall the CLI:  pip uninstall cloudsecure${NC}"
echo -e "${DIM}To redeploy, run:          ./deploy.sh${NC}"
echo ""
