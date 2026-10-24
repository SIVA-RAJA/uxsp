#!/usr/bin/env bash
# ==============================================================================
# UXSP Static Application Security Testing (SAST) Scanner
#
# Runs comprehensive static security analysis across Python and JavaScript/TS:
#   1. Ruff Security Rules (flake8-bandit / S rules)
#   2. Bandit AST Deep Security Scanner
#   3. Python Dependency Security Audit (pip-audit)
#   4. JavaScript/TypeScript SDK Security Audit (npm audit)
#
# Usage:
#   ./scripts/run_sast.sh [options]
#
# Options:
#   --skip-deps      Skip network dependency audits (pip-audit, npm audit)
#   --sarif-dir DIR  Save Bandit SARIF report into DIR
#   -h, --help       Show this help message
# ==============================================================================

set -euo pipefail

# --- Color definitions ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# --- Project root directory ---
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

SKIP_DEPS=false
SARIF_DIR=""

for arg in "$@"; do
    case "$arg" in
        --skip-deps)
            SKIP_DEPS=true
            ;;
        --sarif-dir)
            shift
            SARIF_DIR="${1:-}"
            ;;
        -h|--help)
            head -n 20 "$0" | grep -E '^#' | sed 's/^# \?//'
            exit 0
            ;;
    esac
done

# --- Resolve Python / CLI Binaries ---
if [ -d "$ROOT_DIR/.venv/bin" ]; then
    PYTHON="$ROOT_DIR/.venv/bin/python"
    BANDIT="$ROOT_DIR/.venv/bin/bandit"
    RUFF="$ROOT_DIR/.venv/bin/ruff"
    PIP_AUDIT="$ROOT_DIR/.venv/bin/pip-audit"
else
    PYTHON="$(command -v python3 || command -v python || true)"
    BANDIT="$(command -v bandit || true)"
    RUFF="$(command -v ruff || true)"
    PIP_AUDIT="$(command -v pip-audit || true)"
fi

echo -e "${BOLD}${BLUE}======================================================================${NC}"
echo -e "${BOLD}${BLUE}    UXSP Static Application Security Testing (SAST) Suite             ${NC}"
echo -e "${BOLD}${BLUE}======================================================================${NC}"
echo -e "Working Directory: ${ROOT_DIR}"
echo -e "Python Executable: ${PYTHON:-not found}"
echo ""

TOTAL_STEPS=4
PASSED_STEPS=0
FAILED_STEPS=0

run_step() {
    local step_num="$1"
    local title="$2"
    local cmd="$3"

    echo -e "${BOLD}[Step ${step_num}/${TOTAL_STEPS}] ${title}...${NC}"
    if eval "$cmd"; then
        echo -e "${GREEN}✔ PASSED: ${title}${NC}\n"
        PASSED_STEPS=$((PASSED_STEPS + 1))
    else
        echo -e "${RED}✘ FAILED: ${title}${NC}\n"
        FAILED_STEPS=$((FAILED_STEPS + 1))
    fi
}

# --- Step 1: Ruff Security Checks ---
if [ -n "$RUFF" ] && [ -x "$RUFF" ]; then
    run_step 1 "Ruff Security Rules (flake8-bandit / S rules)" \
        "\"$RUFF\" check --select S uxsp"
else
    echo -e "${YELLOW}⚠ SKIPPED: ruff not found in environment${NC}\n"
fi

# --- Step 2: Bandit AST Deep Security Scan ---
if [ -n "$BANDIT" ] && [ -x "$BANDIT" ]; then
    BANDIT_CMD="\"$BANDIT\" -c pyproject.toml -r uxsp"
    if [ -n "$SARIF_DIR" ]; then
        mkdir -p "$SARIF_DIR"
        BANDIT_CMD="\"$BANDIT\" -c pyproject.toml -r uxsp -f sarif -o \"$SARIF_DIR/bandit.sarif\""
    fi
    run_step 2 "Bandit Python AST Security Scanner" "$BANDIT_CMD"
else
    echo -e "${YELLOW}⚠ SKIPPED: bandit not found in environment${NC}\n"
fi

# --- Step 3: Python Dependency Security Audit ---
if [ "$SKIP_DEPS" = true ]; then
    echo -e "${YELLOW}⚠ SKIPPED Step 3: --skip-deps specified${NC}\n"
elif [ -n "$PIP_AUDIT" ] && [ -x "$PIP_AUDIT" ]; then
    run_step 3 "pip-audit Python Dependency Vulnerability Scan" \
        "\"$PIP_AUDIT\" --desc"
else
    echo -e "${YELLOW}⚠ SKIPPED Step 3: pip-audit not found in environment${NC}\n"
fi

# --- Step 4: JavaScript/TypeScript SDK Audit ---
if [ "$SKIP_DEPS" = true ]; then
    echo -e "${YELLOW}⚠ SKIPPED Step 4: --skip-deps specified${NC}\n"
elif [ -d "$ROOT_DIR/sdks/js" ] && command -v npm >/dev/null 2>&1; then
    run_step 4 "npm audit JS/TS SDK Security Check" \
        "(cd \"$ROOT_DIR/sdks/js\" && npm audit)"
else
    echo -e "${YELLOW}⚠ SKIPPED Step 4: npm or sdks/js not found${NC}\n"
fi

# --- Summary ---
echo -e "${BOLD}${BLUE}======================================================================${NC}"
echo -e "${BOLD}${BLUE}    SAST Scan Summary                                                 ${NC}"
echo -e "${BOLD}${BLUE}======================================================================${NC}"
echo -e "Passed: ${GREEN}${PASSED_STEPS}${NC} | Failed: ${RED}${FAILED_STEPS}${NC}"

if [ "$FAILED_STEPS" -gt 0 ]; then
    echo -e "${RED}${BOLD}SAST detected security issues that must be addressed.${NC}"
    exit 1
else
    echo -e "${GREEN}${BOLD}All SAST checks passed clean!${NC}"
    exit 0
fi
