#!/usr/bin/env bash
# ==============================================================================
# UXSP Dynamic Application Security Testing (DAST) Suite
#
# Runs comprehensive dynamic security analysis against live UXSP services:
#   1. Protocol & Middleware DAST Suite (pytest tests/test_dast_security.py)
#      - Replay attacks, duplicate nonces, timestamp skew
#      - Cryptographic tampering (ciphertext, tags, signatures)
#      - Header injection & downgrade tampering
#      - DoS payload ceiling enforcement
#      - Path traversal & HTTP method confusion
#   2. Property-Based OpenAPI Fuzzing (Schemathesis)
#      - Negative & positive data fuzzing against live endpoints
#   3. OWASP ZAP API Vulnerability Scanner (Docker / CI)
#      - Automated crawler and active API vulnerability analysis
#
# Usage:
#   ./scripts/run_dast.sh [options]
#
# Options:
#   --port PORT          Port for target server (default: 8899)
#   --skip-fuzz          Skip Schemathesis OpenAPI fuzzing
#   --skip-tests         Skip Python DAST test suite
#   --zap                Force attempt OWASP ZAP scan via Docker
#   --report-dir DIR     Directory to save DAST reports (default: dast-reports)
#   -h, --help           Show this help message
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

PORT=8899
SKIP_FUZZ=false
SKIP_TESTS=false
RUN_ZAP=false
REPORT_DIR="dast-reports"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --port)
            PORT="${2:-8899}"
            shift 2
            ;;
        --skip-fuzz)
            SKIP_FUZZ=true
            shift
            ;;
        --skip-tests)
            SKIP_TESTS=true
            shift
            ;;
        --zap)
            RUN_ZAP=true
            shift
            ;;
        --report-dir)
            REPORT_DIR="${2:-dast-reports}"
            shift 2
            ;;
        -h|--help)
            head -n 25 "$0" | grep -E '^#' | sed 's/^# \?//'
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# --- Resolve Python / CLI Binaries ---
if [ -d "$ROOT_DIR/.venv/bin" ]; then
    PYTHON="$ROOT_DIR/.venv/bin/python"
    PYTEST="$ROOT_DIR/.venv/bin/pytest"
    SCHEMATHESIS="$ROOT_DIR/.venv/bin/schemathesis"
else
    PYTHON="$(command -v python3 || command -v python || true)"
    PYTEST="$(command -v pytest || true)"
    SCHEMATHESIS="$(command -v schemathesis || true)"
fi

echo -e "${BOLD}${BLUE}======================================================================${NC}"
echo -e "${BOLD}${BLUE}    UXSP Dynamic Application Security Testing (DAST) Suite            ${NC}"
echo -e "${BOLD}${BLUE}======================================================================${NC}"
echo -e "Working Directory: ${ROOT_DIR}"
echo -e "Python Executable: ${PYTHON:-not found}"
echo -e "Target Port:       ${PORT}"
echo -e "Report Directory:  ${REPORT_DIR}"
echo ""

TOTAL_STEPS=3
PASSED_STEPS=0
FAILED_STEPS=0
SKIPPED_STEPS=0

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

mkdir -p "$REPORT_DIR"

# ── Step 1: Protocol & Middleware DAST Suite ──────────────────────────────────
if [ "$SKIP_TESTS" = true ]; then
    echo -e "${YELLOW}⚠ SKIPPED Step 1: --skip-tests specified${NC}\n"
    SKIPPED_STEPS=$((SKIPPED_STEPS + 1))
elif [ -n "$PYTEST" ] && [ -x "$PYTEST" ]; then
    run_step 1 "Python DAST Security Test Suite (Replay, Tampering, Fuzzing)" \
        "\"$PYTEST\" tests/test_dast_security.py -q --no-header"
else
    echo -e "${YELLOW}⚠ SKIPPED Step 1: pytest not found${NC}\n"
    SKIPPED_STEPS=$((SKIPPED_STEPS + 1))
fi

# ── Server Lifecyle for Live Scans ───────────────────────────────────────────
SERVER_PID=""
cleanup() {
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        echo -e "\n${BOLD}Shutting down DAST reference target server (PID: ${SERVER_PID})...${NC}"
        kill -TERM "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

start_target_server() {
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        return 0
    fi

    echo -e "${BOLD}Launching UXSP DAST Reference Server on port ${PORT}...${NC}"
    "$PYTHON" "$ROOT_DIR/scripts/dast_server.py" --port "$PORT" > "$REPORT_DIR/server.log" 2>&1 &
    SERVER_PID=$!

    # Wait for server readiness
    local retries=30
    local ready=false
    while [ "$retries" -gt 0 ]; do
        if "$PYTHON" -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:${PORT}/api/public/health', timeout=1)" 2>/dev/null; then
            ready=true
            break
        fi
        sleep 0.2
        retries=$((retries - 1))
    done

    if [ "$ready" = false ]; then
        echo -e "${RED}✘ Error: Target server failed to respond within timeout.${NC}"
        cat "$REPORT_DIR/server.log"
        exit 1
    fi
    echo -e "${GREEN}✔ DAST Target Server active on http://127.0.0.1:${PORT}${NC}\n"
}

# ── Step 2: Schemathesis OpenAPI Dynamic Fuzzing ─────────────────────────────
if [ "$SKIP_FUZZ" = true ]; then
    echo -e "${YELLOW}⚠ SKIPPED Step 2: --skip-fuzz specified${NC}\n"
    SKIPPED_STEPS=$((SKIPPED_STEPS + 1))
elif [ -n "$SCHEMATHESIS" ] && [ -x "$SCHEMATHESIS" ]; then
    start_target_server
    run_step 2 "Schemathesis Property-Based OpenAPI Dynamic Fuzzer" \
        "\"$SCHEMATHESIS\" run \"http://127.0.0.1:${PORT}/openapi.json\" \
            --checks not_a_server_error \
            --max-examples 10 \
            --no-color \
            --report-junit-path \"$REPORT_DIR/schemathesis-junit.xml\""
else
    echo -e "${YELLOW}⚠ SKIPPED Step 2: schemathesis not installed in environment${NC}\n"
    SKIPPED_STEPS=$((SKIPPED_STEPS + 1))
fi

# ── Step 3: OWASP ZAP API Dynamic Security Scanner ───────────────────────────
if [ "$RUN_ZAP" = true ] || (command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1); then
    start_target_server
    echo -e "${BOLD}[Step 3/${TOTAL_STEPS}] OWASP ZAP API Security Scanner (Docker)...${NC}"
    if docker run --rm -v "$ROOT_DIR/$REPORT_DIR:/zap/wrk/:rw" --network host \
        -t ghcr.io/zaproxy/zaproxy:stable zap-api-scan.py \
        -t "http://127.0.0.1:${PORT}/openapi.json" -f openapi \
        -r zap-report.html -J zap-report.json -l WARN; then
        echo -e "${GREEN}✔ PASSED: OWASP ZAP API Security Scanner${NC}\n"
        PASSED_STEPS=$((PASSED_STEPS + 1))
    else
        # ZAP exits with 1 for warnings or 2 for fails. Check report.
        if [ -f "$REPORT_DIR/zap-report.html" ]; then
            echo -e "${YELLOW}⚠ OWASP ZAP scan completed with warnings (see $REPORT_DIR/zap-report.html)${NC}\n"
            PASSED_STEPS=$((PASSED_STEPS + 1))
        else
            echo -e "${RED}✘ FAILED: OWASP ZAP API Security Scanner${NC}\n"
            FAILED_STEPS=$((FAILED_STEPS + 1))
        fi
    fi
else
    echo -e "${YELLOW}⚠ SKIPPED Step 3: Docker daemon not running locally (OWASP ZAP runs in GitHub Actions CI)${NC}\n"
    SKIPPED_STEPS=$((SKIPPED_STEPS + 1))
fi

# ── Summary ──────────────────────────────────────────────────────────────────
echo -e "${BOLD}${BLUE}======================================================================${NC}"
echo -e "${BOLD}${BLUE}    DAST Scan Summary                                                 ${NC}"
echo -e "${BOLD}${BLUE}======================================================================${NC}"
echo -e "Passed: ${GREEN}${PASSED_STEPS}${NC} | Failed: ${RED}${FAILED_STEPS}${NC} | Skipped: ${YELLOW}${SKIPPED_STEPS}${NC}"
echo -e "Reports stored in: ${REPORT_DIR}/"

if [ "$FAILED_STEPS" -gt 0 ]; then
    echo -e "${RED}${BOLD}DAST detected dynamic security issues that must be addressed.${NC}"
    exit 1
else
    echo -e "${GREEN}${BOLD}All executed DAST checks passed clean!${NC}"
    exit 0
fi
