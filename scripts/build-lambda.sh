#!/usr/bin/env bash
# Build a Lambda deployment zip for a given phase.
#
# Usage: ./scripts/build-lambda.sh <phase-name>
# Example: ./scripts/build-lambda.sh phase5-notification-test
# Output: terraform/<phase>/lambda.zip
#
# Works from any working directory — all paths resolved via BASH_SOURCE.

set -euo pipefail

# Resolve absolute paths from script location
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CLI_DIR="${REPO_ROOT}/cli"
TF_DIR="${REPO_ROOT}/terraform"

# Validate arguments
if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <phase-name>" >&2
    echo "Example: $0 phase5-notification-test" >&2
    exit 1
fi

PHASE="$1"
PHASE_DIR="${TF_DIR}/${PHASE}"

if [[ ! -d "${PHASE_DIR}" ]]; then
    echo "Error: Phase directory terraform/${PHASE} not found" >&2
    exit 1
fi

if [[ ! -f "${PHASE_DIR}/lambda/handler.py" ]]; then
    echo "Error: lambda/handler.py not found in terraform/${PHASE}" >&2
    exit 1
fi

PACKAGE_DIR="${PHASE_DIR}/lambda/package"
ZIP_PATH="${PHASE_DIR}/lambda.zip"

echo "==> Cleaning previous build..." >&2
rm -rf "${PACKAGE_DIR}" "${ZIP_PATH}"
mkdir -p "${PACKAGE_DIR}"

echo "==> Installing trailpolicy package (no deps)..." >&2
pip install --target "${PACKAGE_DIR}" "${CLI_DIR}" --quiet --no-deps

echo "==> Installing runtime dependencies..." >&2
pip install --target "${PACKAGE_DIR}" boto3 jmespath --quiet --upgrade

echo "==> Stripping test suite and dist-info..." >&2
rm -rf "${PACKAGE_DIR}/trailpolicy/tests"
rm -rf "${PACKAGE_DIR}"/*.dist-info

echo "==> Copying Lambda handler..." >&2
cp "${PHASE_DIR}/lambda/handler.py" "${PACKAGE_DIR}/"

echo "==> Creating zip..." >&2
cd "${PACKAGE_DIR}"
zip -r "${ZIP_PATH}" . -q

echo "==> Lambda package created: ${ZIP_PATH}" >&2
echo "    Size: $(du -h "${ZIP_PATH}" | cut -f1)" >&2
