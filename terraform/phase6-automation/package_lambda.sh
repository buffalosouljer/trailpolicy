#!/usr/bin/env bash
# Package the trailpolicy core library + handler into a Lambda deployment zip.
#
# Usage: ./package_lambda.sh
# Output: ./lambda.zip

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PACKAGE_DIR="${SCRIPT_DIR}/lambda/package"
CLI_DIR="${SCRIPT_DIR}/../../cli"
ZIP_PATH="${SCRIPT_DIR}/lambda.zip"

echo "==> Cleaning previous build..."
rm -rf "${PACKAGE_DIR}" "${ZIP_PATH}"
mkdir -p "${PACKAGE_DIR}"

echo "==> Installing trailpolicy package into Lambda package dir..."
pip install --target "${PACKAGE_DIR}" "${CLI_DIR}" --quiet --no-deps

echo "==> Installing runtime dependencies..."
pip install --target "${PACKAGE_DIR}" boto3 jmespath --quiet --upgrade

echo "==> Copying Lambda handler..."
cp "${SCRIPT_DIR}/lambda/handler.py" "${PACKAGE_DIR}/"

echo "==> Creating zip..."
cd "${PACKAGE_DIR}"
zip -r "${ZIP_PATH}" . -q

echo "==> Lambda package created: ${ZIP_PATH}"
echo "    Size: $(du -h "${ZIP_PATH}" | cut -f1)"
