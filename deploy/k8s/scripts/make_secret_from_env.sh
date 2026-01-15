#!/usr/bin/env bash
set -euo pipefail

# Generate a Kubernetes Secret manifest from a .env file.
#
# Usage:
#   bash deploy/k8s/scripts/make_secret_from_env.sh .env > secret.yaml
#
# The script extracts variables that should live in a Secret:
# - LAP_GATEWAY_SIGNING_KEY
# - LAP_API_KEYS_JSON
# - LAP_TRUSTED_REVIEWER_KEYS_JSON (optional)

ENV_FILE="${1:-.env}"
NAMESPACE="${LAP_NAMESPACE:-lap-system}"
NAME="${LAP_SECRET_NAME:-lap-gateway-secrets}"

if [[ ! -f "${ENV_FILE}" ]]; then
  echo "Env file not found: ${ENV_FILE}" >&2
  exit 1
fi

# shellcheck disable=SC1090
set -a
source "${ENV_FILE}"
set +a

req() {
  local k="$1"
  local v="${!k:-}"
  if [[ -z "${v}" ]]; then
    echo "Missing required env var in ${ENV_FILE}: ${k}" >&2
    exit 1
  fi
}

req LAP_GATEWAY_SIGNING_KEY
req LAP_API_KEYS_JSON

cat <<YAML
apiVersion: v1
kind: Secret
metadata:
  name: ${NAME}
  namespace: ${NAMESPACE}
type: Opaque
stringData:
  LAP_GATEWAY_SIGNING_KEY: "${LAP_GATEWAY_SIGNING_KEY}"
  LAP_API_KEYS_JSON: '${LAP_API_KEYS_JSON}'
YAML

if [[ -n "${LAP_TRUSTED_REVIEWER_KEYS_JSON:-}" ]]; then
  echo "  LAP_TRUSTED_REVIEWER_KEYS_JSON: '${LAP_TRUSTED_REVIEWER_KEYS_JSON}'"
fi
