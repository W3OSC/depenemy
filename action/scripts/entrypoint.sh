#!/bin/bash
set -euo pipefail

WORKDIR="${GITHUB_WORKSPACE:-/github/workspace}"
SARIF_OUT="${WORKDIR}/depenemy.sarif"
CONFIG_FILE="${WORKDIR}/.depenemy-action.yml"

# Inputs arrive as INPUT_* environment variables (Docker action convention)
REGISTRIES="${INPUT_APPROVED_REGISTRIES:-registry.npmjs.org}"
FAIL_ON="${INPUT_FAIL_ON:-error}"
PATHS="${INPUT_PATHS:-.}"
CUSTOM_CONFIG="${INPUT_CONFIG:-}"

cd "$WORKDIR"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  🔍 depenemy — Supply Chain Scanner"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Paths     : $PATHS"
echo "  Fail-on   : $FAIL_ON"
echo "  Registries: $REGISTRIES"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# ── Generate config from action inputs (unless caller provides one) ──
if [ -z "$CUSTOM_CONFIG" ]; then
  python3 /scripts/gen-config.py "$REGISTRIES" > "$CONFIG_FILE"
  CONFIG_ARG="--config $CONFIG_FILE"
  echo "[ config ] Generated $CONFIG_FILE from action inputs"
else
  CONFIG_ARG="--config $CUSTOM_CONFIG"
  echo "[ config ] Using caller-provided config: $CUSTOM_CONFIG"
fi

echo ""

# ── Run depenemy scan ────────────────────────────────────
SCAN_EXIT=0
# shellcheck disable=SC2086
depenemy scan $PATHS \
  $CONFIG_ARG \
  --output sarif \
  --output-file "$SARIF_OUT" \
  --fail-on "$FAIL_ON" \
  ${INPUT_GITHUB_TOKEN:+--github-token "$INPUT_GITHUB_TOKEN"} \
  || SCAN_EXIT=$?

# ── Propagate outputs ────────────────────────────────────
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  echo "sarif-file=$SARIF_OUT" >> "$GITHUB_OUTPUT"
fi

# ── Final status ─────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
if [ "$SCAN_EXIT" = "0" ]; then
  echo "  ✅ depenemy scan passed"
else
  echo "  🚫 depenemy scan found blocking issues (exit $SCAN_EXIT)"
fi
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

exit "$SCAN_EXIT"
