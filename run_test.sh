#!/usr/bin/env bash
set -euo pipefail

# Pull amd64 Docker images on Apple Silicon
if [[ $(uname -m) == "arm64" ]]; then
  echo "Detected Apple Silicon (ARM64), pulling amd64 Docker images via Rosetta 2..."
  docker pull --platform linux/amd64 arcium/trusted-dealer:latest > /dev/null 2>&1
  docker pull --platform linux/amd64 arcium/arx-node:latest > /dev/null 2>&1
fi

REAL_SOLANA_TEST_VALIDATOR="$(command -v solana-test-validator)"
WRAP_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "$WRAP_DIR"
}
trap cleanup EXIT
cat > "$WRAP_DIR/solana-test-validator" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
REAL_SOLANA_TEST_VALIDATOR="${REAL_SOLANA_TEST_VALIDATOR:?REAL_SOLANA_TEST_VALIDATOR is not set}"
filtered_args=()
while (($#)); do
  if [[ "$1" == "--warp-slot" ]]; then
    shift 2
    continue
  fi
  filtered_args+=("$1")
  shift
done
exec "$REAL_SOLANA_TEST_VALIDATOR" "${filtered_args[@]}"
EOF
chmod +x "$WRAP_DIR/solana-test-validator"
REAL_SOLANA_TEST_VALIDATOR="$REAL_SOLANA_TEST_VALIDATOR" PATH="$WRAP_DIR:$PATH" arcium test "$@"
