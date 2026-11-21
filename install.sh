#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLUGIN_ID="io.github.pradeepjung45.devdock"
PLUGIN_DIR="${HOME}/.config/omarchy/plugins/${PLUGIN_ID}"
LOCAL_BIN="${HOME}/.local/bin"

echo "==> Building DevDock Rust backend (release)..."
CARGO_ARGS=(build --release --manifest-path "${REPO_DIR}/Cargo.toml")
if [[ -f "${REPO_DIR}/Cargo.lock" ]]; then
  CARGO_ARGS+=(--locked)
fi

if [[ "${REPO_DIR}" == "${PLUGIN_DIR}" ]]; then
  BUILD_DIR="$(mktemp -d "${TMPDIR:-/tmp}/devdock-build.XXXXXX")"
  trap 'rm -rf "${BUILD_DIR}"' EXIT
  CARGO_TARGET_DIR="${BUILD_DIR}" cargo "${CARGO_ARGS[@]}"
  BUILT_BIN="${BUILD_DIR}/release/devdock"
else
  cargo "${CARGO_ARGS[@]}"
  BUILT_BIN="${REPO_DIR}/target/release/devdock"
fi

echo "==> Installing CLI binary to ${LOCAL_BIN}/devdock..."
mkdir -p "${LOCAL_BIN}"
install -m 755 "${BUILT_BIN}" "${LOCAL_BIN}/devdock"

echo "==> Installing Omarchy plugin files to ${PLUGIN_DIR}..."
if [[ "${REPO_DIR}" == "${PLUGIN_DIR}" ]]; then
  mkdir -p "${PLUGIN_DIR}/bin"
  install -m 755 "${BUILT_BIN}" "${PLUGIN_DIR}/bin/devdock"
else
  rm -rf "${PLUGIN_DIR}"
  mkdir -p "${PLUGIN_DIR}/bin"
  cp "${REPO_DIR}/manifest.json" "${PLUGIN_DIR}/"
  cp "${REPO_DIR}/Panel.qml" "${PLUGIN_DIR}/"
  cp "${REPO_DIR}/DevDockIcon.qml" "${PLUGIN_DIR}/"
  cp "${REPO_DIR}/Service.qml" "${PLUGIN_DIR}/"
  cp "${REPO_DIR}/Model.js" "${PLUGIN_DIR}/"
  cp "${REPO_DIR}/LICENSE" "${PLUGIN_DIR}/"
  cp "${REPO_DIR}/README.md" "${PLUGIN_DIR}/"
  if [[ -f "${REPO_DIR}/preview.png" ]]; then
    cp "${REPO_DIR}/preview.png" "${PLUGIN_DIR}/"
  fi
  install -m 755 "${BUILT_BIN}" "${PLUGIN_DIR}/bin/devdock"
fi

if command -v omarchy-plugin-validate >/dev/null 2>&1; then
  echo "==> Validating plugin manifest..."
  omarchy-plugin-validate "${PLUGIN_DIR}"
elif [[ -x /usr/share/omarchy/bin/omarchy-plugin-validate ]]; then
  echo "==> Validating plugin manifest..."
  /usr/share/omarchy/bin/omarchy-plugin-validate "${PLUGIN_DIR}"
fi

if command -v omarchy-shell >/dev/null 2>&1; then
  echo "==> Rescanning Omarchy plugins..."
  omarchy-shell shell rescanPlugins || true
fi

if command -v omarchy >/dev/null 2>&1; then
  echo "==> Enabling ${PLUGIN_ID} in Omarchy..."
  omarchy plugin enable "${PLUGIN_ID}" || true
fi

echo "==> Done! Toggle DevDock via the bar widget or: omarchy-shell ${PLUGIN_ID} toggle"
echo "    Terminal CLI: devdock status"
