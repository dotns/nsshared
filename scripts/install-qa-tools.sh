#!/usr/bin/env bash

set -euo pipefail

log() {
  echo "$*" >&2
}

warn() {
  if [[ -t 2 ]]; then
    printf '\033[33mwarning: %s\033[0m\n' "$*" >&2
    return 0
  fi
  echo "warning: $*" >&2
}

err() {
  if [[ -t 2 ]]; then
    printf '\033[31merror: %s\033[0m\n' "$*" >&2
    exit 1
  fi
  echo "error: $*" >&2
  exit 1
}

[[ "$(uname -s)" == "Linux" ]] || err "QA tool bootstrap only supports Linux"
[[ "$(uname -m)" == "x86_64" ]] || err "QA tool bootstrap only supports x86_64"

install_root="${QA_TOOLS_INSTALL_ROOT:-$HOME/.cargo}"
install_bin="$install_root/bin"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

mkdir -p "$install_bin"

install_tool() {
  local crate="$1"
  local version="$2"
  local asset="$3"
  local sha256="$4"
  local binary="$5"
  local url="$6"
  local archive="$tmp_dir/$asset"
  local extract_dir="$tmp_dir/$crate"
  local -a matches

  log "Installing ${crate} ${version}"
  if curl --proto '=https' --tlsv1.2 --location --fail --silent --show-error \
    --connect-timeout 15 --max-time 180 --output "$archive" "$url"
  then
    if ! printf '%s  %s\n' "$sha256" "$archive" | sha256sum --check --status
    then
      err "${crate} ${version} checksum mismatch"
    fi

    mkdir -p "$extract_dir"
    tar -xzf "$archive" -C "$extract_dir"
    mapfile -t matches < <(find "$extract_dir" -type f -name "$binary" -print)
    (( ${#matches[@]} == 1 )) || err "${crate} ${version} archive must contain exactly one ${binary} binary"
    install -m 0755 "${matches[0]}" "$install_bin/$binary"
  else
    warn "${crate} binary download failed; falling back to locked cargo install"
    cargo install --locked --root "$install_root" "$crate" --version "$version"
  fi
}

install_tool \
  cargo-deny \
  0.20.2 \
  cargo-deny-0.20.2-x86_64-unknown-linux-musl.tar.gz \
  9f12ed4c49936e09b48bf862b595cde2fe64fcbd9d74dfacac6131ca824c8d5f \
  cargo-deny \
  https://github.com/EmbarkStudios/cargo-deny/releases/download/0.20.2/cargo-deny-0.20.2-x86_64-unknown-linux-musl.tar.gz

install_tool \
  cargo-shear \
  1.13.3 \
  cargo-shear-x86_64-unknown-linux-musl.tar.gz \
  21ba04662e0eaa6059ca7e1adf48f3bdf1c6656b613b926f3bda0dc6f5b38f82 \
  cargo-shear \
  https://github.com/Boshen/cargo-shear/releases/download/v1.13.3/cargo-shear-x86_64-unknown-linux-musl.tar.gz

install_tool \
  cargo-nextest \
  0.9.146 \
  cargo-nextest-0.9.146-x86_64-unknown-linux-musl.tar.gz \
  b64617e8640624e8f9ba99819e37d7971154e97836d7ae4774fed4715501a6aa \
  cargo-nextest \
  https://github.com/nextest-rs/nextest/releases/download/cargo-nextest-0.9.146/cargo-nextest-0.9.146-x86_64-unknown-linux-musl.tar.gz

install_tool \
  typos-cli \
  1.48.0 \
  typos-v1.48.0-x86_64-unknown-linux-musl.tar.gz \
  72a930c9a94fc3914aa56835c5b859c892a797d40c1c42638b98d93f16ff519c \
  typos \
  https://github.com/crate-ci/typos/releases/download/v1.48.0/typos-v1.48.0-x86_64-unknown-linux-musl.tar.gz
