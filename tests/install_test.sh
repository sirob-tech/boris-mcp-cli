#!/usr/bin/env sh

set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT HUP INT TERM

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

assert_contains() {
  haystack=$1
  needle=$2
  case "$haystack" in
    *"$needle"*) ;;
    *) fail "expected output to contain: $needle" ;;
  esac
}

assert_not_contains() {
  haystack=$1
  needle=$2
  case "$haystack" in
    *"$needle"*) fail "expected output not to contain: $needle" ;;
    *) ;;
  esac
}

make_bmcp() {
  path=$1
  version=$2
  mkdir -p "$(dirname "$path")"
  printf '#!/usr/bin/env sh\nprintf "bmcp %s\\n"\n' "$version" >"$path"
  chmod +x "$path"
}

test_verify_warns_when_another_binary_wins() (
  install_dir="$TMP/installed"
  shadow_dir="$TMP/shadow"
  make_bmcp "$install_dir/bmcp" "2.0.0"
  make_bmcp "$shadow_dir/bmcp" "1.0.0"

  BMCP_INSTALLER_TEST_MODE=1
  BMCP_INSTALL_DIR=$install_dir
  export BMCP_INSTALLER_TEST_MODE BMCP_INSTALL_DIR
  PATH="$shadow_dir:$PATH"
  export PATH
  . "$ROOT/install.sh"

  output=$(verify)
  assert_contains "$output" "Verification: bmcp 2.0.0 ($install_dir/bmcp)"
  assert_contains "$output" "Another bmcp takes precedence on PATH: $shadow_dir/bmcp"
  assert_contains "$output" "The newly installed binary is: $install_dir/bmcp"
)

test_verify_accepts_the_installed_binary_on_path() (
  install_dir="$TMP/active"
  make_bmcp "$install_dir/bmcp" "2.0.0"

  BMCP_INSTALLER_TEST_MODE=1
  BMCP_INSTALL_DIR=$install_dir
  export BMCP_INSTALLER_TEST_MODE BMCP_INSTALL_DIR
  PATH="$install_dir:$PATH"
  export PATH
  . "$ROOT/install.sh"

  output=$(verify)
  assert_contains "$output" "Verification: bmcp 2.0.0 ($install_dir/bmcp)"
  assert_not_contains "$output" "takes precedence on PATH"
)

test_verify_warns_when_another_binary_wins
test_verify_accepts_the_installed_binary_on_path
printf 'install tests passed\n'
