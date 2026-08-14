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

assert_fails() {
  desc=$1
  shift
  if output=$("$@" 2>&1); then
    fail "$desc: expected a non-zero exit, got success with: $output"
  fi
  LAST_OUTPUT=$output
}

sha256_hex() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

test_verify_checksum_accepts_a_matching_digest() (
  BMCP_INSTALLER_TEST_MODE=1
  export BMCP_INSTALLER_TEST_MODE
  . "$ROOT/install.sh"

  work="$TMP/sums-ok"
  mkdir -p "$work"
  printf 'payload\n' >"$work/bmcp.tar.gz"
  printf '%s  bmcp-linux-amd64.tar.gz\n' "$(sha256_hex "$work/bmcp.tar.gz")" >"$work/checksums.txt"

  verify_checksum "$work/bmcp.tar.gz" "$work/checksums.txt" "bmcp-linux-amd64.tar.gz"
)

test_verify_checksum_rejects_a_mismatch() (
  BMCP_INSTALLER_TEST_MODE=1
  export BMCP_INSTALLER_TEST_MODE
  . "$ROOT/install.sh"

  work="$TMP/sums-bad"
  mkdir -p "$work"
  printf 'payload\n' >"$work/bmcp.tar.gz"
  printf '%s  bmcp-linux-amd64.tar.gz\n' "0000000000000000000000000000000000000000000000000000000000000000" >"$work/checksums.txt"

  assert_fails "mismatched checksum" \
    verify_checksum "$work/bmcp.tar.gz" "$work/checksums.txt" "bmcp-linux-amd64.tar.gz"
  assert_contains "$LAST_OUTPUT" "Checksum mismatch"
)

test_verify_checksum_rejects_a_missing_entry() (
  BMCP_INSTALLER_TEST_MODE=1
  export BMCP_INSTALLER_TEST_MODE
  . "$ROOT/install.sh"

  work="$TMP/sums-absent"
  mkdir -p "$work"
  printf 'payload\n' >"$work/bmcp.tar.gz"
  printf '%s  bmcp-darwin-arm64.tar.gz\n' "$(sha256_hex "$work/bmcp.tar.gz")" >"$work/checksums.txt"

  assert_fails "checksums.txt without our asset" \
    verify_checksum "$work/bmcp.tar.gz" "$work/checksums.txt" "bmcp-linux-amd64.tar.gz"
  assert_contains "$LAST_OUTPUT" "no entry for bmcp-linux-amd64.tar.gz"
)

test_verify_checksum_rejects_an_empty_checksums_file() (
  BMCP_INSTALLER_TEST_MODE=1
  export BMCP_INSTALLER_TEST_MODE
  . "$ROOT/install.sh"

  work="$TMP/sums-empty"
  mkdir -p "$work"
  printf 'payload\n' >"$work/bmcp.tar.gz"
  : >"$work/checksums.txt"

  assert_fails "empty checksums.txt" \
    verify_checksum "$work/bmcp.tar.gz" "$work/checksums.txt" "bmcp-linux-amd64.tar.gz"
  assert_contains "$LAST_OUTPUT" "missing or empty"
)

test_verify_archive_members_accepts_regular_files() (
  BMCP_INSTALLER_TEST_MODE=1
  export BMCP_INSTALLER_TEST_MODE
  . "$ROOT/install.sh"

  work="$TMP/tar-ok"
  mkdir -p "$work/src"
  printf 'binary\n' >"$work/src/bmcp"
  printf 'license\n' >"$work/src/LICENSE"
  (cd "$work/src" && tar -czf "$work/ok.tar.gz" bmcp LICENSE)

  verify_archive_members "$work/ok.tar.gz"
)

test_verify_archive_members_rejects_a_symlink() (
  BMCP_INSTALLER_TEST_MODE=1
  export BMCP_INSTALLER_TEST_MODE
  . "$ROOT/install.sh"

  work="$TMP/tar-symlink"
  mkdir -p "$work/src"
  ln -s /etc/passwd "$work/src/bmcp"
  (cd "$work/src" && tar -czf "$work/evil.tar.gz" bmcp)

  assert_fails "symlink member named bmcp" verify_archive_members "$work/evil.tar.gz"
  assert_contains "$LAST_OUTPUT" "non-regular member"
)

# The shape a real archive has. A single-member archive passes even with a
# broken guard, so this is the case that actually tests it: `grep -q -v` reads
# as "no line matches" on BSD grep and ugrep, so one regular member was enough
# to suppress the whole check.
test_verify_archive_members_rejects_a_symlink_beside_regular_files() (
  BMCP_INSTALLER_TEST_MODE=1
  export BMCP_INSTALLER_TEST_MODE
  . "$ROOT/install.sh"

  work="$TMP/tar-symlink-mixed"
  mkdir -p "$work/src"
  printf 'license\n' >"$work/src/LICENSE"
  printf 'readme\n' >"$work/src/README.md"
  ln -s /etc/passwd "$work/src/bmcp"
  (cd "$work/src" && tar -czf "$work/evil.tar.gz" LICENSE README.md bmcp)

  assert_fails "symlink among regular members" verify_archive_members "$work/evil.tar.gz"
  assert_contains "$LAST_OUTPUT" "non-regular member"
)

test_verify_archive_members_rejects_a_hardlink() (
  BMCP_INSTALLER_TEST_MODE=1
  export BMCP_INSTALLER_TEST_MODE
  . "$ROOT/install.sh"

  work="$TMP/tar-hardlink"
  mkdir -p "$work/src"
  printf 'license\n' >"$work/src/LICENSE"
  ln "$work/src/LICENSE" "$work/src/bmcp"
  (cd "$work/src" && tar -czf "$work/evil.tar.gz" LICENSE bmcp)

  assert_fails "hardlink member" verify_archive_members "$work/evil.tar.gz"
  assert_contains "$LAST_OUTPUT" "non-regular member"
)

test_validate_version_rejects_path_traversal() (
  BMCP_INSTALLER_TEST_MODE=1
  export BMCP_INSTALLER_TEST_MODE
  . "$ROOT/install.sh"

  # curl collapses ../ client-side, so this resolves to another repo entirely
  # and drags checksums.txt along with it.
  assert_fails "traversal in BMCP_VERSION" validate_version "../../../../golang/go/archive/refs/tags"
  assert_fails "slash in BMCP_VERSION" validate_version "v1.2.3/../../evil"
  assert_fails "dotdot in BMCP_VERSION" validate_version "v1..2"
  assert_fails "empty version" validate_version ""
  assert_fails "unprefixed version" validate_version "1.2.3"

  validate_version "v1.2.3"
  validate_version "v0.4.0-rc.1"
)

test_verify_archive_members_rejects_traversal() (
  BMCP_INSTALLER_TEST_MODE=1
  export BMCP_INSTALLER_TEST_MODE
  . "$ROOT/install.sh"

  work="$TMP/tar-traversal"
  mkdir -p "$work/src/sub"
  printf 'binary\n' >"$work/src/sub/bmcp"
  # -P keeps the ../ prefix; without it GNU tar strips the traversal and the
  # archive under test would no longer contain the thing being tested.
  (cd "$work/src/sub" && tar -Pczf "$work/evil.tar.gz" ../sub/bmcp)
  assert_contains "$(tar -tzf "$work/evil.tar.gz")" "../sub/bmcp"

  assert_fails "traversal member" verify_archive_members "$work/evil.tar.gz"
  assert_contains "$LAST_OUTPUT" "unsafe paths"
)

test_verify_warns_when_another_binary_wins
test_verify_accepts_the_installed_binary_on_path
test_verify_checksum_accepts_a_matching_digest
test_verify_checksum_rejects_a_mismatch
test_verify_checksum_rejects_a_missing_entry
test_verify_checksum_rejects_an_empty_checksums_file
test_verify_archive_members_accepts_regular_files
test_verify_archive_members_rejects_a_symlink
test_verify_archive_members_rejects_a_symlink_beside_regular_files
test_verify_archive_members_rejects_a_hardlink
test_verify_archive_members_rejects_traversal
test_validate_version_rejects_path_traversal
printf 'install tests passed\n'
