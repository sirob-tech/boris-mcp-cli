#!/usr/bin/env sh
# Real end-to-end exercise of the self-update path: build a deliberately old
# binary that still looks like a shipped release, then make it fetch, verify and
# install the current release from GitHub for real.
#
# Unit tests cover this path against a fake GitHub. They cannot cover the parts
# that only exist in reality: the actual release layout, the actual checksums
# file, and — on macOS — the actual Developer ID signature on the shipped
# artifact. This script is the only thing that does.
#
# It therefore depends on a release that has artifacts, and skips when the
# latest one does not have them yet — see the asset check below.

set -eu

REPO="sirob-tech/boris-mcp-cli"
CODESIGN_REQUIREMENT="=anchor apple generic and certificate leaf[subject.OU] = T962D4K3Y7"

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT HUP INT TERM

BIN_DIR="$TMP/bin"
BMCP="$BIN_DIR/bmcp"
mkdir -p "$BIN_DIR"

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

info() {
  printf '[e2e] %s\n' "$1"
}

# A skip is a pass with a reason, and a pass nobody can tell apart from a real
# one is how a check stops meaning anything. The annotation puts the reason on
# the run summary rather than 200 lines into a green job's log.
skip() {
  printf '[e2e] SKIP: %s\n' "$1"
  [ -z "${GITHUB_ACTIONS:-}" ] || printf '::notice title=update-e2e skipped::%s\n' "$1"
  exit 0
}

digest() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

LATEST=$(curl -sI "https://github.com/${REPO}/releases/latest" \
  | grep -i '^location:' \
  | sed -E 's|.*/tag/([^[:space:]]+).*|\1|' \
  | tr -d '\r')
[ -n "$LATEST" ] || fail "could not resolve the latest release tag"
LATEST_PLAIN=${LATEST#v}
info "latest release: $LATEST"

# release-please publishes the release object minutes before GoReleaser puts
# anything in it, and both workflows start from the same push to main — so on
# every release commit this script resolves LATEST to a release that is real,
# is what /releases/latest returns, and is empty. Downloading from it 404s, and
# that 404 says nothing about the code under test.
#
# Skip rather than fail: "the published release is installable" is already
# owned by `smoke` in release.yml, which runs after GoReleaser and retries. A
# check that is red on every release commit trains everyone to ignore red CI on
# exactly the commits where a broken release would otherwise be silent.
#
# Only a 404 is that not-yet state. Any other non-200 is an anomaly worth
# failing on, or the skip becomes a way for real breakage to pass quietly.
ASSET="bmcp-$(go env GOOS)-$(go env GOARCH).tar.gz"
for want in "$ASSET" checksums.txt; do
  url="https://github.com/${REPO}/releases/download/${LATEST}/${want}"
  # curl writes %{http_code} even when it exits non-zero — 000 if it never got a
  # response — so take what it printed and only invent a value if it printed
  # nothing at all.
  code=$(curl -sIL -o /dev/null -w '%{http_code}' "$url") || true
  [ -n "$code" ] || code=000
  case "$code" in
    200) ;;
    404) skip "release $LATEST has no $want yet (release.yml is probably still building it) — nothing to update to" ;;
    *) fail "HEAD $url returned HTTP $code" ;;
  esac
done

info "building an old bmcp that still looks like a release build"
(
  cd "$ROOT"
  go build \
    -ldflags "-X main.version=0.0.1 -X main.buildCommit=citest -X main.buildDate=citest" \
    -o "$BMCP" ./cmd/bmcp
)
cat >"$BIN_DIR/.bmcp.install.json" <<EOF
{"method":"install.sh","repo":"${REPO}","version":"v0.0.1"}
EOF

before=$(digest "$BMCP")

info "update --check should report the update without applying it"
check_out=$("$BMCP" update --check 2>&1) || fail "update --check exited non-zero: $check_out"
case "$check_out" in
  *"$LATEST_PLAIN"*) ;;
  *) fail "update --check did not mention $LATEST_PLAIN: $check_out" ;;
esac
[ "$(digest "$BMCP")" = "$before" ] || fail "update --check must not modify the binary"

info "applying the update"
update_out=$("$BMCP" update 2>&1) || fail "update exited non-zero: $update_out"
printf '%s\n' "$update_out"

[ "$(digest "$BMCP")" != "$before" ] || fail "the binary was not replaced"
[ -x "$BMCP" ] || fail "the replaced binary is not executable"

installed=$("$BMCP" version 2>&1 | sed -n '1p')
case "$installed" in
  "bmcp $LATEST_PLAIN") ;;
  *) fail "expected 'bmcp $LATEST_PLAIN' after the update, got '$installed'" ;;
esac

# The trail that makes a post-update "bmcp broke" report reproducible. Asserted
# against the receipt rather than `bmcp version`, because the binary now running
# is the released one, which may predate the feature that prints the trail.
grep -q '"to": *"'"${LATEST_PLAIN}"'"' "$BIN_DIR/.bmcp.install.json" \
  || fail "the update was not recorded in $BIN_DIR/.bmcp.install.json"
grep -q '"method": *"install.sh"' "$BIN_DIR/.bmcp.install.json" \
  || fail "the update did not preserve the install method in the receipt"

[ -f "$BIN_DIR/.bmcp.old" ] || fail "the replaced binary was not kept for rollback"
[ ! -f "$BIN_DIR/.bmcp.update.lock" ] || fail "the update lock was not released"

# The assertion that makes flipping codesignFailClosed safe later: it fails CI
# on a signing regression while the client itself is still warn-only.
if [ "$(uname -s)" = "Darwin" ]; then
  info "verifying the Developer ID signature on the shipped artifact"
  /usr/bin/codesign --verify --strict -R "$CODESIGN_REQUIREMENT" "$BMCP" \
    || fail "the released darwin binary failed Developer ID verification"

  # A wrong Team ID must be rejected, or the check above proves nothing.
  if /usr/bin/codesign --verify --strict \
    -R "=anchor apple generic and certificate leaf[subject.OU] = XXXXXXXXXX" "$BMCP" 2>/dev/null; then
    fail "codesign accepted a wrong Team ID — the requirement string is not discriminating"
  fi
fi

# Rollback runs against two local builds rather than the binary just updated
# above: that one is now the released version, which need not carry the update
# command at all. Keeping this phase self-contained also keeps it meaningful on
# every release, not just the ones that happen to postdate this feature.
info "rolling back"
RB_DIR="$TMP/rollback"
mkdir -p "$RB_DIR"
(
  cd "$ROOT"
  go build -ldflags "-X main.version=0.0.1 -X main.buildCommit=citest" -o "$RB_DIR/.bmcp.old" ./cmd/bmcp
  go build -ldflags "-X main.version=0.0.2 -X main.buildCommit=citest" -o "$RB_DIR/bmcp" ./cmd/bmcp
)
cat >"$RB_DIR/.bmcp.install.json" <<EOF
{"method":"install.sh","repo":"${REPO}","version":"v0.0.2"}
EOF

current=$("$RB_DIR/bmcp" version 2>&1 | sed -n '1p')
[ "$current" = "bmcp 0.0.2" ] || fail "rollback fixture is wrong, got '$current'"

rollback_out=$("$RB_DIR/bmcp" update --rollback 2>&1) || fail "rollback exited non-zero: $rollback_out"
rolled_back=$("$RB_DIR/bmcp" version 2>&1 | sed -n '1p')
[ "$rolled_back" = "bmcp 0.0.1" ] || fail "expected 'bmcp 0.0.1' after rollback, got '$rolled_back'"

# A second rollback has nothing to restore and must say so rather than break the
# install.
if "$RB_DIR/bmcp" update --rollback >/dev/null 2>&1; then
  fail "a second rollback should fail: there is no further backup"
fi
still_there=$("$RB_DIR/bmcp" version 2>&1 | sed -n '1p')
[ "$still_there" = "bmcp 0.0.1" ] || fail "a failed rollback must leave the binary intact, got '$still_there'"

printf 'update end-to-end passed (0.0.1 -> %s, rollback 0.0.2 -> 0.0.1)\n' "$LATEST_PLAIN"
