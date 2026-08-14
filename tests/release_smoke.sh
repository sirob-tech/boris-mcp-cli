#!/usr/bin/env sh
# Post-publish smoke test: prove a release is actually installable.
#
# v0.4.0 shipped as a release object with zero assets — release-please creates
# the release and tag, GoReleaser uploads the assets afterwards, so a GoReleaser
# failure leaves an empty release that /releases/latest still resolves to. Every
# `curl | sh` install 404s from that moment on, and nothing in CI noticed.
#
# This checks the release the way a user meets it: over the public download
# URLs, through install.sh, ending at an executable that reports the expected
# version. It deliberately does not use `gh` or an API token for the download
# path — an authenticated check would pass against a draft release that the
# public cannot fetch at all.
#
# Usage: sh tests/release_smoke.sh v1.2.3

set -eu

REPO="sirob-tech/boris-mcp-cli"
CODESIGN_REQUIREMENT="=anchor apple generic and certificate leaf[subject.OU] = T962D4K3Y7"

# checksums.txt plus one archive per shipped platform. Hard-coded rather than
# derived from .goreleaser.yaml: the point is to catch a release that quietly
# stopped producing an asset, and a list derived from the same config that
# produced the gap would move right along with it.
EXPECTED_ASSETS="bmcp-darwin-amd64.tar.gz
bmcp-darwin-arm64.tar.gz
bmcp-linux-amd64.tar.gz
bmcp-linux-arm64.tar.gz
checksums.txt"

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)

TAG="${1:-${BMCP_SMOKE_VERSION:-}}"
if [ -z "$TAG" ]; then
  echo "usage: sh tests/release_smoke.sh <tag>   (e.g. v0.4.0)" >&2
  exit 2
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT HUP INT TERM

fail() {
  echo "FAIL: $1" >&2
  exit 1
}

pass() {
  echo "ok   $1"
}

echo "== smoke testing $REPO $TAG =="

# 1. Every expected asset is publicly downloadable.
#
# A fetch of the download URL rather than a listing from the API: this is the
# exact path install.sh takes, and it fails the same way for an asset that
# exists in the API but cannot be fetched.
#
# Retried because this runs seconds after the upload finished, and an asset can
# 404 briefly while it propagates. Retrying a real 404 only costs the wait.
for asset in $EXPECTED_ASSETS; do
  url="https://github.com/${REPO}/releases/download/${TAG}/${asset}"
  code=000
  attempt=1
  while [ "$attempt" -le 5 ]; do
    code=$(curl -sSL -o /dev/null -w '%{http_code}' "$url" || echo "000")
    [ "$code" = "200" ] && break
    attempt=$((attempt + 1))
    sleep 5
  done
  [ "$code" = "200" ] || fail "asset $asset is not downloadable (HTTP $code) — $url"
  pass "asset $asset is downloadable"
done

# 2. install.sh pinned to this tag produces a working binary.
#
# The installer under test is the one in this checkout, which at release time is
# the tagged tree. It verifies the checksum and archive members itself, so a
# clean exit here also means the published checksums.txt matches the published
# archive.
BIN_DIR="$TMP/bin"
mkdir -p "$BIN_DIR"
if ! BMCP_VERSION="$TAG" BMCP_INSTALL_DIR="$BIN_DIR" sh "$ROOT/install.sh" >"$TMP/install.log" 2>&1; then
  cat "$TMP/install.log" >&2
  fail "install.sh could not install $TAG"
fi
pass "install.sh installed $TAG"

BMCP="$BIN_DIR/bmcp"
[ -x "$BMCP" ] || fail "installer left no executable at $BMCP"

# 3. The binary runs and reports the version that was asked for.
#
# GoReleaser stamps the tag without its leading v, so v1.2.3 prints "bmcp 1.2.3".
# A mismatch means the release shipped an artifact built from the wrong ref —
# which the download checks above cannot see.
if ! out=$("$BMCP" version 2>&1); then
  echo "$out" >&2
  fail "installed binary could not run: $BMCP version"
fi
reported=$(printf '%s\n' "$out" | sed -n '1s/^bmcp //p')
expected=${TAG#v}
[ "$reported" = "$expected" ] || fail "binary reports version '$reported', expected '$expected'"
pass "binary reports version $reported"

# 4. On macOS the artifact carries the Developer ID signature.
#
# `bmcp update` refuses to swap in a darwin binary that fails this exact
# requirement, so an unsigned release is one that no installed binary can update
# into — the failure would only surface on the release after the broken one.
if [ "$(uname -s)" = "Darwin" ]; then
  if ! codesign --verify --strict "$BMCP" 2>"$TMP/codesign.log"; then
    cat "$TMP/codesign.log" >&2
    fail "released darwin binary is not validly signed"
  fi
  if ! codesign --verify -R "$CODESIGN_REQUIREMENT" "$BMCP" 2>"$TMP/codesign-req.log"; then
    cat "$TMP/codesign-req.log" >&2
    fail "released darwin binary does not satisfy the bmcp update signing requirement"
  fi
  pass "darwin binary satisfies the Developer ID requirement"
fi

# 5. /releases/latest resolves here.
#
# This is the check that would have caught v0.4.0 for what it was. A release
# marked prerelease or draft is excluded from /releases/latest, so a tag that
# publishes fine but never becomes latest still leaves plain `curl | sh` on the
# older version. Advisory rather than fatal: a deliberate prerelease is a real
# thing to publish, and only the caller knows which it meant.
latest=$(curl -sSI "https://github.com/${REPO}/releases/latest" \
  | grep -i '^location:' \
  | sed -E 's|.*/tag/([^[:space:]]+).*|\1|' \
  | tr -d '\r')
if [ "$latest" = "$TAG" ]; then
  pass "/releases/latest resolves to $TAG"
else
  echo "warn /releases/latest resolves to '${latest:-<unresolved>}', not $TAG" >&2
  echo "     a bare 'curl | sh' install will not get $TAG" >&2
fi

echo "== $TAG is installable =="
