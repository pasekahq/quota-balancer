#!/usr/bin/env bash
# Release steps shared by .github/workflows/release.yml and a maintainer's dry run (docs/release.md).
#
#   ci/release.sh version                   the workspace version from Cargo.toml
#   ci/release.sh check-tag TAG             fail unless TAG is v + the workspace version
#   ci/release.sh build TARGET              static release build of qb for TARGET, reproducible
#                                           (remapped paths), then the static and --version checks
#   ci/release.sh check-static BIN          fail unless BIN is a static ELF (no interpreter, no
#                                           shared libraries)
#   ci/release.sh package TARGET OUT        qb-<version>-TARGET.tar.gz and qb-TARGET in OUT
#   ci/release.sh notes VERSION             CHANGELOG.md's section of VERSION on stdout
#   ci/release.sh sums DIR                  DIR/SHA256SUMS over every other file in DIR
#
# Run from the repository root. Build output: ${CARGO_TARGET_DIR:-target}/TARGET/release/qb.
set -euo pipefail

die() { echo "::error::$*" >&2; exit 1; }

version() {
  # The first `version = "..."` of Cargo.toml is [workspace.package]'s.
  sed -n 's/^version = "\([^"]*\)"$/\1/p' Cargo.toml | head -n 1
}

check_tag() {
  local tag="$1" want
  want="v$(version)"
  [ "$want" != "v" ] || die "no workspace version in Cargo.toml"
  [ "$tag" = "$want" ] || die "tag $tag does not match the workspace version ($want)"
  echo "tag $tag matches the workspace version"
}

check_static() {
  local bin="$1"
  file "$bin"
  file -b "$bin" | grep -q '^ELF ' || die "$bin is not an ELF binary"
  if readelf -lW "$bin" | grep -q 'INTERP'; then
    die "$bin asks for a program interpreter: not static"
  fi
  if readelf -dW "$bin" | grep -q '(NEEDED)'; then
    die "$bin needs shared libraries: not static"
  fi
  echo "$bin is static"
}

build() {
  local target="$1" env_cc bin rev out want
  # Reproducible: no build path in the binary, the commit time as the only time.
  SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)"
  export SOURCE_DATE_EPOCH
  export CARGO_INCREMENTAL=0
  export RUSTFLAGS="-D warnings --remap-path-prefix=$PWD=/qb --remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo --remap-path-prefix=${RUSTUP_HOME:-$HOME/.rustup}=/rustup"
  # ring compiles C for the musl target; the host gcc does, as in CI's budgets job.
  env_cc="CC_${target//-/_}"
  if [ -z "${!env_cc:-}" ] && ! command -v "${target%%-*}-linux-musl-gcc" >/dev/null; then
    export "$env_cc=gcc"
  fi
  cargo build --release --locked --target "$target"
  bin="${CARGO_TARGET_DIR:-target}/$target/release/qb"
  check_static "$bin"
  # A binary for another architecture cannot run here; the release workflow builds natively.
  if [ "$(uname -m)" = "${target%%-*}" ]; then
    rev="${QB_BUILD_REVISION:-$(git rev-parse --short=12 HEAD)}"
    want="qb $(version) ($rev)"
    out="$("$bin" --version)"
    [ "$out" = "$want" ] || die "$bin --version printed '$out', expected '$want'"
    echo "$out"
  fi
  sha256sum "$bin"
}

package() {
  local target="$1" out="$2" v name stage
  v="$(version)"
  name="qb-$v-$target"
  mkdir -p "$out"
  stage="$(mktemp -d)"
  mkdir "$stage/$name"
  install -m 0755 "${CARGO_TARGET_DIR:-target}/$target/release/qb" "$stage/$name/qb"
  install -m 0644 LICENSE README.md CHANGELOG.md "$stage/$name/"
  # Same input, same bytes: sorted names, fixed owner and times, no gzip timestamp.
  SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}"
  tar --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner \
    --mode=u+rwX,go+rX,go-w \
    --format=gnu -C "$stage" -cf - "$name" | gzip -n -9 >"$out/$name.tar.gz"
  rm -rf "$stage"
  install -m 0755 "${CARGO_TARGET_DIR:-target}/$target/release/qb" "$out/qb-$target"
  ls -l "$out/$name.tar.gz" "$out/qb-$target"
}

notes() {
  local v="$1" text
  # From the version's heading to the next heading, without the link definitions at the end.
  text="$(awk -v v="$v" '
    index($0, "## [" v "]") == 1 { on = 1; next }
    on && /^## / { exit }
    on && /^\[[^]]*\]: / { next }
    on { print }
  ' CHANGELOG.md)"
  [ -n "$(printf '%s' "$text" | tr -d '[:space:]')" ] || die "CHANGELOG.md has no section for $v"
  printf '%s\n' "$text" | sed -e '/./,$!d'
}

sums() {
  local dir="$1"
  (
    cd "$dir"
    rm -f SHA256SUMS
    find . -maxdepth 1 -type f ! -name SHA256SUMS -printf '%f\n' | LC_ALL=C sort \
      | xargs -r sha256sum -- >"${TMPDIR:-/tmp}/SHA256SUMS.$$"
    mv "${TMPDIR:-/tmp}/SHA256SUMS.$$" SHA256SUMS
    [ -s SHA256SUMS ] || die "no assets in $dir"
    sha256sum -c SHA256SUMS
    cat SHA256SUMS
  )
}

cmd="${1:-}"
shift || true
case "$cmd" in
  version) version ;;
  check-tag) check_tag "$@" ;;
  check-static) check_static "$@" ;;
  build) build "$@" ;;
  package) package "$@" ;;
  notes) notes "$@" ;;
  sums) sums "$@" ;;
  *) sed -n '2,14p' "$0" >&2; exit 2 ;;
esac
