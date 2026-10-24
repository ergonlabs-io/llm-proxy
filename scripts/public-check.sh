#!/usr/bin/env bash
# Check that a release is public: an anonymous `git clone` of the tag and an
# anonymous `docker pull` of its image must both succeed.
#
# Usage: scripts/public-check.sh [TAG]   (default: the highest v* tag here)
#
# "Anonymous" means no stored credential can help. The clone runs with no
# credential helper, no askpass program and no terminal prompt, and with the
# user's and system git config ignored (a global `url.insteadOf` could rewrite
# the URL to ssh). The pull runs with an empty, throwaway DOCKER_CONFIG, so no
# `docker login` and no credential store applies.
#
# The release workflow tags the image with the version without its leading
# `v` (tag v1.0.0 publishes ghcr.io/ergonlabs-io/llm-proxy:1.0.0).
#
# Exit status is 0 only if both checks pass. Both always run, and each failure
# is reported with the command's own output.
set -uo pipefail

REPO_URL="${PUBLIC_CHECK_REPO:-https://github.com/ergonlabs-io/llm-proxy.git}"
IMAGE="${PUBLIC_CHECK_IMAGE:-ghcr.io/ergonlabs-io/llm-proxy}"

tag="${1:-}"
if [ -z "$tag" ]; then
	tag="$(git tag -l 'v*' --sort=-v:refname | head -n 1)"
fi
if [ -z "$tag" ]; then
	echo "public-check: no TAG given and no v* tag found in this checkout" >&2
	exit 2
fi
image_ref="$IMAGE:${tag#v}"

work="$(mktemp -d "${TMPDIR:-/tmp}/llm-proxy-public-check.XXXXXX")"
trap 'command rm -rf "$work"' EXIT

failures=()

echo "== anonymous git clone: $REPO_URL @ $tag"
if env GIT_TERMINAL_PROMPT=0 GIT_ASKPASS= SSH_ASKPASS= \
	GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 \
	git -c credential.helper= clone --quiet --depth 1 --branch "$tag" \
	"$REPO_URL" "$work/clone" >"$work/clone.log" 2>&1; then
	echo "   ok: cloned $(git -C "$work/clone" rev-parse --short HEAD)"
else
	echo "   FAILED: anonymous clone of $REPO_URL at $tag"
	sed 's/^/   | /' "$work/clone.log"
	failures+=("git clone $REPO_URL ($tag)")
fi

echo "== anonymous docker pull: $image_ref"
if ! command -v docker >/dev/null 2>&1; then
	echo "   FAILED: docker not found on PATH"
	failures+=("docker pull $image_ref (no docker)")
else
	mkdir -p "$work/docker-config"
	echo '{}' >"$work/docker-config/config.json"
	if DOCKER_CONFIG="$work/docker-config" docker pull --quiet "$image_ref" \
		>"$work/pull.log" 2>&1; then
		echo "   ok: pulled $image_ref"
	else
		echo "   FAILED: anonymous pull of $image_ref"
		sed 's/^/   | /' "$work/pull.log"
		failures+=("docker pull $image_ref")
	fi
fi

if [ "${#failures[@]}" -gt 0 ]; then
	echo
	echo "public-check: FAILED (${#failures[@]} of 2):"
	printf '  - %s\n' "${failures[@]}"
	echo "If the repository or the GHCR package is still private, this is expected."
	exit 1
fi
echo
echo "public-check: ok: $tag is publicly clonable and pullable"
