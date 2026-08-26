#!/usr/bin/env bash

set -Eeuo pipefail

: "${GH_TOKEN:?GH_TOKEN is required}"
: "${VERSION:?VERSION is required}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
: "${GITHUB_SHA:?GITHUB_SHA is required}"

release_version="${VERSION#v}"
expected_assets=(
  SHA256SUMS
  "headscale-ops_${release_version}_linux_amd64"
  "headscale-ops_${release_version}_linux_arm64"
)

published_release_id=""
publication_verified=false

gh_api() {
  gh api -H "X-GitHub-Api-Version: 2026-03-10" "$@"
}

resolve_remote_tag() {
  local object_json object_type object_sha
  object_json="$(gh_api "repos/${GITHUB_REPOSITORY}/git/ref/tags/${VERSION}")"
  object_type="$(jq -r '.object.type' <<<"$object_json")"
  object_sha="$(jq -r '.object.sha' <<<"$object_json")"
  while [[ "$object_type" == "tag" ]]; do
    object_json="$(gh_api "repos/${GITHUB_REPOSITORY}/git/tags/${object_sha}")"
    object_type="$(jq -r '.object.type' <<<"$object_json")"
    object_sha="$(jq -r '.object.sha' <<<"$object_json")"
  done
  if [[ "$object_type" != "commit" ]]; then
    echo "Release tag resolves to unsupported object type ${object_type}." >&2
    return 1
  fi
  printf '%s\n' "$object_sha"
}

verify_remote_assets() {
  local release_id="$1"
  local assets_json expected_names actual_names asset local_digest remote_digest asset_count

  assets_json="$(gh_api "repos/${GITHUB_REPOSITORY}/releases/${release_id}/assets?per_page=100")"
  expected_names="$(printf '%s\n' "${expected_assets[@]}" | sort)"
  actual_names="$(jq -r '.[].name' <<<"$assets_json" | sort)"
  if [[ "$actual_names" != "$expected_names" ]]; then
    echo "Release assets differ from the verified set." >&2
    printf 'Expected:\n%s\nActual:\n%s\n' "$expected_names" "$actual_names" >&2
    return 1
  fi

  for asset in "${expected_assets[@]}"; do
    local_digest="sha256:$(sha256sum "dist/${asset}" | cut -d ' ' -f 1)"
    asset_count="$(jq --arg name "$asset" '[.[] | select(.name == $name)] | length' <<<"$assets_json")"
    if [[ "$asset_count" -ne 1 ]]; then
      echo "Release must contain exactly one asset named ${asset}." >&2
      return 1
    fi
    remote_digest="$(jq -r --arg name "$asset" '.[] | select(.name == $name) | (.digest // "")' <<<"$assets_json")"
    if [[ "$remote_digest" != "$local_digest" ]]; then
      echo "GitHub-reported digest for ${asset} does not match the verified file." >&2
      return 1
    fi
  done
}

cleanup_unverified_publication() {
  local status=$?
  local state_json state_status draft immutable
  trap - EXIT HUP INT TERM

  if [[ -n "$published_release_id" && "$publication_verified" != "true" ]]; then
    set +e
    state_json="$(gh_api "repos/${GITHUB_REPOSITORY}/releases/${published_release_id}" 2>/tmp/release-cleanup.err)"
    state_status=$?
    if [[ "$state_status" -ne 0 ]]; then
      echo "Could not determine whether release ${VERSION} became public; inspect it manually before retrying." >&2
      if [[ -s /tmp/release-cleanup.err ]]; then
        cat /tmp/release-cleanup.err >&2
      fi
    else
      draft="$(jq -r '.draft' <<<"$state_json")"
      immutable="$(jq -r '.immutable // false' <<<"$state_json")"
      if [[ "$draft" == "false" && "$immutable" != "true" ]]; then
        if gh_api --method DELETE "repos/${GITHUB_REPOSITORY}/releases/${published_release_id}" >/dev/null; then
          echo "Removed unverified mutable release ${VERSION}; the unchanged tag can be retried." >&2
        else
          echo "Could not remove mutable release ${VERSION}; inspect it manually before retrying." >&2
        fi
      elif [[ "$draft" == "false" && "$immutable" == "true" ]]; then
        echo "Release ${VERSION} became immutable but final verification did not complete; rerun this workflow to resume verification." >&2
      fi
    fi
  fi

  exit "$status"
}

trap cleanup_unverified_publication EXIT
trap 'exit 130' HUP INT TERM

if [[ "$(resolve_remote_tag)" != "$GITHUB_SHA" ]]; then
  echo "Remote release tag does not resolve to the verified workflow revision." >&2
  exit 1
fi

prerelease=false
if [[ "$VERSION" == *-* ]]; then
  prerelease=true
fi

releases_json="$(gh_api --paginate --slurp "repos/${GITHUB_REPOSITORY}/releases?per_page=100")"
matching_releases="$(jq --arg version "$VERSION" '[.[][] | select(.tag_name == $version)]' <<<"$releases_json")"
release_count="$(jq 'length' <<<"$matching_releases")"
if [[ "$release_count" -gt 1 ]]; then
  echo "More than one release record exists for ${VERSION}; failing closed." >&2
  exit 1
fi

release_id=""
release_is_immutable=false
if [[ "$release_count" -eq 1 ]]; then
  release_json="$(jq '.[0]' <<<"$matching_releases")"
  if [[ "$(jq -r '.prerelease' <<<"$release_json")" != "$prerelease" ]]; then
    echo "Existing release prerelease state does not match the version tag." >&2
    exit 1
  fi
  release_id="$(jq -r '.id' <<<"$release_json")"
  if [[ "$(jq -r '.draft' <<<"$release_json")" != "true" ]]; then
    verify_remote_assets "$release_id"
    release_json="$(gh_api "repos/${GITHUB_REPOSITORY}/releases/${release_id}")"
    if [[ "$(jq -r '.immutable // false' <<<"$release_json")" == "true" ]]; then
      release_is_immutable=true
    else
      gh_api --method DELETE "repos/${GITHUB_REPOSITORY}/releases/${release_id}" >/dev/null
      echo "Removed matching mutable release ${VERSION} so it can be recreated under the enabled immutability policy." >&2
      release_id=""
    fi
  fi
fi

if [[ "$release_is_immutable" != "true" ]]; then
  if [[ -z "$release_id" ]]; then
    release_json="$(gh_api --method POST "repos/${GITHUB_REPOSITORY}/releases" \
      -f tag_name="$VERSION" \
      -f target_commitish="$GITHUB_SHA" \
      -f name="headscale-ops ${VERSION}" \
      -F draft=true \
      -F prerelease="$prerelease" \
      -F generate_release_notes=true)"
    release_id="$(jq -r '.id' <<<"$release_json")"
  fi

  for asset in "${expected_assets[@]}"; do
    local_digest="sha256:$(sha256sum "dist/${asset}" | cut -d ' ' -f 1)"
    assets_json="$(gh_api "repos/${GITHUB_REPOSITORY}/releases/${release_id}/assets?per_page=100")"
    matching_assets="$(jq --arg name "$asset" '[.[] | select(.name == $name)]' <<<"$assets_json")"
    asset_count="$(jq 'length' <<<"$matching_assets")"
    if [[ "$asset_count" -gt 1 ]]; then
      echo "Draft contains duplicate asset name ${asset}; failing closed." >&2
      exit 1
    fi
    if [[ "$asset_count" -eq 1 ]]; then
      remote_digest="$(jq -r '.[0].digest // ""' <<<"$matching_assets")"
      if [[ "$remote_digest" != "$local_digest" ]]; then
        echo "Existing draft asset ${asset} does not match the verified SHA-256 digest." >&2
        exit 1
      fi
      continue
    fi

    gh_api --method POST \
      -H "Content-Type: application/octet-stream" \
      --input "dist/${asset}" \
      -f name="$asset" \
      "https://uploads.github.com/repos/${GITHUB_REPOSITORY}/releases/${release_id}/assets" \
      >/tmp/uploaded-asset.json
    if [[ "$(jq -r '.digest // ""' /tmp/uploaded-asset.json)" != "$local_digest" ]]; then
      echo "GitHub-reported digest for uploaded asset ${asset} does not match the verified file." >&2
      exit 1
    fi
  done

  verify_remote_assets "$release_id"

  published_release_id="$release_id"
  gh_api --method PATCH "repos/${GITHUB_REPOSITORY}/releases/${release_id}" \
    -F draft=false \
    -F prerelease="$prerelease" \
    -f make_latest=false \
    >/tmp/published-release.json

  immutable=false
  for ((attempt = 0; attempt < 12; attempt++)); do
    if release_json="$(gh_api "repos/${GITHUB_REPOSITORY}/releases/${release_id}")"; then
      immutable="$(jq -r '.immutable // false' <<<"$release_json")"
      if [[ "$immutable" == "true" ]]; then
        break
      fi
    fi
    sleep 5
  done
  if [[ "$immutable" != "true" ]]; then
    echo "Release ${VERSION} did not become immutable within 60 seconds." >&2
    exit 1
  fi
fi

if [[ "$(resolve_remote_tag)" != "$GITHUB_SHA" ]]; then
  echo "Immutable release tag does not resolve to the verified workflow revision." >&2
  exit 1
fi
verify_remote_assets "$release_id"

authenticated=false
for ((attempt = 0; attempt < 12; attempt++)); do
  if gh release verify "$VERSION" --repo "$GITHUB_REPOSITORY"; then
    all_assets_verified=true
    for asset in "${expected_assets[@]}"; do
      if ! gh release verify-asset "$VERSION" "dist/${asset}" --repo "$GITHUB_REPOSITORY"; then
        all_assets_verified=false
        break
      fi
    done
    if [[ "$all_assets_verified" == "true" ]]; then
      authenticated=true
      break
    fi
  fi
  sleep 5
done
if [[ "$authenticated" != "true" ]]; then
  echo "Immutable release attestation or asset verification did not complete within 60 seconds." >&2
  exit 1
fi

publication_verified=true
trap - EXIT HUP INT TERM
