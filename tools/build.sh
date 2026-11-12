#!/usr/bin/env bash
set -euo pipefail
project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
profile_id="${PROFILE:-muyu-os4.0.3.0}"
cd "$project_dir"
python3 tools/maintain.py --profile "$profile_id" doctor
read_profile() {
  python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$project_dir/profiles/$profile_id.json" "$1"
}
kernel_dir="$project_dir/.local/kernel"
repo_tool="$project_dir/.local/repo-tool/repo"
mkdir -p "$project_dir/.local" "$project_dir/build-record"
case "${1:-build}" in
  init)
    repo_commit="$(read_profile repo_commit)"
    mkdir -p "$(dirname "$repo_tool")" "$kernel_dir"
    git -C "$(dirname "$repo_tool")" init
    git -C "$(dirname "$repo_tool")" fetch --depth=1 https://gerrit.googlesource.com/git-repo "$repo_commit"
    git -C "$(dirname "$repo_tool")" checkout --detach FETCH_HEAD
    test "$(git -C "$(dirname "$repo_tool")" rev-parse HEAD)" = "$repo_commit"
    cd "$kernel_dir"
    "$repo_tool" init -u https://android.googlesource.com/kernel/manifest -b "$(read_profile manifest_commit)" --depth=1 --repo-url=https://gerrit.googlesource.com/git-repo --repo-rev="$repo_commit"
    mkdir -p .repo/local_manifests
    printf '%s\n' "<manifest><extend-project name=\"kernel/common\" revision=\"$(read_profile common_commit)\" /></manifest>" > .repo/local_manifests/pin.xml
    ;;
  sync)
    cd "$kernel_dir"
    "$repo_tool" sync -c -j4 --no-clone-bundle --no-tags
    "$repo_tool" manifest -r -o "$project_dir/build-record/manifest.xml"
    ;;
  build)
    # prepare_sources writes next to kernel; copy its records to the artifact root.
    python3 tools/maintain.py --profile "$profile_id" prepare --kernel "$kernel_dir"
    cp -a "$project_dir/.local/build-record/." "$project_dir/build-record/"
    cd "$kernel_dir"
    tools/bazel run //common:kernel_aarch64_dist --config=fast --config=stamp --lto=thin \
      --defconfig_fragment=//common:arch/arm64/configs/droidspaces.fragment \
      -- --dist_dir="$project_dir/dist" 2>&1 | tee "$project_dir/build-record/build.log"
    common/scripts/extract-ikconfig "$project_dir/dist/Image" > "$project_dir/dist/.config"
    cd "$project_dir"
    python3 tools/maintain.py --profile "$profile_id" verify-build --artifact "$project_dir/dist"
    ;;
  *) echo 'Usage: tools/build.sh init|sync|build' >&2; exit 2 ;;
esac
