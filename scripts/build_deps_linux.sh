#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIBS_DIR="${ROOT_DIR}/libs/linux"
BUILD_ROOT="${ROOT_DIR}/.deps-build"
JOBS="${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)}"
REQUIRED_ONLY=0

usage() {
  cat <<'EOF'
Usage:
  bash scripts/build_deps_linux.sh [--required-only] [--clean]

Options:
  --required-only  Build only libraries required by CMake (libregf, libscca,
                   libevtx, libevt, libspdlog).
  --clean          Remove previous temporary build directories before starting.
  -h, --help       Show this help.

Environment:
  JOBS=<n>         Parallel build jobs. Default: detected CPU count.
EOF
}

clean_requested=0
while (($# > 0)); do
  case "$1" in
    --required-only)
      REQUIRED_ONLY=1
      ;;
    --clean)
      clean_requested=1
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
  shift
done

if ((clean_requested)); then
  rm -rf "${BUILD_ROOT}"
fi

mkdir -p "${LIBS_DIR}" "${BUILD_ROOT}"

if ! command -v git >/dev/null 2>&1; then
  echo "git is required" >&2
  exit 1
fi

if ! command -v cmake >/dev/null 2>&1; then
  echo "cmake is required" >&2
  exit 1
fi

if ! command -v make >/dev/null 2>&1; then
  echo "make is required" >&2
  exit 1
fi

log() {
  printf '[deps] %s\n' "$*"
}

prepare_checkout() {
  local repo_url="$1"
  local checkout_dir="$2"

  if [[ -d "${checkout_dir}/.git" ]]; then
    log "Updating $(basename "${checkout_dir}")"
    git -C "${checkout_dir}" fetch --depth=1 origin
    git -C "${checkout_dir}" reset --hard origin/HEAD
  else
    log "Cloning ${repo_url}"
    git clone --depth=1 "${repo_url}" "${checkout_dir}"
  fi
}

flatten_static_layout() {
  local prefix_dir="$1"
  local lib_name="$2"
  local archive_path="${prefix_dir}/lib/${lib_name}.a"

  if [[ ! -f "${archive_path}" ]]; then
    echo "Expected archive not found: ${archive_path}" >&2
    exit 1
  fi

  cp "${archive_path}" "${prefix_dir}/${lib_name}.a"
}

build_libyal() {
  local repo_name="$1"
  local prefix_dir="${LIBS_DIR}/${repo_name}"
  local checkout_dir="${BUILD_ROOT}/${repo_name}"

  prepare_checkout "https://github.com/libyal/${repo_name}.git" "${checkout_dir}"

  rm -rf "${prefix_dir}"
  mkdir -p "${prefix_dir}"

  pushd "${checkout_dir}" >/dev/null
  if [[ -x "./synclibs.sh" ]]; then
    ./synclibs.sh
  fi
  ./autogen.sh
  CFLAGS="-fPIC" CXXFLAGS="-fPIC" ./configure \
    --prefix="${prefix_dir}" \
    --enable-static \
    --disable-shared
  make -j"${JOBS}"
  make install
  popd >/dev/null

  flatten_static_layout "${prefix_dir}" "${repo_name}"
}

build_spdlog() {
  local prefix_dir="${LIBS_DIR}/libspdlog"
  local checkout_dir="${BUILD_ROOT}/spdlog"
  local build_dir="${checkout_dir}/build"

  prepare_checkout "https://github.com/gabime/spdlog.git" "${checkout_dir}"

  rm -rf "${prefix_dir}" "${build_dir}"
  mkdir -p "${build_dir}"

  cmake -S "${checkout_dir}" -B "${build_dir}" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="${prefix_dir}" \
    -DBUILD_SHARED_LIBS=OFF \
    -DSPDLOG_BUILD_SHARED=OFF \
    -DSPDLOG_BUILD_EXAMPLE=OFF \
    -DSPDLOG_BUILD_EXAMPLE_HO=OFF \
    -DSPDLOG_BUILD_TESTS=OFF \
    -DSPDLOG_BUILD_TESTS_HO=OFF \
    -DSPDLOG_BUILD_BENCH=OFF \
    -DSPDLOG_BUILD_WARNINGS=OFF \
    -DSPDLOG_BUILD_PIC=ON \
    -DSPDLOG_FMT_EXTERNAL=OFF
  cmake --build "${build_dir}" -j"${JOBS}"
  cmake --install "${build_dir}"

  flatten_static_layout "${prefix_dir}" "libspdlog"
}

required_libs=(
  libregf
  libscca
  libevtx
  libevt
)

optional_libs=(
  libesedb
  libfusn
  libvshadow
  libhibr
  libfsntfs
)

for lib in "${required_libs[@]}"; do
  build_libyal "${lib}"
done

if ((REQUIRED_ONLY == 0)); then
  for lib in "${optional_libs[@]}"; do
    build_libyal "${lib}"
  done
fi

build_spdlog

log "Finished. Static libraries are available under ${LIBS_DIR}"
