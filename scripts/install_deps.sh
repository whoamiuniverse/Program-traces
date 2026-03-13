#!/usr/bin/env bash

set -euo pipefail

# Stage 1: determine host platform, output layout and build options.
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOST_OS="$(uname -s)"
INSTALL_SYSTEM_DEPS=0
REQUIRED_ONLY=0
CLEAN_BUILD_ROOT=0

detect_jobs() {
  if command -v nproc >/dev/null 2>&1; then
    nproc
    return
  fi
  if command -v sysctl >/dev/null 2>&1; then
    sysctl -n hw.logicalcpu
    return
  fi
  getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4
}

JOBS="${JOBS:-$(detect_jobs)}"

case "${HOST_OS}" in
  Darwin)
    PLATFORM_ID="macos"
    ;;
  Linux)
    PLATFORM_ID="linux"
    ;;
  *)
    echo "Unsupported host OS: ${HOST_OS}" >&2
    exit 1
    ;;
esac

LIBS_DIR="${ROOT_DIR}/libs/${PLATFORM_ID}"
BUILD_ROOT="${ROOT_DIR}/.deps-build/${PLATFORM_ID}"

usage() {
  cat <<EOF
Usage:
  bash scripts/install_deps.sh [--install-system-deps] [--required-only] [--clean]

Stages performed by this script:
  1. Detect host OS and select libs output directory (${LIBS_DIR})
  2. Optionally install system packages needed for autotools/cmake builds
  3. Clone or update third-party dependency sources
  4. Build required static libraries (libregf, libscca, libevtx, libevt, libspdlog)
  5. Build optional forensic libraries when --required-only is not used
  6. Flatten the output layout to match CMake expectations under libs/<platform>/

Options:
  --install-system-deps  Install host packages first (apt/dnf/pacman on Linux, brew on macOS)
  --required-only        Build only the mandatory libraries expected by CMake
  --clean                Remove the temporary .deps-build/<platform> directory before starting
  -h, --help             Show this help

Environment:
  JOBS=<n>               Parallel build jobs. Default: auto-detected
EOF
}

while (($# > 0)); do
  case "$1" in
    --install-system-deps)
      INSTALL_SYSTEM_DEPS=1
      ;;
    --required-only)
      REQUIRED_ONLY=1
      ;;
    --clean)
      CLEAN_BUILD_ROOT=1
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

log() {
  printf '[deps] %s\n' "$*"
}

stage() {
  printf '\n[deps][stage] %s\n' "$*"
}

require_command() {
  local binary="$1"
  if ! command -v "${binary}" >/dev/null 2>&1; then
    echo "Required command not found: ${binary}" >&2
    exit 1
  fi
}

run_with_sudo() {
  if [[ "${EUID}" -eq 0 ]]; then
    "$@"
    return
  fi
  require_command sudo
  sudo "$@"
}

install_linux_packages() {
  if command -v apt-get >/dev/null 2>&1; then
    stage "2/6 Install Linux packages with apt-get"
    run_with_sudo apt-get update
    run_with_sudo apt-get install -y \
      autoconf \
      automake \
      autopoint \
      build-essential \
      ca-certificates \
      cmake \
      git \
      libtool \
      pkg-config \
      python3 \
      zlib1g-dev
    return
  fi

  if command -v dnf >/dev/null 2>&1; then
    stage "2/6 Install Linux packages with dnf"
    run_with_sudo dnf install -y \
      autoconf \
      automake \
      ca-certificates \
      cmake \
      gcc \
      gcc-c++ \
      gettext \
      gettext-devel \
      git \
      libtool \
      make \
      pkgconf-pkg-config \
      python3 \
      zlib-devel
    return
  fi

  if command -v pacman >/dev/null 2>&1; then
    stage "2/6 Install Linux packages with pacman"
    run_with_sudo pacman -Sy --noconfirm \
      autoconf \
      automake \
      base-devel \
      cmake \
      git \
      gettext \
      libtool \
      pkgconf \
      python \
      zlib
    return
  fi

  echo "Unsupported Linux package manager. Install build tools manually and rerun." >&2
  exit 1
}

install_macos_packages() {
  stage "2/6 Verify Xcode CLT and install Homebrew packages"

  if ! xcode-select -p >/dev/null 2>&1; then
    echo "Xcode Command Line Tools are required. Run: xcode-select --install" >&2
    exit 1
  fi

  if [[ -x "/opt/homebrew/bin/brew" ]]; then
    export PATH="/opt/homebrew/bin:${PATH}"
  elif [[ -x "/usr/local/bin/brew" ]]; then
    export PATH="/usr/local/bin:${PATH}"
  fi

  require_command brew
  brew update
  brew install autoconf automake cmake git libtool pkg-config gettext
}

prepare_host() {
  stage "1/6 Detect host platform"
  log "Host OS: ${HOST_OS}"
  log "Target libs dir: ${LIBS_DIR}"
  log "Parallel jobs: ${JOBS}"

  if ((CLEAN_BUILD_ROOT)); then
    log "Cleaning ${BUILD_ROOT}"
    rm -rf "${BUILD_ROOT}"
  fi

  mkdir -p "${LIBS_DIR}" "${BUILD_ROOT}"

  if ((INSTALL_SYSTEM_DEPS == 0)); then
    stage "2/6 System package installation skipped"
    log "Re-run with --install-system-deps to install host prerequisites automatically"
  elif [[ "${PLATFORM_ID}" == "linux" ]]; then
    install_linux_packages
  else
    install_macos_packages
  fi

  require_command git
  require_command cmake
  if command -v gmake >/dev/null 2>&1; then
    MAKE_BIN="gmake"
  else
    MAKE_BIN="make"
  fi
  require_command "${MAKE_BIN}"

  if [[ "${PLATFORM_ID}" == "macos" ]] && command -v brew >/dev/null 2>&1; then
    local gettext_prefix
    gettext_prefix="$(brew --prefix gettext 2>/dev/null || true)"
    if [[ -n "${gettext_prefix}" ]]; then
      export PATH="${gettext_prefix}/bin:${PATH}"
    fi
  fi
}

prepare_checkout() {
  local repo_url="$1"
  local checkout_dir="$2"

  if [[ -d "${checkout_dir}/.git" ]]; then
    log "Updating $(basename "${checkout_dir}")"
    git -C "${checkout_dir}" fetch --depth=1 origin
    git -C "${checkout_dir}" reset --hard origin/HEAD
    git -C "${checkout_dir}" clean -fdx
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
  "${MAKE_BIN}" -j"${JOBS}"
  "${MAKE_BIN}" install
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

verify_layout() {
  local required_archives=(
    "${LIBS_DIR}/libregf/libregf.a"
    "${LIBS_DIR}/libscca/libscca.a"
    "${LIBS_DIR}/libevtx/libevtx.a"
    "${LIBS_DIR}/libevt/libevt.a"
    "${LIBS_DIR}/libspdlog/libspdlog.a"
  )

  for archive in "${required_archives[@]}"; do
    if [[ ! -f "${archive}" ]]; then
      echo "Missing expected output archive: ${archive}" >&2
      exit 1
    fi
  done
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

prepare_host

stage "3/6 Clone/update dependency sources"
log "Dependency sources will be cached under ${BUILD_ROOT}"

stage "4/6 Build required static libraries"
for lib in "${required_libs[@]}"; do
  build_libyal "${lib}"
done

if ((REQUIRED_ONLY == 0)); then
  stage "5/6 Build optional forensic libraries"
  for lib in "${optional_libs[@]}"; do
    build_libyal "${lib}"
  done
else
  stage "5/6 Skip optional forensic libraries"
  log "--required-only was provided"
fi

stage "6/6 Build spdlog and verify output layout"
build_spdlog
verify_layout

log "Finished. Static libraries are available under ${LIBS_DIR}"
