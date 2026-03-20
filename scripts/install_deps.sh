#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOST_OS="$(uname -s)"
REQUIRED_ONLY=0
CLEAN_BUILD_ROOT=0
CLEANUP_AFTER=0
CLEANUP_ONLY=0
CLEANUP_DONE=0
STAGE_INDEX=0

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

deps_to_remove=(
  libregf
  libscca
  libevtx
  libevt
  libesedb
  libfusn
  libvshadow
  libhibr
  libfsntfs
  libspdlog
)

required_archives=(
  "${LIBS_DIR}/libregf/libregf.a"
  "${LIBS_DIR}/libscca/libscca.a"
  "${LIBS_DIR}/libevtx/libevtx.a"
  "${LIBS_DIR}/libevt/libevt.a"
  "${LIBS_DIR}/libspdlog/libspdlog.a"
)

usage() {
  cat <<EOF
Usage:
  bash scripts/install_deps.sh [--required-only] [--clean] [--cleanup-after]
  bash scripts/install_deps.sh --cleanup-only

Stages performed by this script:
  1. Detect host OS and select libs output directory (${LIBS_DIR})
  2. Check for required build tools; offer to install any that are missing
     via the detected package manager (brew / apt / dnf / yum / pacman)
  3. Clone or update third-party dependency sources
  4. Build required static libraries (libregf, libscca, libevtx, libevt, libspdlog)
  5. Build optional forensic libraries when --required-only is not used
  6. Verify output layout under libs/<platform>/
  7. (Optional) Cleanup downloaded/build artifacts

Options:
  --required-only        Build only the mandatory libraries expected by CMake
  --clean                Remove the temporary .deps-build/<platform> directory before starting
  --cleanup-after        Always remove downloaded/build artifacts after build
  --cleanup-only         Skip build and only remove .deps-build + libs/<platform>/<dep>
  -h, --help             Show this help

Environment:
  JOBS=<n>               Parallel build jobs. Default: auto-detected
EOF
}

repeat_char() {
  local char="$1"
  local count="$2"
  local out=""
  local i
  for ((i = 0; i < count; ++i)); do
    out+="${char}"
  done
  printf '%s' "${out}"
}

render_stage() {
  local index="$1"
  local title="$2"
  local width=36
  local percent=$((index * 100 / TOTAL_STAGES))
  local filled=$((percent * width / 100))
  local empty=$((width - filled))
  local filled_bar
  local empty_bar
  filled_bar="$(repeat_char "#" "${filled}")"
  empty_bar="$(repeat_char "-" "${empty}")"

  printf '\n\033[1;36m[%s%s]\033[0m %3d%%  \033[1m(%d/%d)\033[0m %s\n' \
    "${filled_bar}" "${empty_bar}" "${percent}" "${index}" "${TOTAL_STAGES}" "${title}"
}

stage() {
  STAGE_INDEX=$((STAGE_INDEX + 1))
  render_stage "${STAGE_INDEX}" "$*"
}

log() {
  printf '[deps-%s] %s\n' "${PLATFORM_ID}" "$*"
}

while (($# > 0)); do
  case "$1" in
    --install-system-deps)
      echo "Option --install-system-deps is no longer supported." >&2
      echo "This script must not install packages into the OS." >&2
      echo "Install required build tools manually and rerun." >&2
      exit 2
      ;;
    --required-only)
      REQUIRED_ONLY=1
      ;;
    --clean)
      CLEAN_BUILD_ROOT=1
      ;;
    --cleanup-after)
      CLEANUP_AFTER=1
      ;;
    --cleanup-only)
      CLEANUP_ONLY=1
      CLEANUP_AFTER=1
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

if ((CLEANUP_ONLY)); then
  TOTAL_STAGES=3
else
  TOTAL_STAGES=7
  if ((CLEANUP_AFTER)); then
    TOTAL_STAGES=$((TOTAL_STAGES + 1))
  fi
fi

require_command() {
  local binary="$1"
  if ! command -v "${binary}" >/dev/null 2>&1; then
    echo "Required command not found: ${binary}" >&2
    exit 1
  fi
}

require_one_of() {
  local label="$1"
  shift

  local candidate
  for candidate in "$@"; do
    if command -v "${candidate}" >/dev/null 2>&1; then
      printf '%s\n' "${candidate}"
      return 0
    fi
  done

  echo "Required command not found (${label}): $*" >&2
  exit 1
}

# ---------------------------------------------------------------------------
# System package manager detection and optional dependency installation
# ---------------------------------------------------------------------------

detect_pkg_manager() {
  PKG_MANAGER=""
  PKG_INSTALL_CMD=""

  if [[ "${PLATFORM_ID}" == "macos" ]]; then
    if command -v brew >/dev/null 2>&1; then
      PKG_MANAGER="brew"
      PKG_INSTALL_CMD="brew install"
    fi
    return
  fi

  if command -v apt-get >/dev/null 2>&1; then
    PKG_MANAGER="apt"
    PKG_INSTALL_CMD="sudo apt-get install -y"
  elif command -v dnf >/dev/null 2>&1; then
    PKG_MANAGER="dnf"
    PKG_INSTALL_CMD="sudo dnf install -y"
  elif command -v yum >/dev/null 2>&1; then
    PKG_MANAGER="yum"
    PKG_INSTALL_CMD="sudo yum install -y"
  elif command -v pacman >/dev/null 2>&1; then
    PKG_MANAGER="pacman"
    PKG_INSTALL_CMD="sudo pacman -S --noconfirm"
  fi
}

pkg_name_for() {
  local tool="$1"
  case "${PKG_MANAGER}:${tool}" in
    brew:pkg-config)   echo "pkg-config" ;;
    brew:make)         echo "make" ;;
    brew:autopoint)    echo "gettext" ;;
    brew:*)            echo "${tool}" ;;
    pacman:pkg-config) echo "pkgconf" ;;
    pacman:python3)    echo "python" ;;
    pacman:*)          echo "${tool}" ;;
    dnf:pkg-config)    echo "pkgconf" ;;
    yum:pkg-config)    echo "pkgconf" ;;
    *:*)               echo "${tool}" ;;
  esac
}

# Collect all missing required tools, show them, then offer a single prompt
# to install via the detected package manager.
check_and_offer_install() {
  local -a check_tools=()
  check_tools+=(git:git cmake:cmake autoconf:autoconf automake:automake autopoint:autopoint)

  if [[ "${PLATFORM_ID}" == "linux" ]]; then
    check_tools+=(python3:python3)
  fi

  # GNU libtool helpers differ by platform.
  # On macOS (Homebrew), both helpers are usually exposed as glibtoolize/glibtool.
  # On Debian/Ubuntu, the libtool package reliably provides libtoolize, while a
  # standalone libtool binary may be absent from PATH and is not required here.
  if [[ "${PLATFORM_ID}" == "macos" ]]; then
    command -v glibtoolize >/dev/null 2>&1 || check_tools+=(glibtoolize:libtool)
    command -v glibtool    >/dev/null 2>&1 || check_tools+=(glibtool:libtool)
  else
    command -v libtoolize >/dev/null 2>&1 || check_tools+=(libtoolize:libtool)
  fi

  # pkg-config — either binary is acceptable
  if ! command -v pkg-config >/dev/null 2>&1 && ! command -v pkgconf >/dev/null 2>&1; then
    check_tools+=(pkg-config:pkg-config)
  fi

  # make — gmake or make
  if ! command -v gmake >/dev/null 2>&1 && ! command -v make >/dev/null 2>&1; then
    check_tools+=(make:make)
  fi

  local -a missing_bins=()
  local -a missing_pkgs=()
  local entry binary canonical pkg already p

  for entry in "${check_tools[@]}"; do
    binary="${entry%%:*}"
    canonical="${entry##*:}"
    if ! command -v "${binary}" >/dev/null 2>&1; then
      pkg="$(pkg_name_for "${canonical}")"
      missing_bins+=("${binary}")
      # Avoid duplicate packages (e.g. libtool listed twice)
      already=0
      for p in "${missing_pkgs[@]+"${missing_pkgs[@]}"}"; do
        [[ "${p}" == "${pkg}" ]] && already=1 && break
      done
      ((already)) || missing_pkgs+=("${pkg}")
    fi
  done

  if ((${#missing_bins[@]} == 0)); then
    log "All required build tools are present."
    return 0
  fi

  printf '\n'
  log "The following required build tools are missing:"
  for b in "${missing_bins[@]}"; do
    printf '  - %s\n' "${b}"
  done
  printf '\n'

  if [[ -z "${PKG_MANAGER}" ]]; then
    echo "No supported package manager detected (brew / apt / dnf / yum / pacman)." >&2
    echo "Install the tools listed above manually, then rerun this script." >&2
    exit 1
  fi

  log "Detected package manager: ${PKG_MANAGER}"
  printf 'Proposed install command:\n  %s %s\n\n' "${PKG_INSTALL_CMD}" "${missing_pkgs[*]}"
  printf 'Install missing tools now? [y/N] '

  local answer
  read -r answer </dev/tty
  case "${answer}" in
    [yY]|[yY][eE][sS])
      log "Installing: ${missing_pkgs[*]}"
      ${PKG_INSTALL_CMD} "${missing_pkgs[@]}"
      ;;
    *)
      log "Installation declined. Install the tools manually and rerun."
      exit 1
      ;;
  esac
}

cleanup_outputs() {
  rm -rf "${BUILD_ROOT}"

  local dep
  for dep in "${deps_to_remove[@]}"; do
    rm -rf "${LIBS_DIR:?}/${dep}"
  done

  CLEANUP_DONE=1
  log "Removed ${BUILD_ROOT} and dependency directories in ${LIBS_DIR}"
}

on_exit_cleanup() {
  local exit_code="$1"
  if ((exit_code != 0)) && ((CLEANUP_AFTER)) && ((CLEANUP_DONE == 0)); then
    set +e
    log "Build failed (${exit_code}), running mandatory cleanup-after."
    cleanup_outputs
  fi
  exit "${exit_code}"
}

prepare_host() {
  stage "Detect host platform and output layout"
  log "Host OS: ${HOST_OS}"
  log "Target libs dir: ${LIBS_DIR}"
  log "Parallel jobs: ${JOBS}"

  if ((CLEAN_BUILD_ROOT)); then
    log "Cleaning ${BUILD_ROOT}"
    rm -rf "${BUILD_ROOT}"
  fi

  mkdir -p "${LIBS_DIR}" "${BUILD_ROOT}"

  if ((CLEANUP_ONLY)); then
    return
  fi

  stage "Validate local toolchain"
  log "This script builds libraries only under ${LIBS_DIR}."
  log "Missing system tools will be listed and you will be asked to confirm installation."

  if [[ "${PLATFORM_ID}" == "macos" ]]; then
    if ! xcode-select -p >/dev/null 2>&1; then
      echo "Xcode Command Line Tools are required. Run: xcode-select --install" >&2
      exit 1
    fi

    if [[ -x "/opt/homebrew/bin/brew" ]]; then
      export PATH="/opt/homebrew/bin:${PATH}"
    elif [[ -x "/usr/local/bin/brew" ]]; then
      export PATH="/usr/local/bin:${PATH}"
    fi

    if command -v brew >/dev/null 2>&1; then
      local gettext_prefix
      gettext_prefix="$(brew --prefix gettext 2>/dev/null || true)"
      if [[ -n "${gettext_prefix}" ]]; then
        export PATH="${gettext_prefix}/bin:${PATH}"
      fi
    fi
  else
    require_command python3
  fi

  detect_pkg_manager
  check_and_offer_install

  require_command git
  require_command cmake
  require_command autoconf
  require_command automake
  require_command autopoint

  local libtoolize_bin
  libtoolize_bin="$(require_one_of "GNU libtoolize helper" libtoolize glibtoolize)"
  if [[ "${libtoolize_bin}" != "libtoolize" ]]; then
    export LIBTOOLIZE="${libtoolize_bin}"
  fi

  if [[ "${PLATFORM_ID}" == "macos" ]]; then
    local libtool_bin
    libtool_bin="$(require_one_of "GNU libtool helper" glibtool libtool)"
    if [[ "${libtool_bin}" != "libtool" ]]; then
      export LIBTOOL="${libtool_bin}"
    fi
  fi

  if command -v pkg-config >/dev/null 2>&1; then
    :
  elif command -v pkgconf >/dev/null 2>&1; then
    export PKG_CONFIG="pkgconf"
  else
    echo "Required command not found: pkg-config (or pkgconf)" >&2
    exit 1
  fi

  if command -v gmake >/dev/null 2>&1; then
    MAKE_BIN="gmake"
  else
    MAKE_BIN="make"
  fi
  require_command "${MAKE_BIN}"
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
  if [[ ! -x "./configure" ]]; then
    echo "autogen.sh did not generate ./configure in ${checkout_dir}" >&2
    exit 1
  fi
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

if ((CLEANUP_AFTER)); then
  trap 'on_exit_cleanup $?' EXIT
fi

prepare_host

if ((CLEANUP_ONLY)); then
  stage "Cleanup downloaded/build artifacts"
  cleanup_outputs
  stage "Done"
  log "Cleanup-only completed."
  exit 0
fi

stage "Clone/update dependency sources"
log "Dependency sources will be cached under ${BUILD_ROOT}"

stage "Build required static libraries"
for lib in "${required_libs[@]}"; do
  build_libyal "${lib}"
done

if ((REQUIRED_ONLY == 0)); then
  stage "Build optional forensic libraries"
  for lib in "${optional_libs[@]}"; do
    build_libyal "${lib}"
  done
else
  stage "Skip optional forensic libraries"
  log "--required-only was provided"
fi

stage "Build spdlog and verify output layout"
build_spdlog
verify_layout

if ((CLEANUP_AFTER)); then
  stage "Cleanup downloaded/build artifacts"
  cleanup_outputs
fi

stage "Done"
if ((CLEANUP_AFTER)); then
  log "Finished. Dependencies were built and then removed."
else
  log "Finished. Static libraries are available under ${LIBS_DIR}"
fi
