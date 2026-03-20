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
UI_ACTIVE=0
UI_IS_TTY=0
CURRENT_STAGE_TITLE=""
CURRENT_STATUS_TEXT=""
LOG_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/program-traces-deps.XXXXXX")"

if [[ -t 1 ]]; then
  UI_IS_TTY=1
fi

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
  local width=36
  local percent=$((index * 100 / TOTAL_STAGES))
  local filled=$((percent * width / 100))
  local empty=$((width - filled))
  local filled_bar
  local empty_bar
  filled_bar="$(repeat_char "#" "${filled}")"
  empty_bar="$(repeat_char "-" "${empty}")"

  printf '\033[1;36m[%s%s]\033[0m %3d%%  \033[1m(%d/%d)\033[0m' \
    "${filled_bar}" "${empty_bar}" "${percent}" "${index}" "${TOTAL_STAGES}"
}

render_ui() {
  local progress_line
  progress_line="$(render_stage "${STAGE_INDEX}")"

  if ((UI_IS_TTY)); then
    if ((UI_ACTIVE)); then
      printf '\033[1A\r\033[2K%s\n\033[2K%s' "${progress_line}" "${CURRENT_STATUS_TEXT}"
    else
      printf '%s\n%s' "${progress_line}" "${CURRENT_STATUS_TEXT}"
      UI_ACTIVE=1
    fi
    return
  fi

  printf '%s\n%s\n' "${progress_line}" "${CURRENT_STATUS_TEXT}"
}

ui_break() {
  if ((UI_ACTIVE)); then
    printf '\n'
    UI_ACTIVE=0
  fi
}

status() {
  CURRENT_STATUS_TEXT="$*"
  render_ui
}

stage() {
  STAGE_INDEX=$((STAGE_INDEX + 1))
  CURRENT_STAGE_TITLE="$*"
  CURRENT_STATUS_TEXT="$*"
  render_ui
}

log() {
  status "$*"
}

run_quiet() {
  local description="$1"
  shift

  local log_file
  log_file="$(mktemp "${LOG_ROOT}/cmd.XXXXXX.log")"
  status "${description}"

  if "$@" >"${log_file}" 2>&1; then
    rm -f "${log_file}"
    return 0
  fi

  ui_break
  printf 'Error while %s\n' "${description}" >&2
  cat "${log_file}" >&2
  rm -f "${log_file}"
  exit 1
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
    ui_break
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

  ui_break
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
    status "All required build tools are available."
    return 0
  fi

  ui_break
  printf 'Missing required build tools:\n'
  for b in "${missing_bins[@]}"; do
    printf '  - %s\n' "${b}"
  done
  printf '\n'

  if [[ -z "${PKG_MANAGER}" ]]; then
    ui_break
    echo "No supported package manager detected (brew / apt / dnf / yum / pacman)." >&2
    echo "Install the tools listed above manually, then rerun this script." >&2
    exit 1
  fi

  printf 'Detected package manager: %s\n' "${PKG_MANAGER}"
  printf 'Proposed install command:\n  %s %s\n\n' "${PKG_INSTALL_CMD}" "${missing_pkgs[*]}"
  printf 'Install missing tools now? [y/N] '

  local answer
  read -r answer </dev/tty
  case "${answer}" in
    [yY]|[yY][eE][sS])
      run_quiet "Installing missing system packages" ${PKG_INSTALL_CMD} "${missing_pkgs[@]}"
      ;;
    *)
      ui_break
      echo "Installation declined. Install the tools manually and rerun." >&2
      exit 1
      ;;
  esac
}

cleanup_outputs() {
  status "Removing temporary build artifacts"
  rm -rf "${BUILD_ROOT}"

  local dep
  for dep in "${deps_to_remove[@]}"; do
    rm -rf "${LIBS_DIR:?}/${dep}"
  done

  CLEANUP_DONE=1
}

on_exit_cleanup() {
  local exit_code="$1"
  if ((exit_code != 0)) && ((CLEANUP_AFTER)) && ((CLEANUP_DONE == 0)); then
    set +e
    status "Build failed, removing temporary build artifacts"
    cleanup_outputs
  fi
  rm -rf "${LOG_ROOT}"
  ui_break
  exit "${exit_code}"
}

prepare_host() {
  stage "Detect host platform and output layout"
  status "Preparing directories for ${PLATFORM_ID} (${JOBS} jobs)"

  if ((CLEAN_BUILD_ROOT)); then
    status "Cleaning previous build directory"
    rm -rf "${BUILD_ROOT}"
  fi

  mkdir -p "${LIBS_DIR}" "${BUILD_ROOT}"

  if ((CLEANUP_ONLY)); then
    return
  fi

  stage "Validate local toolchain"
  status "Checking required build tools"

  if [[ "${PLATFORM_ID}" == "macos" ]]; then
    if ! xcode-select -p >/dev/null 2>&1; then
      ui_break
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
  status "Validating toolchain"

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
    ui_break
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
  local repo_name
  repo_name="$(basename "${checkout_dir}")"

  if [[ -d "${checkout_dir}/.git" ]]; then
    run_quiet "Updating ${repo_name} source" git -C "${checkout_dir}" fetch --depth=1 origin
    run_quiet "Resetting ${repo_name} source tree" git -C "${checkout_dir}" reset --hard origin/HEAD
    run_quiet "Cleaning ${repo_name} source tree" git -C "${checkout_dir}" clean -fdx
  else
    run_quiet "Cloning ${repo_name} source" git clone --depth=1 "${repo_url}" "${checkout_dir}"
  fi
}

flatten_static_layout() {
  local prefix_dir="$1"
  local lib_name="$2"
  local archive_path="${prefix_dir}/lib/${lib_name}.a"

  if [[ ! -f "${archive_path}" ]]; then
    ui_break
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
    run_quiet "Syncing bundled sources for ${repo_name}" ./synclibs.sh
  fi
  run_quiet "Bootstrapping ${repo_name}" ./autogen.sh
  if [[ ! -x "./configure" ]]; then
    ui_break
    echo "autogen.sh did not generate ./configure in ${checkout_dir}" >&2
    exit 1
  fi
  run_quiet "Configuring ${repo_name}" env CFLAGS="-fPIC" CXXFLAGS="-fPIC" ./configure \
    --prefix="${prefix_dir}" \
    --enable-static \
    --disable-shared
  run_quiet "Compiling ${repo_name}" "${MAKE_BIN}" -j"${JOBS}"
  run_quiet "Installing ${repo_name}" "${MAKE_BIN}" install
  popd >/dev/null

  status "Finalizing ${repo_name} artifacts"
  flatten_static_layout "${prefix_dir}" "${repo_name}"
}

build_spdlog() {
  local prefix_dir="${LIBS_DIR}/libspdlog"
  local checkout_dir="${BUILD_ROOT}/spdlog"
  local build_dir="${checkout_dir}/build"

  prepare_checkout "https://github.com/gabime/spdlog.git" "${checkout_dir}"

  rm -rf "${prefix_dir}" "${build_dir}"
  mkdir -p "${build_dir}"

  run_quiet "Configuring spdlog" cmake -S "${checkout_dir}" -B "${build_dir}" \
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
  run_quiet "Compiling spdlog" cmake --build "${build_dir}" -j"${JOBS}"
  run_quiet "Installing spdlog" cmake --install "${build_dir}"

  status "Finalizing spdlog artifacts"
  flatten_static_layout "${prefix_dir}" "libspdlog"
}

verify_layout() {
  for archive in "${required_archives[@]}"; do
    if [[ ! -f "${archive}" ]]; then
      ui_break
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

trap 'on_exit_cleanup $?' EXIT

prepare_host

if ((CLEANUP_ONLY)); then
  stage "Cleanup downloaded/build artifacts"
  cleanup_outputs
  stage "Done"
  status "Cleanup completed."
  exit 0
fi

stage "Clone/update dependency sources"
status "Dependency sources are cached under ${BUILD_ROOT}"

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
  status "Optional forensic libraries were skipped."
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
  status "Finished. Dependencies were built and then removed."
else
  status "Finished. Static libraries are available under ${LIBS_DIR}"
fi
