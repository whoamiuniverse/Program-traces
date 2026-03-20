cmake_minimum_required(VERSION 3.20)

project(ProgramTraces VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(PROGRAM_TRACES_ENABLE_IPO "Enable interprocedural optimization (LTO) for Release builds" ON)
if (PROGRAM_TRACES_ENABLE_IPO)
    include(CheckIPOSupported)
    check_ipo_supported(RESULT IPO_SUPPORTED OUTPUT IPO_ERROR)
    if (IPO_SUPPORTED)
        set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE ON)
    else()
        message(STATUS "IPO/LTO is not supported: ${IPO_ERROR}")
    endif()
endif()

if (APPLE)
    set(PLATFORM_LIBS_DIR "macos")
elseif (UNIX AND NOT APPLE)
    set(PLATFORM_LIBS_DIR "linux")
else()
    message(FATAL_ERROR "Unsupported platform: ${CMAKE_SYSTEM_NAME}")
endif()

set(PROGRAM_TRACES_LIBS_ROOT "${CMAKE_SOURCE_DIR}/libs" CACHE PATH
    "Root directory with third-party prebuilt libraries")
set(LIBS_BASE_PATH "${PROGRAM_TRACES_LIBS_ROOT}/${PLATFORM_LIBS_DIR}")
set(PROGRAM_TRACES_SRC_ROOT "${CMAKE_SOURCE_DIR}/src")
set(PROGRAM_TRACES_MAIN_SOURCE "${PROGRAM_TRACES_SRC_ROOT}/main.cpp")

# Keep source discovery resilient for CLion/Ninja workflows:
# - *.cpp / *.cc / *.cxx are all treated as translation units
# - header globs are added to CMAKE_CONFIGURE_DEPENDS so CMake
#   reliably re-runs configure when file sets change.
set(PROGRAM_TRACES_SOURCE_GLOBS
    "${PROGRAM_TRACES_SRC_ROOT}/*.cpp"
    "${PROGRAM_TRACES_SRC_ROOT}/*.cc"
    "${PROGRAM_TRACES_SRC_ROOT}/*.cxx"
)
set(PROGRAM_TRACES_HEADER_GLOBS
    "${PROGRAM_TRACES_SRC_ROOT}/*.hpp"
    "${PROGRAM_TRACES_SRC_ROOT}/*.hh"
    "${PROGRAM_TRACES_SRC_ROOT}/*.hxx"
    "${PROGRAM_TRACES_SRC_ROOT}/*.h"
)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
    ${PROGRAM_TRACES_SOURCE_GLOBS}
    ${PROGRAM_TRACES_HEADER_GLOBS}
)

file(GLOB_RECURSE ALL_SOURCES CONFIGURE_DEPENDS
    ${PROGRAM_TRACES_SOURCE_GLOBS}
)

set(PROGRAM_TRACES_LIBRARY_SOURCES ${ALL_SOURCES})
list(REMOVE_ITEM PROGRAM_TRACES_LIBRARY_SOURCES ${PROGRAM_TRACES_MAIN_SOURCE})

add_library(program_traces_lib STATIC ${PROGRAM_TRACES_LIBRARY_SOURCES})
add_executable(program_traces ${PROGRAM_TRACES_MAIN_SOURCE})

target_include_directories(program_traces_lib PUBLIC
    ${PROGRAM_TRACES_SRC_ROOT}
    ${LIBS_BASE_PATH}/libregf/include
    ${LIBS_BASE_PATH}/libscca/include
    ${LIBS_BASE_PATH}/libesedb/include
    ${LIBS_BASE_PATH}/libfusn/include
    ${LIBS_BASE_PATH}/libhibr/include
    ${LIBS_BASE_PATH}/libfsntfs/include
    ${LIBS_BASE_PATH}/libvshadow/include
    ${LIBS_BASE_PATH}/libevtx/include
    ${LIBS_BASE_PATH}/libevt/include
    ${LIBS_BASE_PATH}/libspdlog/include
)

set(THIRD_PARTY_STATIC_LIBS
    ${LIBS_BASE_PATH}/libregf/libregf.a
    ${LIBS_BASE_PATH}/libscca/libscca.a
    ${LIBS_BASE_PATH}/libevtx/libevtx.a
    ${LIBS_BASE_PATH}/libevt/libevt.a
    ${LIBS_BASE_PATH}/libspdlog/libspdlog.a
)

set(PROGRAM_TRACES_HAVE_LIBESEDB 0)
if (EXISTS "${LIBS_BASE_PATH}/libesedb/libesedb.a")
    list(APPEND THIRD_PARTY_STATIC_LIBS ${LIBS_BASE_PATH}/libesedb/libesedb.a)
    set(PROGRAM_TRACES_HAVE_LIBESEDB 1)
endif()

set(PROGRAM_TRACES_HAVE_LIBFUSN 0)
if (EXISTS "${LIBS_BASE_PATH}/libfusn/libfusn.a")
    list(APPEND THIRD_PARTY_STATIC_LIBS ${LIBS_BASE_PATH}/libfusn/libfusn.a)
    set(PROGRAM_TRACES_HAVE_LIBFUSN 1)
endif()

set(PROGRAM_TRACES_HAVE_LIBVSHADOW 0)
if (EXISTS "${LIBS_BASE_PATH}/libvshadow/libvshadow.a")
    list(APPEND THIRD_PARTY_STATIC_LIBS ${LIBS_BASE_PATH}/libvshadow/libvshadow.a)
    set(PROGRAM_TRACES_HAVE_LIBVSHADOW 1)
endif()

set(PROGRAM_TRACES_HAVE_LIBHIBR 0)
if (EXISTS "${LIBS_BASE_PATH}/libhibr/libhibr.a")
    list(APPEND THIRD_PARTY_STATIC_LIBS ${LIBS_BASE_PATH}/libhibr/libhibr.a)
    set(PROGRAM_TRACES_HAVE_LIBHIBR 1)
endif()

set(PROGRAM_TRACES_HAVE_LIBFSNTFS 0)
if (EXISTS "${LIBS_BASE_PATH}/libfsntfs/libfsntfs.a")
    list(APPEND THIRD_PARTY_STATIC_LIBS ${LIBS_BASE_PATH}/libfsntfs/libfsntfs.a)
    set(PROGRAM_TRACES_HAVE_LIBFSNTFS 1)
endif()

if ((APPLE OR UNIX) AND NOT EXISTS "${LIBS_BASE_PATH}/libregf/libregf.a")
    message(FATAL_ERROR
        "Missing prebuilt libs for ${CMAKE_SYSTEM_NAME}.\n"
        "Run: bash scripts/install_deps.sh\n"
        "Expected: ${LIBS_BASE_PATH}/")
endif()

target_compile_definitions(program_traces_lib PUBLIC
    PROGRAM_TRACES_HAVE_LIBESEDB=${PROGRAM_TRACES_HAVE_LIBESEDB}
    PROGRAM_TRACES_HAVE_LIBFUSN=${PROGRAM_TRACES_HAVE_LIBFUSN}
    PROGRAM_TRACES_HAVE_LIBVSHADOW=${PROGRAM_TRACES_HAVE_LIBVSHADOW}
    PROGRAM_TRACES_HAVE_LIBHIBR=${PROGRAM_TRACES_HAVE_LIBHIBR}
    PROGRAM_TRACES_HAVE_LIBFSNTFS=${PROGRAM_TRACES_HAVE_LIBFSNTFS}
    PROGRAM_TRACES_VERSION="${PROJECT_VERSION}"
)

foreach(LIB_FILE IN LISTS THIRD_PARTY_STATIC_LIBS)
    if (NOT EXISTS "${LIB_FILE}")
        message(FATAL_ERROR
            "Missing third-party static library: ${LIB_FILE}\n"
            "Expected platform libs under: ${LIBS_BASE_PATH}")
    endif()
endforeach()

if (CMAKE_CXX_COMPILER_ID MATCHES "Clang|AppleClang|GNU")
    target_compile_options(program_traces_lib PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        -Wconversion
        -Wshadow
        -Wnon-virtual-dtor
    )
endif()

target_link_libraries(program_traces_lib PRIVATE ${THIRD_PARTY_STATIC_LIBS})
target_link_libraries(program_traces PRIVATE program_traces_lib)

if (APPLE)
    find_library(COREFOUNDATION_LIB CoreFoundation REQUIRED)
    find_library(IOKIT_LIB IOKit REQUIRED)

    target_link_libraries(program_traces_lib PRIVATE
        ${COREFOUNDATION_LIB}
        ${IOKIT_LIB}
    )
elseif (UNIX AND NOT APPLE)
    find_package(Threads REQUIRED)
    find_library(DL_LIB dl)
    find_library(M_LIB m)
    find_library(ICONV_LIB iconv)

    target_link_libraries(program_traces_lib PRIVATE Threads::Threads)

    if (DL_LIB)
        target_link_libraries(program_traces_lib PRIVATE ${DL_LIB})
    endif()
    if (M_LIB)
        target_link_libraries(program_traces_lib PRIVATE ${M_LIB})
    endif()
    if (ICONV_LIB)
        target_link_libraries(program_traces_lib PRIVATE ${ICONV_LIB})
    endif()
endif()

source_group(TREE ${PROGRAM_TRACES_SRC_ROOT} FILES ${PROGRAM_TRACES_LIBRARY_SOURCES})

option(PROGRAM_TRACES_BUILD_TESTS "Build unit tests" OFF)
if (PROGRAM_TRACES_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
