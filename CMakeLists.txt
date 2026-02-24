cmake_minimum_required(VERSION 3.20)

project(ProgramTraces LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
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

file(GLOB_RECURSE APP_SOURCES
    ${PROGRAM_TRACES_SRC_ROOT}/*.cpp
)
file(GLOB_RECURSE ANALYSIS_SOURCES
    ${PROGRAM_TRACES_SRC_ROOT}/analysis/*.cpp
)
file(GLOB_RECURSE PARSER_SOURCES
    ${PROGRAM_TRACES_SRC_ROOT}/parsers/*.cpp
)
file(GLOB_RECURSE INFRA_SOURCES
    ${PROGRAM_TRACES_SRC_ROOT}/infra/*.cpp
)

set(ALL_SOURCES
    ${APP_SOURCES}
    ${ANALYSIS_SOURCES}
    ${PARSER_SOURCES}
    ${INFRA_SOURCES}
)

add_executable(program_traces ${ALL_SOURCES})

target_include_directories(program_traces PRIVATE
    ${PROGRAM_TRACES_SRC_ROOT}
    ${LIBS_BASE_PATH}/libregf/include
    ${LIBS_BASE_PATH}/libscca/include
    ${LIBS_BASE_PATH}/libevtx/include
    ${LIBS_BASE_PATH}/libevt/include
    ${LIBS_BASE_PATH}/libspdlog/include
    ${LIBS_BASE_PATH}/libfmt/include
)

set(THIRD_PARTY_STATIC_LIBS
    ${LIBS_BASE_PATH}/libregf/libregf.a
    ${LIBS_BASE_PATH}/libscca/libscca.a
    ${LIBS_BASE_PATH}/libevtx/libevtx.a
    ${LIBS_BASE_PATH}/libevt/libevt.a
    ${LIBS_BASE_PATH}/libspdlog/libspdlog.a
    ${LIBS_BASE_PATH}/libfmt/libfmt.a
)

foreach(LIB_FILE IN LISTS THIRD_PARTY_STATIC_LIBS)
    if (NOT EXISTS "${LIB_FILE}")
        message(FATAL_ERROR
            "Missing third-party static library: ${LIB_FILE}\n"
            "Expected platform libs under: ${LIBS_BASE_PATH}")
    endif()
endforeach()

if (CMAKE_CXX_COMPILER_ID MATCHES "Clang|AppleClang|GNU")
    target_compile_options(program_traces PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        -Wconversion
        -Wshadow
        -Wnon-virtual-dtor
    )
endif()

target_link_libraries(program_traces PRIVATE ${THIRD_PARTY_STATIC_LIBS})

if (APPLE)
    find_library(COREFOUNDATION_LIB CoreFoundation REQUIRED)
    find_library(IOKIT_LIB IOKit REQUIRED)

    target_link_libraries(program_traces PRIVATE
        ${COREFOUNDATION_LIB}
        ${IOKIT_LIB}
    )
elseif (UNIX AND NOT APPLE)
    find_package(Threads REQUIRED)
    find_library(DL_LIB dl)
    find_library(M_LIB m)
    find_library(ICONV_LIB iconv)

    target_link_libraries(program_traces PRIVATE Threads::Threads)

    if (DL_LIB)
        target_link_libraries(program_traces PRIVATE ${DL_LIB})
    endif()
    if (M_LIB)
        target_link_libraries(program_traces PRIVATE ${M_LIB})
    endif()
    if (ICONV_LIB)
        target_link_libraries(program_traces PRIVATE ${ICONV_LIB})
    endif()
endif()

source_group(TREE ${PROGRAM_TRACES_SRC_ROOT} FILES ${ALL_SOURCES})
