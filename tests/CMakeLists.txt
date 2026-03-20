find_package(GTest CONFIG QUIET)
if (NOT TARGET GTest::gtest_main)
    find_package(GTest QUIET)
endif()

if (NOT TARGET GTest::gtest_main)
    option(PROGRAM_TRACES_FETCH_GTEST "Download GoogleTest automatically when building tests" OFF)

    if (PROGRAM_TRACES_FETCH_GTEST)
        include(FetchContent)

        FetchContent_Declare(
            googletest
            URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
            DOWNLOAD_EXTRACT_TIMESTAMP TRUE
        )

        set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
        FetchContent_MakeAvailable(googletest)
    else()
        message(WARNING
            "GoogleTest was not found. Skipping program_traces_tests.\n"
            "Install GTest locally or configure with "
            "-DPROGRAM_TRACES_FETCH_GTEST=ON to download it explicitly.")
        return()
    endif()
endif()

set(PROGRAM_TRACES_TEST_SOURCES
    placeholder_smoke.cpp
    test_amcache_analyzer.cpp
    test_cli.cpp
    test_cli_options.cpp
    test_config_utils.cpp
    test_csv_exporter.cpp
    test_lnk_parser.cpp
    test_os_detection.cpp
    test_prefetch_parser.cpp
    test_pipeline_win7.cpp
    test_pipeline_win10.cpp
    test_registry_parser.cpp
    test_shimcache_decoder.cpp
    test_recovery_analyzers.cpp
    test_signature_scanner.cpp
    test_tamper_detectors.cpp
    test_time_utils.cpp
)

add_executable(program_traces_tests ${PROGRAM_TRACES_TEST_SOURCES})
target_link_libraries(program_traces_tests
    PRIVATE
        GTest::gtest_main
        program_traces_lib
)
target_include_directories(program_traces_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}
)
target_compile_definitions(program_traces_tests PRIVATE
    PROGRAM_TRACES_BINARY_PATH="$<TARGET_FILE:program_traces>"
    PROGRAM_TRACES_FIXTURES_DIR="${CMAKE_CURRENT_SOURCE_DIR}/fixtures"
)
add_dependencies(program_traces_tests program_traces)

include(GoogleTest)
gtest_discover_tests(program_traces_tests DISCOVERY_MODE PRE_TEST)
