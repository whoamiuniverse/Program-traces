include(FetchContent)

FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)

set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

set(PROGRAM_TRACES_TEST_SOURCES
    placeholder_smoke.cpp
    test_amcache_analyzer.cpp
    test_cli.cpp
    test_config_utils.cpp
    test_csv_exporter.cpp
    test_lnk_parser.cpp
    test_os_detection.cpp
    test_prefetch_parser.cpp
    test_pipeline_win7.cpp
    test_pipeline_win10.cpp
    test_shimcache_decoder.cpp
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
