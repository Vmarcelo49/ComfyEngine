add_executable(test_target_child test_target_child.c)

set_target_properties(test_target_child PROPERTIES
    C_STANDARD 11
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests
)

add_executable(ce_core_tests test_core.cpp)

target_link_libraries(ce_core_tests PRIVATE ce_core)

set_target_properties(ce_core_tests PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests
)

add_test(NAME ce_core_tests
    COMMAND ce_core_tests $<TARGET_FILE:test_target_child>
)

add_test(NAME cli_e2e
    COMMAND ${CMAKE_SOURCE_DIR}/tests/cli_e2e.sh
)

set_tests_properties(cli_e2e PROPERTIES SKIP_RETURN_CODE 77)
