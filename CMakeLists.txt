cmake_minimum_required(VERSION 3.20)

project(llps C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

add_compile_options(
    -Wall -Wextra -Wpedantic -Werror
    -Wshadow
    -Wconversion -Wsign-conversion
    -Wcast-align -Wcast-qual
    -Wstrict-prototypes -Wmissing-prototypes
    -Wformat=2
    -Wundef
    -Wdouble-promotion
    -fno-common
)

find_package(llam REQUIRED)

set(LLPS_PRIVATE_INCLUDE_DIRS
    ${CMAKE_CURRENT_SOURCE_DIR}/include/llps
    ${CMAKE_CURRENT_SOURCE_DIR}/src/internal
)

set(LLPS_CORE_SOURCES
    src/audit/llps_ip_audit.c
    src/config/llps_config_validate.c
    src/config/yml_parser.c
    src/core/llps_state.c
    src/net/llps_net.c
    src/platform/llps_domain.c
    src/platform/llps_edac.c
    src/platform/llps_memory.c
    src/platform/llps_memory_report.c
    src/platform/llps_numa.c
    src/platform/llps_platform.c
    src/platform/llps_platform_evidence_builder.c
    src/platform/llps_platform_evidence_runtime.c
    src/readiness/llps_readiness.c
    src/readiness/llps_readiness_config.c
    src/readiness/llps_readiness_monitor_worker.c
    src/readiness/llps_readiness_runtime_failures.c
    src/session/llps_control_flag.c
    src/session/llps_free_list_tmr.c
    src/session/llps_runtime_cfg_tmr.c
    src/session/llps_runtime_latches.c
    src/session/llps_safety_counters.c
    src/session/llps_session_integrity.c
    src/session/llps_session_tmr.c
    src/support/llps_crc.c
    src/support/llps_guard.c
    src/support/llps_log.c
    src/support/llps_llam_contract.c
    src/support/llps_secded.c
    src/support/llps_hmac.c
    src/support/llps_software_evidence.c
    src/tmr/llps_evidence.c
    src/tmr/llps_tmr_layout.c
    src/tmr/llps_tmr_memory_prep.c
    src/tmr/llps_tmr_memory_regions.c
    src/tmr/llps_tmr_observer.c
    src/tmr/llps_tmr_platform.c
    src/tmr/llps_tmr_probe.c
    src/tmr/llps_tmr_vote.c
)

set(LLPS_APP_SOURCE src/app/main.c)
set(LLPS_CPPCHECK_SOURCES ${LLPS_APP_SOURCE} ${LLPS_CORE_SOURCES})
set(LLPS_CPPCHECK_ABS_SOURCES)
foreach(src IN LISTS LLPS_CPPCHECK_SOURCES)
    list(APPEND LLPS_CPPCHECK_ABS_SOURCES "${CMAKE_SOURCE_DIR}/${src}")
endforeach()

add_executable(llps
    ${LLPS_APP_SOURCE}
    ${LLPS_CORE_SOURCES}
)
target_link_libraries(llps PRIVATE llam::runtime)
target_include_directories(llps PRIVATE ${LLPS_PRIVATE_INCLUDE_DIRS})
target_compile_definitions(llps PRIVATE _GNU_SOURCE _POSIX_C_SOURCE=200809L)

get_target_property(LLPS_LLAM_INCLUDE_DIRS llam::runtime INTERFACE_INCLUDE_DIRECTORIES)
set(LLPS_CPPCHECK_INCLUDES -I /usr/local/include)
if(LLPS_LLAM_INCLUDE_DIRS)
    foreach(dir IN LISTS LLPS_LLAM_INCLUDE_DIRS)
        list(APPEND LLPS_CPPCHECK_INCLUDES -I ${dir})
    endforeach()
endif()
foreach(dir IN LISTS LLPS_PRIVATE_INCLUDE_DIRS)
    list(APPEND LLPS_CPPCHECK_INCLUDES -I ${dir})
endforeach()

# Add custom target for static analysis (MISRA via cppcheck)
add_custom_target(misra
    COMMAND cppcheck --enable=all --check-level=exhaustive --inline-suppr --suppress=missingIncludeSystem --suppress=*:*/usr/local/* --suppress=checkersReport --suppress=toomanyconfigs --suppress=unmatchedSuppression --suppress=staticFunction --suppress=unusedFunction --suppress=staticFunction:${CMAKE_SOURCE_DIR}/src/core/llps_state.c --inconclusive --error-exitcode=1 ${LLPS_CPPCHECK_INCLUDES} ${LLPS_CPPCHECK_ABS_SOURCES}
    COMMENT "Running MISRA/Static analysis on LLPS source code"
)

# Coverage & Tests
if(BUILD_TESTING)
    enable_testing()
    find_package(Python3 COMPONENTS Interpreter)
    set(LLPS_TEST_CORE_SOURCES ${LLPS_CORE_SOURCES})
    list(REMOVE_ITEM LLPS_TEST_CORE_SOURCES
        src/core/llps_state.c
        src/net/llps_net.c
    )
    add_executable(test_llps
        tests/test_llps.c
        ${LLPS_TEST_CORE_SOURCES}
    )
    # Exclude strict warnings for the test file to avoid casting errors in mocks
    set_target_properties(test_llps PROPERTIES COMPILE_FLAGS "-Wno-error")

    target_link_libraries(test_llps PRIVATE llam::runtime)
    target_include_directories(test_llps PRIVATE ${LLPS_PRIVATE_INCLUDE_DIRS})
    target_compile_definitions(test_llps PRIVATE
        _GNU_SOURCE
        _POSIX_C_SOURCE=200809L
        LLPS_TEST_HOOKS=1
        LLPS_MADV_DONTDUMP=1001
        LLPS_MADV_NOHUGEPAGE=1002
        LLPS_MADV_UNMERGEABLE=1003
        mlock=__wrap_mlock
        mlockall=__wrap_mlockall
        madvise=__wrap_madvise
    )
    target_compile_options(test_llps PRIVATE --coverage)
    target_link_options(test_llps PRIVATE --coverage)
    add_test(NAME test_llps COMMAND test_llps)
    if(Python3_Interpreter_FOUND)
        add_test(
            NAME test_verify_pxf_audit_mac
            COMMAND ${Python3_EXECUTABLE}
                    ${CMAKE_SOURCE_DIR}/tests/test_verify_pxf_audit_mac.py
        )
        add_test(
            NAME test_llam_contract_wrappers
            COMMAND ${Python3_EXECUTABLE}
                    ${CMAKE_SOURCE_DIR}/tests/test_llam_contract_wrappers.py
        )
        add_test(
            NAME test_runtime_blocking_io_policy
            COMMAND ${Python3_EXECUTABLE}
                    ${CMAKE_SOURCE_DIR}/tests/test_runtime_blocking_io_policy.py
        )
        add_test(
            NAME test_run_docker_bench_parser
            COMMAND ${Python3_EXECUTABLE}
                    ${CMAKE_SOURCE_DIR}/tests/test_run_docker_bench_parser.py
        )
        add_test(
            NAME test_run_docker_synthetic_soak
            COMMAND ${Python3_EXECUTABLE}
                    ${CMAKE_SOURCE_DIR}/tests/test_run_docker_synthetic_soak.py
        )
        add_test(
            NAME test_run_docker_prod_check_protocol
            COMMAND ${Python3_EXECUTABLE}
                    ${CMAKE_SOURCE_DIR}/tests/test_run_docker_prod_check_protocol.py
        )
        add_test(
            NAME test_run_llps_verification_suite
            COMMAND ${Python3_EXECUTABLE}
                    ${CMAKE_SOURCE_DIR}/tests/test_run_llps_verification_suite.py
        )
        add_test(
            NAME test_run_llps_completion_audit
            COMMAND ${Python3_EXECUTABLE}
                    ${CMAKE_SOURCE_DIR}/tests/test_run_llps_completion_audit.py
        )
        add_test(
            NAME test_docker_entrypoint_policy
            COMMAND ${Python3_EXECUTABLE}
                    ${CMAKE_SOURCE_DIR}/tests/test_docker_entrypoint_policy.py
        )
        add_test(
            NAME test_repo_layout_policy
            COMMAND ${Python3_EXECUTABLE}
                    ${CMAKE_SOURCE_DIR}/tests/test_repo_layout_policy.py
        )
    endif()

    add_custom_target(coverage
        COMMAND ./test_llps
        COMMENT "Running Tests"
    )
endif()
