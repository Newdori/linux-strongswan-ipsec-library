cmake_minimum_required(VERSION 3.16)

project(ipsec_native VERSION 0.1.0 LANGUAGES C)

include(GNUInstallDirs)
include(CTest)
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

option(IPSEC_NATIVE_BUILD_APPLICATION "Build the v15-compatible CLI application" ON)
option(IPSEC_NATIVE_BUILD_INTEGRATION_TESTS
       "Build tests that require a configured live strongSwan peer" OFF)

set(IPSEC_NATIVE_SOURCES
    core/error.c
    core/ipsec.c
    core/log.c
    core/netlink.c
    core/util.c
    vici/vici_algorithm.c
    vici/vici_client.c
    vici/vici_connection.c
    vici/vici_credential.c
    vici/vici_packet.c
    vici/vici_parser.c
    vici/vici_sa.c
    vici/vici_stats.c
    vici/vici_transport.c
    xfrm/xfrm_policy.c
    xfrm/xfrm_state.c
    xfrm/xfrm_stats.c
    route/address.c
    route/interface.c
    route/route.c)

add_library(ipsec_native_objects OBJECT ${IPSEC_NATIVE_SOURCES})
set_target_properties(ipsec_native_objects PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED YES
    C_EXTENSIONS NO
    POSITION_INDEPENDENT_CODE YES)
target_include_directories(ipsec_native_objects
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/../include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/internal
        ${CMAKE_CURRENT_SOURCE_DIR}/vici
        ${CMAKE_CURRENT_SOURCE_DIR}/xfrm
        ${CMAKE_CURRENT_SOURCE_DIR}/route)
target_compile_definitions(ipsec_native_objects PRIVATE
    _POSIX_C_SOURCE=200809L)
target_compile_options(ipsec_native_objects PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -Werror)

add_library(ipsec_native_static STATIC
    $<TARGET_OBJECTS:ipsec_native_objects>)
set_target_properties(ipsec_native_static PROPERTIES
    OUTPUT_NAME ipsec)
target_include_directories(ipsec_native_static PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
target_link_libraries(ipsec_native_static PUBLIC Threads::Threads)

add_library(ipsec_native_shared SHARED
    $<TARGET_OBJECTS:ipsec_native_objects>)
set_target_properties(ipsec_native_shared PROPERTIES
    OUTPUT_NAME ipsec
    VERSION ${PROJECT_VERSION}
    SOVERSION 0)
target_include_directories(ipsec_native_shared PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
target_link_libraries(ipsec_native_shared PUBLIC Threads::Threads)
target_link_options(ipsec_native_shared PRIVATE
    "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/libipsec.map")

install(TARGETS ipsec_native_static ipsec_native_shared
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(FILES
    ../include/ipsec.h
    ../include/ipsec_error.h
    ../include/ipsec_types.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

if(IPSEC_NATIVE_BUILD_APPLICATION)
    add_executable(ipsec_app
        ../apps/cli.c
        ../apps/command.c
        ../apps/config.c
        ../apps/lifecycle.c
        ../apps/status.c
        ../apps/main.c)
    set_target_properties(ipsec_app PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED YES
        C_EXTENSIONS NO)
    target_compile_definitions(ipsec_app PRIVATE
        _POSIX_C_SOURCE=200809L)
    target_compile_options(ipsec_app PRIVATE
        -Wall -Wextra -Wpedantic -Werror)
    target_include_directories(ipsec_app PRIVATE
        ../apps)
    target_link_libraries(ipsec_app PRIVATE ipsec_native_static)
endif()

if(BUILD_TESTING)
    add_executable(test_app_loop
        ../tests/unit/test_app_loop.c
        ../apps/lifecycle.c)
    set_target_properties(test_app_loop PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED YES
        C_EXTENSIONS NO)
    target_compile_definitions(test_app_loop PRIVATE
        _POSIX_C_SOURCE=200809L)
    target_compile_options(test_app_loop PRIVATE
        -Wall -Wextra -Wpedantic -Werror)
    target_include_directories(test_app_loop PRIVATE
        ../include ../apps)
    add_test(NAME app_loop COMMAND test_app_loop)

    add_executable(test_app_config
        ../tests/unit/test_app_config.c
        ../apps/config.c)
    set_target_properties(test_app_config PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED YES
        C_EXTENSIONS NO)
    target_compile_definitions(test_app_config PRIVATE
        _POSIX_C_SOURCE=200809L)
    target_compile_options(test_app_config PRIVATE
        -Wall -Wextra -Wpedantic -Werror)
    target_include_directories(test_app_config PRIVATE
        ../include ../apps)
    add_test(NAME app_config COMMAND test_app_config
        ${CMAKE_CURRENT_SOURCE_DIR}/../tests/fixtures/v15_endpoint.conf)

    add_executable(test_app_command
        ../tests/unit/test_app_command.c
        ../apps/command.c)
    set_target_properties(test_app_command PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED YES
        C_EXTENSIONS NO)
    target_compile_definitions(test_app_command PRIVATE
        _POSIX_C_SOURCE=200809L)
    target_compile_options(test_app_command PRIVATE
        -Wall -Wextra -Wpedantic -Werror)
    target_include_directories(test_app_command PRIVATE
        ../include ../apps)
    add_test(NAME app_command COMMAND test_app_command)

    add_executable(test_vici_packet
        ../tests/unit/test_vici_packet.c
        core/util.c
        vici/vici_packet.c
        vici/vici_parser.c)
    set_target_properties(test_vici_packet PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED YES
        C_EXTENSIONS NO)
    target_compile_definitions(test_vici_packet PRIVATE
        _POSIX_C_SOURCE=200809L)
    target_compile_options(test_vici_packet PRIVATE
        -Wall -Wextra -Wpedantic -Werror)
    target_include_directories(test_vici_packet PRIVATE
        ../include internal vici)
    target_link_libraries(test_vici_packet PRIVATE Threads::Threads)
    add_test(NAME vici_packet COMMAND test_vici_packet)

    add_executable(test_xfrm_stats
        ../tests/unit/test_xfrm_stats.c
        core/util.c
        xfrm/xfrm_stats.c)
    set_target_properties(test_xfrm_stats PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED YES
        C_EXTENSIONS NO)
    target_compile_definitions(test_xfrm_stats PRIVATE
        _POSIX_C_SOURCE=200809L)
    target_compile_options(test_xfrm_stats PRIVATE
        -Wall -Wextra -Wpedantic -Werror)
    target_include_directories(test_xfrm_stats PRIVATE
        ../include internal xfrm)
    target_link_libraries(test_xfrm_stats PRIVATE Threads::Threads)
    add_test(NAME xfrm_stats COMMAND test_xfrm_stats)

    add_executable(test_xfrm_netlink
        ../tests/unit/test_xfrm_netlink.c)
    add_executable(test_route_netlink
        ../tests/unit/test_route_netlink.c)
    foreach(IPSEC_NATIVE_NETLINK_TEST test_xfrm_netlink test_route_netlink)
        set_target_properties(${IPSEC_NATIVE_NETLINK_TEST} PROPERTIES
            C_STANDARD 11
            C_STANDARD_REQUIRED YES
            C_EXTENSIONS NO)
        target_compile_options(${IPSEC_NATIVE_NETLINK_TEST} PRIVATE
            -Wall -Wextra -Wpedantic -Werror)
        target_include_directories(${IPSEC_NATIVE_NETLINK_TEST} PRIVATE
            ../include internal xfrm route)
        target_link_libraries(${IPSEC_NATIVE_NETLINK_TEST} PRIVATE
            ipsec_native_static)
    endforeach()
    add_test(NAME xfrm_netlink COMMAND test_xfrm_netlink)
    add_test(NAME route_netlink COMMAND test_route_netlink)

    if(IPSEC_NATIVE_BUILD_INTEGRATION_TESTS)
        add_executable(test_live_ipsec ../tests/integration/test_live_ipsec.c)
        set_target_properties(test_live_ipsec PROPERTIES
            C_STANDARD 11
            C_STANDARD_REQUIRED YES
            C_EXTENSIONS NO)
        target_compile_definitions(test_live_ipsec PRIVATE
            _POSIX_C_SOURCE=200809L)
        target_compile_options(test_live_ipsec PRIVATE
            -Wall -Wextra -Wpedantic -Werror)
        target_link_libraries(test_live_ipsec PRIVATE ipsec_native_static)
    endif()
endif()
