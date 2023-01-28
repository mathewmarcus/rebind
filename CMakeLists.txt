cmake_minimum_required(VERSION 3.10)

project(rebind VERSION 0.1.0 LANGUAGES C)

find_file(CAP_H sys/capability.h)
find_library(LIBCAP libcap.so)

if (CAP_H AND LIBCAP)
    set(CAP_FOUND TRUE)
else()
    set(CAP_FOUND FALSE)
endif()

configure_file(src/_rebind_privs.h.in ${CMAKE_SOURCE_DIR}/src/_rebind_privs.h @ONLY)

add_library(_rebind_rr OBJECT src/_rebind_rr.h src/_rebind_rr.c)
add_library(_rebind_privs OBJECT src/_rebind_privs.h src/_rebind_privs.c)
add_library(_rebind_query OBJECT src/_rebind_query.h src/_rebind_query.c)
add_library(_rebind OBJECT src/rebind.h src/_rebind.c)

add_executable(rebind src/main.c)

if (${CMAKE_BUILD_TYPE} AND ${CMAKE_BUILD_TYPE} STREQUAL "Release")
    target_link_options(rebind PRIVATE "-s")
endif()

target_link_libraries(rebind m _rebind_rr _rebind_privs _rebind_query _rebind)

if (CAP_FOUND)
    target_link_libraries(rebind ${LIBCAP})
    install(TARGETS rebind RUNTIME)
    install(CODE "execute_process(COMMAND setcap \"cap_net_bind_service=p\" ${CMAKE_INSTALL_PREFIX}/bin/rebind)")
else()
    install(TARGETS rebind RUNTIME PERMISSIONS SETUID OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
endif()

