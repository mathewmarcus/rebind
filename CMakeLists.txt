cmake_minimum_required(VERSION 3.10)

project(rebind VERSION 0.1.0)

find_file(CAP_H sys/capability.h)
find_library(LIBCAP libcap.so)

if (CAP_H AND LIBCAP)
    set(CAP_FOUND TRUE)
else()
    set(CAP_FOUND FALSE)
endif()

add_library(_rebind_rr OBJECT src/_rebind_rr.h src/_rebind_rr.c)

configure_file(src/rebind.h.in ${CMAKE_SOURCE_DIR}/src/rebind.h @ONLY)

add_executable(rebind src/main.c)

if (CAP_FOUND)
    target_link_libraries(rebind ${LIBCAP} m _rebind_rr)
    install(TARGETS rebind RUNTIME)
    install(CODE "execute_process(COMMAND setcap \"cap_net_bind_service=p\" ${CMAKE_INSTALL_PREFIX}/bin/rebind)")
else()
    install(TARGETS rebind RUNTIME PERMISSIONS SETUID OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
endif()

