set(CLI_COMMON_SRC
    common/Cli.cpp
    common/PatchStore.cpp
    common/Stateless.cpp
    common/Ipc.cpp
)

set(CLI_COMMON_HDR
    common/Cli.h
    common/PatchStore.h
    common/Ipc.h
)

set(CLI_DAEMON_SRC
    daemon/Sessions.cpp
    daemon/SessionCmds.cpp
)

set(CLI_DAEMON_HDR
    daemon/Sessions.h
)

add_library(ce_cli STATIC
    ${CLI_COMMON_SRC} ${CLI_COMMON_HDR}
    ${CLI_DAEMON_SRC} ${CLI_DAEMON_HDR}
)

target_link_libraries(ce_cli PUBLIC ce_core)

target_compile_definitions(ce_cli PRIVATE _GNU_SOURCE)

add_executable(comfy client/ClientMain.cpp)
target_link_libraries(comfy PRIVATE ce_cli)

add_executable(comfyd daemon/DaemonMain.cpp)
target_link_libraries(comfyd PRIVATE ce_cli)
