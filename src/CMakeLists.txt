find_library(CAPSTONE_LIB capstone)
if(NOT CAPSTONE_LIB)
    message(FATAL_ERROR "capstone library not found. Please install capstone (e.g. libcapstone-dev).")
endif()

set(CORE_SRC
    core/ProcessEnumerator.cpp
    core/TargetProcess.cpp
    core/MemoryScanner.cpp
    core/CodeInjector.cpp
    core/DebugWatch.cpp
    core/ScalarCodec.cpp
    core/CheatTable.cpp
    core/AutoAssembler.cpp
    core/Analysis.cpp
    core/Disassembler.cpp
    core/PointerScanner.cpp
)

set(CORE_HDR
    ${CMAKE_SOURCE_DIR}/include/core/ProcessEnumerator.h
    ${CMAKE_SOURCE_DIR}/include/core/TargetProcess.h
    ${CMAKE_SOURCE_DIR}/include/core/MemoryScanner.h
    ${CMAKE_SOURCE_DIR}/include/core/CodeInjector.h
    ${CMAKE_SOURCE_DIR}/include/core/DebugWatch.h
    ${CMAKE_SOURCE_DIR}/include/core/ScalarCodec.h
    ${CMAKE_SOURCE_DIR}/include/core/CheatTable.h
    ${CMAKE_SOURCE_DIR}/include/core/AutoAssembler.h
    ${CMAKE_SOURCE_DIR}/include/core/Analysis.h
    ${CMAKE_SOURCE_DIR}/include/core/Disassembler.h
    ${CMAKE_SOURCE_DIR}/include/core/PointerScanner.h
)

add_library(ce_core STATIC ${CORE_SRC} ${CORE_HDR})

target_include_directories(ce_core PUBLIC
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/third_party
)

target_link_libraries(ce_core PUBLIC ${CAPSTONE_LIB})

target_compile_definitions(ce_core PRIVATE _GNU_SOURCE)

set(GUI_SRC
    main.cpp
    gui/MainWindow.cpp
    gui/ProcessListModel.cpp
    gui/ProcessDialog.cpp
    gui/PointerScannerDialog.cpp
    gui/AutoAssemblerDialog.cpp
    gui/MemoryViewerWindow.cpp
    gui/ValueMonitorDialog.cpp
    gui/WatchWindow.cpp
    gui/AobInjectionDialog.cpp
)

set(GUI_HDR
    ${CMAKE_SOURCE_DIR}/include/gui/MainWindow.h
    ${CMAKE_SOURCE_DIR}/include/gui/ProcessListModel.h
    ${CMAKE_SOURCE_DIR}/include/gui/ProcessDialog.h
    ${CMAKE_SOURCE_DIR}/include/gui/PointerScannerDialog.h
    ${CMAKE_SOURCE_DIR}/include/gui/AutoAssemblerDialog.h
    ${CMAKE_SOURCE_DIR}/include/gui/MemoryViewerWindow.h
    ${CMAKE_SOURCE_DIR}/include/gui/ValueMonitorDialog.h
    ${CMAKE_SOURCE_DIR}/include/gui/WatchWindow.h
    ${CMAKE_SOURCE_DIR}/include/gui/AobInjectionDialog.h
)

add_executable(comfyengine ${GUI_SRC} ${GUI_HDR})

target_link_libraries(comfyengine PRIVATE ce_core Qt6::Widgets)

target_compile_definitions(comfyengine PRIVATE _GNU_SOURCE)

option(CE_BUILD_CLI "Build comfy CLI and comfyd daemon" ON)
if(CE_BUILD_CLI)
    add_subdirectory(cli)
endif()
