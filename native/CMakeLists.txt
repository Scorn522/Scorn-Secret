cmake_minimum_required(VERSION 3.20)

project(himitsu LANGUAGES C CXX)

find_package(JNI REQUIRED)

option(HIMITSU_LLVM_OBFUSCATION "Enable selective OLLVM-compatible passes" OFF)
option(HIMITSU_PROTECTION_SYMBOLS "Generate PDB/MAP files for protector function selection" OFF)
option(HIMITSU_BUILD_AUTH_TEST "Build the native authentication integration test" OFF)
option(HIMITSU_LOCAL_TEST "Use standalone development capabilities, without a remote license service" OFF)
set(
    HIMITSU_LLVM_STRONG_FLAGS
    "-mllvm;-enable-fla;-mllvm;-enable-bcf;-mllvm;-enable-sub;-mllvm;-enable-sobf;-mllvm;-enable-indibran"
    CACHE STRING
    "Semicolon-separated compiler flags for strongly protected sources"
)
set(
    HIMITSU_LLVM_MEDIUM_FLAGS
    "-mllvm;-enable-sub;-mllvm;-enable-sobf"
    CACHE STRING
    "Semicolon-separated compiler flags for medium protected sources"
)
set(
    HIMITSU_LLVM_AUTH_FLAGS
    "-mllvm;-enable-sub"
    CACHE STRING
    "Compiler flags for the WinHTTP/exception-heavy authentication client"
)
set(
    HIMITSU_LLVM_EXCEPTION_STRONG_FLAGS
    "-mllvm;-enable-fla;-mllvm;-enable-bcf;-mllvm;-enable-sub;-mllvm;-enable-constenc"
    CACHE STRING
    "Full protection profile for exception-boundary sources"
)
set(
    HIMITSU_LLVM_CRYPTO_STRONG_FLAGS
    "-mllvm;-enable-fla;-mllvm;-enable-bcf;-mllvm;-enable-sub;-mllvm;-enable-constenc;-mllvm;-enable-indibran"
    CACHE STRING
    "Full structural protection profile for crypto and device sources"
)
set(NATIVE_BRIDGE_CLASS
    "${CMAKE_CURRENT_SOURCE_DIR}/../build/classes/java/main/com/himitsu/secret/bridge/NativeBridge.class"
)
set(EMBEDDED_BRIDGE_HEADER
    "${CMAKE_CURRENT_BINARY_DIR}/generated/himitsu/embedded/native_bridge_class.hpp"
)
set(LOGIN_PIG_SPRITE "${CMAKE_CURRENT_SOURCE_DIR}/assets/zhu_spritesheet.png")
set(EMBEDDED_LOGIN_PIG_HEADER
    "${CMAKE_CURRENT_BINARY_DIR}/generated/himitsu/embedded/login_pig_sprite.hpp"
)
set(BUILD_INFO_HEADER
    "${CMAKE_CURRENT_BINARY_DIR}/generated/himitsu/build_info.hpp"
)

add_custom_target(himitsu_build_info
    COMMAND ${CMAKE_COMMAND}
        "-DOUTPUT=${BUILD_INFO_HEADER}"
        -P "${CMAKE_CURRENT_SOURCE_DIR}/tools/generate_build_info.cmake"
    BYPRODUCTS "${BUILD_INFO_HEADER}"
    VERBATIM
)
set_source_files_properties("${BUILD_INFO_HEADER}" PROPERTIES GENERATED TRUE)

add_custom_command(
    OUTPUT "${EMBEDDED_BRIDGE_HEADER}"
    COMMAND ${CMAKE_COMMAND} -E make_directory
        "${CMAKE_CURRENT_BINARY_DIR}/generated/himitsu/embedded"
    COMMAND ${CMAKE_COMMAND}
        -DINPUT=${NATIVE_BRIDGE_CLASS}
        -DOUTPUT=${EMBEDDED_BRIDGE_HEADER}
        -DSYMBOL=native_bridge_class
        -P "${CMAKE_CURRENT_SOURCE_DIR}/tools/embed_class.cmake"
    DEPENDS "${NATIVE_BRIDGE_CLASS}" "${CMAKE_CURRENT_SOURCE_DIR}/tools/embed_class.cmake"
    VERBATIM
)

add_custom_target(himitsu_embedded_bridge DEPENDS "${EMBEDDED_BRIDGE_HEADER}")

add_custom_command(
    OUTPUT "${EMBEDDED_LOGIN_PIG_HEADER}"
    COMMAND ${CMAKE_COMMAND} -E make_directory
        "${CMAKE_CURRENT_BINARY_DIR}/generated/himitsu/embedded"
    COMMAND ${CMAKE_COMMAND}
        -DINPUT=${LOGIN_PIG_SPRITE}
        -DOUTPUT=${EMBEDDED_LOGIN_PIG_HEADER}
        -DSYMBOL=login_pig_sprite_png
        -P "${CMAKE_CURRENT_SOURCE_DIR}/tools/embed_class.cmake"
    DEPENDS "${LOGIN_PIG_SPRITE}" "${CMAKE_CURRENT_SOURCE_DIR}/tools/embed_class.cmake"
    VERBATIM
)

add_custom_target(himitsu_embedded_login_pig DEPENDS "${EMBEDDED_LOGIN_PIG_HEADER}")

add_library(himitsu SHARED
    "${EMBEDDED_BRIDGE_HEADER}"
    "${EMBEDDED_LOGIN_PIG_HEADER}"
    "${BUILD_INFO_HEADER}"
    src/bootstrap/dll_main.cpp
    src/bootstrap/early_guard.cpp
    src/bootstrap/exports.cpp
    src/bootstrap/runtime_bootstrap.cpp
    src/core/command_dispatcher.cpp
    src/core/native_log.cpp
    src/core/runtime_state.cpp
    src/jvm/class_control.cpp
    src/jvm/java_vm.cpp
    src/jvm/jvmti_guard.cpp
    src/jvm/late_recovery.cpp
    src/jvm/source_images.cpp
    src/jvm/native_bridge.cpp
    src/platform/windows/instrumentation_guard.cpp
    src/platform/windows/directx_overlay_assets.cpp
    src/platform/windows/module_guard.cpp
    src/platform/windows/module_conceal.cpp
    src/platform/windows/swap_buffers_hook.cpp
    src/platform/windows/thread_guard.cpp
    src/validation/auth_client.cpp
    src/validation/auth_config.cpp
    src/validation/auth_crypto.cpp
    src/validation/capability_registry.cpp
    src/validation/device_identity.cpp
    src/validation/game_pause.cpp
    src/validation/integrity_check.cpp
    src/validation/validation_backend.cpp
    src/validation/validation_gate.cpp
    src/validation/runtime_lease.cpp
    src/validation/validation_ui.cpp
    third_party/imgui/imgui.cpp
    third_party/imgui/imgui_draw.cpp
    third_party/imgui/imgui_impl_dx9.cpp
    third_party/imgui/imgui_impl_win32.cpp
    third_party/imgui/imgui_tables.cpp
    third_party/imgui/imgui_widgets.cpp
    third_party/minhook/src/buffer.c
    third_party/minhook/src/hook.c
    third_party/minhook/src/trampoline.c
    third_party/minhook/src/hde/hde32.c
    third_party/minhook/src/hde/hde64.c
)
add_dependencies(himitsu himitsu_embedded_bridge himitsu_embedded_login_pig himitsu_build_info)

set(HIMITSU_STRONG_PROTECTION_SOURCES
    src/bootstrap/runtime_bootstrap.cpp
    src/core/command_dispatcher.cpp
    src/jvm/class_control.cpp
    src/platform/windows/module_conceal.cpp
    src/validation/validation_gate.cpp
    src/validation/integrity_check.cpp
)
set(HIMITSU_AUTH_STABLE_PROTECTION_SOURCES
    src/validation/auth_client.cpp
    src/validation/auth_config.cpp
    src/validation/auth_crypto.cpp
    src/validation/capability_registry.cpp
    src/validation/device_identity.cpp
    src/validation/runtime_lease.cpp
    src/validation/validation_backend.cpp
    src/validation/validation_ui.cpp
)
set(HIMITSU_MEDIUM_PROTECTION_SOURCES
    src/core/runtime_state.cpp
    src/jvm/java_vm.cpp
    src/jvm/native_bridge.cpp
)

if(HIMITSU_LLVM_OBFUSCATION)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR
            "HIMITSU_LLVM_OBFUSCATION requires a Clang/OLLVM-compatible compiler"
        )
    endif()
    set_property(
        SOURCE ${HIMITSU_STRONG_PROTECTION_SOURCES}
        APPEND PROPERTY COMPILE_OPTIONS ${HIMITSU_LLVM_STRONG_FLAGS}
    )
    set_property(
        SOURCE ${HIMITSU_MEDIUM_PROTECTION_SOURCES}
        APPEND PROPERTY COMPILE_OPTIONS ${HIMITSU_LLVM_MEDIUM_FLAGS}
    )
    set_property(
        SOURCE ${HIMITSU_AUTH_STABLE_PROTECTION_SOURCES}
        APPEND PROPERTY COMPILE_OPTIONS ${HIMITSU_LLVM_AUTH_FLAGS}
    )
    target_compile_definitions(himitsu PRIVATE HIMITSU_LLVM_OBFUSCATION=1)
    message(STATUS "Selective LLVM protection enabled")
    message(STATUS "  Strong flags: ${HIMITSU_LLVM_STRONG_FLAGS}")
    message(STATUS "  Medium flags: ${HIMITSU_LLVM_MEDIUM_FLAGS}")
    message(STATUS "  Auth stable flags: ${HIMITSU_LLVM_AUTH_FLAGS}")
endif()

target_compile_features(himitsu PRIVATE cxx_std_20)
target_compile_definitions(himitsu PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0A00 WINVER=0x0A00)
if(HIMITSU_LOCAL_TEST)
    if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../build/local-config/himitsu/local_test_build.hpp")
        message(FATAL_ERROR "Generate the local-test packaging configuration first")
    endif()
    target_compile_definitions(himitsu PRIVATE HIMITSU_LOCAL_TEST=1)
    target_include_directories(himitsu PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../build/local-config")
endif()
target_include_directories(himitsu PRIVATE
    include
    third_party/imgui
    third_party/minhook/include
    "${CMAKE_CURRENT_BINARY_DIR}/generated"
    ${JNI_INCLUDE_DIRS}
)
target_link_libraries(himitsu PRIVATE
    ${JNI_LIBRARIES}
    opengl32
    gdi32
    user32
    bcrypt
    crypt32
    ncrypt
    winhttp
    d3d9
    d3d11
    dxgi
    ole32
    windowscodecs
    dwmapi
)

set(HIMITSU_MSVC_FRONTEND OFF)
if(MSVC OR CMAKE_CXX_SIMULATE_ID STREQUAL "MSVC")
    set(HIMITSU_MSVC_FRONTEND ON)
endif()

if(HIMITSU_MSVC_FRONTEND)
    target_compile_options(himitsu PRIVATE
        $<$<COMPILE_LANGUAGE:C>:/W4>
        $<$<COMPILE_LANGUAGE:C>:/utf-8>
        $<$<COMPILE_LANGUAGE:CXX>:/W4>
        $<$<COMPILE_LANGUAGE:CXX>:/permissive->
        $<$<COMPILE_LANGUAGE:CXX>:/EHsc>
        $<$<COMPILE_LANGUAGE:CXX>:/utf-8>
    )
    if(HIMITSU_PROTECTION_SYMBOLS)
        target_compile_options(himitsu PRIVATE
            $<$<COMPILE_LANGUAGE:CXX>:/Zi>
            $<$<COMPILE_LANGUAGE:CXX>:/Gy>
        )
        target_link_options(himitsu PRIVATE
            /DEBUG:FULL
            /MAP
            /MAPINFO:EXPORTS
        )
    endif()
    set_source_files_properties(
        third_party/imgui/imgui.cpp
        third_party/imgui/imgui_draw.cpp
        third_party/imgui/imgui_impl_dx9.cpp
        third_party/imgui/imgui_impl_win32.cpp
        third_party/imgui/imgui_tables.cpp
        third_party/imgui/imgui_widgets.cpp
        PROPERTIES COMPILE_OPTIONS "/W0"
    )
else()
    target_compile_options(himitsu PRIVATE -Wall -Wextra -Wpedantic)
endif()

set_target_properties(himitsu PROPERTIES
    OUTPUT_NAME "himitsu"
    PREFIX ""
)

if(HIMITSU_BUILD_AUTH_TEST)
    add_executable(himitsu_auth_test
        tools/auth_client_test.cpp
        src/validation/auth_client.cpp
        src/validation/auth_config.cpp
        src/validation/auth_crypto.cpp
        src/validation/device_identity.cpp
    )
    target_compile_features(himitsu_auth_test PRIVATE cxx_std_20)
    target_compile_definitions(himitsu_auth_test PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
    target_include_directories(himitsu_auth_test PRIVATE include)
    target_link_libraries(himitsu_auth_test PRIVATE bcrypt crypt32 ncrypt winhttp)
    if(HIMITSU_MSVC_FRONTEND)
        target_compile_options(himitsu_auth_test PRIVATE /utf-8 /EHsc)
    endif()
endif()
