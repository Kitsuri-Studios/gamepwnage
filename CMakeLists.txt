cmake_minimum_required(VERSION 3.20)

project(gamepwnage
    VERSION 1.0.0
    LANGUAGES C
    DESCRIPTION "Cross Platform Game Hacking API(s)"
)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

if(BUILD_SHARED_LIB MATCHES "true")
    set(GAMEPWNAGE_BUILD_SHARED ON CACHE BOOL "" FORCE)
endif()
if(GPWN_DEBUG_BUILD MATCHES "true")
    set(GAMEPWNAGE_DEBUG ON CACHE BOOL "" FORCE)
endif()
if(USING_SIMD MATCHES "true")
    set(GAMEPWNAGE_ENABLE_SIMD ON CACHE BOOL "" FORCE)
endif()

option(GAMEPWNAGE_BUILD_SHARED "Build shared library instead of static" OFF)
option(GAMEPWNAGE_ENABLE_SIMD "Enable SIMD optimizations (NEON/AVX2)" OFF)
option(GAMEPWNAGE_DEBUG "Enable debug logging" OFF)

set(GAMEPWNAGE_SOURCES
    src/dynlib.c
    src/extras.c
    src/inlinehook.c
    src/mem.c
    src/memscan.c
    src/nop.c
    src/plthook.c
    src/proc.c
    src/vftable.c
)

set(GAMEPWNAGE_HEADERS
    include/gamepwnage/config.h
    include/gamepwnage/dynlib.h
    include/gamepwnage/extras.h
    include/gamepwnage/inlinehook.h
    include/gamepwnage/mem.h
    include/gamepwnage/memscan.h
    include/gamepwnage/nop.h
    include/gamepwnage/plthook.h
    include/gamepwnage/proc.h
    include/gamepwnage/vftable.h
)

if(CMAKE_SYSTEM_PROCESSOR MATCHES "arm" OR CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64")
    list(APPEND GAMEPWNAGE_SOURCES src/armhook.c)
    list(APPEND GAMEPWNAGE_HEADERS include/gamepwnage/armhook.h)
endif()

if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64" OR CMAKE_SYSTEM_PROCESSOR MATCHES "i386")
    list(APPEND GAMEPWNAGE_SOURCES src/hook86.c)
    list(APPEND GAMEPWNAGE_HEADERS include/gamepwnage/hook86.h)
endif()

if(GAMEPWNAGE_BUILD_SHARED)
    add_library(gamepwnage SHARED ${GAMEPWNAGE_SOURCES})
else()
    add_library(gamepwnage STATIC ${GAMEPWNAGE_SOURCES})
endif()

add_library(gamepwnage::gamepwnage ALIAS gamepwnage)

set_target_properties(gamepwnage PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED ON
    C_EXTENSIONS ON
    POSITION_INDEPENDENT_CODE ON
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
)

target_include_directories(gamepwnage
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include/gamepwnage>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/gamepwnage>
)

target_compile_definitions(gamepwnage
    PRIVATE GPWN_USING_BUILD_CONFIG
)

if(GAMEPWNAGE_DEBUG)
    target_compile_definitions(gamepwnage PRIVATE GPWN_DEBUG)
endif()

if(GAMEPWNAGE_BUILD_SHARED)
    target_compile_definitions(gamepwnage PRIVATE EXPORT_SYM)
endif()

if(GAMEPWNAGE_ENABLE_SIMD)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "arm" OR CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64")
        target_compile_definitions(gamepwnage PRIVATE USING_NEON)
        target_compile_options(gamepwnage PRIVATE -mfpu=neon -mfloat-abi=hard)
    endif()
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64" OR CMAKE_SYSTEM_PROCESSOR MATCHES "i386")
        target_compile_definitions(gamepwnage PRIVATE USING_AVX2)
        target_compile_options(gamepwnage PRIVATE -mavx2)
    endif()
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(gamepwnage PRIVATE dl)
endif()

install(
    TARGETS gamepwnage
    EXPORT gamepwnageTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(
    FILES ${GAMEPWNAGE_HEADERS}
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/gamepwnage
)

install(
    EXPORT gamepwnageTargets
    FILE gamepwnageTargets.cmake
    NAMESPACE gamepwnage::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/gamepwnage
)

configure_package_config_file(
    cmake/gamepwnageConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/gamepwnageConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/gamepwnage
)

write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/gamepwnageConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(
    FILES
        ${CMAKE_CURRENT_BINARY_DIR}/gamepwnageConfig.cmake
        ${CMAKE_CURRENT_BINARY_DIR}/gamepwnageConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/gamepwnage
)

install(
    FILES LICENSE
    DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/licenses/gamepwnage
)
