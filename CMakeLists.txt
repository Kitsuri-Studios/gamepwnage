# CMake script for gamepwnage
# https://github.com/bitwaree/gamepwnage

cmake_minimum_required(VERSION 3.20)

# project config
project(gamepwnage VERSION 0.0.0)

if(WIN32)
    message(FATAL_ERROR "Windows builds are not supported yet.")
endif()

set(CMAKE_POSITION_INDEPENDENT_CODE ON)
add_compile_definitions(-DGPWN_USING_BUILD_CONFIG)

# enable debug
if(GPWN_DEBUG_BUILD MATCHES "true")
    add_compile_definitions(-DGPWN_DEBUG)
endif()

if(USING_SIMD MATCHES "true")
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "arm" OR CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64")
        add_compile_definitions(-DUSING_NEON)
        add_compile_options(-mfpu=neon -mfloat-abi=hard)
    endif()
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64" OR CMAKE_SYSTEM_PROCESSOR MATCHES "i386")
        add_compile_definitions(-DUSING_AVX2)
        add_compile_options(-mavx2)
    endif()
endif()

set(SOURCE_FILES
    "src/dynlib.c"
    "src/extras.c"
    "src/inlinehook.c"
    "src/mem.c"
    "src/memscan.c"
    "src/nop.c"
    "src/plthook.c"
    "src/proc.c"
    "src/vftable.c")

set(HEADER_FILES
    "include/gamepwnage/dynlib.h"
    "include/gamepwnage/extras.h"
    "include/gamepwnage/inlinehook.h"
    "include/gamepwnage/mem.h"
    "include/gamepwnage/memscan.h"
    "include/gamepwnage/nop.h"
    "include/gamepwnage/plthook.h"
    "include/gamepwnage/proc.h"
    "include/gamepwnage/vftable.h")

if(CMAKE_SYSTEM_PROCESSOR MATCHES "arm" OR CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64")
    set(SOURCE_FILES ${SOURCE_FILES} "src/armhook.c")
    set(HEADER_FILES ${HEADER_FILES}
        "include/gamepwnage/armhook.h"
        "include/gamepwnage/reloc64.h")
endif()

if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64" OR CMAKE_SYSTEM_PROCESSOR MATCHES "i386")
    set(SOURCE_FILES ${SOURCE_FILES} "src/hook86.c")
    set(HEADER_FILES ${HEADER_FILES} "include/gamepwnage/hook86.h")
endif()

if(BUILD_SHARED_LIB MATCHES "true")
    add_library(gamepwnage SHARED ${SOURCE_FILES})
    add_definitions(-DEXPORT_SYM)
else()
    add_library(gamepwnage STATIC ${SOURCE_FILES})
endif()

target_include_directories(gamepwnage PUBLIC "include/gamepwnage")
install(FILES ${HEADER_FILES} DESTINATION include/gamepwnage)
install(TARGETS gamepwnage LIBRARY DESTINATION lib)
