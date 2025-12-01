# CMake script for gamepwnage
# https://github.com/bitwaree/gamepwnage

cmake_minimum_required(VERSION 3.20)

# project config
project(gamepwnage VERSION 0.0.0)

# build lib
if(WIN32)
    # in case of windows
    # configure the source files
    set(SOURCE_FILES "src/windows/mem.c" "src/windows/mem_ex.c" "src/windows/nop.c" "src/windows/nop_ex.c" "src/windows/hook86.c")
    set(HEADER_FILES "src/windows/mem.h" "src/windows/nop.h" "src/windows/hook86.h")
    # set visual studio flags
    if(MSVC)
        # Set the C and C++ compiler flags
        # set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /MT")
        # set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /MT")
        set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded")
    endif()

    # Set the runtime library to static for all configurations
    # set(CMAKE_C_RUNTIME_LIBRARY "Multi-Threaded")
    # set(CMAKE_CXX_RUNTIME_LIBRARY "Multi-Threaded")
    # build the lib
    if(BUILD_SHARED_LIB MATCHES "true")
        add_definitions("-DSHARED_LIB")
        add_library(gamepwnage SHARED ${SOURCE_FILES})
    else()
        # in case of dll
        # add_definitions("-DSTATIC_LIB")
        add_library(gamepwnage STATIC ${SOURCE_FILES})
    endif()

    install(FILES ${HEADER_FILES} DESTINATION include/gamepwnage)
    install(TARGETS gamepwnage LIBRARY DESTINATION lib)

else()
    # in case of unix based systems

    set(SOURCE_FILES "src/mem.c" "src/nop.c" "src/proc.c" "src/dynlib.c")
    set(HEADER_FILES "src/config.h" "src/mem.h" "src/nop.h" "src/proc.h" "src/dynlib.h")

    # set arm specific stuffs
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "arm" OR CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64")
        # if it's arm and unix like system
        set(SOURCE_FILES ${SOURCE_FILES} "src/armhook.c")
	set(HEADER_FILES ${HEADER_FILES} "src/armhook.h")
    endif()
    # set x86 specific files
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64" OR CMAKE_SYSTEM_PROCESSOR MATCHES "i386")
        # if it's x86 and unix like system
        set(SOURCE_FILES ${SOURCE_FILES} "src/hook86.c")
	set(HEADER_FILES ${HEADER_FILES} "src/hook86.h")
    endif()

    if(BUILD_SHARED_LIB MATCHES "true")
        add_library(gamepwnage SHARED ${SOURCE_FILES})
    else()
        # set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DSHARED_LIB")
        # set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DSHARED_LIB")
        add_library(gamepwnage STATIC ${SOURCE_FILES})
    endif()
    # install script
    install(FILES ${HEADER_FILES} DESTINATION include/gamepwnage)
    install(TARGETS gamepwnage LIBRARY DESTINATION lib)
endif()

