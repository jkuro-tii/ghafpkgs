# SPDX-FileCopyrightText: 2022-2026 TII (CRC) and the Ghaf contributors
# SPDX-License-Identifier: Apache-2.0
cmake_minimum_required(VERSION 3.16)
project(leds-proxy C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Default to a Debug build when no build type is specified on the command
# line (e.g. plain `cmake ..` without -DCMAKE_BUILD_TYPE=...).
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
endif()

# Different flags for different build types
set(CMAKE_C_FLAGS_DEBUG "-g -O0 -DDEBUG -Wall -Wextra")
set(CMAKE_C_FLAGS_RELEASE "-O2 -DNDEBUG")
set(CMAKE_C_FLAGS_RELWITHDEBINFO "-O2 -g -DNDEBUG")
set(CMAKE_C_FLAGS_MINSIZEREL "-Os -DNDEBUG")

add_executable(host-led-proxy
    leds-host.c
)

add_executable(guest-led-proxy
    leds-guest.c
)

target_include_directories(host-led-proxy PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)
target_include_directories(guest-led-proxy PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_compile_options(host-led-proxy PRIVATE -Wall -Wextra)
target_compile_options(guest-led-proxy PRIVATE -Wall -Wextra)

install(TARGETS host-led-proxy RUNTIME DESTINATION bin)
install(TARGETS guest-led-proxy RUNTIME DESTINATION bin)
