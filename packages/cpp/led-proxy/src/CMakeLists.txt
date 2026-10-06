# SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors
# SPDX-License-Identifier: Apache-2.0
cmake_minimum_required(VERSION 3.16)
project(leds-proxy C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Different flags for different build types
set(CMAKE_C_FLAGS_DEBUG "-g -O0 -DDEBUG -Wall -Wextra")
set(CMAKE_C_FLAGS_RELEASE "-O2 -DNDEBUG")
set(CMAKE_C_FLAGS_RELWITHDEBINFO "-O2 -g -DNDEBUG")
set(CMAKE_C_FLAGS_MINSIZEREL "-Os -DNDEBUG")

    # find_package(PkgConfig REQUIRED)
    # pkg_check_modules(GIO        REQUIRED IMPORTED_TARGET gio-2.0)
    # pkg_check_modules(GLIB       REQUIRED IMPORTED_TARGET glib-2.0)
    # pkg_check_modules(GTK4       REQUIRED IMPORTED_TARGET gtk4)
    # pkg_check_modules(RSVG       REQUIRED IMPORTED_TARGET librsvg-2.0)
    # pkg_check_modules(CAIRO      REQUIRED IMPORTED_TARGET cairo)

add_executable(host-led-proxy
    common/protocol.c
    common/protocol.h
    host/leds.c
    host/main.c
)

add_executable(guest-led-proxy
    common/protocol.c
    common/protocol.h
    guest/uleds.c
    guest/main.c
)

target_include_directories(host-led-proxy PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/common
)
target_include_directories(guest-led-proxy PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/common
)

target_compile_options(host-led-proxy PRIVATE -Wall -Wextra)
target_compile_options(guest-led-proxy PRIVATE -Wall -Wextra)

# target_link_libraries(dbus-proxy PRIVATE
#     PkgConfig::GIO
#     PkgConfig::GLIB
#     PkgConfig::GTK4
#     PkgConfig::RSVG
#     PkgConfig::CAIRO
# )

install(TARGETS host-led-proxy RUNTIME DESTINATION bin)
install(TARGETS guest-led-proxy RUNTIME DESTINATION bin)
