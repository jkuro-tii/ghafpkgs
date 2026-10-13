# Copyright 2026 TII (SSRC) and the Ghaf contributors
# SPDX-License-Identifier: Apache-2.0
{
  stdenv,
  cmake,
  pkg-config,
  glib,
  # gtk4,
  # util-linux,
  # librsvg,
  # cairo,
  # cppcheck,
  # valgrind,
  # dbus,
  # python3,
  # gobject-introspection,
  lib,
}:
stdenv.mkDerivation {
  pname = "led-proxy";
  version = "0.0.1";

  src = ./src;

  nativeBuildInputs = [
    cmake
    pkg-config
    cppcheck
    valgrind
  ];
  buildInputs = [
    glib
    gtk4
    util-linux
    librsvg
    cairo
  ];


  meta = {
    description = "LED proxy for Ghaf framework";
    homepage = "https://github.com/tiiuae/ghafpkgs";
    license = lib.licenses.asl20;
    platforms = lib.platforms.linux;
  };
}
