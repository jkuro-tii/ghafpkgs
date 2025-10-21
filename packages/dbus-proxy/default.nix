# Copyright 2025 TII (SSRC) and the Ghaf contributors
# SPDX-License-Identifier: Apache-2.0
{
  stdenv,
  cmake,
  gcc,
  pkgs,
  lib,
  ...
}:
stdenv.mkDerivation {
  name = "dbus-proxy";

  src = ./dbus-proxy;

  nativeBuildInputs = [ cmake ];
  sourceRoot = "./dbus-proxy";
  cmakeFlags = [
    "-DCMAKE_BUILD_TYPE=Release"
    "-DBUILD_SHARED_LIBS=ON"
  ];
  installPhase = ''
    mkdir -p $out/bin
    install -Dm755 dbus-proxy $out/bin/dbus-proxy
  '';
  meta = {
    description = "DBus proxy";
    platforms = [
      "x86_64-linux"
      "aarch64-linux"
    ];
    license = lib.licenses.asl20;
    mainProgram = "dbus-proxy";
  };
}
