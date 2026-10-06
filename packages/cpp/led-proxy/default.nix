# Copyright 2026 TII (SSRC) and the Ghaf contributors
# SPDX-License-Identifier: Apache-2.0
{
  stdenv,
  alsa-utils,
  cmake,
  coreutils,
  glib,
  gnused,
  makeWrapper,
  pkg-config,
  util-linux,
  lib,
}:
stdenv.mkDerivation {
  pname = "led-proxy";
  version = "0.0.1";

  src = ./src;

  # Set CMake build type
  cmakeFlags = [
    "-DCMAKE_BUILD_TYPE=Release"
  ];
  nativeBuildInputs = [
    cmake
    pkg-config
    makeWrapper
  ];
  buildInputs = [
    glib
    util-linux
  ];

  postInstall = ''
    # use the above src variable
      install -Dm755 $src/setup-audio-led \
        $out/bin/setup-audio-led

      wrapProgram $out/bin/setup-audio-led \
        --prefix PATH : ${
          lib.makeBinPath [
            alsa-utils
            gnused
            coreutils
          ]
        }
  '';

  meta = {
    description = "LED proxy for Ghaf framework";
    homepage = "https://github.com/tiiuae/ghafpkgs";
    license = lib.licenses.asl20;
    platforms = lib.platforms.linux;
  };
}
