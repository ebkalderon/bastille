let
  moz_overlay = import (builtins.fetchTarball https://github.com/mozilla/nixpkgs-mozilla/archive/master.tar.gz);
  pkgs = import <nixpkgs> { overlays = [ moz_overlay ]; };
in
  with pkgs;
  pkgs.mkShell {
    buildInputs = [
      (rustChannelOf { channel = "stable"; }).rust
      osxfuse
      pkg-config
    ] ++ lib.optionals stdenv.isDarwin [
      darwin.apple_sdk.frameworks.Security
      darwin.apple_sdk.frameworks.CoreServices
    ];
  }
