{
  description = "Melodi development shell";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs?rev=4c1018dae018162ec878d42fec712642d214fdfa";
    flake-utils.url = "github:numtide/flake-utils";

    meshtastic-protobufs = {
      url = "github:meshtastic/protobufs";
      flake = false;
    };

    # Runtime sources, version-matched to the packaged generator, for instrumented builds.
    nanopb-src = {
      url = "github:nanopb/nanopb/0.4.9.1";
      flake = false;
    };
  };

  outputs =
    { nixpkgs, flake-utils, meshtastic-protobufs, nanopb-src, ... }:
    flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-linux" ] (
      system:
      let
        pkgs = import nixpkgs { inherit system; };

        # The packaged generator's shim resolves its python module relative to its own
        # realpath and misses it, so PYTHONPATH is set explicitly.
        nanopbPath = "${pkgs.nanopb.python-module}/${pkgs.python3.sitePackages}";
        nanopbGenerator = pkgs.writeShellScriptBin "protoc-gen-nanopb" ''
          export PYTHONPATH="${nanopbPath}''${PYTHONPATH:+:$PYTHONPATH}"
          exec ${pkgs.nanopb.generator}/bin/protoc-gen-nanopb "$@"
        '';
        nanopbCli = pkgs.writeShellScriptBin "nanopb_generator" ''
          export PYTHONPATH="${nanopbPath}''${PYTHONPATH:+:$PYTHONPATH}"
          exec ${pkgs.nanopb.generator}/bin/nanopb_generator "$@"
        '';

        # Freestanding C99 codec, C++20 daemon, kernel module from Phase 6.
        toolchain = with pkgs; [
          cmake
          ninja
          pkg-config
          gnumake
          mold
          ccache
          bear
        ];

        libs = [
          nanopbGenerator
          nanopbCli
          pkgs.nanopb.runtime
          pkgs.protobuf
          pkgs.libsodium
          pkgs.monocypher
        ];

        # doctest and catch2 both present so Phase 1 can pick either.
        testing = with pkgs; [
          doctest
          catch2_3
          aflplusplus
          honggfuzz
          gcovr
          lcov
        ];

        analysis = with pkgs; [
          clang-tools
          cppcheck
          include-what-you-use
          gdb
          valgrind
          strace
        ];

        # meshtasticd -s drives the simulated mesh; the python CLI configures real radios.
        meshtasticTools = with pkgs; [
          meshtasticd
          meshtastic
          picotool
          esptool
        ];

        # Serial and packet inspection against the attached radio.
        diagnostics = with pkgs; [
          tio
          picocom
          socat
          usbutils
          tcpdump
          wireshark-cli
        ];

        kernelDev = with pkgs; [
          linuxHeaders
          kmod
          iproute2
        ];
      in
      {
        devShells.default = pkgs.mkShell.override { stdenv = pkgs.clangStdenv; } {
          packages =
            toolchain ++ libs ++ testing ++ analysis
            ++ meshtasticTools ++ diagnostics ++ kernelDev;

          # protoc include root: the protos import as "meshtastic/x.proto".
          MESHTASTIC_PROTO_DIR = "${meshtastic-protobufs}";
          # Prebuilt runtime for the daemon; sources for sanitizer-instrumented builds.
          NANOPB_INCLUDE = "${pkgs.nanopb.runtime}/include/nanopb";
          NANOPB_LIB = "${pkgs.nanopb.runtime}/lib";
          NANOPB_SRC = "${nanopb-src}";
          NANOPB_PROTO = "${pkgs.nanopb}/share/nanopb/generator/proto";
          MELODI_SERIAL_DEFAULT = "/dev/serial/by-id";

          shellHook = ''
            echo "melodi: clang ${pkgs.clang.version}, meshtasticd ${pkgs.meshtasticd.version}"
            echo "melodi: protos   $MESHTASTIC_PROTO_DIR"
            echo "melodi: nanopb   $NANOPB_SRC"
          '';
        };
      }
    );
}
