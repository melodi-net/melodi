{
  description = "Melodi external-module development shell";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs?rev=4c1018dae018162ec878d42fec712642d214fdfa";
    flake-utils.url = "github:numtide/flake-utils";

    sparse-src = {
      url = "git+https://git.kernel.org/pub/scm/devel/sparse/sparse.git?rev=37156835e3d725b6d750f000be33ba3814bb2310";
      flake = false;
    };

    meshtastic-protobufs = {
      url = "github:meshtastic/protobufs";
      flake = false;
    };
  };

  outputs =
    { nixpkgs, flake-utils, meshtastic-protobufs, sparse-src, ... }:
    flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-linux" ] (
      system:
      let
        pkgs = import nixpkgs { inherit system; };
        sparse-current = pkgs.sparse.overrideAttrs (_: {
          version = "0.6.4-unstable-37156835";
          src = sparse-src;
        });
      in
      {
        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            bc
            bear
            ccache
            clang-tools
            cppcheck
            elfutils
            ethtool
            gcc
            go
            gnumake
            iproute2
            kmod
            libsodium
            openssl
            pahole
            pkg-config
            qemu
            rustc
            cargo
            sparse-current
            swtpm
            tpm2-tools
            udev
            usbutils
            zig
            meshtastic
          ];

          MESHTASTIC_PROTO_DIR = "${meshtastic-protobufs}";

          shellHook = ''
            echo "melodi: external modules use /lib/modules/$(uname -r)/build"
            echo "melodi: Meshtastic schemas $MESHTASTIC_PROTO_DIR"
          '';
        };
      }
    );
}
