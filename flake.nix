{
  description = "ISCY development shell";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs { inherit system; };
        python = pkgs.python311;
        runtimeLibs = pkgs.lib.makeLibraryPath [
          pkgs.stdenv.cc.cc.lib
          pkgs.zlib
          pkgs.zstd
          pkgs.openssl
          pkgs.openblas
          pkgs.libpq
          pkgs.sqlite
          pkgs.libjpeg
          pkgs.freetype
        ];
        iscyBackendApp = pkgs.writeShellApplication {
          name = "iscy-backend";
          runtimeInputs = [
            pkgs.cargo
            pkgs.rustc
            pkgs.pkg-config
            pkgs.cmake
            pkgs.ninja
            pkgs.clang
            pkgs.gcc14
            pkgs.sqlite
            pkgs.libpq
            pkgs.openssl
            pkgs.openblas
          ];
          text = ''
            if [ ! -f rust/iscy-backend/Cargo.toml ]; then
              echo "Bitte aus dem ISCY-Repository-Root starten." >&2
              exit 1
            fi

            export RUST_BACKEND_BIND="''${RUST_BACKEND_BIND:-127.0.0.1:9000}"
            export DATABASE_URL="''${DATABASE_URL:-sqlite:///db.sqlite3}"
            export LD_LIBRARY_PATH="${runtimeLibs}:''${LD_LIBRARY_PATH:-}"
            export CC=${pkgs.clang}/bin/clang
            export CXX=${pkgs.clang}/bin/clang++
            export FORCE_CMAKE=1
            export CARGO_INCREMENTAL="''${CARGO_INCREMENTAL:-0}"
            export RUST_MIN_STACK="''${RUST_MIN_STACK:-67108864}"
            export CMAKE_ARGS="-DGGML_BLAS=ON -DGGML_BLAS_VENDOR=OpenBLAS -DLLAMA_BUILD_TOOLS=OFF -DLLAMA_BUILD_EXAMPLES=OFF -DLLAMA_BUILD_SERVER=OFF"

            exec cargo run --manifest-path rust/iscy-backend/Cargo.toml --bin iscy-backend -- "$@"
          '';
        };
      in
      {
        formatter = pkgs.nixfmt-rfc-style;

        apps.default = {
          type = "app";
          program = "${iscyBackendApp}/bin/iscy-backend";
        };

        apps.iscy-backend = {
          type = "app";
          program = "${iscyBackendApp}/bin/iscy-backend";
        };

        devShells.default = pkgs.mkShell {
          packages = [
            python
            pkgs.git
            pkgs.pkg-config
            pkgs.cmake
            pkgs.ninja
            pkgs.clang
            pkgs.gcc14
            pkgs.gnumake
            pkgs.rustc
            pkgs.cargo
            pkgs.rustfmt
            pkgs.clippy
            pkgs.openblas
            pkgs.libpq
            pkgs.sqlite
          ];

          shellHook = ''
            export PIP_DISABLE_PIP_VERSION_CHECK=1
            export LD_LIBRARY_PATH="${runtimeLibs}:$LD_LIBRARY_PATH"
            export CC=${pkgs.clang}/bin/clang
            export CXX=${pkgs.clang}/bin/clang++
            export FORCE_CMAKE=1
            export CMAKE_ARGS="-DGGML_BLAS=ON -DGGML_BLAS_VENDOR=OpenBLAS -DLLAMA_BUILD_TOOLS=OFF -DLLAMA_BUILD_EXAMPLES=OFF -DLLAMA_BUILD_SERVER=OFF"
            echo "ISCY dev shell ready"
          '';
        };
      }
    );
}
