{
  description = "ISCY development shell";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
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
      in {
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
      });
}
