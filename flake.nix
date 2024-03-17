{
  description = "Await network to be ready (for MacOS)";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    naersk = {
      url = "github:nix-community/naersk";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay, naersk }:
    let
      systems = [ "x86_64-darwin" "aarch64-darwin" ];
    in
    { } // flake-utils.lib.eachSystem systems (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
        };
        inherit (builtins) attrValues;
        inherit (pkgs) mkShell;
        inherit (pkgs.stdenv) hostPlatform;
        inherit (nixpkgs.lib) optionalAttrs;

        buildPackages = {
          common = {
            inherit (pkgs.rust-bin.stable.latest) minimal rust-src rust-analysis rust-analyzer-preview;
            inherit (pkgs.rust-bin.nightly.latest) rustfmt-preview;
          };
          darwin = {
            inherit (pkgs) libiconv libclang stdenv;
          };
        };

        packages =
          buildPackages.common //
          (optionalAttrs hostPlatform.isDarwin buildPackages.darwin)
        ;

        naersk' = pkgs.callPackage naersk {
          rustc = pkgs.rust-bin.stable.latest.default;
          cargo = pkgs.rust-bin.stable.latest.default;
        };
        binary = naersk'.buildPackage {
          pname = "netawait";
          src = ./.;
        };

      in
      {
        devShells = {
          default = mkShell {
            packages = attrValues packages;
            nativeBuildInputs = [ pkgs.libclang.lib pkgs.stdenv pkgs.libclang ];
            shellHook = ''
              # clang-sys needs to be able to find libclang during building
              export LIBCLANG_PATH="${pkgs.libclang.lib}/lib"
              # clang-sys will call out to `xcodebuild` if this is not defined,
              # which is very annoying if you haven't accepted the xcode
              # license agreement.
              export CLANG_PATH="${pkgs.clang}/bin/clang"
            '';
          };
        };

        packages = {
          default = binary;
          netawait = binary;
        };
      });
}
