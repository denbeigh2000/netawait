{
  description = "Await network to be ready (for MacOS)";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay }:
    let
      systems = [
        "x86_64-linux"
        "x86_64-darwin"
        "aarch64-linux"
        "aarch64-darwin"
      ];
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
            inherit (pkgs.rust-bin.stable.latest) default;
            inherit (pkgs.rust-bin.nightly.latest) rustfmt;
          };
          darwin = {
            inherit (pkgs) libiconv libclang stdenv;
          };
        };

        packages =
          buildPackages.common //
          (optionalAttrs hostPlatform.isDarwin buildPackages.darwin)
        ;

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

      });

}
