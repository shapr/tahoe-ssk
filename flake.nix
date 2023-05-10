{
  description = "A Haskell implementation of the Tahoe-LAFS SSK cryptographic protocols";

  inputs = {
    # Nix Inputs
    flake-utils.url = github:numtide/flake-utils;
    hs-flake-utils.url = "git+https://whetstone.private.storage/jcalderone/hs-flake-utils.git?ref=main";
    nixpkgs.follows = "hs-flake-utils/nixpkgs";
    tahoe-chk = {
      url = "git+https://whetstone.private.storage/PrivateStorage/tahoe-chk?ref=refs/tags/0.1.0.1";
      inputs.nixpkgs.follows = "hs-flake-utils/nixpkgs";
    };
  };

  outputs = {
    self,
    nixpkgs,
    flake-utils,
    hs-flake-utils,
    tahoe-chk,
  }: let
    ulib = flake-utils.lib;
    ghcVersion = "ghc8107";
  in
    ulib.eachSystem ["x86_64-linux" "aarch64-darwin"] (system: let
      # Get a nixpkgs customized for this system
      pkgs = import nixpkgs {
        inherit system;
      };
      hslib = hs-flake-utils.lib {
        inherit pkgs;
        src = ./.;
        compilerVersion = ghcVersion;
        packageName = "tahoe-ssk";
        hsPkgsOverrides = hprev: hfinal: {
          tahoe-chk = tahoe-chk.outputs.packages.${system}.default;
        };
      };
    in {
      checks = hslib.checks {};
      devShells = hslib.devShells {
        extraBuildInputs = pkgs:
          with pkgs; [
            zlib
          ];
      };
      packages = hslib.packages {};
      apps.hlint = hslib.apps.hlint {};

      # Using the working directory of `nix run`, do a build with cabal and
      # then run the test suite.
      apps.cabal-test = {
        type = "app";
        program = "${
          pkgs.writeShellApplication {
            name = "cabal-build-and-test";
            runtimeInputs = with pkgs; [pkg-config haskell.compiler.${ghcVersion} cabal-install];

            text = ''
              cabal update hackage.haskell.org
              cabal build
              cabal run tests
            '';
          }
        }/bin/cabal-build-and-test";
      };
    });
}
