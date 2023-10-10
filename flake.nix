{
  description = "A Haskell implementation of the Tahoe-LAFS SSK cryptographic protocols";

  inputs = {
    # Nix Inputs
    flake-utils.url = github:numtide/flake-utils;
    hs-flake-utils.url = "git+https://whetstone.private.storage/jcalderone/hs-flake-utils.git?ref=main";
    nixpkgs.follows = "hs-flake-utils/nixpkgs";
    tahoe-chk = {
      url = "git+https://whetstone.private.storage/PrivateStorage/tahoe-chk?ref=refs/tags/0.2.0.0";
      inputs.nixpkgs.follows = "hs-flake-utils/nixpkgs";
    };
    tahoe-capabilities = {
      url = "git+https://whetstone.private.storage/PrivateStorage/tahoe-capabilities";
      inputs.nixpkgs.follows = "hs-flake-utils/nixpkgs";
    };
  };

  outputs = {
    self,
    nixpkgs,
    flake-utils,
    hs-flake-utils,
    tahoe-chk,
    tahoe-capabilities,
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
          tahoe-capabilities = tahoe-capabilities.outputs.packages.${system}.default;
        };
      };
    in {
      checks = hslib.checks {};
      devShells = hslib.devShells {
        shellHook = ''
          nix run .#write-cabal-project
        '';
        extraBuildInputs = pkgs:
          with pkgs; [
            zlib
          ];
      };
      packages = hslib.packages {};
      apps.hlint = hslib.apps.hlint {};

      apps.write-cabal-project = hslib.apps.write-cabal-project {
        localPackages = {
          "tahoe-chk" = tahoe-chk.sourceInfo.outPath;
          "tahoe-capabilities" = tahoe-capabilities.sourceInfo.outPath;
        };
      };

      apps.cabal-test = hslib.apps.cabal-test {
        preBuild = "nix run .#write-cabal-project";
      };

      apps.release = hslib.apps.release {};
    });
}
