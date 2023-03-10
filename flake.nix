{
  description = "faythe";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-22.11";
    utils.url = "github:numtide/flake-utils";
    crane.url = "github:ipetkov/crane";
    crane.inputs.nixpkgs.follows = "nixpkgs";
    crane.inputs.flake-utils.follows = "utils";
  };

  outputs = { self, crane, nixpkgs, utils }:
  let
    pname = "faythe";
    system = "x86_64-linux";
    pkgs = import nixpkgs {
      inherit system;
      overlays = [ crane-overlay self.overlays.default ];
    };
    crane-overlay = final: prev: {
      # crane's lib is not exposed as an overlay in its flake (should be added
      # upstream ideally) so this interface might be brittle, but avoids
      # accidentally passing a detached nixpkgs from its flake (or its follows)
      # on to consumers.
      craneLib = crane.mkLib final;
    };
  in {
    packages.${system}.${pname} = pkgs.${pname};
    defaultPackage.${system} = pkgs.${pname};

    overlays.default = final: prev: {
      "${pname}" = final.craneLib.buildPackage {
        src =
          let
            srcPath = ./.;
          in
            with final; lib.cleanSourceWith {
              src = srcPath;
              filter = path: type:
                craneLib.filterCargoSources path type ||
                lib.hasPrefix "${toString srcPath}/test" path;
            };
        nativeBuildInputs = with final; [
          pkg-config
        ];
        buildInputs = with final; [
          openssl
        ];
      };
    };

    devShell.${system} = with pkgs; mkShell {
      buildInputs = [
        cargo
        crate2nix
        openssl.dev
        pkgconfig
        rustc
        zlib.dev
        dnsutils # runtime
        kubectl # runtime
      ];
    };
  };
}
