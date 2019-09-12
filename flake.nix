{
  description = "faythe";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-22.11";
    utils.url = "github:numtide/flake-utils";
    utils.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { self, nixpkgs, utils }:
  let
    pname = "faythe";
    system = "x86_64-linux";
    pkgs = import nixpkgs {
      inherit system;
      overlays = [];
    };
  in {
    packages.${system}.${pname} = (import ./Cargo.nix {
      inherit pkgs;
    }).rootCrate.build;

    defaultPackage.${system} = self.packages.${system}.${pname};

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
