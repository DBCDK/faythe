{
  description = "faythe";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.05";
    crane.url = "github:ipetkov/crane";
    crane.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { self, crane, nixpkgs }:
  let
    pname = "faythe";
    system = "x86_64-linux";
    pkgs = import nixpkgs {
      inherit system;
      overlays = [ crane-overlay self.overlays.default ];
      config = {
        allowUnfreePredicate = pkg:
          builtins.elem (builtins.parseDrvName (pkg.name or pkg.pname)).name [
            "vault"
          ];
      };
    };
    crane-overlay = final: prev: {
      # crane's lib is not exposed as an overlay in its flake (should be added
      # upstream ideally) so this interface might be brittle, but avoids
      # accidentally passing a detached nixpkgs from its flake (or its follows)
      # on to consumers.
      craneLib = (crane.mkLib final).overrideScope (_: scopePrev: {
        mkCargoDerivation = args: scopePrev.mkCargoDerivation ({
          RUSTFLAGS = "-D warnings";
        } // args);
      });
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

    checks.${system} = {
      sample-configs = pkgs.runCommandNoCC "check-sample-configs" { nativeBuildInputs = [ pkgs.${pname} ]; } ''
        DIR=${./config-samples}
        for FILE in $(ls -1 $DIR); do
          echo "Testing: $DIR/$FILE"
          faythe $DIR/$FILE --config-check >>$out
        done
      '';
      vault = pkgs.callPackage ./nixos/vault-test.nix {};
    };

    devShell.${system} = with pkgs; mkShell {
      buildInputs = [
        rust-analyzer
        cargo
        crate2nix
        openssl.dev
        pkg-config
        rustc
        zlib.dev
        dnsutils # runtime
        kubectl # runtime
      ];
    };
  };
}
