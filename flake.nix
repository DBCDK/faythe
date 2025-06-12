{
  description = "faythe";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
    crane.url = "github:ipetkov/crane";
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
      craneLib = crane.mkLib final;
    };
  in {
    packages.${system} = {
	${pname} = pkgs.${pname};
	default = pkgs.${pname};
    };

    overlays.default = final: prev:
      let
        src = with final; lib.cleanSourceWith {
          src = ./.;
          filter = path: type:
            craneLib.filterCargoSources path type ||
            lib.hasPrefix "${toString ./.}/test" path;
        };

        commonArgs = {
          inherit src;
          nativeBuildInputs = [
            final.pkg-config
          ];
          buildInputs = [
            final.openssl
          ];
        };

        cargoArtifacts = final.craneLib.buildDepsOnly (commonArgs);
      in
      {
        "${pname}" = final.craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
        });

        "${pname}-clippy" = final.craneLib.cargoClippy (commonArgs // {
          inherit cargoArtifacts;
          cargoClippyExtraArgs = "--all-targets -- --deny warnings";
        });
      };

    checks.${system} = {
      sample-configs = pkgs.runCommandNoCC "check-sample-configs" { nativeBuildInputs = [ pkgs.${pname} ]; } ''
        DIR=${./config-samples}
        for FILE in $(ls -1 $DIR); do
          echo "Testing: $DIR/$FILE"
          faythe $DIR/$FILE --config-check >>$out
        done
      '';
      file = pkgs.callPackage ./nixos/file-test.nix {};
      vault = pkgs.callPackage ./nixos/vault-test.nix {};
      clippy = pkgs."${pname}-clippy";
    };

    devShells.${system}.default = with pkgs; mkShell {
      buildInputs = [
        rust-analyzer
        cargo
        clippy
        crate2nix
        openssl.dev
        pkg-config
        rustc
        zlib.dev
        # runtime
        dnsutils
        # needed to validdate renovate config
        renovate
      ];
    };
  };
}
