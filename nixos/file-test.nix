{ lib, pkgs }:
let
  testLib = import ./lib.nix {
    inherit lib pkgs;
  };

  domain = testLib.domain;
  cert_path = "/tmp/faythe";
in
testLib.mkFaytheTest ({ nodes, ... }: {
  name = "faythe-file-test";
  extraModules.client = [
    ({ config, pkgs, ... }: {
      environment.systemPackages = [pkgs.openssl];

      systemd.services.faythe.preStart = ''
        mkdir -p ${cert_path}
      '';
    })
  ];
  faytheExtraConfig = {
    file_monitor_configs = [
      {
        directory = cert_path;
        prune = true;
        specs = [
          {
            name = "path1-test";
            cn = "path1.${domain}";
            key_file_name = "key.pem";
          }
        ];
      }
    ];
  };
  testScript = ''
    with subtest("Normal first time issue"):
        client.wait_until_succeeds("stat ${cert_path}/path1-test")

        client.wait_until_succeeds("""
          journalctl -u faythe | grep "path1-test" | grep -q "touched"
          journalctl -u faythe | grep -q "changing group for"
        """)

        client.succeed("""
          openssl x509 -in ${cert_path}/path1-test/fullchain.pem -text -noout | grep -q "Issuer: CN=Pebble Intermediate"
        """)
  '';
})
