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

      users.users.certuser = {
        isNormalUser = true;
      };

      users.groups.certgroup = {};
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
          {
            name = "path2-test";
            cn = "path2.${domain}";
            key_file_name = "key.pem";
            cert_file_perms = {
              user = "certuser";
              group = "certgroup";
              mode = "644";
            };
            key_file_perms = {
              user = "certuser";
              mode = "600";
            };
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
          openssl x509 -in ${cert_path}/path1-test/fullchain.pem -text -noout | grep -q "Issuer: CN=Pebble Intermediate"
        """)

        client.succeed("""
          test "$(stat -c %a ${cert_path}/path1-test/fullchain.pem)" == "644"
          test "$(stat -c %a ${cert_path}/path1-test/key.pem)" == "640"
        """)

    with subtest("First time issue with custom permissions and user"):
        client.wait_until_succeeds("stat ${cert_path}/path2-test")

        client.wait_until_succeeds("""
          journalctl -u faythe | grep "path2-test" | grep -q "touched"
          openssl x509 -in ${cert_path}/path2-test/fullchain.pem -text -noout | grep -q "Issuer: CN=Pebble Intermediate"
        """)

        client.succeed("""
          test "$(stat -c %U ${cert_path}/path2-test/fullchain.pem)" == "certuser"
          test "$(stat -c %U ${cert_path}/path2-test/key.pem)" == "certuser"
        """)

        client.succeed("""
          test "$(stat -c %G ${cert_path}/path2-test/fullchain.pem)" == "certgroup"
          test "$(stat -c %G ${cert_path}/path2-test/key.pem)" == "root"
        """)

        client.succeed("""
          test "$(stat -c %a ${cert_path}/path2-test/fullchain.pem)" == "644"
          test "$(stat -c %a ${cert_path}/path2-test/key.pem)" == "600"
        """)
  '';
})
