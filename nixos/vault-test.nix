{ lib, pkgs }:
let
  testLib = import ./lib.nix {
    inherit lib pkgs;
  };

  role_id_path = "/tmp/vault-role-id";
  secret_id_path = "/tmp/vault-secret-id";

  domain = testLib.domain;
  vault_host = "vault.${domain}";
  ns_host = testLib.ns_host;

  # dev server
  vault_addr = "http://localhost:8200";
in
testLib.mkFaytheTest ({ nodes, ... }: {
  name = "faythe-vault-test";
  extraModules.client = [
    ({ config, pkgs, ... }: {
      environment = {
        systemPackages = with pkgs; [
          vault
        ];
        variables.VAULT_ADDR = vault_addr;
      };

      services.vault = {
        enable = true;
        # start unsealed and with known root token
        dev = true;
        devRootTokenID = "vaultroot";
      };

      systemd.services.faythe = {
        wants = [ "vault-provision.service" ];
        after = [ "vault-provision.service" ];
      };

      # FIXME: upstream this, makes ordering nicer
      systemd.services.vault.serviceConfig.Type = "notify";

      systemd.services.vault-provision = {
        path = with pkgs; [
          vault
          getent
          openssl
        ];
        environment.VAULT_ADDR = vault_addr;
        wants = [ "vault.service" ];
        after = [ "vault.service" ];
        serviceConfig.Type = "oneshot";

        script = ''
          set -x
          set -euo pipefail

          vault login ${config.services.vault.devRootTokenID}

          vault policy write faythe-policy ${
            pkgs.writeText "faythe-policy.json" (
              builtins.toJSON {
                path."kv/data/path1/*" = {
                  capabilities = [
                    "list"
                    "read"
                    "create"
                    "update"
                  ];
                };
                path."kv/metadata/path1/*" = {
                  capabilities = [
                    "list"
                    "read"
                    "create"
                    "update"
                  ];
                };
                path."kv/data/path2/*" = {
                  capabilities = [
                    "list"
                    "read"
                    "create"
                    "update"
                  ];
                };
                path."kv/metadata/path2/*" = {
                  capabilities = [
                    "list"
                    "read"
                    "create"
                    "update"
                  ];
                };
              }
            )
          }

          vault auth enable approle
          vault write auth/approle/role/faythe type=service policies=faythe-policy

          vault read -field=role_id auth/approle/role/faythe/role-id > ${role_id_path}
          vault write -f -field=secret_id auth/approle/role/faythe/secret-id > ${secret_id_path}

          vault secrets enable -path=kv kv-v2
        '';
      };
    })
  ];
  extraBindZoneFileLines = ''
    ${vault_host}. IN A ${nodes.client.networking.primaryIPAddress}
  '';
  faytheExtraConfig = {
    vault_monitor_configs = [
      {
        inherit role_id_path secret_id_path vault_addr;
        key_prefix = "path1";
        specs = [
          {
            name = "path1-test";
            cn = "path1.${domain}";
          }
        ];
      }
      {
        inherit role_id_path secret_id_path vault_addr;
        key_prefix = "path2";
        specs = [
          {
            name = "path2-test";
            cn = "path2.${domain}";
          }
        ];
      }
    ];
  };
  testScript = ''
    client.wait_until_succeeds("host ${vault_host}")

    with subtest("Can get certs"):
        client.wait_until_succeeds("""
          vault kv get kv/path1/path1-test/cert && vault kv get kv/path2/path2-test/cert
        """)

    with subtest("Wakes up on old meta timestamp"):
        client.succeed("""
          date +%s > starttime
          vault kv put kv/path1/path1-test/faythe value=2000-01-01T00:00:00.000+00:00
        """)

        client.wait_until_succeeds("""
          journalctl --since "@$(cat starttime)" -u faythe | grep "State for cert: path1.faythe.test" | grep -q "Valid"
          journalctl --since "@$(cat starttime)" -u faythe | grep "path1-test" | grep -q "touched"
        """)

        client.succeed("""
          date -d "$(vault kv get -field value kv/path1/path1-test/faythe)" +%s > refreshtime
        """)

        client.succeed("""
          [ $(cat refreshtime) -gt $(cat starttime) ]
        """)

    with subtest("No failed dispatch in vaultrs"):
        client.fail("""
          journalctl -u faythe | grep -q "dispatch task is gone: runtime dropped the dispatch task"
        """)

    with subtest("Has success metrics"):
        client.succeed("""
          curl localhost:9105/metrics | grep -q 'faythe_issue_successes{cert="path1-test"} 1'
        """)
  '';
})
