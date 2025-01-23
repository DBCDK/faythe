{ lib, pkgs }:
let
  nixos-lib = import (pkgs.path + "/nixos/lib") { };
  acme-test-module = "${pkgs.path}/nixos/tests/common/acme/server";

  role_id_path = "/tmp/vault-role-id";
  secret_id_path = "/tmp/vault-secret-id";

  domain = "faythe.test";
  vault_host = "vault.${domain}";
  ns_host = "ns.${domain}";

  # dev server
  vault_addr = "http://localhost:8200";

in
nixos-lib.runTest (
  test@{ nodes, ... }:
  {
    hostPkgs = pkgs;
    name = "faythe-vault-test";
    defaults = {
      nixpkgs.pkgs = pkgs;
      networking.nameservers = lib.mkForce [ nodes.ns.networking.primaryIPAddress ];
      networking.dhcpcd.enable = false;
      security.pki.certificateFiles = [ nodes.acme.test-support.acme.caCert ];
      networking.hosts."${nodes.acme.networking.primaryIPAddress}" = [ nodes.acme.test-support.acme.caDomain ];
    };
    nodes = {
      acme =
        { pkgs, ... }:
        {
          imports = [ acme-test-module ];
        };

      ns =
        { pkgs, ... }:
        {
          environment.systemPackages = with pkgs; [
            dig
            dnsutils
          ];

          networking.firewall.allowedTCPPorts = [ 53 ];
          networking.firewall.allowedUDPPorts = [ 53 ];

          services.bind.enable = true;

          services.bind.zones."${domain}" = {
            master = true;
            file = "/etc/bind/zones/${domain}.zone";
            # the bind zone module is very opinionated and this sets allow-transfer.
            slaves = [ nodes.client.networking.primaryIPAddress ];
            extraConfig = ''
              allow-update { ${nodes.client.networking.primaryIPAddress}; };
            '';
          };

          # Hack to allow access to the directory copied from environment.etc
          systemd.services.bind.serviceConfig.ExecStartPre = "+${pkgs.coreutils}/bin/chown named /etc/bind/zones";

          environment.etc."bind/zones/${domain}.zone" = {
            mode = "0644";
            user = "named";
            group = "named";
            text = ''
              $TTL 60
              ${domain}. IN SOA ${ns_host}. admin.${domain}. ( 1 3h 1h 1w 1d )

              @ IN NS ${ns_host}.

              ${ns_host}. IN A ${nodes.ns.networking.primaryIPAddress}

              ${vault_host}. IN A ${nodes.client.networking.primaryIPAddress}
            '';
          };
        };

      client =
        { pkgs, config, ... }:
        let

          faytheConfig = {
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
            lets_encrypt_url = "https://${nodes.acme.test-support.acme.caDomain}/dir";
            lets_encrypt_email = "test_mail@${domain}";
            zones = {
              "${domain}" = {
                auth_dns_server = ns_host;
                challenge_driver.nsupdate ={
                  server = ns_host;
                  key = "test";
                };
              };
            };
            val_dns_servers = [ ns_host ];
          };

          faytheConfigFile = pkgs.writeText "faythe.config.json" (builtins.toJSON faytheConfig);

          faytheConfigFileChecked = pkgs.runCommand "faythe.config.checked.json" { } ''
            ${pkgs.faythe}/bin/faythe --config-check ${faytheConfigFile}
            ln -s ${faytheConfigFile} $out
          '';
        in
        {
          environment.systemPackages = with pkgs; [
            dig
            dnsutils
            vault
            getent
            lsof
          ];

          environment.variables.VAULT_ADDR = vault_addr;

          services.vault = {
            enable = true;
            # start unsealed and with known root token
            dev = true;
            devRootTokenID = "vaultroot";
          };

          # FIXME: upstream this, makes ordering nicer
          systemd.services.vault.serviceConfig.Type = "notify";

          systemd.services.vault-provision = {
            path = with pkgs; [
              vault
              getent
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

          systemd.services.faythe = {
            path = with pkgs; [
              dnsutils
              dig
            ];
            environment.RUST_BACKTRACE = "full";
            environment.RUST_LOG = "warn,acme_lib=debug";
            wantedBy = [ "multi-user.target" ];
            wants = [ "vault-provision.service" ];
            after = [ "vault-provision.service" ];
            serviceConfig = {
              ExecStart = "${pkgs.faythe}/bin/faythe ${faytheConfigFileChecked}";
            };
          };
        };
    };
    testScript = ''
      start_all()

      ns.wait_for_unit("network-online.target")
      acme.wait_for_unit("network-online.target")
      client.wait_for_unit("network-online.target")

      ns.wait_for_unit("bind.service")

      client.wait_until_succeeds("ping -c1 ${nodes.ns.networking.primaryIPAddress}")
      client.wait_until_succeeds("host ${vault_host}")
      client.fail("host doesnotexist.${domain}")

      client.wait_for_unit("faythe.service")

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
    '';
  }
)
