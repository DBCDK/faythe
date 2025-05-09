{ pkgs, lib }:
let
  nixos-lib = import (pkgs.path + "/nixos/lib") { };
  acme-test-module = "${pkgs.path}/nixos/tests/common/acme/server";

  domain = "faythe.test";
  ns_host = "ns.${domain}";

  # Pebble in version > 2.3.1 (NixOS 24.11 and up) is ramping up towards ACME
  # profiles and not issuing CNs for tlsserver profile certs. We want to test
  # against behaviour that matches the current letsencrypt behaviour, so stick
  # to 2.3.1.
  pebble-cn-overlay = self: super: {
    pebble = super.pebble.overrideAttrs (oa: rec {
      version = "2.3.1";
      src = self.fetchFromGitHub {
        owner = "letsencrypt";
        repo = "pebble";
        rev = "v${version}";
        hash = "sha256-S9+iRaTSRt4F6yMKK0OJO6Zto9p0dZ3q/mULaipudVo=";
      };
    });
  };
in
{
  inherit domain ns_host;
  mkFaytheTest = faytheTest:
    nixos-lib.runTest (
      test@{ nodes, ... }:
      let
        args = faytheTest test;
        optionalExtraModules = name:
          (args.extraModules or {}).${name} or [];
      in
      {
        hostPkgs = pkgs;
        name = args.name;
        defaults = {
          nixpkgs.overlays = [ pebble-cn-overlay ];
          nixpkgs.pkgs = pkgs;
          networking.nameservers = lib.mkForce [ nodes.ns.networking.primaryIPAddress ];
          networking.dhcpcd.enable = false;
          security.pki.certificateFiles = [ nodes.acme.test-support.acme.caCert ];
          networking.hosts."${nodes.acme.networking.primaryIPAddress}" = [ nodes.acme.test-support.acme.caDomain ];
          virtualisation.cores = 2;
        };
        nodes = {
          acme =
            { pkgs, ... }:
            {
              imports = [ acme-test-module ] ++ (optionalExtraModules "acme");
            };

          ns =
            { pkgs, ... }:
            {
              imports = optionalExtraModules "ns";

              environment.systemPackages = with pkgs; [
                dig
                dnsutils
              ];

              environment.etc."bind/zones/${domain}.zone" = {
                mode = "0644";
                user = "named";
                group = "named";
                text = ''
                  $TTL 60
                  ${domain}. IN SOA ${ns_host}. admin.${domain}. ( 1 3h 1h 1w 1d )

                  @ IN NS ${ns_host}.

                  ${ns_host}. IN A ${nodes.ns.networking.primaryIPAddress}
                '' + args.extraBindZoneFileLines;
              };

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
            };

          client =
            { pkgs, config, ... }:
            let
              faytheConfig = {
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
              } // args.faytheExtraConfig;

              faytheConfigFile = pkgs.writeText "faythe.config.json" (builtins.toJSON faytheConfig);

              faytheConfigFileChecked = pkgs.runCommand "faythe.config.checked.json" { } ''
                ${pkgs.faythe}/bin/faythe --config-check ${faytheConfigFile}
                ln -s ${faytheConfigFile} $out
              '';
            in
            {
              imports = optionalExtraModules "client";

              environment.systemPackages = with pkgs; [
                dig
                dnsutils
                getent
                lsof
              ];

              systemd.services.faythe = {
                path = with pkgs; [
                  dnsutils
                  dig
                ];
                environment.RUST_BACKTRACE = "full";
                environment.RUST_LOG = "warn,acme_lib=debug";
                wantedBy = [ "multi-user.target" ];
                preStart = ''
                  # vault provisioning time was masking this, but we need to
                  # wait for system nameserver to be up before we can start faythe
                  while ! dig +short -t SOA ${domain}; do
                    echo "Waiting for nameserver to be up"
                    sleep 1
                  done
                '';
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
          client.fail("host doesnotexist.${domain}")

          client.wait_for_unit("faythe.service")
        '' + args.testScript;
      }
    );
  }
