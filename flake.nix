{
  description = "Packet generation MCP server for interface send/receive";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        pythonEnv = pkgs.python3.withPackages (ps: [ ps.fastmcp ps.scapy ]);
      in
      {
        devShells.default = pkgs.mkShell {
          packages = [ pythonEnv ];
        };

        packages.default = pkgs.stdenv.mkDerivation {
          name = "packetio-mcp";
          src = ./.;
          nativeBuildInputs = [ pkgs.makeWrapper ];
          installPhase = ''
            mkdir -p $out/bin $out/lib/packetio-mcp
            cp -r src $out/lib/packetio-mcp/src
            makeWrapper ${pythonEnv}/bin/python3 $out/bin/packetio-mcp \
              --add-flags "-m packetio_mcp.server" \
              --set PYTHONPATH "$out/lib/packetio-mcp/src" \
              --prefix PATH : ${pythonEnv}/bin
          '';
        };

        apps.default = {
          type = "app";
          program = "${self.packages.${system}.default}/bin/packetio-mcp";
        };
      }
    );
}
