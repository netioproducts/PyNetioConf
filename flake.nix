{
  description = "PyNetioConf - universal module to control and configure all NETIO devices";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        python = pkgs.python3;

        pynetioconf = python.pkgs.buildPythonPackage {
          pname = "PyNetioConf";
          version = (builtins.fromTOML (builtins.readFile ./pyproject.toml)).project.version;
          pyproject = true;

          src = ./.;

          build-system = [ python.pkgs.setuptools ];

          dependencies = with python.pkgs; [
            websocket-client
            requests
            urllib3
            typing-extensions
          ];

          pythonImportsCheck = [ "PyNetioConf" ];

          meta = {
            description = "Universal module to control and configure all NETIO devices";
            homepage = "https://github.com/netioproducts/PyNetioConf";
            license = pkgs.lib.licenses.mit;
          };
        };
      in
      {
        packages = {
          default = pynetioconf;
          inherit pynetioconf;
        };

        devShells.default = pkgs.mkShell {
          packages = [
            (python.withPackages (
              ps: with ps; [
                websocket-client
                requests
                urllib3
                typing-extensions
                setuptools
                build
                pip
              ]
            ))
          ];

          shellHook = ''
            export PYTHONPATH="$PWD/src''${PYTHONPATH:+:$PYTHONPATH}"
          '';
        };
      }
    );
}
