{
  description = "Python encryption flake";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
  };

  outputs = { nixpkgs, ... }:
  let
    system = "x86_64-linux";
    pkgs = import nixpkgs { inherit system; };
  in {
    devShells.${system}.default = pkgs.mkShell {
      packages = with pkgs; [
        (python3.withPackages (py-pkgs: with py-pkgs; [
          cryptography
          python-lsp-server
        ]))
        openssl
      ];
    };
  };
}
