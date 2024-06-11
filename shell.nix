let
  nixpkgs = fetchTarball "https://github.com/NixOS/nixpkgs/tarball/nixos-24.05";
  pkgs = import nixpkgs { config = {}; overlays = []; };
in

pkgs.mkShellNoCC {
  packages = with pkgs; [
    codeql
    semgrep
    netcat-gnu
    clang
    cmake
    libpcap
  ];
  
  GREETING = "Welcome to the Portsentry dev environment!";

  shellHook = ''
    echo $GREETING
  '';
}
