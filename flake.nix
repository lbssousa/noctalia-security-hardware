{
  description = "lbssousa/security-hardware Noctalia plugin and its noctalia-security-hw helper";

  inputs.nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAll = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      overlays.default = final: _: { noctalia-security-hw = final.callPackage ./nix/package.nix { }; };

      packages = forAll (pkgs: rec {
        noctalia-security-hw = pkgs.callPackage ./nix/package.nix { };
        default = noctalia-security-hw;
      });

      checks = forAll (pkgs: {
        inherit (self.packages.${pkgs.stdenv.hostPlatform.system}) noctalia-security-hw;
      });

      formatter = forAll (pkgs: pkgs.nixfmt);
    };
}
