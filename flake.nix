{
  description = "bend-sha2: SHA-256 in Bend (cryptohash-sha256), FIPS 180-4";

  inputs = {
    # the pinned Bend (2.0.39, with BendTT for --verdict), as mugen-app's
    bend-frp.url = "github:hhefesto/bend-frp";
    nixpkgs.follows = "bend-frp/nixpkgs";
  };

  outputs = inputs@{ self, nixpkgs, bend-frp, ... }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
      lib = pkgs.lib;
      bend = bend-frp.packages.${system}.bend;
      # the libraries this one imports (../bend-NAME/), put beside it
      deps = [  ];
      modules = [ "Sha2" ];
      # modules over foreign (C) effects: the check names those defs, and
      # nothing else may fail
      foreign = [ ];
      # run `script` in a writable copy of the source, its libraries beside it
      inSource = name: tools: script:
        pkgs.runCommand "bend-sha2-${name}" { nativeBuildInputs = [ bend ] ++ tools; } ''
          export HOME=$TMPDIR BEND_NO_TELEMETRY=1
          mkdir w
          cp -r ${self} w/bend-sha2
          ${lib.concatMapStrings (x: "cp -r ${inputs."bend-${x}"} w/bend-${x}\n") deps}
          chmod -R u+w w
          cd w/bend-sha2
          ${script}
          touch $out
        '';
    in {
      # the source, to put beside a Bend program as bend-sha2/
      packages.${system}.default = pkgs.runCommand "bend-sha2" { } ''
        cp -r ${self} $out
        chmod u+w $out
        rm -f $out/flake.nix $out/flake.lock
      '';

      checks.${system} = {
        modules = inSource "modules" [ ] (lib.concatMapStrings (m: ''
          echo "== ${m}"
          bend ${m}.bend --check-only 2>&1 | tee m.log
          grep -q 'ALL PROOFS CHECK' m.log
        '') modules + lib.concatMapStrings (m: ''
          echo "== ${m} (foreign effects)"
          bend ${m}.bend --check-only 2>&1 | tee m.log || true
          grep -q '^defs that depend on foreign effects: ' m.log
          ! grep -v -e '^SOME PROOFS FAIL$' -e '^Error: [0-9]* defs\? rel[a-z]* on unsafe or foreign code:$' \
            -e '^defs that depend on foreign effects: ' m.log
        '') foreign);
      };
    };
}
