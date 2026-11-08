# noctalia-security-hw, the helper of the lbssousa/security-hardware Noctalia plugin:
# fingerprints over fprintd's D-Bus API, FIDO2/U2F keys (pamu2fcfg, fido2-token,
# pamtester), the OpenPGP card (gpg) and resident SSH keys (ssh-keygen). The check
# phase runs the helper's tests and the panel's, against a mock of the plugin API.
{
  lib,
  stdenvNoCC,
  python3,
  luau,
  gobject-introspection,
  wrapGAppsNoGuiHook,
  glib,
  gnupg,
  libfido2,
  openssh,
  pam_u2f,
  pamtester,
}:

let
  pythonEnv = python3.withPackages (ps: [ ps.pygobject3 ]);
in
stdenvNoCC.mkDerivation {
  pname = "noctalia-security-hw";
  version = "2.0.0";

  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../helper
      ../security-hardware
      ../tests
    ];
  };

  strictDeps = true;
  __structuredAttrs = true;

  nativeBuildInputs = [
    gobject-introspection
    wrapGAppsNoGuiHook
  ];
  buildInputs = [
    glib
    pythonEnv
  ];
  nativeCheckInputs = [
    python3
    luau
  ];

  dontBuild = true;
  doCheck = true;

  checkPhase = ''
    runHook preCheck
    patchShebangs --build helper/noctalia-security-hw
    python3 -m unittest discover -s helper/tests
    for lang in en pt-BR; do
      python3 tests/bundle.py tests/panel_test.luau "$lang" > "panel-$lang.luau"
      luau "panel-$lang.luau"
    done
    runHook postCheck
  '';

  installPhase = ''
    runHook preInstall
    mkdir -p $out/lib/noctalia-security-hw
    cp -r helper/noctalia_security_hw $out/lib/noctalia-security-hw/
    install -Dm755 helper/noctalia-security-hw $out/bin/noctalia-security-hw
    # The check phase patched the shebang for the build platform: PyGObject's Python here.
    sed -i '1s|.*|#!${pythonEnv.interpreter}|' $out/bin/noctalia-security-hw
    runHook postInstall
  '';

  preFixup = ''
    gappsWrapperArgs+=(
      --prefix PATH : ${
        lib.makeBinPath [
          gnupg
          libfido2
          openssh
          pam_u2f
          pamtester
        ]
      }
      --set NOCTALIA_SECURITY_HW_SELF $out/bin/noctalia-security-hw
    )
  '';

  meta = {
    description = "Fingerprint, FIDO2, OpenPGP card and resident SSH key helper for the Noctalia security-hardware plugin";
    homepage = "https://github.com/lbssousa/noctalia-security-hardware";
    license = lib.licenses.mit;
    platforms = lib.platforms.linux;
    mainProgram = "noctalia-security-hw";
  };
}
