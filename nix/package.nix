# noctalia-security-hw, the helper of the lbssousa/security-hardware Noctalia plugin:
# fingerprints over fprintd's D-Bus API, FIDO2/U2F keys (pamu2fcfg, fido2-token,
# pamtester) and the OpenPGP card (gpg).
{
  lib,
  stdenvNoCC,
  python3,
  gobject-introspection,
  wrapGAppsNoGuiHook,
  glib,
  gnupg,
  libfido2,
  pam_u2f,
  pamtester,
}:

stdenvNoCC.mkDerivation {
  pname = "noctalia-security-hw";
  version = "1.0.0";

  src = ../helper/noctalia-security-hw.py;
  dontUnpack = true;

  strictDeps = true;
  __structuredAttrs = true;

  nativeBuildInputs = [
    gobject-introspection
    wrapGAppsNoGuiHook
  ];
  buildInputs = [
    glib
    (python3.withPackages (ps: [ ps.pygobject3 ]))
  ];

  installPhase = ''
    runHook preInstall
    install -Dm755 $src $out/bin/noctalia-security-hw
    patchShebangs --host $out/bin/noctalia-security-hw
    runHook postInstall
  '';

  preFixup = ''
    gappsWrapperArgs+=(--prefix PATH : ${
      lib.makeBinPath [
        gnupg
        libfido2
        pam_u2f
        pamtester
      ]
    })
  '';

  meta = {
    description = "Fingerprint, FIDO2 and OpenPGP card helper for the Noctalia security-hardware plugin";
    homepage = "https://github.com/lbssousa/noctalia-security-hardware";
    license = lib.licenses.mit;
    platforms = lib.platforms.linux;
    mainProgram = "noctalia-security-hw";
  };
}
