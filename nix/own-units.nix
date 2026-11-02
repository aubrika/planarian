# The system services Planarian's module itself declares (nix/module.nix,
# nix/posture.nix). They are not classified as network tools (§12d): their
# failures have their own posture (Absent, Crashed, Integrity). A plain
# value, not an option, so no configuration can widen it (an owner's
# definition would otherwise replace the set and exclude a VPN).
[ "planariad" "planarian-recovery" "planarian-respond@" "planarian-posture-check" "planarian-posture-lift" "planarian-hold@" ]
