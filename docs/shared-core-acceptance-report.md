# Shared-core candidate acceptance report

Candidate: `eaf5a567d2ccbfd06b7159d6e63dac4c2a2d970a`. Instruction baseline: `805cd1c953d78044a8c94ef9e3d35e33eb1dfb1a`.
Source fingerprint: `e46fb5cc7dc28959abcb7a45859c88a7f42b16d13c05243c28582551b2782b00`.
The [machine manifest](shared-core-acceptance.json) enumerates 126 current
catalog IDs and 195 applicable ID/role/harness slots; every catalog
slot is NOT_RUN and no waiver is adopted. The [reconciliation](shared-core-review.md)
maps all R01–R16, S01–S07, P09 and GC dispositions to source/regressions.

**Acceptance incomplete; keep draft.** Source implementation and focused regression
code are prepared. This is not compiled correctness, a proof result, VM acceptance
or a full personal-profile measurement. Nothing is merged or release-certified.

## Executed on this immutable candidate

- 34 Python controls PASS: acceptance 9, proof-accounting 9, manifest 6, performance 10.
  These use explicit stub/synthetic evidence to detect false passes, not to claim
  repaired systems or successful verifiers.
- Actual baseline runner rejects none of seven injected bad build/verdict sets;
  the seven negative assertions fail as expected. The fixed actual runner passes
  those controls. Actual baseline metric functions also fail two controls: missed
  exited-helper CPU and invented p99 without frame samples; current controls pass.
- Dependency boundaries, shell syntax, YAML/TOML parsing and patch whitespace PASS.
- Source accounting finds 45 unique proof IDs/47 historical invariant support edges
  and 13 explicit trust sites. It explicitly makes no successful proof claim.

Commands, expected/actual exit codes, tool versions and hashed logs are in the
[local receipt](evidence/shared-core-local/receipt.json). Its before/after source
fingerprint is unchanged and bound to this full candidate. Python is 3.12.14 and
Git 2.52.0; Rust/Cargo/Nix/Verus/Kani are unavailable in this executor. Required
Rust fmt/clippy/tests, fake/demo catalogs, Nix/proofs and VM checks remain NOT_RUN.

## Open decisions and required evidence

- R11/B-20: Linux check-then-rename cannot preserve arbitrary-editor races. The
  authored real-backend characterization remains UNRUN; an enforceable writer
  boundary or explicitly adopted justified contract change is required.
- S01/S02: installed-entry UEFI/systemd-boot crash/fallback/confirmation targets
  are authored but UNRUN. Other bootloader/initrd layouts have no unified claim.
  Early readiness/checked commitment versus delayed confirmation needs adoption.
- S03/G5: a newly explicit external progress assumption is proposed, not adopted.
  Current declared support 47:57 / trust 38 / internal 5 regresses against unchanged
  baseline 47:56 / trust 37 / internal 5. The existing ratchet must reject it; no baseline
  reset conceals it. Owner must decide the contract and any justified amendment.
- GC: historical job 123953787557 at 805cd1c shows valid candidate2 Prepared, GC
  Committed, then 900 seconds with no approval response. That does not prove candidate
  deletion. Transport/step error handling is corrected; normal/retain-all root
  survival and valid-approval commit oracles remain. Exact hang reproduction and
  cause/fix validation still require the real VM case.
- Every authored Rust regression/counterfactual, actual Verus/Kani artifact, complete
  current fake/VM catalog, ext4/nodatacow-btrfs filesystem durability/ENOSPC case and
  installed-entry crash matrix remains required. XFS/ZFS are outside this claim.
- Headless complete-owned-work costs/frame data, actual scheduler wakeups and full
  personal-profile GPU/Proton/physical-input measurements are NOT_RUN. Proposed
  reference workload, numerical margins and capture plan require review before
  measurement; headless/synthetic evidence cannot satisfy personal acceptance.

Agent launching-user permissions, Runtime GC, retain-all protection including
emergency collection, protected-root cleanup and independent root-terminal/no-self
approval are preserved. Local signed prefixes provide no off-machine witness or
compromised-root resistance; Firecracker smoke remains non-gating Phase A.

## Evidence-only follow-up boundary

This report, reconciliation, manifest and docs/evidence may follow the candidate
in an evidence-only commit. They are explicitly excluded from source fingerprinting.
No implementation, fixture, build/CI input or governing contract may change in that
commit. Any such change selects a new candidate and requires affected checks to rerun.
Historical/mixed-revision results remain labeled and are never combined into a
single release certificate.
