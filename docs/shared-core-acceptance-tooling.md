# Shared-core acceptance tooling evidence

Instruction baseline: `805cd1c953d78044a8c94ef9e3d35e33eb1dfb1a`.
This report concerns R12, R14 and R15. It is local regression and source
evidence; it does not certify the candidate's Rust, VM or proof results.

## Contracts and implementation

- R12: `nix/gym/run-vm.sh` preserves Nix build failures and validates an
  exact catalog-derived expected ID set. Failed, missing, malformed,
  duplicate and unexpected verdicts fail the run. Evaluation/selection
  failure cannot turn into an empty successful run. Stale output files
  are removed before each attempted collection.
- R15: `nix/gym/acceptance.py` derives the acceptance role and harness
  applicability from the catalog. Applicable `UNSUPPORTED` requires a
  waiver for the exact ID, harness and role, with a reason, reviewer,
  review permalink and unexpired date. A waiver cannot excuse FAIL,
  PARTIAL, ERROR or missing evidence. No waivers are adopted in this PR.
  The fake runner exports per-case JSON and rejects applicable Unsupported
  by default (exit 3 is unsupported coverage; execution failures retain exit 1).
  The wrapper can waive only the coverage status. CI validates complete fake coverage and exact VM cases;
  critical VM checks now also run on pull requests.
- R14: `docs/proof-obligations.toml` proposes 45 unique obligation IDs
  and explicit verifier/source/invariant mappings. The existing 47:56
  support-edge ratchet remains unchanged. `nix/gym/proofs.py` runs fixed
  Verus/Kani commands, checks successful verifier output, records versions,
  and binds receipts to the complete before/after source snapshot and log.
  The gate rejects removed baseline invariants, duplicate IDs, ordinary
  unverified functions, and missing, stale, edited or failed artifacts. Conditional/external proof declarations and
  redirected proof modules and unused-macro token declarations are rejected conservatively; dependency sources
  and compile-time included fixtures are bound with the workspace sources.
  The proposed mapping needs owner review and the changed implementation
  still needs successful real verifier runs. Mocked outputs in accounting
  tests are test fixtures only.
  Kani receipts require a separately named successful result for every mapped
  harness and complete zero-failure summaries for both commands. Trust-site
  counting normalizes Rust whitespace/attributes and ignores comments and
  string data; formatting an `external_body` or `assume` differently cannot
  remove it from the ratchet. The current site count remains 13.

## Reproduce the local regressions

```sh
python3 nix/gym/test_acceptance.py
python3 nix/gym/test_proofs.py
python3 nix/gym/test_manifest.py
bash -n nix/gym/run-vm.sh nix/gym/run-fake.sh
```

Results in this environment: nine acceptance tests, nine proof-accounting
tests and six manifest-accounting tests pass. The acceptance tests include a stub Nix CLI whose evaluation
succeeds while every build fails, as well as FAIL, PARTIAL, ERROR,
UNSUPPORTED, missing and duplicate verdict cases. Complete PASS sets and
a correctly scoped waiver are positive controls.

To run the same runner regression against the instruction baseline:

```sh
git show 805cd1c953d78044a8c94ef9e3d35e33eb1dfb1a:nix/gym/run-vm.sh > /tmp/planarian-baseline-run-vm.sh
PLANARIAN_VM_RUNNER=/tmp/planarian-baseline-run-vm.sh \
  python3 nix/gym/test_acceptance.py AcceptanceContract.test_actual_runner_propagates_build_and_verdict_failures
```

The baseline returns exit 0 for all seven injected bad cases; all seven
subtests detect that behavior. The fixed runner returns nonzero for every
bad case and zero for the PASS control. These are tests of the actual shell
runner and verdict validator, without building a VM.

The live catalog is always read rather than frozen to a historical count.
At reconciliation it has 126 IDs: 93 must-pass, 20 repair and 13 intent;
102 are fake-applicable, 92 VM-applicable and one bench-applicable.
Hardware/VM applicability and catalog changes remain reviewable source
changes. Historical successful CI is not used as current candidate evidence.

## Candidate manifest and run receipts

`nix/gym/manifest.py` records catalog runs against a full immutable Git SHA
and collects their results into a machine-readable manifest. Every current
catalog ID, role and applicable harness is enumerated; missing evidence starts
as `NOT_RUN`, never PASS. The source fingerprint covers implementation,
fixtures, assets, build/CI inputs and governing documentation, including file
modes. Receipts bind the actual runner command, exact selected scope, tool
versions, exit status, source before/after, log and acceptance-report hashes.
The recorder forces the VM flake to the recorded checkout. Collection rejects
mixed revisions, dirty or missing candidate objects, changed sources, edited
reports, incomplete coverage, failed commands and duplicate run evidence.

After committing and checking out the immutable implementation candidate:

```sh
candidate=$(git rev-parse HEAD)
python3 nix/gym/manifest.py record --source-revision "$candidate" --harness fake --output docs/evidence/fake
python3 nix/gym/manifest.py record --source-revision "$candidate" --harness vm --output docs/evidence/vm
python3 nix/gym/manifest.py collect --source-revision "$candidate" \
  --receipt docs/evidence/fake/receipt.json --receipt docs/evidence/vm/receipt.json \
  --output docs/shared-core-acceptance.json
```

Collection also works with no receipts to produce an explicit outstanding
inventory. If the candidate's Git objects are unavailable, it marks the
inventory unbound and refuses to accept run results. This is useful for draft
review, not certification. Catalog receipts alone do not establish Rust checks,
successful Verus/Kani proofs, installed-entry boot behavior, real-filesystem
durability or reference-hardware performance: those independent gates and all
finding dispositions remain visibly outstanding in the generated manifest,
and overall `acceptance_complete` stays false. Attach their actual results to
the final candidate report rather than inferring them from catalog passes.

Evidence-only files in `docs/evidence/`, `docs/shared-core-review.md`,
`docs/shared-core-acceptance.json` and `docs/shared-core-acceptance-report.md`
are excluded from the implementation fingerprint. They must contain evidence,
not governing requirements or fixtures. A documentation-only followup in those
locations can preserve the tested candidate relationship; a change to SPEC,
another governing document, implementation, fixtures or tooling invalidates
the receipts. Synthetic receipts in the manifest-accounting tests are positive
accounting controls and make no claim that a real catalog or proof was run.
