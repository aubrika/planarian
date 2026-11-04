{
  "repository": "aubrika/planarian",
  "pr_number": 70,
  "branch": "lane-change-path/move-probe",
  "expected_head": "a97db855be43fb282369e4d7a2dad81079f23f15",
  "parent": "a455eb1fbf66268849ef8f2c06b4d227379b1ac8",
  "base_tree": "0ed880964e6c3265e4bff24894fbaf27ad93bfd7",
  "base_branch": "lane-nix/gainable-caps",
  "source_head": "a97db855be43fb282369e4d7a2dad81079f23f15",
  "three_way_base": "895eaa1a991625f29866115c598a027587aa583b",
  "root": "/workspace/scratch/ready70/restack/work",
  "pr_body_file": "/workspace/scratch/ready70/restack/PR_BODY.md",
  "files": [
    {
      "path": "crates/backends/netwatch/src/ebpf.rs",
      "mode": "100644",
      "bytes": 3835,
      "sha256": "5b24fc9e4c8b34c89d7dfde1b63057c4a865952a9008575fcbddcb32f8151b1d"
    },
    {
      "path": "crates/backends/netwatch/src/lib.rs",
      "mode": "100644",
      "bytes": 18403,
      "sha256": "d7023413b953c1053e8c69d254c4e092f0cdfdc006e7fd829c94fa2ab553dd19"
    },
    {
      "path": "crates/backends/netwatch/src/loader.rs",
      "mode": "100644",
      "bytes": 20710,
      "sha256": "e522a314db967f1afaee40865b7567fe07e3ce07689a11b41793a2a87a92db24"
    },
    {
      "path": "crates/backends/netwatch/src/model.rs",
      "mode": "100644",
      "bytes": 27184,
      "sha256": "761a2e30a953ba4307ba5c28fbc93cce27704ad7536a67e3b1a9f0130017f44b"
    },
    {
      "path": "crates/backends/netwatch/src/parse.rs",
      "mode": "100644",
      "bytes": 19607,
      "sha256": "c8e96bb4ab169aec3618daaf9007791526016fb24fdce19fa47a6b8de40885f2"
    },
    {
      "path": "crates/backends/netwatch/src/props.rs",
      "mode": "100644",
      "bytes": 27011,
      "sha256": "6c24083541e99f95402fa5abcf633cbced269c4ab5c32df5335e9077568ae99b"
    },
    {
      "path": "crates/backends/netwatch/src/rename_props.rs",
      "mode": "100644",
      "bytes": 11278,
      "sha256": "097acdbee4f0b5ecb04a2a2743d4ef6295b552e47258db223f0d7fea43275c38"
    },
    {
      "path": "crates/backends/netwatch/src/snapshot.rs",
      "mode": "100644",
      "bytes": 8273,
      "sha256": "226bf043df6af22389d5460b27c1fc043409271b5be9fa83f3ccb9cabdcfd08d"
    },
    {
      "path": "crates/backends/netwatch/src/tests.rs",
      "mode": "100644",
      "bytes": 111607,
      "sha256": "187f5b28a5f859520753731137b9c5bd4658241122c50edd7072db2b933a01df"
    },
    {
      "path": "crates/backends/netwatch-ebpf/src/main.rs",
      "mode": "100644",
      "bytes": 21194,
      "sha256": "350d1e1d1bfad028d1274acd23238441e9705120a38ec33b6aa0f03d86305fbd"
    },
    {
      "path": "docs/bypasses.md",
      "mode": "100644",
      "bytes": 20746,
      "sha256": "e0115b859c2be097d55e486fbf060b8334f75d0196daaa1a45992df87c4242df"
    },
    {
      "path": "docs/regression-ledger.md",
      "mode": "100644",
      "bytes": 48842,
      "sha256": "a696fa2e2ec1f591b5e8d659bd3813c7b2041cb38949eb5bc18d09903bcb2f9f"
    },
    {
      "path": "nix/package.nix",
      "mode": "100644",
      "bytes": 3635,
      "sha256": "6c10c9806acadbd449cfd1c314b6e5f5e39f706f2d449c5797faea57c8e3e2fd"
    },
    {
      "path": "nix/tests/netwatch.nix",
      "mode": "100644",
      "bytes": 36408,
      "sha256": "ebe4ccda04e60d7ac302555f02b9a3fbbde74112da43784910733054cfe5e7e3"
    }
  ],
  "unchanged_dependency_workflow": ".github/workflows/vm.yml",
  "integration_notes": [
    "Both shared-doc conflicts resolved: B24 and B25 each appear once in Closed; D16/B18 rows preserved verbatim, N12/N16/N17 retained; 83 unique regression IDs with actual per-lane counts.",
    "All non-doc output matches normalized a97db855 exactly except the equivalent lazy-if replacement for its CI-reported redundant closure at parse.rs180. Shared PR VM workflow matches a455eb1 byte for byte and is inherited.",
    "Parent tree retains #68 capability helper, lock, module/eval fixtures, reconciliation and concurrency test without rewriting them.",
    "One final newline on every output file; embedded VM Python parses. No Rust/Nix execution available locally; final rebased-head CI/VM validation remains pending."
  ],
  "pr_body_sha256": "04f361438e753bf811234451c90e8811e2fd9f258cc6fad79de298e41943c919",
  "ci_style_fix": {
    "job_id": 126812357270,
    "file": "crates/backends/netwatch/src/parse.rs",
    "before": "route.then(|| read_names())",
    "after": "if route { Some(read_names()) } else { None }"
  }
}
