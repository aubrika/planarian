# Planarian

A self-healing layer for declaratively configured computers. It keeps desired state, observed state and health separate, repairs divergences deterministically first, and runs every change through one executor as a journaled, revertible transaction. It ships first as a Rust service on NixOS 26.05.

- Specification: [`docs/SPEC.md`](docs/SPEC.md) (v4.3)
- Agent instructions: [`docs/AGENTS.md`](docs/AGENTS.md)
- Phase A fault catalog: [`crates/gym/catalog/phase-a.toml`](crates/gym/catalog/phase-a.toml), with review notes in [`docs/catalog-review.md`](docs/catalog-review.md)

Status: Phase A, first deliverable (fault catalog) awaiting owner review. No code yet.

License: [MPL-2.0](LICENSE).
