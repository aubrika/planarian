//! Garbage-collection planning under the §12b bounds. Pure: the backends
//! measure, this decides.
//!
//! Two bounds hold at once: keep at most `keep` generations, and keep their
//! store closures within `max_bytes`. Whichever is exceeded, generations are
//! collected oldest first until both hold. The protected set (I3) is never
//! collected; if it alone exceeds the space bound, everything unprotected is
//! collected and the shortfall is reported (`BudgetUnsatisfiable`): the budget
//! is then a target, not a guarantee.

use crate::ids::{GenerationId, Timestamp};
use serde::{Deserialize, Serialize};

/// Owner settings (`services.planarian.gc`), not manifest options.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct GcBudget {
    /// Generations to keep at most (§12b default 10).
    pub keep_generations: usize,
    /// Generations may use at most this share of the Nix store's
    /// filesystem, in tenths of a percent (§12b default 20% = 200).
    pub generations_permille: u32,
    /// Generations to keep at most in an emergency (the store or journal
    /// filesystem is nearly full).
    pub keep_emergency: usize,
    /// `services.planarian.gc.retainAllGenerations`: never collect a
    /// generation, even in an emergency (a full history, or generations kept
    /// for export). Other store garbage is still collected; a space bound the
    /// generations exceed is reported, never enforced.
    pub retain_all: bool,
}

impl Default for GcBudget {
    fn default() -> Self {
        GcBudget { keep_generations: 10, generations_permille: 200, keep_emergency: 3, retain_all: false }
    }
}

impl GcBudget {
    /// The space bound for a filesystem of `fs_bytes`.
    pub fn max_bytes(&self, fs_bytes: u64) -> u64 {
        (fs_bytes as u128 * self.generations_permille as u128 / 1000) as u64
    }

    /// The generations `plan` may not collect: the I3 set, and with
    /// `retain_all` every generation on disk.
    pub fn protected(&self, on_disk: &[GenerationId], protect: &[GenerationId]) -> Vec<GenerationId> {
        if self.retain_all { on_disk.to_vec() } else { protect.to_vec() }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GcPlan {
    /// Oldest first.
    pub delete: Vec<GenerationId>,
    pub kept: Vec<GenerationId>,
    /// Size of the kept generations' closures, when known.
    pub kept_bytes: u64,
    pub max_bytes: u64,
    /// `BudgetUnsatisfiable`: the protected set alone is this far over the space bound.
    pub shortfall: Option<u64>,
}

/// Plan a collection. `gens` are the generations on disk, `protect` the I3
/// set; `measure` gives the size of a set of generations' combined closures.
pub fn plan(
    gens: &[GenerationId],
    protect: &[GenerationId],
    keep: usize,
    max_bytes: u64,
    mut measure: impl FnMut(&[GenerationId]) -> u64,
) -> GcPlan {
    let mut kept: Vec<GenerationId> = gens.to_vec();
    kept.sort();
    kept.dedup();
    let mut delete = vec![];
    let mut bytes = measure(&kept);
    loop {
        if kept.len() <= keep && bytes <= max_bytes {
            break;
        }
        let Some(i) = kept.iter().position(|g| !protect.contains(g)) else { break };
        delete.push(kept.remove(i));
        bytes = measure(&kept);
    }
    let shortfall = (bytes > max_bytes).then(|| bytes - max_bytes);
    GcPlan { delete, kept, kept_bytes: bytes, max_bytes, shortfall }
}

/// The last collection's result, for `planarian status` and the console.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpaceReport {
    pub at: Timestamp,
    pub generations: usize,
    pub bytes: u64,
    pub max_bytes: u64,
    pub collected: usize,
    pub shortfall: Option<u64>,
}

impl SpaceReport {
    pub fn of(plan: &GcPlan, at: Timestamp) -> SpaceReport {
        SpaceReport {
            at,
            generations: plan.kept.len(),
            bytes: plan.kept_bytes,
            max_bytes: plan.max_bytes,
            collected: plan.delete.len(),
            shortfall: plan.shortfall,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn g(n: u64) -> GenerationId {
        GenerationId(n)
    }

    const GB: u64 = 1 << 30;

    /// Each generation's closure is 2 GB with nothing shared.
    fn size(gs: &[GenerationId]) -> u64 {
        gs.len() as u64 * 2 * GB
    }

    #[test]
    fn retain_all_collects_no_generation_and_reports_the_overrun() {
        let gens: Vec<_> = (1..=13).map(g).collect();
        let b = GcBudget { retain_all: true, ..GcBudget::default() };
        let p = plan(&gens, &b.protected(&gens, &[g(13)]), b.keep_emergency, 7 * GB, size);
        assert!(p.delete.is_empty());
        assert_eq!(p.kept.len(), 13);
        assert_eq!(p.shortfall, Some(26 * GB - 7 * GB));
    }

    #[test]
    fn count_bound_collects_oldest_first() {
        let gens: Vec<_> = (1..=13).map(g).collect();
        let p = plan(&gens, &[g(2), g(13)], 10, u64::MAX, size);
        assert_eq!(p.delete, vec![g(1), g(3), g(4)]);
        assert_eq!(p.kept.len(), 10);
        assert!(p.kept.contains(&g(2)), "protected stays even when oldest");
        assert_eq!(p.shortfall, None);
    }

    #[test]
    fn space_bound_collects_below_the_count() {
        let gens: Vec<_> = (1..=6).map(g).collect();
        let p = plan(&gens, &[g(6)], 10, 7 * GB, size);
        assert_eq!(p.delete, vec![g(1), g(2), g(3)]);
        assert_eq!(p.kept_bytes, 6 * GB);
        assert_eq!(p.shortfall, None);
    }

    #[test]
    fn unsatisfiable_budget_never_touches_the_protected_set() {
        let gens: Vec<_> = (1..=5).map(g).collect();
        let protect = [g(1), g(4), g(5)];
        let p = plan(&gens, &protect, 10, GB, size);
        assert_eq!(p.delete, vec![g(2), g(3)]);
        assert_eq!(p.kept, protect.to_vec());
        assert_eq!(p.shortfall, Some(5 * GB));
    }

    #[test]
    fn within_both_bounds_collects_nothing() {
        let gens: Vec<_> = (1..=4).map(g).collect();
        let p = plan(&gens, &[], 10, 100 * GB, size);
        assert!(p.delete.is_empty());
    }

    #[test]
    fn budget_share() {
        assert_eq!(GcBudget::default().max_bytes(100 * GB), 20 * GB);
    }
}
