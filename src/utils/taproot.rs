use std::{cmp::Reverse, collections::BinaryHeap, sync::Arc};

use bdk_wallet::miniscript::{
    Miniscript, MiniscriptKey, Tap,
    descriptor::TapTree,
    policy::{Concrete, compiler::CompilerError},
};

use crate::error::BDKCliError as Error;

/// Upper bound on taproot leaves, matching rust-miniscript's `MAX_COMPILATION_LEAVES`.
const MAX_TAPLEAVES: usize = 1024;

/// Probability weight with a total order, so it can key a `BinaryHeap`.
#[derive(PartialEq)]
struct Weight(f64);

impl Eq for Weight {}

impl PartialOrd for Weight {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Weight {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.total_cmp(&other.0)
    }
}

/// Flatten root-level disjunctions (`or`, `thresh(1, ..)`) into `(probability, branch)`
/// pairs, one per disjunctive branch.
fn tapleaf_branches<Pk: MiniscriptKey>(
    policy: &Concrete<Pk>,
    prob: f64,
    out: &mut Vec<(f64, Concrete<Pk>)>,
) {
    match policy {
        Concrete::Or(subs) => {
            let total: usize = subs.iter().map(|(weight, _)| *weight).sum();
            for (weight, sub) in subs {
                tapleaf_branches(sub, prob * *weight as f64 / total as f64, out);
            }
        }
        Concrete::Thresh(thresh) if thresh.is_or() => {
            for sub in thresh.iter() {
                tapleaf_branches(sub, prob / thresh.n() as f64, out);
            }
        }
        other => out.push((prob, other.clone())),
    }
}

/// Compile `policy` into a taproot script tree with one leaf per disjunctive branch,
/// Huffman-weighted by branch probability.
///
/// This stands in for rust-miniscript's `compile_tr`, which picks a key from the policy
/// as the internal key. The caller needs to keep its own verifiable unspendable internal
/// key, so only the tree is built here.
pub fn compile_tap_tree<Pk: MiniscriptKey>(policy: &Concrete<Pk>) -> Result<TapTree<Pk>, Error> {
    // Validate the whole policy first, as `Concrete::compile` does. Checking each branch
    // alone would miss problems that span branches, such as a key reused in two of them.
    policy.is_valid().map_err(CompilerError::from)?;
    match policy.is_safe_nonmalleable() {
        (false, _) => return Err(CompilerError::TopLevelNonSafe.into()),
        (_, false) => return Err(CompilerError::ImpossibleNonMalleableCompilation.into()),
        _ => {}
    }

    let mut branches = Vec::new();
    tapleaf_branches(policy, 1.0, &mut branches);

    if branches.len() > MAX_TAPLEAVES {
        return Err(Error::Generic(format!(
            "Policy compiles to {} taproot leaves, the maximum is {MAX_TAPLEAVES}",
            branches.len()
        )));
    }

    let mut heap = BinaryHeap::new();
    for (prob, branch) in branches {
        let leaf: Miniscript<Pk, Tap> = branch.compile()?;
        leaf.sanity_check()
            .map_err(|e| Error::Generic(format!("Unsafe policy branch: {e}")))?;
        heap.push((Reverse(Weight(prob)), TapTree::Leaf(Arc::new(leaf))));
    }

    while heap.len() > 1 {
        let (Reverse(Weight(p1)), left) = heap.pop().expect("heap has two nodes");
        let (Reverse(Weight(p2)), right) = heap.pop().expect("heap has two nodes");
        heap.push((Reverse(Weight(p1 + p2)), TapTree::combine(left, right)));
    }

    heap.pop()
        .map(|(_, tree)| tree)
        .ok_or_else(|| Error::Generic("Policy has no spending path".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    /// `(depth, script)` of every leaf, in tree order.
    fn leaves(policy: &str) -> Vec<(usize, String)> {
        let policy: Concrete<String> = Concrete::from_str(policy).unwrap();
        compile_tap_tree(&policy)
            .unwrap()
            .iter()
            .map(|(depth, ms)| (usize::from(depth), ms.to_string()))
            .collect()
    }

    #[test]
    fn splits_or_into_one_leaf_per_branch() {
        let found = leaves("or(pk(A),pk(B))");
        assert_eq!(found.len(), 2);
        assert!(found.iter().all(|(depth, _)| *depth == 1));
    }

    #[test]
    fn flattens_nested_disjunctions() {
        assert_eq!(leaves("or(pk(A),or(pk(B),pk(C)))").len(), 3);
        assert_eq!(leaves("thresh(1,pk(A),pk(B),pk(C),pk(D))").len(), 4);
        assert_eq!(leaves("or(pk(A),thresh(1,pk(B),pk(C)))").len(), 3);
    }

    #[test]
    fn puts_likely_branches_nearer_the_root() {
        // A is 10x as likely as B or C, so the Huffman tree keeps it one step from the root.
        let found = leaves("or(10@pk(A),or(1@pk(B),1@pk(C)))");
        let depth_of = |script: &str| found.iter().find(|(_, s)| s == script).unwrap().0;

        assert_eq!(depth_of("pk(A)"), 1);
        assert_eq!(depth_of("pk(B)"), 2);
        assert_eq!(depth_of("pk(C)"), 2);
    }

    #[test]
    fn single_key_is_one_leaf_at_the_root() {
        assert_eq!(leaves("pk(A)"), vec![(0, "pk(A)".to_string())]);
    }

    #[test]
    fn keeps_a_conjunction_in_one_leaf() {
        assert_eq!(leaves("and(pk(A),pk(B))").len(), 1);
    }

    #[test]
    fn only_splits_one_of_n_thresholds() {
        assert_eq!(leaves("thresh(2,pk(A),pk(B),pk(C))").len(), 1);
    }

    #[test]
    fn splits_a_disjunction_below_a_conjunction_only_at_the_root() {
        // The `or` sits under an `and`, so it is not a root-level disjunction.
        assert_eq!(leaves("and(or(pk(A),pk(B)),pk(C))").len(), 1);
    }

    #[test]
    fn same_policy_always_gives_the_same_tree() {
        let policy = "thresh(1,pk(A),pk(B),pk(C),pk(D),pk(E))";
        assert_eq!(leaves(policy), leaves(policy));
    }
}
