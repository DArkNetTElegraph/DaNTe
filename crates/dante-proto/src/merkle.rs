//! RFC 6962 Merkle tree hashing, inclusion proofs, and consistency proofs.
//!
//! Functions take **leaf hashes** (`[u8; 32]` each), not raw entries; compute a
//! leaf hash with [`leaf_hash`]. Domain separation follows RFC 6962: `0x00` for
//! leaves, `0x01` for internal nodes.
//!
//! - [`root`] — the Merkle Tree Hash (MTH) of an ordered list of leaves
//! - [`inclusion_proof`] / [`verify_inclusion`] — "leaf *i* is in this tree"
//! - [`consistency_proof`] / [`verify_consistency`] — "the size-*n* tree is an
//!   append-only extension of the size-*m* tree" (split-view detection)

use dante_crypto::hash::{sha256, sha256_parts};

/// A 32-byte hash (leaf hash, node hash, or tree root).
pub type Hash = [u8; 32];

/// MTH of the empty tree: `SHA-256("")`.
pub fn empty_root() -> Hash {
    sha256(&[])
}

/// Leaf hash of a raw entry: `SHA-256(0x00 || entry)`.
pub fn leaf_hash(entry: &[u8]) -> Hash {
    sha256_parts(&[&[0x00], entry])
}

/// Internal node hash: `SHA-256(0x01 || left || right)`.
pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    sha256_parts(&[&[0x01], left, right])
}

/// Largest power of two strictly less than `n` (`n >= 2`).
fn split(n: usize) -> usize {
    debug_assert!(n >= 2);
    let mut k = 1;
    while k << 1 < n {
        k <<= 1;
    }
    k
}

/// The Merkle Tree Hash of `leaves` (each element is already a leaf hash).
pub fn root(leaves: &[Hash]) -> Hash {
    match leaves.len() {
        0 => empty_root(),
        1 => leaves[0],
        n => {
            let k = split(n);
            node_hash(&root(&leaves[..k]), &root(&leaves[k..]))
        }
    }
}

/// Audit path proving `index` is present in a tree of `leaves`, ordered from the
/// leaf's sibling outward. `None` if `index` is out of range.
pub fn inclusion_proof(index: usize, leaves: &[Hash]) -> Option<Vec<Hash>> {
    let n = leaves.len();
    if index >= n {
        return None;
    }
    if n == 1 {
        return Some(Vec::new());
    }
    let k = split(n);
    let mut path = if index < k {
        let mut p = inclusion_proof(index, &leaves[..k])?;
        p.push(root(&leaves[k..]));
        p
    } else {
        let mut p = inclusion_proof(index - k, &leaves[k..])?;
        p.push(root(&leaves[..k]));
        p
    };
    path.shrink_to_fit();
    Some(path)
}

fn root_from_inclusion(index: usize, size: usize, leaf: &Hash, path: &[Hash]) -> Option<Hash> {
    if size == 0 || index >= size {
        return None;
    }
    if size == 1 {
        return if path.is_empty() { Some(*leaf) } else { None };
    }
    let (last, rest) = path.split_last()?;
    let k = split(size);
    if index < k {
        Some(node_hash(&root_from_inclusion(index, k, leaf, rest)?, last))
    } else {
        Some(node_hash(
            last,
            &root_from_inclusion(index - k, size - k, leaf, rest)?,
        ))
    }
}

/// Verify an [`inclusion_proof`]: does `leaf` sit at `index` in a tree of
/// `size` leaves whose root is `expected_root`?
pub fn verify_inclusion(
    index: usize,
    size: usize,
    leaf: &Hash,
    path: &[Hash],
    expected_root: &Hash,
) -> bool {
    root_from_inclusion(index, size, leaf, path).as_ref() == Some(expected_root)
}

fn subproof(m: usize, leaves: &[Hash], on_border: bool) -> Vec<Hash> {
    let n = leaves.len();
    if m == n {
        return if on_border {
            Vec::new()
        } else {
            vec![root(leaves)]
        };
    }
    let k = split(n);
    if m <= k {
        let mut p = subproof(m, &leaves[..k], on_border);
        p.push(root(&leaves[k..]));
        p
    } else {
        let mut p = subproof(m - k, &leaves[k..], false);
        p.push(root(&leaves[..k]));
        p
    }
}

/// Proof that a tree of `leaves` is an append-only extension of its own first
/// `old_size` leaves. `None` if `old_size` is 0 or exceeds the tree.
pub fn consistency_proof(old_size: usize, leaves: &[Hash]) -> Option<Vec<Hash>> {
    let n = leaves.len();
    if old_size == 0 || old_size > n {
        return None;
    }
    if old_size == n {
        return Some(Vec::new());
    }
    Some(subproof(old_size, leaves, true))
}

/// Verify a [`consistency_proof`] between `old_root` (size `old_size`) and
/// `new_root` (size `new_size`). Implements RFC 6962-bis §2.1.4.2.
pub fn verify_consistency(
    old_size: usize,
    new_size: usize,
    old_root: &Hash,
    new_root: &Hash,
    proof: &[Hash],
) -> bool {
    if old_size > new_size {
        return false;
    }
    if old_size == new_size {
        return proof.is_empty() && old_root == new_root;
    }
    if old_size == 0 {
        return proof.is_empty();
    }

    // If old_size is a power of two, the old tree is a complete left subtree of
    // the new one and its root is the implicit first path element.
    let mut work: Vec<Hash> = Vec::with_capacity(proof.len() + 1);
    if old_size.is_power_of_two() {
        work.push(*old_root);
    }
    work.extend_from_slice(proof);
    if work.is_empty() {
        return false;
    }

    // `fnode` walks the old tree's rightmost node, `snode` the new tree's.
    let mut fnode = old_size - 1;
    let mut snode = new_size - 1;
    while fnode & 1 == 1 {
        fnode >>= 1;
        snode >>= 1;
    }

    let mut iter = work.iter();
    let mut fr = *iter.next().unwrap();
    let mut sr = fr;

    for c in iter {
        if snode == 0 {
            return false;
        }
        if fnode & 1 == 1 || fnode == snode {
            fr = node_hash(c, &fr);
            sr = node_hash(c, &sr);
            if fnode & 1 == 0 {
                loop {
                    fnode >>= 1;
                    snode >>= 1;
                    if fnode & 1 == 1 || fnode == 0 {
                        break;
                    }
                }
            }
        } else {
            sr = node_hash(&sr, c);
        }
        fnode >>= 1;
        snode >>= 1;
    }

    fnode == 0 && &fr == old_root && &sr == new_root
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use super::*;

    fn leaves(n: usize) -> Vec<Hash> {
        (0..n).map(|i| leaf_hash(&[i as u8, 0xAB])).collect()
    }

    #[test]
    fn rfc6962_domain_separated_hashes() {
        // RFC 6962: empty tree is SHA-256 of the empty string.
        assert_eq!(
            empty_root(),
            hex!("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
        // RFC 6962 test entry "L123456": leaf hash = SHA-256(0x00 || entry).
        assert_eq!(
            leaf_hash(b"L123456"),
            hex!("395aa064aa4c29f7010acfe3f25db9485bbd4b91897b6ad7ad547639252b4d56")
        );
        // Internal node over leaf("a"), leaf("b") = SHA-256(0x01 || la || lb).
        assert_eq!(
            node_hash(&leaf_hash(b"a"), &leaf_hash(b"b")),
            hex!("b137985ff484fb600db93107c77b0365c80d78f5b429ded0fd97361d077999eb")
        );
    }

    #[test]
    fn known_small_roots() {
        assert_eq!(root(&[]), empty_root());
        let l = leaves(1);
        assert_eq!(root(&l), l[0]);
        let l = leaves(2);
        assert_eq!(root(&l), node_hash(&l[0], &l[1]));
        let l = leaves(3);
        assert_eq!(root(&l), node_hash(&node_hash(&l[0], &l[1]), &l[2]));
        let l = leaves(4);
        assert_eq!(
            root(&l),
            node_hash(&node_hash(&l[0], &l[1]), &node_hash(&l[2], &l[3]))
        );
    }

    #[test]
    fn inclusion_proofs_verify_for_every_leaf() {
        for n in 1..=40usize {
            let l = leaves(n);
            let r = root(&l);
            for i in 0..n {
                let p = inclusion_proof(i, &l).unwrap();
                assert!(verify_inclusion(i, n, &l[i], &p, &r), "n={n} i={i}");
                // wrong leaf must fail
                assert!(!verify_inclusion(i, n, &leaf_hash(b"nope"), &p, &r));
                // wrong index must fail
                if i + 1 < n {
                    assert!(!verify_inclusion(i + 1, n, &l[i], &p, &r));
                }
            }
        }
    }

    #[test]
    fn inclusion_proof_out_of_range_is_none() {
        assert!(inclusion_proof(5, &leaves(5)).is_none());
    }

    #[test]
    fn consistency_proofs_verify_for_every_split() {
        for n in 1..=40usize {
            let l = leaves(n);
            let new_root = root(&l);
            for m in 1..=n {
                let old_root = root(&l[..m]);
                let p = consistency_proof(m, &l).unwrap();
                assert!(
                    verify_consistency(m, n, &old_root, &new_root, &p),
                    "m={m} n={n}"
                );
            }
        }
    }

    #[test]
    fn consistency_rejects_forks_and_tampering() {
        let l = leaves(16);
        let new_root = root(&l);
        let m = 6;
        let old_root = root(&l[..m]);
        let good = consistency_proof(m, &l).unwrap();
        assert!(verify_consistency(m, 16, &old_root, &new_root, &good));

        // A different history for the first m leaves: same old size, wrong root.
        let mut forked = l.clone();
        forked[2] = leaf_hash(b"tampered");
        let forked_old_root = root(&forked[..m]);
        assert!(!verify_consistency(
            m,
            16,
            &forked_old_root,
            &new_root,
            &good
        ));

        // Tampered proof element.
        let mut bad = good.clone();
        if let Some(h) = bad.first_mut() {
            h[0] ^= 1;
        }
        assert!(!verify_consistency(m, 16, &old_root, &new_root, &bad));

        // Claimed new root that isn't the real one.
        let wrong_new = leaf_hash(b"not the root");
        assert!(!verify_consistency(m, 16, &old_root, &wrong_new, &good));
    }

    #[test]
    fn consistency_edge_cases() {
        let l = leaves(10);
        let r = root(&l);
        // equal sizes: empty proof, roots must match
        assert!(verify_consistency(10, 10, &r, &r, &[]));
        assert!(!verify_consistency(10, 10, &r, &leaf_hash(b"x"), &[]));
        // old_size 0
        assert!(verify_consistency(0, 10, &empty_root(), &r, &[]));
        // old_size > new_size
        assert!(!verify_consistency(11, 10, &r, &r, &[]));
        // power-of-two old size (prepend path)
        let old_root = root(&l[..8]);
        let p = consistency_proof(8, &l).unwrap();
        assert!(verify_consistency(8, 10, &old_root, &r, &p));
    }
}
