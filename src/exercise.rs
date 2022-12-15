//! Merkle Tree and Merkle Proof types.

use crate::{
    error::Error,
    hash::{DigestProvider, MerkleHash},
};
use std::marker::PhantomData;

/// Denote whether a node in the proof is a leaf value or node hash
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Node {
    Leaf(u64),
    Node(MerkleHash),
}

/// Merkle Proof for an individual leaf
#[derive(Debug, Clone)]
pub struct MerkleProof<HF: DigestProvider> {
    _hasher: PhantomData<HF>,
    /// Path through the tree to the root node
    pub(crate) path: Vec<ProofMembershipElement>,
}

impl<HF: DigestProvider> MerkleProof<HF> {
    /// Compute the implied Merkle Root Hash from the pre-calculated path
    pub fn compute_implied_root(&self, leaf: u64) -> MerkleHash {
        let mut last_hash = HF::default_hash();
        for proof_element in &self.path {
            match &proof_element.element {
                Node::Leaf(sibling_value) => {
                    if proof_element.index & 1 == 1 {
                        last_hash =
                            HF::hash_pair(&leaf.to_le_bytes(), &sibling_value.to_be_bytes());
                    } else {
                        last_hash =
                            HF::hash_pair(&sibling_value.to_be_bytes(), &leaf.to_le_bytes());
                    }
                }
                Node::Node(sibling_hash) => {
                    if proof_element.index & 1 == 1 {
                        last_hash = HF::hash_pair(&sibling_hash, &last_hash)
                    } else {
                        last_hash = HF::hash_pair(&last_hash, &sibling_hash)
                    }
                }
            }
        }
        last_hash
    }
}

/// Individual proof element containing a value or an intermediate node hash
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofMembershipElement {
    /// Index of the node in the tree
    pub(crate) index: usize,
    /// Value of leaf or hash of the node
    pub(crate) element: Node,
}

impl ProofMembershipElement {
    /// Create new proof membership element
    pub fn new(index: usize, element: Node) -> Self {
        Self { index, element }
    }
}

/// Merkle Tree data structure
#[derive(Debug)]
pub struct MerkleTree<HF: DigestProvider> {
    _hasher: PhantomData<HF>,
    pub(crate) nodes: Vec<MerkleHash>,
    pub(crate) leaves: Vec<u64>,
}

impl<HF: DigestProvider> MerkleTree<HF> {
    /// Create an empty three with specified depth
    pub fn new(depth: usize, initial_leaf: u64) -> Self {
        let num_leaves = 1 << depth;
        let leaves = vec![initial_leaf; num_leaves];
        let mut hashes = vec![HF::hash_pair(&[0u8; 8], &[0u8; 8]); 1];
        let mut nodes = Vec::new();

        for i in 1..depth {
            hashes.push(HF::hash_pair(&hashes[i - 1], &hashes[i - 1]));
        }
        hashes.reverse();
        for i in 0..(num_leaves - 1) {
            let (depth, _) = get_depth_and_offset(i);
            nodes.push(hashes[depth].clone())
        }
        Self {
            _hasher: PhantomData,
            nodes,
            leaves,
        }
    }

    /// Set an individual leaf and recompute the Merkle Root
    pub fn set(&mut self, leaf_index: usize, value: u64) -> Result<(), Error> {
        let mut node_hash = self.compute_new_leaf_hash(leaf_index, value)?;
        self.leaves[leaf_index] = value;
        let working_index = leaf_index + self.num_leaves() - 1;
        let (depth, _) = get_depth_and_offset(working_index);
        let mut parent_index = get_parent_index(working_index);
        self.nodes[parent_index] = node_hash;

        for _ in 1..(depth + 1) {
            parent_index = get_parent_index(parent_index);
            let (left_child_index, right_child_index) = child_indices(parent_index);
            node_hash = HF::hash_pair(
                &self.nodes[left_child_index],
                &self.nodes[right_child_index],
            );
            self.nodes[parent_index] = node_hash;
        }
        Ok(())
    }

    /// Get the value and index of a leaf's sibling for a given leaf index
    pub fn get_leaf_sibling(&self, leaf_index: usize) -> Result<(u64, usize), Error> {
        self.leaf_exists(leaf_index)?;
        if leaf_index & 1 == 1 {
            let sibling_index = leaf_index - 1;
            Ok((self.leaves[sibling_index], sibling_index))
        } else {
            let sibling_index = leaf_index + 1;
            Ok((self.leaves[leaf_index + 1], sibling_index))
        }
    }

    /// Get the merkle hash of a node by index
    pub fn get_node(&self, node_index: usize) -> Result<&MerkleHash, Error> {
        self.node_exists(node_index)?;
        Ok(&self.nodes[node_index])
    }

    /// Compute new leaf hash
    pub(crate) fn compute_new_leaf_hash(
        &self,
        leaf_index: usize,
        value: u64,
    ) -> Result<MerkleHash, Error> {
        self.leaf_exists(leaf_index)?;
        if leaf_index & 1 == 1 {
            Ok(HF::hash_pair(
                &self.leaves[leaf_index - 1].to_le_bytes(),
                &value.to_le_bytes(),
            ))
        } else {
            Ok(HF::hash_pair(
                &value.to_le_bytes(),
                &self.leaves[leaf_index + 1].to_le_bytes(),
            ))
        }
    }

    /// Get the number of leaves in the tree
    pub fn num_leaves(&self) -> usize {
        self.leaves.len()
    }

    /// Ensure the leaf is a member of the tree
    fn leaf_exists(&self, leaf_index: usize) -> Result<(), Error> {
        if leaf_index >= self.num_leaves() {
            return Err(Error::ExceededMaxIndex(leaf_index, self.num_leaves()));
        }
        Ok(())
    }

    /// Ensure an intermediate node is a member of the tree
    fn node_exists(&self, node_index: usize) -> Result<(), Error> {
        if node_index >= self.nodes.len() {
            return Err(Error::ExceededMaxIndex(node_index, self.nodes.len()));
        }
        Ok(())
    }

    /// Get the merkle root of the tree
    pub fn root(&self) -> &MerkleHash {
        &self.nodes[0]
    }
}

/// Calculate a Merkle Proof from a tree and leaf index
pub fn proof<HF: DigestProvider>(
    tree: &MerkleTree<HF>,
    leaf_index: usize,
) -> Result<MerkleProof<HF>, Error> {
    let mut path = Vec::new();
    let (leaf_sibling, sibling_index) = tree.get_leaf_sibling(leaf_index)?;
    path.push(ProofMembershipElement::new(
        sibling_index,
        Node::Leaf(leaf_sibling),
    ));

    let mut working_index = leaf_index + tree.num_leaves() - 1;
    let (depth, _) = get_depth_and_offset(working_index);
    working_index = get_parent_index(working_index);
    for _ in 1..depth {
        if working_index & 1 == 1 {
            path.push(ProofMembershipElement::new(
                working_index + 1,
                Node::Node(tree.get_node(working_index + 1)?.clone()),
            ));
        } else {
            path.push(ProofMembershipElement::new(
                working_index - 1,
                Node::Node(tree.get_node(working_index - 1)?.clone()),
            ));
        }
        working_index = get_parent_index(working_index);
    }
    Ok(MerkleProof {
        _hasher: Default::default(),
        path,
    })
}

pub fn verify<HF: DigestProvider>(proof: &MerkleProof<HF>, index: u64) -> MerkleHash {
    proof.compute_implied_root(index)
}

/// Get a node's index given it's depth and offset
pub fn get_node_index(depth: usize, offset: usize) -> Result<usize, Error> {
    let index = (1 << depth ^ offset).saturating_sub(1);
    if index == 0 && depth > 0 {
        Err(Error::ExceededMaxOffset(depth, offset))
    } else {
        Ok(index)
    }
}

/// Get a node's depth and offset given it's index
pub fn get_depth_and_offset(index: usize) -> (usize, usize) {
    let mut depth = 0usize;
    let index = index + 1;
    while (index >> depth) > 1 {
        depth += 1;
    }
    (depth, index - (1 << depth))
}

/// Get a node's parent index given it's own index
pub fn get_parent_index(node_index: usize) -> usize {
    node_index.saturating_sub(1) >> 1
}

/// Get a node's child indices given it's own index
pub fn child_indices(node_index: usize) -> (usize, usize) {
    ((node_index << 1) + 1, (node_index << 1) + 2)
}

/// Given an index in the tree and a depth, return the leftmost index
pub fn get_leftmost_child_index(tree_depth: usize, index: usize) -> Option<usize> {
    let (start_depth, _) = get_depth_and_offset(index);
    let mut leftmost_child_index = index;
    for _ in start_depth..tree_depth {
        let (left, _) = child_indices(leftmost_child_index);
        leftmost_child_index = left;
    }
    if leftmost_child_index == index {
        return None;
    }
    Some(leftmost_child_index)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{hash_pair, hash_u64};
    use blake2::Blake2s256;
    use hex_literal::hex;
    use sha3::Sha3_256;

    #[test]
    fn exercise_1_test_merkle_index() {
        // Ensure the correct index is computed for a given depth and offset
        let mut index = 0usize;
        for i in 0..6 {
            for j in 0..(1 << i) {
                assert_eq!(get_node_index(i, j).unwrap(), index);
                index += 1;
            }
        }
        assert_eq!(index, 63);
    }

    #[test]
    fn exercise_2_test_parent_index() {
        // Ensure the correct parent index for a given node index is computed
        assert_eq!(get_parent_index(0), 0);
        for i in 1..63 {
            assert_eq!(get_parent_index(i), (i - 1) / 2);
        }
    }

    #[test]
    // Note that if a leftmost child index is to be found, an implicit tree depth also
    // must be specified
    fn exercise_2_test_leftmost_child_index() {
        assert_eq!(get_leftmost_child_index(5, 0).unwrap(), 31);
        assert_eq!(get_leftmost_child_index(5, 2).unwrap(), 47);
        assert_eq!(get_leftmost_child_index(5, 14).unwrap(), 59);
        assert_eq!(get_leftmost_child_index(5, 30).unwrap(), 61);
        assert!(get_leftmost_child_index(0, 0).is_none());
        for i in 31..63 {
            assert!(get_leftmost_child_index(5, i).is_none());
        }
    }

    #[test]
    fn exercise_2_test_depth_and_offset() {
        // Ensure a proper depth and offset is found for a given index
        let mut index = 0usize;
        for i in 0..6 {
            for j in 0..(1 << i) {
                assert_eq!(get_depth_and_offset(index), (i, j));
                index += 1;
            }
        }
        assert_eq!(index, 63);
    }

    #[test]
    fn exercise_3_test_merkle_tree_initialization() {
        // Get all of the hashes at the edges of the tree for each depth
        let tree = MerkleTree::<Sha3_256>::new(4, 0);
        let level_3_hash_max_bound = &tree.nodes[14];
        let level_3_hash_min_bound = &tree.nodes[7];
        let level_2_hash_max_bound = &tree.nodes[6];
        let level_2_hash_min_bound = &tree.nodes[3];
        let level_1_hash_max_bound = &tree.nodes[2];
        let level_1_hash_min_bound = &tree.nodes[1];
        let root = tree.root();

        // Verify the merkle tree computed matches precomputed hashes
        assert_eq!(
            level_3_hash_max_bound,
            hex!("193c5175327519b341546929f2770157bd2175e185d3387132557004787e2e2d")
        );
        assert_eq!(
            level_3_hash_min_bound,
            hex!("193c5175327519b341546929f2770157bd2175e185d3387132557004787e2e2d")
        );
        assert_eq!(
            level_2_hash_max_bound,
            hex!("913429c737e10b1d9811958ccaf6a9f04b8f4226977e8964c391d8cfd1c3993c")
        );
        assert_eq!(
            level_2_hash_min_bound,
            hex!("913429c737e10b1d9811958ccaf6a9f04b8f4226977e8964c391d8cfd1c3993c")
        );
        assert_eq!(
            level_1_hash_max_bound,
            hex!("06b978c81e775b7665fd1ae491bd6d74a3eef7b646b13c7583951dfe1d000eff")
        );
        assert_eq!(
            level_1_hash_min_bound,
            hex!("06b978c81e775b7665fd1ae491bd6d74a3eef7b646b13c7583951dfe1d000eff")
        );
        assert_eq!(
            root,
            hex!("a55029460d7cd0bc4c3cf969a5d05a536b52997b8d20d272ca54fcfc5a3ffa09")
        );
    }

    #[test]
    fn exercise_4_test_set_new_merkle_tree_value() {
        // Initialize a tree with depth 3
        let mut tree = MerkleTree::<Sha3_256>::new(3, 0);

        // Set two leaves (one within, one at the rightmost boundary) to different values
        tree.set(2, 42).unwrap();
        tree.set(7, 31421).unwrap();

        // Calculate the implied hash to see if the Merkle Root re-computation is correct
        let hash_pos_6 = hash_u64::<Sha3_256>(0, 31421);
        let hash_pos_4 = hash_u64::<Sha3_256>(42, 0);
        let zero_hash = hash_u64::<Sha3_256>(0, 0);
        let hash_pos_2 = hash_pair::<Sha3_256>(&zero_hash, &hash_pos_6);
        let hash_pos_1 = hash_pair::<Sha3_256>(&zero_hash, &hash_pos_4);
        assert_eq!(
            tree.root(),
            &hash_pair::<Sha3_256>(&hash_pos_1, &hash_pos_2)
        );

        // Set the leftmost boundary leaf and check again if the root computation is correct
        tree.set(0, u64::MAX).unwrap();
        let hash_pos_3 = hash_u64::<Sha3_256>(u64::MAX, 0);
        let hash_pos_1 = hash_pair::<Sha3_256>(&hash_pos_3, &hash_pos_4);
        assert_eq!(
            tree.root(),
            &hash_pair::<Sha3_256>(&hash_pos_1, &hash_pos_2)
        );
    }

    #[test]
    fn exercise_5_test_merkle_tree_verification() {
        let mut tree = MerkleTree::<Sha3_256>::new(20, 0);
        tree.set(5, 42).unwrap();
        tree.set(42, 5).unwrap();

        let proof_1 = proof::<Sha3_256>(&tree, 5).unwrap();
        assert_eq!(&verify::<Sha3_256>(&proof_1, 42), tree.root());
        let proof_2 = proof::<Sha3_256>(&tree, 42).unwrap();
        assert_eq!(&verify::<Sha3_256>(&proof_2, 5), tree.root());

        let mut tree = MerkleTree::<Blake2s256>::new(20, 0);
        tree.set(5, 42).unwrap();
        tree.set(42, 5).unwrap();

        let proof_1 = proof::<Blake2s256>(&tree, 5).unwrap();
        assert_eq!(&verify::<Blake2s256>(&proof_1, 42), tree.root());
        let proof_2 = proof::<Blake2s256>(&tree, 42).unwrap();
        assert_eq!(&verify::<Blake2s256>(&proof_2, 5), tree.root());
    }
}
