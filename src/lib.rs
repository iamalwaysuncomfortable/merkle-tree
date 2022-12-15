//! Merkle Tree proving system

mod error;
mod exercise;
mod hash;

pub use crate::{
    error::Error,
    exercise::{
        get_depth_and_offset, get_leftmost_child_index, get_node_index, get_parent_index, proof,
        verify, MerkleProof, MerkleTree, Node, ProofMembershipElement,
    },
    hash::{DigestProvider, MerkleHash},
};

#[cfg(test)]
mod test_utils {
    use super::*;
    /// Calculate the implied root of a Merkle Proof
    pub(crate) fn hash_pair<HF: DigestProvider>(left: &[u8], right: &[u8]) -> MerkleHash {
        HF::hash_pair(left, right)
    }

    pub(crate) fn hash_u64<HF: DigestProvider>(left: u64, right: u64) -> MerkleHash {
        HF::hash_pair(&left.to_le_bytes(), &right.to_le_bytes())
    }
}
