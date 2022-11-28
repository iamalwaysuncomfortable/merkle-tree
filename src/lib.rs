//! Merkle Tree proving system

mod error;
mod exercise;
mod hash;

pub use crate::{
    error::Error,
    exercise::{proof, verify, MerkleProof, MerkleTree, ProofMembershipElement},
    hash::hash_nodes,
};
