//!SHA3 Hash ingest function
use crate::{Error, Node};
use blake2::Blake2s256;
use sha3::{Digest, Sha3_256};
use std::ops::Deref;

/// Domain separation tags
const MERKLE_HASH_DOMAIN: &[u8] = b"MerkleHash";

pub trait DigestProvider {
    fn hash_pair(left: &[u8], right: &[u8]) -> MerkleHash;
    fn hash_nodes(left: Node, right: Node) -> Result<MerkleHash, Error> {
        match (left, right) {
            (Node::Leaf(l), Node::Leaf(r)) => {
                Ok(Self::hash_pair(&l.to_le_bytes(), &r.to_le_bytes()))
            }
            (Node::Node(l), Node::Node(r)) => Ok(Self::hash_pair(&l, &r)),
            _ => Err(Error::NodeTypeMismatch),
        }
    }
    fn default_hash() -> MerkleHash;
}

impl DigestProvider for Sha3_256 {
    fn hash_pair(left: &[u8], right: &[u8]) -> MerkleHash {
        let mut hasher = Sha3_256::default();
        hasher.update(MERKLE_HASH_DOMAIN);
        hasher.update(left);
        hasher.update(right);
        let hash = MerkleHash(hasher.finalize().to_vec());
        hash
    }

    fn default_hash() -> MerkleHash {
        MerkleHash([0u8; 32].into())
    }
}

impl DigestProvider for Blake2s256 {
    fn hash_pair(left: &[u8], right: &[u8]) -> MerkleHash {
        let mut hasher = Blake2s256::default();
        hasher.update(MERKLE_HASH_DOMAIN);
        hasher.update(left);
        hasher.update(right);
        MerkleHash(hasher.finalize().to_vec())
    }

    fn default_hash() -> MerkleHash {
        MerkleHash([0u8; 32].into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleHash(Vec<u8>);

impl Deref for MerkleHash {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<[u8]> for &MerkleHash {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

// Support common hash lengths
impl PartialEq<[u8; 16]> for &MerkleHash {
    fn eq(&self, other: &[u8; 16]) -> bool {
        &self.0 == other
    }
}

impl PartialEq<[u8; 20]> for &MerkleHash {
    fn eq(&self, other: &[u8; 20]) -> bool {
        &self.0 == other
    }
}

impl PartialEq<[u8; 32]> for &MerkleHash {
    fn eq(&self, other: &[u8; 32]) -> bool {
        &self.0 == other
    }
}

impl PartialEq<[u8; 64]> for &MerkleHash {
    fn eq(&self, other: &[u8; 64]) -> bool {
        &self.0 == other
    }
}

impl PartialEq<[u8; 128]> for &MerkleHash {
    fn eq(&self, other: &[u8; 128]) -> bool {
        &self.0 == other
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::hash_pair;
    use hex_literal::hex;

    #[test]
    fn test_hash_leaves_sha() {
        let result_level_3 = hash_pair::<Sha3_256>(&[0u8; 8], &[0u8; 8]);
        let result_level_2 = hash_pair::<Sha3_256>(&result_level_3, &result_level_3);
        let result_level_1 = hash_pair::<Sha3_256>(&result_level_2, &result_level_2);
        let result_level_0 = hash_pair::<Sha3_256>(&result_level_1, &result_level_1);
        assert_eq!(
            &result_level_3,
            hex!("193c5175327519b341546929f2770157bd2175e185d3387132557004787e2e2d")
        );
        assert_eq!(
            &result_level_2,
            hex!("913429c737e10b1d9811958ccaf6a9f04b8f4226977e8964c391d8cfd1c3993c")
        );
        assert_eq!(
            &result_level_1,
            hex!("06b978c81e775b7665fd1ae491bd6d74a3eef7b646b13c7583951dfe1d000eff")
        );
        assert_eq!(
            &result_level_0,
            hex!("a55029460d7cd0bc4c3cf969a5d05a536b52997b8d20d272ca54fcfc5a3ffa09")
        );
    }
}
