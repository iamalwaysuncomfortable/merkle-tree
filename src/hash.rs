//!SHA3 Hash ingest function

use sha3::{Digest, Sha3_256};
use std::ops::Deref;

/// Domain separation tags
pub(crate) const MERKLE_HASH: &[u8] = b"MerkleHash";

/// Hash two nodes on a merkle tree by concatenating the left and
/// right leaves and taking the SHA3 hash of the concatenated value.
/// Since SHA3 uses a sponge construction internally, inputs can be
/// added can be raw leaf values or hash outputs from intermediate
/// nodes
pub fn hash_nodes(left: &[u8], right: &[u8]) -> MerkleHash {
    let mut hasher = Sha3_256::default();
    let mut result = [0u8; 32];

    hasher.update(MERKLE_HASH);
    hasher.update(&[left, right].concat());
    result.copy_from_slice(hasher.finalize().as_slice());
    MerkleHash(result)
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct MerkleHash(pub [u8; 32]);

/// Container for Merkle Hashes
impl From<(u64, u64)> for MerkleHash {
    fn from(value: (u64, u64)) -> Self {
        hash_nodes(&value.0.to_le_bytes(), &value.1.to_le_bytes())
    }
}

impl Deref for MerkleHash {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl PartialEq<[u8; 32]> for MerkleHash {
    fn eq(&self, other: &[u8; 32]) -> bool {
        &self.0 == other
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ::hex_literal::hex;

    #[test]
    fn test_hash_leaves() {
        let result_level_3 = hash_nodes(&[0u8; 8], &[0u8; 8]);
        let result_level_2 = hash_nodes(&result_level_3, &result_level_3);
        let result_level_1 = hash_nodes(&result_level_2, &result_level_2);
        let result_level_0 = hash_nodes(&result_level_1, &result_level_1);
        assert_eq!(
            result_level_3,
            hex!("193c5175327519b341546929f2770157bd2175e185d3387132557004787e2e2d")
        );
        assert_eq!(
            result_level_2,
            hex!("913429c737e10b1d9811958ccaf6a9f04b8f4226977e8964c391d8cfd1c3993c")
        );
        assert_eq!(
            result_level_1,
            hex!("06b978c81e775b7665fd1ae491bd6d74a3eef7b646b13c7583951dfe1d000eff")
        );
        assert_eq!(
            result_level_0,
            hex!("a55029460d7cd0bc4c3cf969a5d05a536b52997b8d20d272ca54fcfc5a3ffa09")
        );
    }
}
