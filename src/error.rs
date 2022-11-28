//! Merkle Tree Errors

use displaydoc::Display;

#[derive(Debug, Display)]
pub enum Error {
    /// Offset: {1} exceeded maximum number of nodes at requested depth: {0}
    ExceededMaxOffset(usize, usize),
    /// Requested index: {0} exceeds number of nodes or leaves: {1}
    ExceededMaxIndex(usize, usize),
}
