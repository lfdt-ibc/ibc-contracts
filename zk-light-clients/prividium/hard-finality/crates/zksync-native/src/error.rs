// SPDX-License-Identifier: Apache-2.0

use core::fmt;

use crate::{Address, Hash};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProofError {
    EmptyBatch,
    AddressMismatch {
        expected: Address,
        actual: Address,
    },
    SlotCountMismatch {
        expected: usize,
        actual: usize,
    },
    SlotMismatch {
        position: usize,
        expected: Hash,
        actual: Hash,
    },
    TooManySiblings {
        actual: usize,
        maximum: usize,
    },
    LeftNeighborNotLess,
    RightNeighborNotGreater,
    NeighborsNotLinked {
        left_next_index: u64,
        right_index: u64,
    },
    NeighborRootMismatch,
    BatchRootMismatch {
        position: usize,
    },
    ExpectedRootMismatch,
    ExpectedNativeAbsence,
    EmptyHashDepthOutOfRange {
        depth: u8,
    },
}

impl fmt::Display for ProofError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyBatch => formatter.write_str("a storage-proof batch must not be empty"),
            Self::AddressMismatch { .. } => formatter.write_str("queried address mismatch"),
            Self::SlotCountMismatch { expected, actual } => write!(
                formatter,
                "storage-slot proof count mismatch: expected {expected}, got {actual}"
            ),
            Self::SlotMismatch { position, .. } => {
                write!(
                    formatter,
                    "queried storage slot mismatch at position {position}"
                )
            }
            Self::TooManySiblings { actual, maximum } => write!(
                formatter,
                "too many explicit siblings: maximum {maximum}, got {actual}"
            ),
            Self::LeftNeighborNotLess => {
                formatter.write_str("left-neighbor key is not less than the queried key")
            }
            Self::RightNeighborNotGreater => {
                formatter.write_str("right-neighbor key is not greater than the queried key")
            }
            Self::NeighborsNotLinked { .. } => {
                formatter.write_str("left and right neighbors are not linked")
            }
            Self::NeighborRootMismatch => {
                formatter.write_str("neighbor proofs reconstruct different roots")
            }
            Self::BatchRootMismatch { position } => write!(
                formatter,
                "storage proof at position {position} reconstructs a different root"
            ),
            Self::ExpectedRootMismatch => {
                formatter.write_str("reconstructed native root does not match the expected root")
            }
            Self::ExpectedNativeAbsence => {
                formatter.write_str("proof authenticates an existing native leaf")
            }
            Self::EmptyHashDepthOutOfRange { depth } => {
                write!(formatter, "empty-subtree depth {depth} is out of range")
            }
        }
    }
}
