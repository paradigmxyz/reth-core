//! Block header data primitive.

use crate::{InMemorySize, MaybeCompact, MaybeSerde};
use alloy_primitives::Sealable;
use core::{fmt, hash::Hash};

/// Re-exported alias
pub use alloy_consensus::BlockHeader as AlloyBlockHeader;

/// Helper trait that unifies all behaviour required by block header to support full node
/// operations.
pub trait FullBlockHeader: BlockHeader + MaybeCompact {}

impl<T> FullBlockHeader for T where T: BlockHeader + MaybeCompact {}

/// Abstraction of a block header.
pub trait BlockHeader:
    Send
    + Sync
    + Unpin
    + Clone
    + Hash
    + Default
    + fmt::Debug
    + PartialEq
    + Eq
    + alloy_rlp::Encodable
    + alloy_rlp::Decodable
    + alloy_consensus::BlockHeader
    + Sealable
    + InMemorySize
    + MaybeSerde
    + AsRef<Self>
    + 'static
{
    /// Converts a regular ethereum block header into this type.
    fn from_ethereum_header(header: alloy_consensus::Header) -> Self;
}

impl BlockHeader for alloy_consensus::Header {
    #[inline]
    fn from_ethereum_header(header: Self) -> Self {
        header
    }
}
