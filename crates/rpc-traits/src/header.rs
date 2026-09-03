use alloy_consensus::Sealable;
use reth_primitives_traits::SealedHeader;

/// Conversion trait for obtaining RPC header from a consensus header.
pub trait FromConsensusHeader<T> {
    /// Takes a consensus header and converts it into `self`.
    fn from_consensus_header(header: SealedHeader<T>) -> Self;
}

impl<T: Sealable> FromConsensusHeader<T> for alloy_rpc_types_eth::Header<T> {
    fn from_consensus_header(header: SealedHeader<T>) -> Self {
        Self::from_consensus(header.into(), None, None)
    }
}
