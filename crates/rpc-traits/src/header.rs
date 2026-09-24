use alloy_consensus::Sealable;
use alloy_primitives::U256;
use reth_primitives_traits::SealedHeader;

/// Conversion trait for obtaining RPC header from a consensus header.
pub trait FromConsensusHeader<T> {
    /// Takes a consensus header and converts it into `self`.
    ///
    /// `block_size` is present for full block responses and absent for header-only responses.
    fn from_consensus_header(header: SealedHeader<T>, block_size: Option<usize>) -> Self;
}

impl<T: Sealable> FromConsensusHeader<T> for alloy_rpc_types_eth::Header<T> {
    fn from_consensus_header(header: SealedHeader<T>, block_size: Option<usize>) -> Self {
        Self::from_consensus(header.into(), None, block_size.map(U256::from))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::Header;

    #[test]
    fn block_size_is_only_set_when_provided() {
        let header = || SealedHeader::new_unhashed(Header::default());

        let rpc_header = alloy_rpc_types_eth::Header::from_consensus_header(header(), None);
        assert_eq!(rpc_header.size, None);

        let rpc_header = alloy_rpc_types_eth::Header::from_consensus_header(header(), Some(42));
        assert_eq!(rpc_header.size, Some(U256::from(42)));
    }
}
