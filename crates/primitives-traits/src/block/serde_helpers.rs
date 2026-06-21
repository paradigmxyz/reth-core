//! Serde helpers for block wrapper types.

use crate::{
    block::{SealedBlock, SealedOrRecoveredBlock},
    Block,
};

/// Serializes a [`SealedBlock`] as its inner block fields.
///
/// This is useful for serde surfaces that need the same representation as `B` while retaining a
/// sealed block in memory.
pub mod sealed_block {
    use super::*;

    /// Serializes a sealed block as `{ header, body }` without including the cached seal.
    pub fn serialize<B, S>(block: &SealedBlock<B>, serializer: S) -> Result<S::Ok, S::Error>
    where
        B: Block,
        B::Header: serde::Serialize,
        B::Body: serde::Serialize,
        S: serde::Serializer,
    {
        B::serialize_ref(block.header(), block.body(), serializer)
    }

    /// Deserializes a sealed block from `{ header, body }`, computing the block seal.
    pub fn deserialize<'de, B, D>(deserializer: D) -> Result<SealedBlock<B>, D::Error>
    where
        B: Block,
        B::Header: serde::Deserialize<'de>,
        B::Body: serde::Deserialize<'de>,
        D: serde::Deserializer<'de>,
    {
        let (header, body) = B::deserialize_from_fields(deserializer)?;
        Ok(SealedBlock::seal_slow(B::new(header, body)))
    }
}

/// Serializes a [`SealedOrRecoveredBlock`] as its inner block fields.
///
/// Recovered senders are not included in the serde representation.
pub mod sealed_or_recovered_block {
    use super::*;

    /// Serializes the sealed view of a sealed-or-recovered block as `{ header, body }`.
    pub fn serialize<B, S>(
        block: &SealedOrRecoveredBlock<B>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        B: Block,
        B::Header: serde::Serialize,
        B::Body: serde::Serialize,
        S: serde::Serializer,
    {
        super::sealed_block::serialize(block.sealed_block(), serializer)
    }

    /// Deserializes from `{ header, body }` into the sealed-only variant.
    pub fn deserialize<'de, B, D>(deserializer: D) -> Result<SealedOrRecoveredBlock<B>, D::Error>
    where
        B: Block,
        B::Header: serde::Deserialize<'de>,
        B::Body: serde::Deserialize<'de>,
        D: serde::Deserializer<'de>,
    {
        super::sealed_block::deserialize(deserializer).map(SealedOrRecoveredBlock::sealed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    use alloy_consensus::{Block as AlloyBlock, Header, TxEnvelope};

    type TestBlock = AlloyBlock<TxEnvelope, Header>;

    #[derive(serde::Serialize)]
    struct WrappedSealedBlock<'a> {
        #[serde(with = "crate::block::serde_helpers::sealed_block")]
        block: &'a SealedBlock<TestBlock>,
    }

    #[derive(serde::Serialize)]
    struct WrappedSealedOrRecoveredBlock<'a> {
        #[serde(with = "crate::block::serde_helpers::sealed_or_recovered_block")]
        block: &'a SealedOrRecoveredBlock<TestBlock>,
    }

    #[derive(serde::Deserialize)]
    struct OwnedWrappedSealedBlock {
        #[serde(with = "crate::block::serde_helpers::sealed_block")]
        block: SealedBlock<TestBlock>,
    }

    #[derive(serde::Deserialize)]
    struct OwnedWrappedSealedOrRecoveredBlock {
        #[serde(with = "crate::block::serde_helpers::sealed_or_recovered_block")]
        block: SealedOrRecoveredBlock<TestBlock>,
    }

    #[test]
    fn sealed_block_serializes_as_plain_block() {
        let plain_block = TestBlock::default();
        let sealed_block = SealedBlock::seal_slow(plain_block.clone());

        let wrapped = serde_json::to_value(WrappedSealedBlock { block: &sealed_block }).unwrap();

        assert_eq!(wrapped["block"], serde_json::to_value(plain_block).unwrap());
        assert!(wrapped["block"]["header"]["parentHash"].is_string());
        assert!(wrapped["block"]["header"]["header"].is_null());
    }

    #[test]
    fn sealed_or_recovered_block_serializes_as_plain_block() {
        let plain_block = TestBlock::default();
        let recovered_block = SealedBlock::seal_slow(plain_block.clone()).with_senders(Vec::new());
        let block = SealedOrRecoveredBlock::from(recovered_block);

        let wrapped =
            serde_json::to_value(WrappedSealedOrRecoveredBlock { block: &block }).unwrap();

        assert_eq!(wrapped["block"], serde_json::to_value(plain_block).unwrap());
        assert!(wrapped["block"]["header"]["parentHash"].is_string());
        assert!(wrapped["block"]["header"]["header"].is_null());
    }

    #[test]
    fn sealed_block_deserializes_from_plain_block() {
        let value = serde_json::json!({ "block": TestBlock::default() });

        let wrapped: OwnedWrappedSealedBlock = serde_json::from_value(value).unwrap();

        assert_eq!(wrapped.block.clone_block(), TestBlock::default());
    }

    #[test]
    fn sealed_or_recovered_block_deserializes_from_plain_block() {
        let value = serde_json::json!({ "block": TestBlock::default() });

        let wrapped: OwnedWrappedSealedOrRecoveredBlock = serde_json::from_value(value).unwrap();

        assert_eq!(wrapped.block.sealed_block().clone_block(), TestBlock::default());
    }
}
