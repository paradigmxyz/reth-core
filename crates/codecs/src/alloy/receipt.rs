//! Compact implementation for [`AlloyEthereumReceipt`]

use crate::Compact;
use alloc::vec::Vec;
use alloy_consensus::EthereumReceipt as AlloyEthereumReceipt;
use alloy_primitives::Log;
use bytes::Buf;
use modular_bitfield::prelude::*;

#[allow(non_snake_case)]
mod flags {
    use super::*;

    /// Bitflag fieldset for receipt compact encoding.
    ///
    /// Used bytes: 1 | Unused bits: 0
    #[bitfield]
    #[derive(Clone, Copy, Debug, Default)]
    pub struct ReceiptFlags {
        pub tx_type_len: B2,
        pub success_len: B1,
        pub cumulative_gas_used_len: B4,
        pub __zstd: B1,
    }

    impl ReceiptFlags {
        /// Deserializes this fieldset and returns it, alongside the original slice in an advanced
        /// position.
        pub fn from(mut buf: &[u8]) -> (Self, &[u8]) {
            (Self::from_bytes([buf.get_u8()]), buf)
        }
    }
}

pub(crate) use flags::ReceiptFlags;

impl<T: Compact> Compact for AlloyEthereumReceipt<T> {
    fn to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: bytes::BufMut + AsMut<[u8]>,
    {
        let mut flags = ReceiptFlags::default();
        let mut buffer = bytes::BytesMut::new();

        let tx_type_len = self.tx_type.to_compact(&mut buffer);
        flags.set_tx_type_len(tx_type_len as u8);
        let success_len = self.success.to_compact(&mut buffer);
        flags.set_success_len(success_len as u8);
        let cumulative_gas_used_len = self.cumulative_gas_used.to_compact(&mut buffer);
        flags.set_cumulative_gas_used_len(cumulative_gas_used_len as u8);
        self.logs.to_compact(&mut buffer);

        let zstd = buffer.len() > 7;
        if zstd {
            flags.set___zstd(1);
        }

        let flags = flags.into_bytes();
        buf.put_slice(&flags);
        if zstd {
            reth_zstd_compressors::with_receipt_compressor(|compressor| {
                let compressed = compressor.compress(&buffer).expect("Failed to compress.");
                buf.put(compressed.as_slice());
                flags.len() + compressed.len()
            })
        } else {
            let len = flags.len() + buffer.len();
            buf.put(buffer);
            len
        }
    }

    fn from_compact(buf: &[u8], len: usize) -> (Self, &[u8]) {
        // Decode only this receipt's `len` bytes and return everything after it.
        let (buf, rest) = buf.split_at(len);
        let (flags, mut buf) = ReceiptFlags::from(buf);
        if flags.__zstd() != 0 {
            reth_zstd_compressors::with_receipt_decompressor(|decompressor| {
                let decompressed = decompressor.decompress(buf);
                let mut buf: &[u8] = decompressed;
                let (tx_type, new_buf) = T::from_compact(buf, flags.tx_type_len() as usize);
                buf = new_buf;
                let (success, new_buf) = bool::from_compact(buf, flags.success_len() as usize);
                buf = new_buf;
                let (cumulative_gas_used, new_buf) =
                    u64::from_compact(buf, flags.cumulative_gas_used_len() as usize);
                buf = new_buf;
                let (logs, _) = Vec::<Log>::from_compact(buf, buf.len());
                (Self { tx_type, success, cumulative_gas_used, logs }, rest)
            })
        } else {
            let (tx_type, new_buf) = T::from_compact(buf, flags.tx_type_len() as usize);
            buf = new_buf;
            let (success, new_buf) = bool::from_compact(buf, flags.success_len() as usize);
            buf = new_buf;
            let (cumulative_gas_used, new_buf) =
                u64::from_compact(buf, flags.cumulative_gas_used_len() as usize);
            buf = new_buf;
            let (logs, _) = Vec::<Log>::from_compact(buf, buf.len());
            (Self { tx_type, success, cumulative_gas_used, logs }, rest)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::TxType;
    use proptest::proptest;
    use proptest_arbitrary_interop::arb;

    proptest! {
        #[test]
        fn roundtrip_receipt(receipt in arb::<AlloyEthereumReceipt<TxType>>()) {
            let mut compacted_receipt = Vec::<u8>::new();
            let len = receipt.to_compact(&mut compacted_receipt);
            let (decoded, _) = AlloyEthereumReceipt::<TxType>::from_compact(&compacted_receipt, len);
            assert_eq!(receipt, decoded)
        }
    }

    fn receipt(with_log: bool) -> AlloyEthereumReceipt<TxType> {
        let logs = if with_log {
            vec![Log::new_unchecked(
                alloy_primitives::Address::repeat_byte(0x22),
                vec![alloy_primitives::B256::repeat_byte(0x33)],
                alloy_primitives::Bytes::from_static(b"reth"),
            )]
        } else {
            vec![]
        };
        AlloyEthereumReceipt { tx_type: TxType::Eip1559, success: true, cumulative_gas_used: 21_000, logs }
    }

    // Encodings produced by the codec before the `len`/remainder fix. Decoding them proves the
    // on-disk format is unchanged.
    const UNCOMPRESSED: &str = "16520800";
    const COMPRESSED: &str = "9628b52ffd23fc4269613da5000058520801392201337265746802cc80d1c200102c";

    #[test]
    fn receipt_fixtures_and_remainder() {
        for (with_log, fixture) in [(false, UNCOMPRESSED), (true, COMPRESSED)] {
            let receipt = receipt(with_log);
            let fixture = alloy_primitives::hex::decode(fixture).unwrap();
            assert_eq!(fixture[0] >> 7, with_log as u8, "zstd flag");

            let mut buf = Vec::new();
            let len = receipt.to_compact(&mut buf);
            assert_eq!(buf, fixture, "encoding changed");
            assert_eq!(len, buf.len(), "to_compact must return bytes written");

            let (decoded, rest) = AlloyEthereumReceipt::<TxType>::from_compact(&fixture, fixture.len());
            assert_eq!(decoded, receipt);
            assert!(rest.is_empty());

            // Followed by trailing bytes: consume exactly `len` and return the rest.
            let mut trailing = fixture.clone();
            trailing.extend_from_slice(&[0xde, 0xad]);
            let (decoded, rest) = AlloyEthereumReceipt::<TxType>::from_compact(&trailing, len);
            assert_eq!(decoded, receipt);
            assert_eq!(rest, &[0xde, 0xad]);

            // Nested in a Vec, whose element framing uses the returned length.
            let receipts = vec![receipt.clone(), receipt.clone()];
            let mut nested = Vec::new();
            receipts.to_compact(&mut nested);
            let (decoded, rest) = Vec::<AlloyEthereumReceipt<TxType>>::from_compact(&nested, nested.len());
            assert_eq!(decoded, receipts);
            assert!(rest.is_empty());
        }
    }
}
