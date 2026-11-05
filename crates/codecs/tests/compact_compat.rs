//! Regression coverage against the pre-optimization scratch-buffer encoder.
#![cfg(feature = "std")]
#![allow(missing_docs)]

use alloy_primitives::{Bytes, FixedBytes, B256, U256};
use bytes::{buf::UninitSlice, BufMut, BytesMut};
use reth_codecs::Compact;
use std::panic::{catch_unwind, AssertUnwindSafe};

trait Legacy: Compact {
    fn legacy<B: BufMut + AsMut<[u8]>>(&self, buf: &mut B) -> usize;
}

#[derive(Debug, PartialEq, Compact)]
struct Record {
    nonce: u64,
    amount: u128,
    balance: U256,
    enabled: bool,
    optional: Option<u64>,
    hash: Option<B256>,
}

// Keep the old encoder's order, flag setters, scratch buffer, and length calculation.
impl Legacy for Record {
    fn legacy<B: BufMut + AsMut<[u8]>>(&self, buf: &mut B) -> usize {
        let mut flags = RecordFlags::default();
        let mut buffer = BytesMut::new();
        flags.set_nonce_len(self.nonce.to_compact(&mut buffer) as u8);
        flags.set_amount_len(self.amount.to_compact(&mut buffer) as u8);
        flags.set_balance_len(self.balance.to_compact(&mut buffer) as u8);
        flags.set_enabled_len(self.enabled.to_compact(&mut buffer) as u8);
        flags.set_optional_len(self.optional.to_compact(&mut buffer) as u8);
        flags.set_hash_len(self.hash.specialized_to_compact(&mut buffer) as u8);
        let flags = flags.into_bytes();
        let len = flags.len() + buffer.len();
        buf.put_slice(&flags);
        buf.put(buffer);
        len
    }
}

macro_rules! wrapper {
    ($name:ident, $($inner:tt)+) => {
        #[derive(Debug, PartialEq, Compact)]
        struct $name($($inner)+);
        impl Legacy for $name {
            fn legacy<B: BufMut + AsMut<[u8]>>(&self, buf: &mut B) -> usize {
                let mut buffer = BytesMut::new();
                self.0.to_compact(&mut buffer);
                let flags = $name::bitflag_encoded_bytes();
                assert_eq!(flags, 0);
                let len = buffer.len();
                buf.put_slice(&[]);
                buf.put(buffer);
                len
            }
        }
    };
}
wrapper!(Fixed, B256);
wrapper!(AtLimit, FixedBytes<256>);
wrapper!(OverLimit, FixedBytes<257>);
wrapper!(Variable, Bytes);

#[derive(Debug, PartialEq, Compact)]
struct FlagsOnly {
    a: bool,
    b: bool,
}
impl Legacy for FlagsOnly {
    fn legacy<B: BufMut + AsMut<[u8]>>(&self, buf: &mut B) -> usize {
        let mut flags = FlagsOnlyFlags::default();
        let mut buffer = BytesMut::new();
        flags.set_a_len(self.a.to_compact(&mut buffer) as u8);
        flags.set_b_len(self.b.to_compact(&mut buffer) as u8);
        let flags = flags.into_bytes();
        let len = flags.len() + buffer.len();
        buf.put_slice(&flags);
        buf.put(buffer);
        len
    }
}

#[derive(Debug, PartialEq, Compact)]
struct Empty {}
impl Legacy for Empty {
    fn legacy<B: BufMut + AsMut<[u8]>>(&self, buf: &mut B) -> usize {
        buf.put_slice(&[]);
        buf.put(BytesMut::new());
        0
    }
}

#[derive(Debug, PartialEq, Compact)]
enum Choice {
    Unit,
    Record(Record),
    Fixed(Fixed),
    Last,
}
impl Legacy for Choice {
    fn legacy<B: BufMut + AsMut<[u8]>>(&self, buf: &mut B) -> usize {
        let mut flags = ChoiceFlags::default();
        let mut buffer = BytesMut::new();
        flags.set_variant(match self {
            Self::Unit => 0,
            Self::Record(record) => {
                record.legacy(&mut buffer);
                1
            }
            Self::Fixed(fixed) => {
                fixed.legacy(&mut buffer);
                2
            }
            Self::Last => 3,
        });
        let flags = flags.into_bytes();
        let len = flags.len() + buffer.len();
        buf.put_slice(&flags);
        buf.put(buffer);
        len
    }
}

// Valid growable BufMut whose remaining capacity is constant and whose AsMut must
// never be used by the outer encoder. Neither trait promises backfilling support.
#[derive(Debug, Default)]
struct Opaque(Vec<u8>);
unsafe impl BufMut for Opaque {
    fn remaining_mut(&self) -> usize {
        usize::MAX
    }
    unsafe fn advance_mut(&mut self, count: usize) {
        // SAFETY: forwarded with the same initialization requirement.
        unsafe { self.0.advance_mut(count) }
    }
    fn chunk_mut(&mut self) -> &mut UninitSlice {
        self.0.chunk_mut()
    }
    fn put_slice(&mut self, src: &[u8]) {
        self.0.put_slice(src);
    }
}
impl AsMut<[u8]> for Opaque {
    fn as_mut(&mut self) -> &mut [u8] {
        panic!("destination AsMut must not be inspected")
    }
}

// A fixed buffer exposing all storage through AsMut, with a nonzero write cursor.
#[derive(Debug)]
struct Cursor {
    data: Vec<u8>,
    position: usize,
}
unsafe impl BufMut for Cursor {
    fn remaining_mut(&self) -> usize {
        self.data.len() - self.position
    }
    unsafe fn advance_mut(&mut self, count: usize) {
        assert!(count <= self.remaining_mut());
        self.position += count;
    }
    fn chunk_mut(&mut self) -> &mut UninitSlice {
        UninitSlice::new(&mut self.data[self.position..])
    }
}
impl AsMut<[u8]> for Cursor {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

fn compare<T: Legacy + PartialEq + std::fmt::Debug>(value: &T) {
    let mut expected = vec![];
    let expected_len = value.legacy(&mut expected);
    let mut actual = vec![];
    assert_eq!(value.to_compact(&mut actual), expected_len);
    assert_eq!(actual, expected);
    assert_eq!(T::from_compact(&expected, expected_len).0, *value);
    for prefix in [0, 3, 17] {
        let mut vec = vec![0xa5; prefix];
        assert_eq!(value.to_compact(&mut vec), expected_len);
        assert_eq!(&vec[..prefix], vec![0xa5; prefix]);
        assert_eq!(&vec[prefix..], expected);
        let mut bytes = BytesMut::from(&vec[..prefix]);
        assert_eq!(value.to_compact(&mut bytes), expected_len);
        assert_eq!(&bytes[..], &vec);
        let mut opaque = Opaque(vec![0xa5; prefix]);
        assert_eq!(value.to_compact(&mut opaque), expected_len);
        assert_eq!(opaque.0, vec);
        let mut cursor = Cursor { data: vec![0xa5; prefix + expected.len() + 2], position: prefix };
        assert_eq!(value.to_compact(&mut cursor), expected_len);
        assert_eq!(cursor.position, prefix + expected.len());
        assert_eq!(&cursor.data[..cursor.position], &vec);
        assert_eq!(&cursor.data[cursor.position..], &[0xa5; 2]);
    }
    for extra in [0, 2] {
        let mut storage = vec![0xa5; expected.len() + extra];
        let mut slice = storage.as_mut_slice();
        assert_eq!(value.to_compact(&mut slice), expected_len);
        assert_eq!(slice.len(), extra);
        assert_eq!(&storage[..expected.len()], &expected);
        assert_eq!(&storage[expected.len()..], vec![0xa5; extra]);
    }
}

fn record(n: u64, amount: u128, balance: U256, enabled: bool, some: bool) -> Record {
    Record {
        nonce: n,
        amount,
        balance,
        enabled,
        optional: some.then_some(n),
        hash: some.then_some(B256::repeat_byte(n as u8)),
    }
}

#[test]
fn boundary_values_and_destinations() {
    for n in [0, 1, 127, 128, 255, 256, u32::MAX as u64, u64::MAX] {
        for amount in [0, 1, 255, 256, u128::MAX] {
            for balance in [U256::ZERO, U256::from(256), U256::MAX] {
                for enabled in [false, true] {
                    for some in [false, true] {
                        compare(&record(n, amount, balance, enabled, some));
                    }
                }
            }
        }
    }
    compare(&Empty {});
    for a in [false, true] {
        for b in [false, true] {
            compare(&FlagsOnly { a, b });
        }
    }
    compare(&Fixed(B256::repeat_byte(0xab)));
    compare(&AtLimit(FixedBytes::repeat_byte(0xcc)));
    compare(&OverLimit(FixedBytes::repeat_byte(0xdd)));
    for len in [0, 1, 7, 8, 255, 256, 257, 4096] {
        compare(&Variable(Bytes::from(vec![0xce; len])));
    }
    compare(&Choice::Unit);
    compare(&Choice::Last);
    compare(&Choice::Fixed(Fixed(B256::repeat_byte(0xab))));
    compare(&Choice::Record(record(u64::MAX, u128::MAX, U256::MAX, true, true)));
}

#[test]
fn short_destination_preserves_previous_panic_and_partial_writes() {
    let value = record(0x123456, u128::MAX, U256::MAX, true, true);
    let mut encoded = vec![];
    value.legacy(&mut encoded);
    for capacity in 0..encoded.len() {
        let mut old = vec![0xa5; capacity];
        let mut new = old.clone();
        let mut old_slice = old.as_mut_slice();
        let mut new_slice = new.as_mut_slice();
        let old_panic = catch_unwind(AssertUnwindSafe(|| value.legacy(&mut old_slice)));
        let new_panic = catch_unwind(AssertUnwindSafe(|| value.to_compact(&mut new_slice)));
        assert!(old_panic.is_err() && new_panic.is_err());
        assert_eq!(old_slice.len(), new_slice.len());
        assert_eq!(old, new);
    }
}

#[derive(Debug, PartialEq)]
struct BufferSensitive;
impl Compact for BufferSensitive {
    fn to_compact<B: BufMut + AsMut<[u8]>>(&self, buf: &mut B) -> usize {
        assert_eq!(std::any::type_name::<B>(), std::any::type_name::<BytesMut>());
        assert!(buf.as_mut().is_empty());
        buf.put_u8(0xab);
        1
    }
    fn from_compact(buf: &[u8], _: usize) -> (Self, &[u8]) {
        (Self, &buf[1..])
    }
}
wrapper!(Custom, BufferSensitive);
#[test]
fn custom_fields_keep_the_original_scratch_buffer() {
    compare(&Custom(BufferSensitive));
}

proptest::proptest! {
    #[test]
    fn random_records_match_old_encoding(
        nonce: u64, amount: u128, balance: [u8; 32], enabled: bool, some: bool
    ) {
        compare(&record(nonce, amount, U256::from_be_bytes(balance), enabled, some));
    }
}

#[derive(Debug, PartialEq)]
struct Inherent;
impl Inherent {
    fn to_compact(&self, buf: &mut BytesMut) -> usize {
        BufferSensitive.to_compact(buf)
    }
    fn from_compact(buf: &[u8], _: usize) -> (Self, &[u8]) {
        (Self, &buf[1..])
    }
}
wrapper!(InherentWrapper, Inherent);
#[test]
fn inherent_codec_methods_remain_supported() {
    compare(&InherentWrapper(Inherent));
}

#[test]
fn previous_decoder_remainders_are_preserved() {
    let value = record(256, 257, U256::MAX, true, true);
    let mut bytes = vec![];
    let len = value.legacy(&mut bytes);
    bytes.extend_from_slice(&[0xab, 0xcd]);
    assert_eq!(Record::from_compact(&bytes, len), (value, &[0xab, 0xcd][..]));
    // The pre-existing enum decoder returns everything after the variant byte,
    // including its payload. Do not fix this as part of an encoding optimization.
    let value = Choice::Fixed(Fixed(B256::repeat_byte(0xee)));
    let mut bytes = vec![];
    let len = value.legacy(&mut bytes);
    bytes.extend_from_slice(&[0xab, 0xcd]);
    assert_eq!(Choice::from_compact(&bytes, len), (value, &bytes[1..]));
    // Likewise, a Bytes field consumes the whole remaining buffer, ignoring len.
    assert_eq!(
        Variable::from_compact(&[1, 2, 3], 1),
        (Variable(Bytes::from_static(&[1, 2, 3])), &[][..])
    );
}

#[cfg(feature = "alloy")]
mod compressed {
    use super::*;
    use reth_codecs::CompactZstd;
    use reth_zstd_compressors::{with_tx_compressor, with_tx_decompressor};

    #[derive(Debug, PartialEq, CompactZstd)]
    #[reth_zstd(compressor = with_tx_compressor, decompressor = with_tx_decompressor)]
    struct Compressed {
        payload: Bytes,
    }

    impl Legacy for Compressed {
        fn legacy<B: BufMut + AsMut<[u8]>>(&self, buf: &mut B) -> usize {
            let mut flags = CompressedFlags::default();
            let mut buffer = BytesMut::new();
            self.payload.to_compact(&mut buffer);
            let zstd = buffer.len() > 7;
            if zstd {
                flags.set___zstd(1);
            }
            let flags = flags.into_bytes();
            let len = flags.len() + buffer.len();
            buf.put_slice(&flags);
            if zstd {
                with_tx_compressor(|compressor| {
                    let compressed = compressor.compress(&buffer).expect("Failed to compress.");
                    buf.put(compressed.as_slice());
                });
            } else {
                buf.put(buffer);
            }
            len
        }
    }

    #[test]
    fn zstd_threshold_bytes_and_logical_length_are_unchanged() {
        for len in [0, 1, 6, 7, 8, 9, 255, 256, 257, 4096] {
            compare(&Compressed { payload: Bytes::from(vec![0xab; len]) });
            compare(&Compressed {
                payload: Bytes::from((0..len).map(|i| i as u8).collect::<Vec<_>>()),
            });
        }
    }
}

#[derive(Debug, Compact)]
struct Borrowed<'a> {
    nonce: &'a u64,
    balance: &'a U256,
}
#[test]
fn reference_fields_preserve_encoding_and_decode_panic() {
    let nonce = u64::MAX;
    let balance = U256::MAX;
    let value = Borrowed { nonce: &nonce, balance: &balance };
    let mut flags = BorrowedFlags::default();
    let mut payload = BytesMut::new();
    flags.set_nonce_len(nonce.to_compact(&mut payload) as u8);
    flags.set_balance_len(balance.to_compact(&mut payload) as u8);
    let mut expected = flags.into_bytes().to_vec();
    expected.extend_from_slice(&payload);
    let mut actual = Opaque::default();
    assert_eq!(value.to_compact(&mut actual), expected.len());
    assert_eq!(actual.0, expected);
    assert!(catch_unwind(|| Borrowed::from_compact(&expected, expected.len())).is_err());
}

// Run this same test file against main and the proposed implementation. The digest
// includes actual encoded bytes, returned lengths, decoded values, remaining bytes,
// and panic outcomes for malformed/truncated inputs. It is intentionally independent
// of the optimization metadata so that it also compiles against the old crate.
#[test]
#[ignore = "cross-version compatibility corpus; run explicitly against both revisions"]
fn cross_version_corpus() {
    use std::hash::{DefaultHasher, Hash, Hasher};
    let mut digest = DefaultHasher::new();
    let mut state = 0x48a7_6219_3e0d_b5fcu64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for i in 0..1_000_000 {
        let nonce = next() >> (i % 64);
        let amount = ((u128::from(next()) << 64) | u128::from(next())) >> (i % 128);
        let balance = U256::from_limbs([next(), next(), next(), next()]) >> (i % 256);
        let value = record(nonce, amount, balance, next() & 1 != 0, next() & 1 != 0);
        let mut bytes = vec![0xa5; i % 17];
        let mut expected = bytes.clone();
        let len = value.to_compact(&mut bytes);
        assert_eq!(len, value.legacy(&mut expected));
        assert_eq!(bytes, expected);
        bytes.hash(&mut digest);
        len.hash(&mut digest);
        let (decoded, remaining) = Record::from_compact(&bytes[i % 17..], len);
        assert_eq!(decoded, value);
        assert!(remaining.is_empty());
    }
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    // Exhaust all 16 bits holding the integer lengths and bool flag. Other flags,
    // payload contents, truncation, and supplied len vary deterministically.
    for flags in 0..=u16::MAX {
        let size = (next() as usize) % 180;
        let mut bytes: Vec<u8> = (0..size).map(|_| next() as u8).collect();
        if bytes.len() >= 2 {
            bytes[..2].copy_from_slice(&flags.to_le_bytes());
        }
        for len in [0, size, usize::MAX] {
            match catch_unwind(|| Record::from_compact(&bytes, len)) {
                Ok((value, remaining)) => {
                    true.hash(&mut digest);
                    format!("{value:?}").hash(&mut digest);
                    remaining.hash(&mut digest);
                }
                Err(_) => false.hash(&mut digest),
            }
        }
    }
    std::panic::set_hook(hook);
    println!("compatibility digest: {:016x}", digest.finish());
}
